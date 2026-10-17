package net.imohsen7.l2tpvpn.core

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

internal data class VpnProfile(
    val server: String,
    val username: String,
    val password: String,
    val preSharedKey: String
)

/** Orchestrates independently implemented IKEv1, ESP, L2TPv2 and PPP layers. */
internal class L2tpClient(
    private val service: VpnService,
    private val profile: VpnProfile,
    private val log: (String) -> Unit,
    private val cancelled: AtomicBoolean
) : Closeable {
    private val serverAddress: InetAddress = InetAddress.getAllByName(profile.server.trim()).firstOrNull { it is Inet4Address }
        ?: throw IllegalArgumentException("سرور باید IPv4 داشته باشد؛ تونل IPv6 در این نسخه پیاده‌سازی نشده است")
    private val socket = DatagramSocket(null)
    private lateinit var esp: EspChannel
    private lateinit var l2tp: L2tpLayer
    private lateinit var ppp: PppSession
    private var lastKeepaliveAt = System.currentTimeMillis()

    init {
        try { socket.bind(InetSocketAddress(4500)) }
        catch (_: Exception) { socket.bind(InetSocketAddress(0)) }
        socket.soTimeout = 1000
        if (!service.protect(socket)) throw IllegalStateException("اندروید اجازهٔ خارج‌کردن سوکت VPN از تونل را نداد")
    }

    fun connect(): IpConfiguration {
        require(profile.server.isNotBlank() && profile.username.isNotBlank()) { "آدرس سرور و نام کاربری را وارد کنید" }
        require(profile.password.isNotEmpty() && profile.preSharedKey.isNotEmpty()) { "رمز PPP و کلید پیش‌اشتراک‌شدهٔ IPsec الزامی است" }
        val ike = Ikev1(socket, serverAddress, profile.preSharedKey, log, cancelled)
        val material = ike.establish()
        esp = EspChannel(socket, material, log)
        l2tp = L2tpLayer({ esp.sendUdp1701(it) }, { timeout -> esp.receiveUdp1701(timeout) }, log)
        l2tp.establish()
        ppp = PppSession(profile.username, profile.password, { l2tp.sendPpp(it) }, log)
        ppp.start()
        val deadline = System.currentTimeMillis() + 60000
        while (System.currentTimeMillis() < deadline && !cancelled.get()) {
            maybeKeepalive()
            val frame = l2tp.receivePpp(1000) ?: continue
            ppp.process(frame)
            if (ppp.isConnected()) {
                log("اتصال VPN برقرار شد")
                return ppp.ipConfiguration()
            }
        }
        if (cancelled.get()) throw InterruptedException("اتصال لغو شد")
        error("مذاکرهٔ PPP/IPCP در ۶۰ ثانیه کامل نشد؛ لاگ‌های L2TP و احراز هویت را بررسی کنید")
    }

    fun sendIpPacket(packet: ByteArray) {
        if (cancelled.get() || packet.isEmpty()) return
        val frame = Bin.cat(byteArrayOf(0xff.toByte(), 0x03), Bin.u16(0x0021), packet)
        l2tp.sendPpp(frame)
    }

    fun receiveIpPacket(timeoutMs: Int = 1000): ByteArray? {
        maybeKeepalive()
        val frame = l2tp.receivePpp(timeoutMs) ?: return null
        return ppp.process(frame)
    }

    private fun maybeKeepalive() {
        val now = System.currentTimeMillis()
        if (now - lastKeepaliveAt >= 20000 && socket.isConnected && !cancelled.get()) {
            try {
                val b = byteArrayOf(0xff.toByte())
                socket.send(DatagramPacket(b, b.size)) // RFC 3948 NAT-T keepalive
            } catch (_: Exception) { }
            lastKeepaliveAt = now
        }
    }

    override fun close() {
        cancelled.set(true)
        try { socket.close() } catch (_: Exception) { }
    }
}
