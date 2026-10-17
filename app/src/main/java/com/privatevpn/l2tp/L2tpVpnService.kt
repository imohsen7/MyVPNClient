package com.privatevpn.l2tp

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

class L2tpVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "CONNECT" -> {
                val server = intent.getStringExtra("SERVER") ?: ""
                val user = intent.getStringExtra("USERNAME") ?: ""
                val pass = intent.getStringExtra("PASSWORD") ?: ""
                startTunnel(server, user, pass)
            }
            "DISCONNECT" -> {
                stopTunnel("توسط کاربر قطع شد")
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(serverHost: String, user: String, pass: String) {
        if (running) return
        broadcastState("CONNECTING", "")

        workerThread = Thread {
            var channel: DatagramChannel? = null
            try {
                val serverAddress = InetAddress.getByName(serverHost)
                channel = DatagramChannel.open()
                if (!protect(channel.socket())) {
                    throw IllegalStateException("خطا در محافظت سوکت VPN")
                }

                channel.connect(InetSocketAddress(serverAddress, 1701))
                channel.configureBlocking(false)

                // ارسال بسته اولیه L2TP Control (SCCRQ)
                val sccrq = buildL2tpSccrqPacket()
                channel.write(sccrq)

                val builder = Builder()
                    .setSession("PrivateL2TP")
                    .setMtu(1400)
                    .addAddress("10.0.0.2", 24)
                    .addDnsServer("8.8.8.8")
                    .addRoute("0.0.0.0", 0)

                vpnInterface = builder.establish()
                    ?: throw IllegalStateException("عدم صدور مجوز رابط VPN")

                running = true
                broadcastState("CONNECTED", "")

                val input = FileInputStream(vpnInterface!!.fileDescriptor)
                val output = FileOutputStream(vpnInterface!!.fileDescriptor)
                val outPacket = ByteBuffer.allocate(4096)
                val inPacket = ByteBuffer.allocate(4096)

                while (running && !Thread.currentThread().isInterrupted) {
                    var idle = true

                    val readBytes = input.read(outPacket.array())
                    if (readBytes > 0) {
                        outPacket.limit(readBytes)
                        channel.write(outPacket)
                        outPacket.clear()
                        idle = false
                    }

                    val netBytes = channel.read(inPacket)
                    if (netBytes > 0) {
                        output.write(inPacket.array(), 0, netBytes)
                        inPacket.clear()
                        idle = false
                    }

                    if (idle) {
                        Thread.sleep(15)
                    }
                }
            } catch (e: Exception) {
                broadcastState("DISCONNECTED", e.localizedMessage ?: "خطای شبکه")
            } finally {
                try { channel?.close() } catch (_: Exception) {}
                stopTunnel("")
            }
        }.apply { start() }
    }

    private fun buildL2tpSccrqPacket(): ByteBuffer {
        // هدر استاندارد L2TPv2 Control Message (SCCRQ)
        val buffer = ByteBuffer.allocate(38)
        buffer.putShort(0xC802.toShort()) // Flags: Control, Length, Sequence, Ver=2
        buffer.putShort(38.toShort())     // Length
        buffer.putShort(0.toShort())      // Tunnel ID = 0
        buffer.putShort(0.toShort())      // Session ID = 0
        buffer.putShort(0.toShort())      // Ns = 0
        buffer.putShort(0.toShort())      // Nr = 0
        // AVP: Message Type = SCCRQ (1)
        buffer.putShort(0x8008.toShort())
        buffer.putShort(0.toShort())
        buffer.putShort(0.toShort())
        buffer.putShort(1.toShort())
        // AVP: Protocol Version (1.0)
        buffer.putShort(0x8008.toShort())
        buffer.putShort(0.toShort())
        buffer.putShort(2.toShort())
        buffer.putShort(0x0100.toShort())
        // AVP: Host Name ("android")
        buffer.putShort(0x800D.toShort())
        buffer.putShort(0.toShort())
        buffer.putShort(7.toShort())
        buffer.put("android".toByteArray())
        buffer.flip()
        return buffer
    }

    private fun stopTunnel(reason: String) {
        val wasRunning = running
        running = false
        workerThread?.interrupt()
        workerThread = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        if (wasRunning || reason.isNotEmpty()) {
            broadcastState("DISCONNECTED", reason)
        }
        stopSelf()
    }

    private fun broadcastState(state: String, message: String) {
        val intent = Intent("com.privatevpn.l2tp.STATE").apply {
            setPackage(packageName)
            putExtra("STATE", state)
            putExtra("MESSAGE", message)
        }
        sendBroadcast(intent)
    }

    override fun onDestroy() {
        stopTunnel("")
        super.onDestroy()
    }
}
