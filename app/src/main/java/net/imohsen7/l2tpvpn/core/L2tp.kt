package net.imohsen7.l2tpvpn.core

import java.io.ByteArrayOutputStream
import java.util.ArrayDeque

/** L2TPv2 control and data channel (RFC 2661). The caller supplies already-protected UDP/1701 payloads. */
internal class L2tpLayer(
    private val sendProtectedUdp: (ByteArray) -> Unit,
    private val receiveProtectedUdp: (Int) -> ByteArray?,
    private val log: (String) -> Unit
) {
    private val localTunnelId = nonZero16()
    private val localSessionId = nonZero16()
    private var remoteTunnelId = 0
    private var remoteSessionId = 0
    private var sendNs = 0
    private var peerNs = -1
    private var sendNr = 0
    private val pendingPpp = ArrayDeque<ByteArray>()

    fun establish() {
        log("L2TP: ارسال SCCRQ")
        sendControl(1, 0, 0, listOf(
            avp(2, byteArrayOf(1,0)), // Protocol Version 1.0
            avp(3, Bin.u32(3)),       // Framing Capabilities
            avp(4, Bin.u32(0)),       // Bearer Capabilities
            avp(6, Bin.u16(0x0100)),  // Firmware Revision
            avp(7, "Android-L2TP".toByteArray(Charsets.US_ASCII)),
            avp(8, "Local custom client".toByteArray(Charsets.US_ASCII)),
            avp(9, Bin.u16(localTunnelId)),
            avp(10, Bin.u16(4))
        ))
        val sccrp = awaitControl(2, 12000)
        remoteTunnelId = sccrp.avps[9]?.let { Bin.readU16(it) } ?: error("پاسخ L2TP فاقد Assigned Tunnel ID است")
        require(remoteTunnelId != 0) { "شناسهٔ تونل L2TP نامعتبر است" }
        log("L2TP: تونل کنترل ایجاد شد")
        acknowledgePeer()
        sendControl(3, remoteTunnelId, 0, emptyList()) // SCCCN
        sendControl(10, remoteTunnelId, 0, listOf(
            avp(14, Bin.u16(localSessionId)),
            avp(15, Bin.u32((System.currentTimeMillis() / 1000L) and 0xffffffffL)),
            avp(16, Bin.u32(1000000)), avp(17, Bin.u32(100000000)),
            avp(18, Bin.u32(0)), avp(19, Bin.u32(3))
        )) // ICRQ
        val icrp = awaitControl(11, 12000)
        remoteSessionId = icrp.avps[14]?.let { Bin.readU16(it) } ?: error("پاسخ L2TP فاقد Assigned Session ID است")
        require(remoteSessionId != 0) { "شناسهٔ نشست L2TP نامعتبر است" }
        acknowledgePeer()
        sendControl(12, remoteTunnelId, 0, listOf(
            avp(24, Bin.u32(100000000)), // Tx Connect Speed
            avp(19, Bin.u32(3))          // Framing Type
        )) // ICCN; control packets use Session ID = 0 in the L2TP header.
        log("L2TP: نشست ایجاد شد؛ مذاکرهٔ PPP آغاز می‌شود")
    }

    fun sendPpp(frame: ByteArray) {
        require(remoteTunnelId != 0 && remoteSessionId != 0) { "L2TP session is not open" }
        val hdr = Bin.cat(Bin.u16(0x0002), Bin.u16(remoteTunnelId), Bin.u16(remoteSessionId))
        sendProtectedUdp(Bin.cat(hdr, frame))
    }

    fun receivePpp(timeoutMs: Int = 1000): ByteArray? {
        if (pendingPpp.isNotEmpty()) return pendingPpp.removeFirst()
        val packet = receiveProtectedUdp(timeoutMs) ?: return null
        if (packet.size < 2) return null
        val flags = Bin.readU16(packet, 0)
        val isControl = (flags and 0x8000) != 0
        return if (isControl) {
            val msg = parseControl(packet)
            if (msg != null) {
                acknowledgePeer()
                if (msg.type == 4) error("سرور L2TP نشست را متوقف کرد")
            }
            null
        } else {
            if (packet.size < 6) return null
            val tunnel = Bin.readU16(packet, 2); val session = Bin.readU16(packet, 4)
            if (tunnel != localTunnelId || session != localSessionId) return null
            packet.copyOfRange(6, packet.size).takeIf { it.isNotEmpty() }
        }
    }

    private data class ControlMessage(val type: Int, val avps: Map<Int, ByteArray>, val ns: Int)

    private fun awaitControl(expectedType: Int, timeoutMs: Int): ControlMessage {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val remaining = (deadline - System.currentTimeMillis()).coerceAtMost(1000L).toInt().coerceAtLeast(100)
            val packet = receiveProtectedUdp(remaining) ?: continue
            if (packet.size < 2) continue
            if ((Bin.readU16(packet,0) and 0x8000) == 0) {
                if (packet.size >= 6) pendingPpp.add(packet.copyOfRange(6,packet.size))
                continue
            }
            val msg = parseControl(packet) ?: continue
            if (msg.type == expectedType) return msg
            if (msg.type == 4) error("سرور L2TP پیام StopCCN فرستاد")
            if (msg.type == 1) error("سرور به‌جای پاسخ L2TP، SCCRQ فرستاده است")
        }
        error("مهلت انتظار برای پیام L2TP نوع $expectedType تمام شد")
    }

    private fun parseControl(packet: ByteArray): ControlMessage? {
        if (packet.size < 12) return null
        val flags = Bin.readU16(packet,0)
        val hasLength = flags and 0x4000 != 0
        val hasSequence = flags and 0x0800 != 0
        var p = 2
        val declared = if (hasLength) Bin.readU16(packet,p).also { p += 2 } else packet.size
        if (declared > packet.size || declared < p + 4) return null
        val tunnelId = Bin.readU16(packet,p); p += 2
        val sessionId = Bin.readU16(packet,p); p += 2
        if (sessionId != 0) return null // RFC 2661 control messages use Session ID = 0.
        val sequenceHeaderEnd = p + if (hasSequence) 4 else 0
        if (sequenceHeaderEnd > declared) return null
        if (sequenceHeaderEnd == declared) return null // ZLB ACKs are not sequenced and must not be ACKed again.
        var ns = 0
        if (hasSequence) {
            ns = Bin.readU16(packet,p)
            p += 4 // Ns and Nr. We don't track our peer's acknowledgement of outgoing Ns yet.
        }
        if (peerNs >= 0 && hasSequence && ns != ((peerNs + 1) and 0xffff)) {
            // A duplicate or out-of-order control packet is acknowledged but never processed twice.
            acknowledgePeer(); return null
        }
        if (hasSequence) {
            peerNs = ns
            sendNr = (ns + 1) and 0xffff
        }
        val avps = mutableMapOf<Int, ByteArray>()
        while (p + 6 <= declared) {
            val flagsLen = Bin.readU16(packet,p); val avpLen = flagsLen and 0x03ff
            if (avpLen < 6 || p + avpLen > declared) break
            val vendor = Bin.readU16(packet,p + 2); val attrType = Bin.readU16(packet,p + 4)
            if (vendor == 0 && avpLen >= 6) avps[attrType] = packet.copyOfRange(p + 6, p + avpLen)
            p += avpLen
        }
        val typeBytes = avps[0] ?: return null
        if (typeBytes.size < 2) return null
        val msgType = Bin.readU16(typeBytes)
        // A response is addressed with the locally assigned tunnel/session IDs in the header.
        if (hasLength && tunnelId != localTunnelId && tunnelId != remoteTunnelId && tunnelId != 0) {
            log("L2TP: پیام کنترلی با Tunnel ID غیرمنتظره نادیده گرفته شد")
        }
        return ControlMessage(msgType, avps, ns)
    }

    private fun acknowledgePeer() {
        val destTunnel = if (remoteTunnelId != 0) remoteTunnelId else 0
        val header = Bin.cat(Bin.u16(0xC802), Bin.u16(12), Bin.u16(destTunnel), Bin.u16(0), Bin.u16(sendNs), Bin.u16(sendNr))
        sendProtectedUdp(header)
    }

    private fun sendControl(type: Int, destTunnelId: Int, destSessionId: Int, attrs: List<ByteArray>) {
        val messageAvps = listOf(avp(0, Bin.u16(type))) + attrs
        val body = messageAvps.fold(ByteArray(0)) { a, b -> Bin.cat(a,b) }
        val size = 12 + body.size
        val hdr = Bin.cat(Bin.u16(0xC802), Bin.u16(size), Bin.u16(destTunnelId), Bin.u16(destSessionId), Bin.u16(sendNs), Bin.u16(sendNr))
        sendProtectedUdp(Bin.cat(hdr, body))
        sendNs = (sendNs + 1) and 0xffff
    }

    private fun avp(type: Int, value: ByteArray): ByteArray {
        val len = 6 + value.size
        require(len <= 1023)
        return Bin.cat(Bin.u16(0x8000 or len), Bin.u16(0), Bin.u16(type), value)
    }

    private fun nonZero16(): Int = Bin.readU16(Bin.random(2)).let { if (it == 0) 1 else it }
}
