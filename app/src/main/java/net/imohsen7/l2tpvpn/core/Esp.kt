package net.imohsen7.l2tpvpn.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketTimeoutException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

/** RFC 4303-style ESP transport payloads carried in UDP/4500 as specified by RFC 3948. */
internal class EspChannel(
    private val socket: DatagramSocket,
    private val material: EspMaterial,
    private val log: (String) -> Unit
) {
    private var outboundSequence = 1L
    private var highestInboundSequence = 0L

    @Synchronized fun sendUdp1701(payload: ByteArray) {
        require(payload.size <= 60000) { "L2TP datagram too large" }
        val udp = Bin.cat(Bin.u16(1701), Bin.u16(1701), Bin.u16(payload.size + 8), byteArrayOf(0,0), payload)
        val padLen = (16 - ((udp.size + 2) % 16)) % 16
        val padding = ByteArray(padLen) { (it + 1).toByte() }
        val clear = Bin.cat(udp, padding, byteArrayOf(padLen.toByte(), 17))
        val iv = Bin.random(16)
        val cipher = Crypto.aesCbc(true, material.outboundEncryptionKey, iv, clear)
        val head = Bin.cat(material.remoteSpi, Bin.u32(outboundSequence++))
        val authenticated = Bin.cat(head, iv, cipher)
        val icv = mac(material.espHash, material.outboundAuthenticationKey, authenticated).copyOf(material.icvLength)
        val wire = Bin.cat(authenticated, icv)
        socket.send(DatagramPacket(wire, wire.size)) // UDP socket already connected to the peer's port 4500.
    }

    fun receiveUdp1701(timeoutMs: Int = 1000): ByteArray? {
        socket.soTimeout = timeoutMs
        val buffer = ByteArray(65535)
        val packet = DatagramPacket(buffer, buffer.size)
        try { socket.receive(packet) } catch (_: SocketTimeoutException) { return null }
        var wire = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        if (packet.port != 4500) return null
        if (wire.size >= 4 && wire[0] == 0.toByte() && wire[1] == 0.toByte() && wire[2] == 0.toByte() && wire[3] == 0.toByte()) return null // IKE/non-ESP marker
        if (wire.size < 8 + 16 + 16 + material.icvLength) return null
        if (!wire.copyOfRange(0, 4).contentEquals(material.localSpi)) return null
        val icvOffset = wire.size - material.icvLength
        val signed = wire.copyOfRange(0, icvOffset)
        val actualIcv = wire.copyOfRange(icvOffset, wire.size)
        val expectedIcv = mac(material.espHash, material.inboundAuthenticationKey, signed).copyOf(material.icvLength)
        if (!MessageDigest.isEqual(actualIcv, expectedIcv)) {
            log("ESP: بسته با ICV نامعتبر حذف شد")
            return null
        }
        val seq = Bin.readU32(wire, 4)
        if (seq <= highestInboundSequence) return null
        highestInboundSequence = seq
        val iv = wire.copyOfRange(8, 24)
        val ciphertext = wire.copyOfRange(24, icvOffset)
        if (ciphertext.isEmpty() || ciphertext.size % 16 != 0) return null
        val clear = try { Crypto.aesCbc(false, material.inboundEncryptionKey, iv, ciphertext) } catch (_: Exception) { return null }
        if (clear.size < 2) return null
        val padLen = clear[clear.size - 2].toInt() and 255
        val nextHeader = clear.last().toInt() and 255
        if (nextHeader != 17 || padLen + 2 > clear.size) return null
        val udp = clear.copyOfRange(0, clear.size - padLen - 2)
        if (udp.size < 8 || Bin.readU16(udp, 0) != 1701 || Bin.readU16(udp, 2) != 1701) return null
        val udpLen = Bin.readU16(udp, 4)
        if (udpLen < 8 || udpLen > udp.size) return null
        return udp.copyOfRange(8, udpLen)
    }

    private fun mac(hash: String, key: ByteArray, data: ByteArray): ByteArray {
        val algorithm = if (hash == "SHA256") "HmacSHA256" else "HmacSHA1"
        val m = Mac.getInstance(algorithm)
        m.init(SecretKeySpec(key, algorithm)); return m.doFinal(data)
    }
}
