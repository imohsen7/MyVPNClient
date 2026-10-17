package net.imohsen7.l2tpvpn.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object Bin {
    fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    fun u32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    fun readU16(b: ByteArray, o: Int = 0): Int = ((b[o].toInt() and 255) shl 8) or (b[o + 1].toInt() and 255)
    fun readU32(b: ByteArray, o: Int = 0): Long = ((b[o].toLong() and 255) shl 24) or ((b[o + 1].toLong() and 255) shl 16) or ((b[o + 2].toLong() and 255) shl 8) or (b[o + 3].toLong() and 255)
    fun cat(vararg items: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        items.forEach { out.write(it) }
        return out.toByteArray()
    }
    fun padLeft(b: ByteArray, len: Int): ByteArray {
        if (b.size >= len) return b.copyOfRange(b.size - len, b.size)
        return ByteArray(len - b.size) + b
    }
    fun eq(a: ByteArray, b: ByteArray): Boolean = a.contentEquals(b)
    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    fun fromHex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    fun ipv4(s: String): ByteArray {
        val p = s.split('.')
        require(p.size == 4) { "IPv4 address required" }
        return p.map { it.toInt().also { n -> require(n in 0..255) }.toByte() }.toByteArray()
    }
    fun ipv4String(b: ByteArray, offset: Int = 0): String = (0..3).joinToString(".") { (b[offset + it].toInt() and 255).toString() }
    fun random(n: Int): ByteArray = ByteArray(n).also { java.security.SecureRandom().nextBytes(it) }
    fun tv(type: Int, value: Int): ByteArray = cat(u16(0x8000 or type), u16(value))
    fun tlv(type: Int, value: ByteArray): ByteArray = cat(u16(type), u16(value.size), value)
    fun parseAttributes(raw: ByteArray): Map<Int, ByteArray> {
        val out = linkedMapOf<Int, ByteArray>()
        var p = 0
        while (p + 4 <= raw.size) {
            val t = readU16(raw, p); val lenOrValue = readU16(raw, p + 2); p += 4
            if ((t and 0x8000) != 0) out[t and 0x7fff] = u16(lenOrValue)
            else {
                if (p + lenOrValue > raw.size) break
                out[t] = raw.copyOfRange(p, p + lenOrValue); p += lenOrValue
            }
        }
        return out
    }
}

data class IkePayload(val type: Int, val body: ByteArray) {
    fun encode(nextType: Int): ByteArray = Bin.cat(byteArrayOf(nextType.toByte(), 0), Bin.u16(body.size + 4), body)
}

data class IkePacket(
    val initiatorCookie: ByteArray,
    val responderCookie: ByteArray,
    val nextPayload: Int,
    val exchangeType: Int,
    val flags: Int,
    val messageId: Long,
    val payloadBytes: ByteArray
) {
    fun encode(): ByteArray = Bin.cat(
        initiatorCookie, responderCookie,
        byteArrayOf(nextPayload.toByte(), 0x10, exchangeType.toByte(), flags.toByte()),
        Bin.u32(messageId), Bin.u32(28L + payloadBytes.size), payloadBytes
    )
    companion object {
        fun parse(b: ByteArray): IkePacket {
            require(b.size >= 28) { "IKE packet too short" }
            val len = Bin.readU32(b, 24).toInt()
            require(len in 28..b.size) { "Invalid IKE length" }
            return IkePacket(b.copyOfRange(0,8), b.copyOfRange(8,16), b[16].toInt() and 255,
                b[18].toInt() and 255, b[19].toInt() and 255, Bin.readU32(b,20), b.copyOfRange(28,len))
        }
    }
}

internal fun encodePayloadChain(payloads: List<IkePayload>): Pair<Int, ByteArray> {
    if (payloads.isEmpty()) return 0 to ByteArray(0)
    val out = ByteArrayOutputStream()
    payloads.forEachIndexed { i, p -> out.write(p.encode(payloads.getOrNull(i + 1)?.type ?: 0)) }
    return payloads.first().type to out.toByteArray()
}

internal fun decodePayloadChain(firstType: Int, bytes: ByteArray): List<IkePayload> {
    val out = mutableListOf<IkePayload>()
    var type = firstType
    var pos = 0
    while (type != 0 && pos + 4 <= bytes.size && out.size < 64) {
        val next = bytes[pos].toInt() and 255
        val size = Bin.readU16(bytes, pos + 2)
        if (size < 4 || pos + size > bytes.size) break
        out += IkePayload(type, bytes.copyOfRange(pos + 4, pos + size))
        pos += size
        type = next
    }
    return out
}
