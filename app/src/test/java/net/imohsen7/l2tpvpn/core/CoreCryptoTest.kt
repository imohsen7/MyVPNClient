package net.imohsen7.l2tpvpn.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

class CoreCryptoTest {
    @Test fun md4MatchesPublishedVectors() {
        assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", Bin.hex(Crypto.md4(byteArrayOf())))
        assertEquals("bde52cb31de33e46245e05fbdbd6fb24", Bin.hex(Crypto.md4("a".toByteArray(Charsets.US_ASCII))))
    }

    @Test fun aesCbcRoundTrip() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val iv = ByteArray(16) { (it + 30).toByte() }
        val clear = ByteArray(64) { (it * 7).toByte() }
        val encrypted = Crypto.aesCbc(true, key, iv, clear)
        assertArrayEquals(clear, Crypto.aesCbc(false, key, iv, encrypted))
    }

    @Test fun ikePacketPayloadChainRoundTrip() {
        val payloads = listOf(IkePayload(10, byteArrayOf(1, 2, 3)), IkePayload(5, byteArrayOf(4, 5, 6, 7)))
        val (firstType, body) = encodePayloadChain(payloads)
        val decoded = decodePayloadChain(firstType, body)
        assertEquals(2, decoded.size)
        assertEquals(10, decoded[0].type)
        assertArrayEquals(payloads[0].body, decoded[0].body)
        assertEquals(5, decoded[1].type)
        assertArrayEquals(payloads[1].body, decoded[1].body)

        val packet = IkePacket(ByteArray(8) { it.toByte() }, ByteArray(8) { (it + 8).toByte() }, firstType, 2, 0, 0, body)
        val parsed = IkePacket.parse(packet.encode())
        assertEquals(packet.exchangeType, parsed.exchangeType)
        assertEquals(packet.messageId, parsed.messageId)
        assertArrayEquals(packet.initiatorCookie, parsed.initiatorCookie)
        assertArrayEquals(packet.responderCookie, parsed.responderCookie)
        assertArrayEquals(packet.payloadBytes, parsed.payloadBytes)
    }

    @Test fun modpPublicKeyLengthsAndSharedSecret() {
        val a = BigInteger.valueOf(1234567)
        val b = BigInteger.valueOf(7654321)
        val pubA = Crypto.modpPublic(2, a)
        val pubB = Crypto.modpPublic(2, b)
        assertEquals(128, pubA.size)
        assertEquals(128, pubB.size)
        assertArrayEquals(Crypto.modpShared(2, pubB, a), Crypto.modpShared(2, pubA, b))
        assertEquals(256, Crypto.modpPublic(14, BigInteger.valueOf(12345)).size)
    }
}
