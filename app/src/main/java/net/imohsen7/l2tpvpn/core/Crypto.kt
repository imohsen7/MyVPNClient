package net.imohsen7.l2tpvpn.core

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

internal object Crypto {
    private val p1024 = BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
        "FFFFFFFFFFFFFFFF", 16)
    private val p2048 = BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

    fun digest(hash: String, vararg blocks: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(if (hash == "SHA256") "SHA-256" else "SHA-1")
        blocks.forEach { md.update(it) }
        return md.digest()
    }
    fun prf(hash: String, key: ByteArray, vararg blocks: ByteArray): ByteArray {
        val m = Mac.getInstance(if (hash == "SHA256") "HmacSHA256" else "HmacSHA1")
        m.init(SecretKeySpec(key, m.algorithm)); blocks.forEach { m.update(it) }
        return m.doFinal()
    }
    fun expandPrf(hash: String, key: ByteArray, requested: Int): ByteArray {
        if (requested <= key.size) return key.copyOf(requested)
        var prev = prf(hash, key, byteArrayOf(0))
        val out = java.io.ByteArrayOutputStream()
        out.write(prev)
        while (out.size() < requested) {
            prev = prf(hash, key, prev)
            out.write(prev)
        }
        return out.toByteArray().copyOf(requested)
    }
    fun aesCbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }
    fun modpPublic(group: Int, privateValue: BigInteger): ByteArray {
        val p = prime(group)
        return Bin.padLeft(BigInteger.valueOf(2).modPow(privateValue, p).toByteArray().let { if (it.firstOrNull() == 0.toByte()) it.copyOfRange(1,it.size) else it }, p.bitLength() / 8)
    }
    fun modpShared(group: Int, peerPublic: ByteArray, privateValue: BigInteger): ByteArray {
        val p = prime(group); val y = BigInteger(1, peerPublic)
        require(y > BigInteger.ONE && y < p.subtract(BigInteger.ONE)) { "Invalid DH peer public value" }
        val shared = y.modPow(privateValue, p).toByteArray().let { if (it.firstOrNull() == 0.toByte()) it.copyOfRange(1,it.size) else it }
        return Bin.padLeft(shared, p.bitLength() / 8)
    }
    private fun prime(group: Int): BigInteger = when (group) {
        2 -> p1024
        14 -> p2048
        else -> throw IllegalArgumentException("Unsupported DH group $group")
    }
    fun modpPrivate(group: Int): BigInteger {
        val bytes = Bin.random(if (group == 2) 32 else 48)
        return BigInteger(1, bytes).mod(prime(group).subtract(BigInteger.valueOf(3))).add(BigInteger.valueOf(2))
    }
    fun md4(message: ByteArray): ByteArray {
        // RFC 1320 MD4, used only by the PPP MS-CHAPv2 password-hash step.
        val len = message.size.toLong() * 8
        val padLen = ((56 - ((message.size + 1) % 64) + 64) % 64)
        val padded = message + byteArrayOf(0x80.toByte()) + ByteArray(padLen) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(len).array()
        var a0 = 0x67452301; var b0 = 0xefcdab89.toInt(); var c0 = 0x98badcfe.toInt(); var d0 = 0x10325476
        fun rot(x: Int, n: Int) = (x shl n) or (x ushr (32 - n))
        fun f(x:Int,y:Int,z:Int)=(x and y) or (x.inv() and z)
        fun g(x:Int,y:Int,z:Int)=(x and y) or (x and z) or (y and z)
        fun h(x:Int,y:Int,z:Int)=x xor y xor z
        for (off in padded.indices step 64) {
            val x = IntArray(16) { i -> ByteBuffer.wrap(padded, off + i*4, 4).order(ByteOrder.LITTLE_ENDIAN).int }
            var a=a0; var b=b0; var c=c0; var d=d0
            val r1=intArrayOf(3,7,11,19); for (i in 0..15) { val s=r1[i%4]; val t=rot(a+f(b,c,d)+x[i],s); a=d; d=c; c=b; b=t }
            val order2=intArrayOf(0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15); val r2=intArrayOf(3,5,9,13)
            for (i in 0..15) { val s=r2[i%4]; val t=rot(a+g(b,c,d)+x[order2[i]]+0x5a827999,s); a=d; d=c; c=b; b=t }
            val order3=intArrayOf(0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15); val r3=intArrayOf(3,9,11,15)
            for (i in 0..15) { val s=r3[i%4]; val t=rot(a+h(b,c,d)+x[order3[i]]+0x6ed9eba1,s); a=d; d=c; c=b; b=t }
            a0+=a; b0+=b; c0+=c; d0+=d
        }
        val bb=ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN); bb.putInt(a0).putInt(b0).putInt(c0).putInt(d0); return bb.array()
    }
}
