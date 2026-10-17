package net.imohsen7.l2tpvpn.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.math.BigInteger
import java.util.concurrent.atomic.AtomicBoolean

internal data class EspMaterial(
    val localSpi: ByteArray,
    val remoteSpi: ByteArray,
    val outboundEncryptionKey: ByteArray,
    val outboundAuthenticationKey: ByteArray,
    val inboundEncryptionKey: ByteArray,
    val inboundAuthenticationKey: ByteArray,
    val espHash: String,
    val icvLength: Int
)

/** RFC 2409 IKEv1 Main Mode + Quick Mode, PSK authentication, NAT-T ESP transport. */
internal class Ikev1(
    private val socket: DatagramSocket,
    private val server: InetAddress,
    private val psk: String,
    private val log: (String) -> Unit,
    private val cancelled: AtomicBoolean
) {
    private val cookieI = Bin.random(8)
    private var cookieR = ByteArray(8)
    private var serverPort = 500
    private var clientLocalAddress = byteArrayOf(0, 0, 0, 0)
    private var negotiatedHash = "SHA1"
    private var encryptionBits = 128
    private var dhGroup = 14
    private var skeyid = byteArrayOf()
    private var skeyidD = byteArrayOf()
    private var skeyidA = byteArrayOf()
    private var skeyidE = byteArrayOf()
    private var dhPrivate = BigInteger.ONE
    private var dhPublic = byteArrayOf()
    private var peerDhPublic = byteArrayOf()
    private var nonceI = byteArrayOf()
    private var nonceR = byteArrayOf()
    private var sharedSecret = byteArrayOf()
    private var localIdBody = byteArrayOf()
    private var initiatorSaBody = byteArrayOf()
    private var phase1LastBlock = byteArrayOf()

    fun establish(): EspMaterial {
        checkCancelled()
        log("IKE: شروع مذاکرهٔ IKEv1")
        val offered = listOf(
            Phase1Transform(7, "SHA256", 1, 14, 256),
            Phase1Transform(7, "SHA256", 1, 14, 128),
            Phase1Transform(7, "SHA1", 1, 14, 256),
            Phase1Transform(7, "SHA1", 1, 14, 128),
            Phase1Transform(7, "SHA1", 1, 2, 128)
        )
        val sa = buildPhase1Sa(offered)
        initiatorSaBody = sa.body
        val vid = Bin.fromHex("4a131c81070358455c5728f20e95452f") // RFC 3947 NAT-T vendor ID
        val (next1, body1) = encodePayloadChain(listOf(sa, IkePayload(13, vid)))
        sendIke(IkePacket(cookieI, ByteArray(8), next1, 2, 0, 0, body1).encode(), 500)

        val msg2 = receiveIke(10000)
        require(msg2.exchangeType == 2 && msg2.initiatorCookie.contentEquals(cookieI)) { "پاسخ معتبر IKE دریافت نشد" }
        cookieR = msg2.responderCookie
        val replyPayloads = decodePayloadChain(msg2.nextPayload, msg2.payloadBytes)
        if (replyPayloads.none { it.type == 13 && it.body.contentEquals(vid) }) {
            error("سرور پشتیبانی استاندارد NAT-T (RFC 3947) را اعلام نکرد؛ این نسخه به ESP روی UDP/4500 نیاز دارد")
        }
        val selectedSa = replyPayloads.firstOrNull { it.type == 1 } ?: error("سرور پیشنهاد IKE را قبول نکرد")
        val selected = parsePhase1Transform(selectedSa.body)
        negotiatedHash = selected.hash
        encryptionBits = selected.keyBits
        dhGroup = selected.group
        log("IKE: الگوریتم انتخاب‌شده ${selected.hash}/AES-${selected.keyBits}/DH${selected.group}")

        dhPrivate = Crypto.modpPrivate(dhGroup)
        dhPublic = Crypto.modpPublic(dhGroup, dhPrivate)
        nonceI = Bin.random(32)
        val localIp = clientLocalAddress
        val remoteIp = server.address
        val natRemote = Crypto.digest(negotiatedHash, cookieI, cookieR, remoteIp, Bin.u16(serverPort))
        // Port zero intentionally signals NAT-T to the responder; UDP-encapsulated ESP is required by an unprivileged app.
        val natLocal = Crypto.digest(negotiatedHash, cookieI, cookieR, localIp, Bin.u16(0))
        val (next3, body3) = encodePayloadChain(listOf(
            IkePayload(4, dhPublic), IkePayload(10, nonceI), IkePayload(13, vid),
            IkePayload(20, natRemote), IkePayload(20, natLocal)
        ))
        sendIke(IkePacket(cookieI, cookieR, next3, 2, 0, 0, body3).encode(), serverPort)

        val msg4 = receiveIke(12000)
        require(msg4.exchangeType == 2 && msg4.initiatorCookie.contentEquals(cookieI) && msg4.responderCookie.contentEquals(cookieR)) { "پاسخ تبادل کلید IKE معتبر نیست" }
        val p4 = decodePayloadChain(msg4.nextPayload, msg4.payloadBytes)
        peerDhPublic = p4.firstOrNull { it.type == 4 }?.body ?: error("کلید عمومی DH سرور دریافت نشد")
        nonceR = p4.firstOrNull { it.type == 10 }?.body ?: error("Nonce سرور دریافت نشد")
        sharedSecret = Crypto.modpShared(dhGroup, peerDhPublic, dhPrivate)
        derivePhase1Keys()
        val iv0 = Crypto.digest(negotiatedHash, dhPublic, peerDhPublic).copyOfRange(0, 16)
        val idLocal = Bin.cat(byteArrayOf(1, 0), Bin.u16(0), localIp)
        localIdBody = idLocal
        val hashI = Crypto.prf(negotiatedHash, skeyid, dhPublic, peerDhPublic, cookieI, cookieR, initiatorSaBody, idLocal)
        val phase5Payloads = listOf(IkePayload(5, idLocal), IkePayload(8, hashI))
        val encrypted5 = encryptPayloadPacket(5, phase5Payloads, 0, iv0, 2)
        sendIke(encrypted5, 4500)
        val msg6 = receiveIke(12000)
        require(msg6.exchangeType == 2 && msg6.flags and 1 == 1) { "پاسخ رمز‌شدهٔ احراز هویت IKE دریافت نشد" }
        val iv6 = lastBlock(msg6.payloadBytes)
        val p6 = decryptPacket(msg6, lastBlock(IkePacket.parse(encrypted5).payloadBytes))
        val idRemote = p6.firstOrNull { it.type == 5 }?.body ?: error("شناسهٔ IKE سرور موجود نیست")
        val hashR = p6.firstOrNull { it.type == 8 }?.body ?: error("HASH_R سرور موجود نیست")
        val expectedR = Crypto.prf(negotiatedHash, skeyid, peerDhPublic, dhPublic, cookieR, cookieI,
            initiatorSaBody, idRemote)
        require(constantTimeEquals(hashR, expectedR)) { "احراز هویت IKE ناموفق است؛ کلید پیش‌اشتراک‌شده یا تنظیمات رمزنگاری را بررسی کنید" }
        phase1LastBlock = iv6
        log("IKE: احراز هویت IPsec موفق")
        return negotiateQuickMode()
    }

    private data class Phase1Transform(val encryption: Int, val hash: String, val auth: Int, val group: Int, val keyBits: Int)
    private data class Phase2Transform(val keyBits: Int, val auth: Int, val encapsulation: Int)

    private fun buildPhase1Sa(transforms: List<Phase1Transform>): IkePayload {
        val out = java.io.ByteArrayOutputStream()
        transforms.forEachIndexed { idx, t ->
            val attrs = Bin.cat(
                Bin.tv(1, t.encryption), Bin.tv(2, if (t.hash == "SHA256") 4 else 2),
                Bin.tv(3, t.auth), Bin.tv(4, t.group), Bin.tv(14, t.keyBits),
                Bin.tv(11, 1), Bin.tlv(12, Bin.u32(28800))
            )
            val len = 8 + attrs.size
            out.write(byteArrayOf(if (idx == transforms.lastIndex) 0 else 3, 0) + Bin.u16(len) + byteArrayOf((idx + 1).toByte(), 1, 0, 0) + attrs)
        }
        val transformsBytes = out.toByteArray()
        val proposalBody = byteArrayOf(1, 1, 0, transforms.size.toByte()) + transformsBytes
        val proposal = byteArrayOf(0, 0) + Bin.u16(proposalBody.size + 4) + proposalBody
        return IkePayload(1, Bin.cat(Bin.u32(1), Bin.u32(1), proposal))
    }

    private fun parsePhase1Transform(saBody: ByteArray): Phase1Transform {
        require(saBody.size >= 16) { "SA پاسخ کوتاه است" }
        var p = 8
        val proposalLen = Bin.readU16(saBody, p + 2)
        require(proposalLen >= 8 && p + proposalLen <= saBody.size) { "Proposal پاسخ خراب است" }
        val spiSize = saBody[p + 6].toInt() and 255
        var t = p + 8 + spiSize
        val end = p + proposalLen
        while (t + 8 <= end) {
            val len = Bin.readU16(saBody, t + 2)
            if (len < 8 || t + len > end) break
            val transformId = saBody[t + 5].toInt() and 255
            val attrs = Bin.parseAttributes(saBody.copyOfRange(t + 8, t + len))
            fun av(k: Int, d: Int) = attrs[k]?.let { if (it.size >= 2) Bin.readU16(it) else d } ?: d
            if (transformId == 1) {
                val enc = av(1, 7); val hashId = av(2, 2); val auth = av(3, 1); val group = av(4, 2)
                val bits = av(14, if (enc == 7) 128 else 128)
                require(enc == 7 && auth == 1) { "فقط AES-CBC با PSK در حال حاضر پشتیبانی می‌شود" }
                require(hashId == 2 || hashId == 4) { "الگوریتم HASH سرور پشتیبانی نمی‌شود" }
                require(group == 2 || group == 14) { "گروه DH سرور پشتیبانی نمی‌شود" }
                return Phase1Transform(enc, if (hashId == 4) "SHA256" else "SHA1", auth, group, bits)
            }
            t += len
        }
        error("هیچ Transform سازگاری در پاسخ IKE پیدا نشد")
    }

    private fun derivePhase1Keys() {
        val secret = psk.toByteArray(Charsets.UTF_8)
        skeyid = Crypto.prf(negotiatedHash, secret, nonceI, nonceR)
        skeyidD = Crypto.prf(negotiatedHash, skeyid, sharedSecret, cookieI, cookieR, byteArrayOf(0))
        skeyidA = Crypto.prf(negotiatedHash, skeyid, skeyidD, sharedSecret, cookieI, cookieR, byteArrayOf(1))
        skeyidE = Crypto.prf(negotiatedHash, skeyid, skeyidA, sharedSecret, cookieI, cookieR, byteArrayOf(2))
    }

    private fun encryptPayloadPacket(firstType: Int, payloads: List<IkePayload>, messageId: Long, iv: ByteArray, exchange: Int): ByteArray {
        val (_, plain0) = encodePayloadChain(payloads)
        // RFC 2409 section 5.3: always pad to the next block; bytes before the
        // last are zero, and the last byte stores (padding length - 1).
        val padLength = 16 - (plain0.size % 16)
        val padding = ByteArray(padLength)
        padding[padLength - 1] = (padLength - 1).toByte()
        val plain = Bin.cat(plain0, padding)
        val key = Crypto.expandPrf(negotiatedHash, skeyidE, encryptionBits / 8)
        val cipher = Crypto.aesCbc(true, key, iv, plain)
        return IkePacket(cookieI, cookieR, firstType, exchange, 1, messageId, cipher).encode()
    }

    private fun decryptPacket(pkt: IkePacket, iv: ByteArray): List<IkePayload> {
        val key = Crypto.expandPrf(negotiatedHash, skeyidE, encryptionBits / 8)
        val clear = Crypto.aesCbc(false, key, iv, pkt.payloadBytes)
        return decodePayloadChain(pkt.nextPayload, clear)
    }

    private fun lastBlock(b: ByteArray): ByteArray {
        require(b.size >= 16) { "CBC ciphertext is too short" }
        return b.copyOfRange(b.size - 16, b.size)
    }

    private fun negotiateQuickMode(): EspMaterial {
        log("IPsec: مذاکرهٔ ESP transport/NAT-T")
        val messageIdBytes = Bin.random(4).also { if (it.all { b -> b == 0.toByte() }) it[3] = 1 }
        val mid = Bin.readU32(messageIdBytes)
        val localSpi = Bin.random(4).also { if (it.all { b -> b == 0.toByte() }) it[3] = 1 }
        val nonceQmI = Bin.random(32)
        // L2TP selectors are limited to UDP/1701. A wildcard local selector survives client NAT,
        // while the peer selector pins traffic to the configured VPN gateway.
        val idCi = idUdp1701Subnet(byteArrayOf(0,0,0,0), byteArrayOf(0,0,0,0))
        val idCr = idUdp1701Subnet(server.address, byteArrayOf(255.toByte(),255.toByte(),255.toByte(),255.toByte()))
        val sa = buildPhase2Sa(localSpi, listOf(Phase2Transform(256, 5, 4), Phase2Transform(128, 5, 4), Phase2Transform(256, 2, 4), Phase2Transform(128, 2, 4)))
        val hashInput1 = encodePayloadChain(listOf(sa, IkePayload(10, nonceQmI), IkePayload(5, idCi), IkePayload(5, idCr))).second
        val hash1 = Crypto.prf(negotiatedHash, skeyidA, messageIdBytes, hashInput1)
        val payloads1 = listOf(IkePayload(8, hash1), sa, IkePayload(10, nonceQmI), IkePayload(5, idCi), IkePayload(5, idCr))
        var iv = Crypto.digest(negotiatedHash, phase1LastBlock, messageIdBytes).copyOfRange(0, 16)
        val pkt1 = encryptPayloadPacket(8, payloads1, mid, iv, 32)
        sendIke(pkt1, 4500)
        iv = lastBlock(IkePacket.parse(pkt1).payloadBytes)
        val pkt2 = receiveIke(15000)
        require(pkt2.exchangeType == 32 && pkt2.messageId == mid && pkt2.flags and 1 == 1) { "پاسخ Quick Mode دریافت نشد" }
        val p2 = decryptPacket(pkt2, iv)
        iv = lastBlock(pkt2.payloadBytes)
        val hash2 = p2.firstOrNull { it.type == 8 }?.body ?: error("HASH(2) دریافت نشد")
        val saR = p2.firstOrNull { it.type == 1 } ?: error("پاسخ ESP SA دریافت نشد")
        val nonceQmR = p2.firstOrNull { it.type == 10 }?.body ?: error("Nonce در Quick Mode موجود نیست")
        val hashIndex = p2.indexOfFirst { it.type == 8 }
        require(hashIndex >= 0) { "HASH(2) payload not found" }
        val responsePayloads = p2.drop(hashIndex + 1)
        val hashInput2 = encodePayloadChain(responsePayloads).second
        val expected2 = Crypto.prf(negotiatedHash, skeyidA, messageIdBytes, nonceQmI, hashInput2)
        require(constantTimeEquals(hash2, expected2)) { "اعتبارسنجی HASH(2) ناموفق بود" }
        val selected = parsePhase2Selection(saR.body)
        val remoteSpi = parsePhase2Spi(saR.body)
        val hash3 = Crypto.prf(negotiatedHash, skeyidA, byteArrayOf(0), messageIdBytes, nonceQmI, nonceQmR)
        val pkt3 = encryptPayloadPacket(8, listOf(IkePayload(8, hash3)), mid, iv, 32)
        sendIke(pkt3, 4500)
        val authHash = if (selected.auth == 5) "SHA256" else "SHA1"
        val authLen = if (authHash == "SHA256") 32 else 20
        val keyLen = selected.keyBits / 8
        val outMat = keymat(remoteSpi, nonceQmI, nonceQmR, keyLen + authLen)
        val inMat = keymat(localSpi, nonceQmI, nonceQmR, keyLen + authLen)
        log("IPsec: SA آماده؛ AES-${selected.keyBits}/${authHash}")
        return EspMaterial(localSpi, remoteSpi,
            outMat.copyOfRange(0, keyLen), outMat.copyOfRange(keyLen, keyLen + authLen),
            inMat.copyOfRange(0, keyLen), inMat.copyOfRange(keyLen, keyLen + authLen), authHash,
            if (authHash == "SHA256") 16 else 12)
    }

    private fun idUdp1701Subnet(ip: ByteArray, mask: ByteArray): ByteArray = Bin.cat(byteArrayOf(4, 17), Bin.u16(1701), ip, mask)

    private fun buildPhase2Sa(localSpi: ByteArray, transforms: List<Phase2Transform>): IkePayload {
        val out = java.io.ByteArrayOutputStream()
        transforms.forEachIndexed { idx, t ->
            val attrs = Bin.cat(
                Bin.tv(6, t.keyBits), Bin.tv(5, t.auth), Bin.tv(4, t.encapsulation),
                Bin.tv(1, 1), Bin.tlv(2, Bin.u32(3600))
            )
            val len = 8 + attrs.size
            out.write(byteArrayOf(if (idx == transforms.lastIndex) 0 else 3, 0) + Bin.u16(len) + byteArrayOf((idx + 1).toByte(), 12, 0, 0) + attrs)
        }
        val proposalBody = byteArrayOf(1, 3, 4, transforms.size.toByte()) + localSpi + out.toByteArray()
        val proposal = byteArrayOf(0,0) + Bin.u16(proposalBody.size + 4) + proposalBody
        return IkePayload(1, Bin.cat(Bin.u32(1), Bin.u32(1), proposal))
    }

    private fun parsePhase2Selection(saBody: ByteArray): Phase2Transform {
        require(saBody.size >= 20) { "ESP SA خیلی کوتاه است" }
        val p = 8
        val proposalLen = Bin.readU16(saBody, p + 2)
        require(proposalLen >= 12 && p + proposalLen <= saBody.size) { "ESP proposal خراب است" }
        val spiSize = saBody[p + 6].toInt() and 255
        var t = p + 8 + spiSize
        val end = p + proposalLen
        while (t + 8 <= end) {
            val len = Bin.readU16(saBody, t + 2)
            if (len < 8 || t + len > end) break
            val id = saBody[t + 5].toInt() and 255
            val a = Bin.parseAttributes(saBody.copyOfRange(t + 8, t + len))
            fun av(k: Int, d: Int) = a[k]?.let { if (it.size >= 2) Bin.readU16(it) else d } ?: d
            if (id == 12) {
                val bits = av(6, 128); val auth = av(5, 2); val encap = av(4, 2)
                require(auth == 2 || auth == 5) { "ESP authentication algorithm is not supported" }
                require(encap == 4) { "Server did not accept UDP-encapsulated ESP; rootless Android requires NAT-T" }
                require(bits == 128 || bits == 256) { "ESP AES key length is unsupported" }
                return Phase2Transform(bits, auth, encap)
            }
            t += len
        }
        error("هیچ ESP transform قابل پشتیبانی در پاسخ پیدا نشد")
    }

    private fun parsePhase2Spi(saBody: ByteArray): ByteArray {
        val proposal = 8
        val spiSize = saBody[proposal + 6].toInt() and 255
        require(spiSize == 4) { "ESP SPI length نامعتبر است" }
        return saBody.copyOfRange(proposal + 8, proposal + 8 + spiSize)
    }

    private fun keymat(spi: ByteArray, ni: ByteArray, nr: ByteArray, size: Int): ByteArray {
        val seed = Bin.cat(byteArrayOf(3), spi, ni, nr)
        var block = byteArrayOf(); val out = java.io.ByteArrayOutputStream()
        while (out.size() < size) {
            block = if (block.isEmpty()) Crypto.prf(negotiatedHash, skeyidD, seed)
                    else Crypto.prf(negotiatedHash, skeyidD, block, seed)
            out.write(block)
        }
        return out.toByteArray().copyOf(size)
    }

    private fun sendIke(packet: ByteArray, port: Int) {
        checkCancelled()
        socket.disconnect()
        socket.connect(InetSocketAddress(server, port))
        clientLocalAddress = socket.localAddress?.address?.takeIf { it.size == 4 } ?: clientLocalAddress
        serverPort = port
        val wire = if (port == 4500) Bin.cat(ByteArray(4), packet) else packet
        socket.send(DatagramPacket(wire, wire.size))
    }

    /** IKE peers may switch their source port from UDP/500 to UDP/4500 after NAT detection. */
    private fun receiveIke(timeoutMs: Int): IkePacket {
        checkCancelled()
        socket.disconnect() // A connected DatagramSocket would silently reject packets from the new NAT-T port.
        val deadline = System.currentTimeMillis() + timeoutMs
        val buffer = ByteArray(65535)
        while (System.currentTimeMillis() < deadline) {
            checkCancelled()
            val remaining = (deadline - System.currentTimeMillis()).coerceAtMost(1500L).toInt().coerceAtLeast(1)
            socket.soTimeout = remaining
            val dp = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(dp)
            } catch (_: SocketTimeoutException) {
                continue
            }
            if (dp.address != server || (dp.port != 500 && dp.port != 4500)) continue
            serverPort = dp.port
            var b = dp.data.copyOfRange(dp.offset, dp.offset + dp.length)
            // A Non-ESP Marker is required on UDP/4500 traffic; depending on NAT-T port
            // transition, the responder's source port is not always a reliable indicator.
            if (b.size >= 4 && b[0] == 0.toByte() && b[1] == 0.toByte() && b[2] == 0.toByte() && b[3] == 0.toByte()) {
                b = b.copyOfRange(4, b.size)
            }
            if (b.size < 28) continue
            return IkePacket.parse(b)
        }
        throw IllegalStateException("پاسخی از سرور VPN دریافت نشد (UDP پورت $serverPort). فایروال و تنظیمات IPsec را بررسی کنید.")
    }

    private fun checkCancelled() { if (cancelled.get()) throw InterruptedException("اتصال لغو شد") }
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = java.security.MessageDigest.isEqual(a, b)
}
