package net.imohsen7.l2tpvpn.core

import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

internal data class IpConfiguration(val address: String, val dnsServers: List<String>, val mtu: Int = 1280)

/** Minimal PPP LCP, PAP, CHAP-MD5, MS-CHAPv2 and IPCP state machine for L2TP sessions. */
internal class PppSession(
    private val username: String,
    private val password: String,
    private val sendFrame: (ByteArray) -> Unit,
    private val log: (String) -> Unit
) {
    private enum class Auth { NONE, PAP, CHAP_MD5, MSCHAPV2 }
    private var peerAuth = Auth.NONE
    private var localLcpOpen = false
    private var peerLcpOpen = false
    private var authSucceeded = false
    private var papSent = false
    private var ipcpStarted = false
    private var localIpcpOpen = false
    private var peerIpcpOpen = false
    private var connected = false
    private var lcpId = 1
    private var papId = 1
    private var ipcpId = 41
    private var peerIpcpRequestId = -1
    private var localIp = "0.0.0.0"
    private var dns1: String? = null
    private var dns2: String? = null
    private var lastMsChapPeerChallenge = byteArrayOf()
    private var lastMsChapAuthenticatorChallenge = byteArrayOf()
    private var lastMsChapNtResponse = byteArrayOf()

    fun start() {
        val magic = Bin.random(4)
        val options = Bin.cat(byteArrayOf(1, 4), Bin.u16(1500), byteArrayOf(5, 6), magic)
        sendControl(0xC021, 1, lcpId, options)
        log("PPP: ارسال LCP Configure-Request")
    }

    fun process(input: ByteArray): ByteArray? {
        if (input.isEmpty()) return null
        var p = 0
        if (input.size >= 2 && input[0] == 0xff.toByte() && input[1] == 0x03.toByte()) p = 2
        if (p >= input.size) return null
        val protocol: Int
        val hdrSize: Int
        if (input[p].toInt() and 1 == 1) { protocol = input[p].toInt() and 255; hdrSize = 1 }
        else {
            if (p + 2 > input.size) return null
            protocol = Bin.readU16(input, p); hdrSize = 2
        }
        val body = input.copyOfRange(p + hdrSize, input.size)
        when (protocol) {
            0xC021 -> handleLcp(body)
            0xC023 -> handlePap(body)
            0xC223 -> handleChap(body)
            0x8021 -> handleIpcp(body)
            0x0021 -> if (connected && body.isNotEmpty()) return body
        }
        return null
    }

    fun isConnected() = connected
    fun ipConfiguration(): IpConfiguration {
        require(connected && localIp != "0.0.0.0") { "PPP IPCP is not established" }
        val dns = listOfNotNull(dns1, dns2).filter { it != "0.0.0.0" }.distinct().ifEmpty { listOf("1.1.1.1") }
        return IpConfiguration(localIp, dns)
    }

    private fun handleLcp(b: ByteArray) {
        if (b.size < 4) return
        val code = b[0].toInt() and 255; val id = b[1].toInt() and 255; val len = Bin.readU16(b,2)
        if (len < 4 || len > b.size) return
        val data = b.copyOfRange(4,len)
        when (code) {
            1 -> { // peer's Configure-Request
                val unsupported = ByteArrayOutputStream()
                var p = 0
                while (p + 2 <= data.size) {
                    val type = data[p].toInt() and 255; val n = data[p+1].toInt() and 255
                    if (n < 2 || p+n > data.size) { unsupported.write(data, p, data.size-p); break }
                    val opt = data.copyOfRange(p,p+n)
                    if (type == 3) {
                        val protocol = if (n >= 4) Bin.readU16(opt,2) else 0
                        when (protocol) {
                            0xC023 -> peerAuth = Auth.PAP
                            0xC223 -> {
                                val algorithm = if (n >= 5) opt[4].toInt() and 255 else 5
                                peerAuth = when (algorithm) { 0x81 -> Auth.MSCHAPV2; 5 -> Auth.CHAP_MD5; else -> Auth.NONE }
                                if (peerAuth == Auth.NONE) unsupported.write(opt)
                            }
                            else -> unsupported.write(opt)
                        }
                    } else if (type !in setOf(1,2,5,7,8)) unsupported.write(opt)
                    p += n
                }
                if (unsupported.size() > 0) sendControl(0xC021, 4, id, unsupported.toByteArray())
                else {
                    sendControl(0xC021, 2, id, data) // Configure-Ack echoes options byte-for-byte
                    peerLcpOpen = true
                    maybeOpenNetworkLayer()
                }
            }
            2 -> if (id == lcpId) { localLcpOpen = true; maybeOpenNetworkLayer() }
            3,4 -> { // NAK / reject our request. Retry with basic MRU only.
                val options = Bin.cat(byteArrayOf(1,4), Bin.u16(1400))
                lcpId = (lcpId + 1) and 255
                sendControl(0xC021, 1, lcpId, options)
            }
            5 -> log("PPP: LCP Terminate-Request دریافت شد")
        }
    }

    private fun maybeOpenNetworkLayer() {
        if (!localLcpOpen || !peerLcpOpen) return
        if (peerAuth == Auth.NONE) authSucceeded = true
        if (peerAuth == Auth.PAP && !papSent) {
            papSent = true
            val u = username.toByteArray(Charsets.UTF_8); val p = password.toByteArray(Charsets.UTF_8)
            if (u.size <= 255 && p.size <= 255) {
                val body = Bin.cat(byteArrayOf(u.size.toByte()), u, byteArrayOf(p.size.toByte()), p)
                sendControl(0xC023, 1, papId, body)
            }
        }
        if (authSucceeded && !ipcpStarted) startIpcp()
    }

    private fun handlePap(b: ByteArray) {
        if (b.size < 4) return
        val code = b[0].toInt() and 255; val id = b[1].toInt() and 255
        if (id != papId) return
        when (code) {
            2 -> { authSucceeded = true; log("PPP: PAP احراز هویت شد"); maybeOpenNetworkLayer() }
            3 -> error("احراز هویت PAP توسط سرور رد شد")
        }
    }

    private fun handleChap(b: ByteArray) {
        if (b.size < 4) return
        val code = b[0].toInt() and 255; val id = b[1].toInt() and 255; val len = Bin.readU16(b,2)
        if (len < 4 || len > b.size) return
        val body = b.copyOfRange(4,len)
        when (code) {
            1 -> { // Challenge
                if (body.isEmpty()) return
                val n = body[0].toInt() and 255
                if (1 + n > body.size) return
                val challenge = body.copyOfRange(1,1+n)
                val response: ByteArray
                when (peerAuth) {
                    Auth.MSCHAPV2 -> {
                        if (challenge.size != 16) error("CHAPv2 challenge نامعتبر است")
                        val peerChallenge = Bin.random(16)
                        val ntResponse = Mschap.challengeResponse(peerChallenge, challenge, username, password)
                        lastMsChapPeerChallenge = peerChallenge; lastMsChapAuthenticatorChallenge = challenge; lastMsChapNtResponse = ntResponse
                        val value = Bin.cat(peerChallenge, ByteArray(8), ntResponse, byteArrayOf(0))
                        response = Bin.cat(byteArrayOf(value.size.toByte()), value, username.toByteArray(Charsets.UTF_8))
                    }
                    Auth.CHAP_MD5 -> {
                        val digest = MessageDigest.getInstance("MD5").digest(Bin.cat(byteArrayOf(id.toByte()), password.toByteArray(Charsets.UTF_8), challenge))
                        response = Bin.cat(byteArrayOf(digest.size.toByte()), digest, username.toByteArray(Charsets.UTF_8))
                    }
                    else -> return
                }
                sendControl(0xC223, 2, id, response)
            }
            3 -> { // Success
                if (peerAuth == Auth.MSCHAPV2) {
                    val message = String(body, Charsets.US_ASCII)
                    val expected = Mschap.authenticatorResponse(username, password, lastMsChapNtResponse, lastMsChapPeerChallenge, lastMsChapAuthenticatorChallenge)
                    val got = Regex("S=([A-Fa-f0-9]{40})").find(message)?.groupValues?.getOrNull(1)
                        ?: error("پاسخ MS-CHAPv2 فاقد authenticator response است")
                    if (!got.equals(Bin.hex(expected), ignoreCase = true)) error("پاسخ متقابل MS-CHAPv2 نامعتبر است")
                }
                authSucceeded = true
                log("PPP: احراز هویت CHAP موفق")
                maybeOpenNetworkLayer()
            }
            4 -> error("احراز هویت CHAP توسط سرور رد شد")
        }
    }

    private fun startIpcp() {
        if (ipcpStarted) return
        ipcpStarted = true
        sendIpcpRequest()
        log("PPP: شروع مذاکرهٔ IPCP")
    }

    private fun sendIpcpRequest() {
        val addr = try { Bin.ipv4(localIp) } catch (_: Exception) { byteArrayOf(0,0,0,0) }
        val d1 = try { Bin.ipv4(dns1 ?: "0.0.0.0") } catch (_: Exception) { byteArrayOf(0,0,0,0) }
        val d2 = try { Bin.ipv4(dns2 ?: "0.0.0.0") } catch (_: Exception) { byteArrayOf(0,0,0,0) }
        val options = Bin.cat(byteArrayOf(3,6), addr, byteArrayOf(129.toByte(),6), d1, byteArrayOf(131.toByte(),6), d2)
        ipcpId = (ipcpId + 1) and 255
        localIpcpOpen = false
        sendControl(0x8021, 1, ipcpId, options)
    }

    private fun handleIpcp(b: ByteArray) {
        if (b.size < 4) return
        val code = b[0].toInt() and 255; val id = b[1].toInt() and 255; val len = Bin.readU16(b,2)
        if (len < 4 || len > b.size) return
        val data = b.copyOfRange(4,len)
        when (code) {
            1 -> { // peer config request
                peerIpcpRequestId = id
                sendControl(0x8021, 2, id, data)
                peerIpcpOpen = true
                maybeConnected()
            }
            2 -> if (id == ipcpId) { localIpcpOpen = true; maybeConnected() }
            3 -> if (id == ipcpId) {
                var p=0
                while (p+2 <= data.size) {
                    val type=data[p].toInt() and 255; val n=data[p+1].toInt() and 255
                    if (n<2 || p+n>data.size) break
                    val value=data.copyOfRange(p+2,p+n)
                    if (n==6 && value.size==4) {
                        when(type) {
                            3 -> { localIp=Bin.ipv4String(value) }
                            129 -> dns1=Bin.ipv4String(value)
                            131 -> dns2=Bin.ipv4String(value)
                        }
                    }
                    p+=n
                }
                sendIpcpRequest()
            }
            4 -> { // server rejected an option: retry address only
                ipcpId = (ipcpId + 1) and 255
                sendControl(0x8021, 1, ipcpId, Bin.cat(byteArrayOf(3,6), try { Bin.ipv4(localIp) } catch (_:Exception) { byteArrayOf(0,0,0,0) }))
            }
            5 -> log("PPP: IPCP Terminate-Request دریافت شد")
        }
    }

    private fun maybeConnected() {
        if (!connected && localIpcpOpen && peerIpcpOpen && localIp != "0.0.0.0") {
            connected = true
            log("PPP: IPCP باز شد؛ آدرس ${localIp}")
        }
    }

    private fun sendControl(protocol: Int, code: Int, id: Int, data: ByteArray) {
        val len = 4 + data.size
        sendFrame(Bin.cat(byteArrayOf(0xff.toByte(),0x03), Bin.u16(protocol), byteArrayOf(code.toByte(), id.toByte()), Bin.u16(len), data))
    }
}

private object Mschap {
    fun challengeResponse(peerChallenge: ByteArray, authChallenge: ByteArray, username: String, password: String): ByteArray {
        val uname = username.substringAfterLast('\\').toByteArray(Charsets.US_ASCII)
        val challenge = MessageDigest.getInstance("SHA-1").digest(Bin.cat(peerChallenge, authChallenge, uname)).copyOfRange(0,8)
        val passwordHash = Crypto.md4(password.toByteArray(Charset.forName("UTF-16LE")))
        val padded = passwordHash + ByteArray(21 - passwordHash.size)
        val out = ByteArrayOutputStream()
        for (i in 0..2) {
            val key = desKey(padded.copyOfRange(i*7, i*7+7))
            val c = Cipher.getInstance("DES/ECB/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key,"DES"))
            out.write(c.doFinal(challenge))
        }
        return out.toByteArray()
    }
    fun authenticatorResponse(username: String, password: String, ntResponse: ByteArray, peerChallenge: ByteArray, authChallenge: ByteArray): ByteArray {
        val passwordHash = Crypto.md4(password.toByteArray(Charset.forName("UTF-16LE")))
        val hashHash = Crypto.md4(passwordHash)
        val magic1 = "Magic server to client signing constant".toByteArray(Charsets.US_ASCII)
        val magic2 = "Pad to make it do more than one iteration".toByteArray(Charsets.US_ASCII)
        val digest = MessageDigest.getInstance("SHA-1").digest(Bin.cat(hashHash, ntResponse, magic1))
        val challenge = MessageDigest.getInstance("SHA-1").digest(Bin.cat(peerChallenge, authChallenge, username.substringAfterLast('\\').toByteArray(Charsets.US_ASCII))).copyOfRange(0,8)
        return MessageDigest.getInstance("SHA-1").digest(Bin.cat(digest, challenge, magic2))
    }
    private fun desKey(seven: ByteArray): ByteArray {
        val k = ByteArray(8)
        k[0] = (seven[0].toInt() and 0xfe).toByte()
        k[1] = (((seven[0].toInt() shl 7) or ((seven[1].toInt() and 255) ushr 1)) and 0xfe).toByte()
        k[2] = (((seven[1].toInt() shl 6) or ((seven[2].toInt() and 255) ushr 2)) and 0xfe).toByte()
        k[3] = (((seven[2].toInt() shl 5) or ((seven[3].toInt() and 255) ushr 3)) and 0xfe).toByte()
        k[4] = (((seven[3].toInt() shl 4) or ((seven[4].toInt() and 255) ushr 4)) and 0xfe).toByte()
        k[5] = (((seven[4].toInt() shl 3) or ((seven[5].toInt() and 255) ushr 5)) and 0xfe).toByte()
        k[6] = (((seven[5].toInt() shl 2) or ((seven[6].toInt() and 255) ushr 6)) and 0xfe).toByte()
        k[7] = ((seven[6].toInt() shl 1) and 0xfe).toByte()
        for (i in k.indices) {
            var v = k[i].toInt() and 255
            var ones=0; for (bit in 1..7) if ((v shr bit) and 1 == 1) ones++
            if (ones % 2 == 0) v = v or 1
            k[i] = v.toByte()
        }
        return k
    }
}
