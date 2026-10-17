package net.imohsen7.l2tpvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import net.imohsen7.l2tpvpn.core.L2tpClient
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class VpnTunnelService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "net.imohsen7.l2tpvpn.CONNECT"
        const val ACTION_DISCONNECT = "net.imohsen7.l2tpvpn.DISCONNECT"
        private const val CHANNEL_ID = "l2tp_vpn_status"
        private const val NOTIFICATION_ID = 17321
    }

    private val runtime by lazy { getSharedPreferences("vpn_runtime", MODE_PRIVATE) }
    private val cancelled = AtomicBoolean(false)
    private val tx = AtomicLong(0)
    private val rx = AtomicLong(0)
    private var pool: ExecutorService? = null
    private var client: L2tpClient? = null
    private var tunnel: ParcelFileDescriptor? = null
    private var errorState = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                setState("Disconnected", "اتصال قطع شد")
                stopVpn("Disconnected")
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                if (runtime.getString("state", "") == "Connected") return START_STICKY
                cancelled.set(false); errorState = false
                tx.set(0); rx.set(0)
                runtime.edit().putLong("tx", 0).putLong("rx", 0).putLong("startedAt", 0).apply()
                createNotificationChannel()
                startForeground(NOTIFICATION_ID, notification("در حال اتصال..."))
                setState("Connecting", "در حال برقراری IPsec/L2TP/PPP")
                pool = Executors.newCachedThreadPool()
                pool?.execute { connectAndRun() }
            }
        }
        return START_STICKY
    }

    private fun connectAndRun() {
        try {
            val profile = ProfileStore.load(this) ?: error("پروفایل VPN ذخیره نشده است")
            logLine("شروع اتصال به سرور")
            val conn = L2tpClient(this, profile, ::logLine, cancelled)
            client = conn
            val cfg = conn.connect()
            if (cancelled.get()) return
            val builder = Builder()
                .setSession("Custom L2TP VPN")
                .setMtu(cfg.mtu)
                .addAddress(cfg.address, 32)
                .addRoute("0.0.0.0", 0)
                // Route IPv6 into the TUN and drop it (this L2TP/PPP profile negotiates IPv4 only), preventing IPv6 bypass.
                .addAddress("fd42:6c32:7470::1", 128)
                .addRoute("::", 0)
            cfg.dnsServers.forEach { try { builder.addDnsServer(it) } catch (_: Exception) {} }
            tunnel = builder.establish() ?: error("اندروید رابط VPN را ایجاد نکرد؛ مجوز VPN را دوباره تأیید کنید")
            runtime.edit().putLong("startedAt", System.currentTimeMillis()).apply()
            setState("Connected", "IPsec، L2TP و PPP برقرار هستند")
            updateNotification("متصل به ${profile.server}")
            logLine("رابط VPN فعال شد؛ مسیر IPv4 از تونل عبور می‌کند")
            startForwarding(conn, tunnel!!)
        } catch (e: InterruptedException) {
            if (!cancelled.get()) fail(e.message ?: "اتصال لغو شد")
        } catch (e: Exception) {
            if (!cancelled.get()) fail(e.message ?: e.javaClass.simpleName)
        }
    }

    private fun startForwarding(conn: L2tpClient, pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        pool?.execute {
            val packetBuffer = ByteArray(32767)
            try {
                while (!cancelled.get()) {
                    val n = input.read(packetBuffer)
                    if (n <= 0) continue
                    val packet = packetBuffer.copyOf(n)
                    // This implementation establishes IPv4 IPCP only. IPv6 is intentionally dropped rather than leaked outside the tunnel.
                    if ((packet[0].toInt() ushr 4) != 4) continue
                    conn.sendIpPacket(packet)
                    tx.addAndGet(n.toLong())
                }
            } catch (e: Exception) {
                if (!cancelled.get()) fail("خطا در ارسال بسته به تونل: ${e.message ?: e.javaClass.simpleName}")
            }
        }
        pool?.execute {
            try {
                while (!cancelled.get()) {
                    val packet = conn.receiveIpPacket(1000) ?: continue
                    if (packet.isEmpty() || (packet[0].toInt() ushr 4) != 4) continue
                    synchronized(output) { output.write(packet); output.flush() }
                    rx.addAndGet(packet.size.toLong())
                }
            } catch (e: Exception) {
                if (!cancelled.get()) fail("خطا در دریافت بسته از تونل: ${e.message ?: e.javaClass.simpleName}")
            }
        }
        pool?.execute {
            while (!cancelled.get()) {
                runtime.edit().putLong("tx", tx.get()).putLong("rx", rx.get()).apply()
                try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
            }
        }
    }

    private fun fail(message: String) {
        if (cancelled.get()) return
        errorState = true
        logLine("خطا: $message")
        setState("Error", message)
        stopVpn("Error")
    }

    private fun stopVpn(finalState: String) {
        cancelled.set(true)
        try { client?.close() } catch (_: Exception) { }
        client = null
        try { tunnel?.close() } catch (_: Exception) { }
        tunnel = null
        try { pool?.shutdownNow() } catch (_: Exception) { }
        pool = null
        runtime.edit().putLong("tx", tx.get()).putLong("rx", rx.get()).apply()
        if (finalState == "Disconnected") setState("Disconnected", "اتصال قطع شد")
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) { }
        stopSelf()
    }

    private fun setState(state: String, detail: String) {
        runtime.edit().putString("state", state).putString("detail", detail).apply()
    }

    private fun logLine(message: String) {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val old = runtime.getString("logs", "") ?: ""
        val lines = (old + "[$timestamp] $message\n").lines().filter { it.isNotBlank() }.takeLast(60).joinToString("\n")
        runtime.edit().putString("logs", lines).apply()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "VPN connection", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun notification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val flags = if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_UPDATE_CURRENT
        val pending = PendingIntent.getActivity(this, 0, intent, flags)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        return builder.setContentTitle("L2TP VPN").setContentText(text).setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending).setOngoing(true).build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, notification(text))
    }

    override fun onDestroy() {
        if (!errorState && runtime.getString("state", "") != "Disconnected") {
            setState("Disconnected", "سرویس VPN متوقف شد")
        }
        cancelled.set(true)
        try { client?.close() } catch (_: Exception) { }
        try { tunnel?.close() } catch (_: Exception) { }
        try { pool?.shutdownNow() } catch (_: Exception) { }
        super.onDestroy()
    }
}
