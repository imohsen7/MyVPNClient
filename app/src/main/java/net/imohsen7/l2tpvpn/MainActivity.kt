package net.imohsen7.l2tpvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var server: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var psk: EditText
    private lateinit var status: TextView
    private lateinit var traffic: TextView
    private lateinit var logView: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("vpn_runtime", MODE_PRIVATE) }

    private val updater = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        ProfileStore.load(this)?.let {
            server.setText(it.server); username.setText(it.username); password.setText(it.password); psk.setText(it.preSharedKey)
        }
        refreshStatus()
    }

    override fun onResume() { super.onResume(); handler.post(updater) }
    override fun onPause() { handler.removeCallbacks(updater); super.onPause() }

    private fun buildUi() {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            layoutDirection = View.LAYOUT_DIRECTION_RTL
            setPadding(dp(20), dp(22), dp(20), dp(24))
        }
        scroll.addView(root)
        setContentView(scroll)

        root.addView(TextView(this).apply { text = "L2TP/IPsec VPN"; textSize = 25f; setPadding(0,0,0,dp(10)) })
        root.addView(TextView(this).apply { text = "پروفایل فقط به‌صورت محلی و رمزگذاری‌شده ذخیره می‌شود."; textSize = 14f })
        server = field(root, "آدرس سرور یا IP", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        username = field(root, "نام کاربری PPP", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        password = field(root, "رمز عبور PPP", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        psk = field(root, "IPsec Pre-Shared Key (PSK)", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)

        val save = Button(this).apply { text = "ذخیرهٔ امن پروفایل"; setOnClickListener { saveProfile() } }
        val connect = Button(this).apply { text = "اتصال"; setOnClickListener { requestConnect() } }
        val disconnect = Button(this).apply { text = "قطع اتصال"; setOnClickListener { stopVpn() } }
        root.addView(save, matchWrap()); root.addView(connect, matchWrap()); root.addView(disconnect, matchWrap())
        status = TextView(this).apply { textSize = 18f; setPadding(0,dp(14),0,dp(4)) }
        traffic = TextView(this).apply { textSize = 16f; setPadding(0,dp(4),0,dp(8)) }
        logView = TextView(this).apply { textSize = 12f; setTextIsSelectable(true); setPadding(0,dp(10),0,0) }
        root.addView(status, matchWrap()); root.addView(traffic, matchWrap()); root.addView(TextView(this).apply { text = "گزارش محلی"; textSize = 15f }, matchWrap()); root.addView(logView, matchWrap())
    }

    private fun field(root: LinearLayout, label: String, type: Int): EditText {
        root.addView(TextView(this).apply { text = label; textSize = 14f; setPadding(0,dp(10),0,dp(3)) }, matchWrap())
        val edit = EditText(this).apply { inputType = type; textSize = 16f; singleLine = true; textDirection = View.TEXT_DIRECTION_LTR; setPadding(dp(10),0,dp(10),0) }
        root.addView(edit, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(48)))
        return edit
    }

    private fun saveProfile(): Boolean {
        try {
            require(server.text.toString().trim().isNotEmpty()) { "آدرس سرور را وارد کنید" }
            require(username.text.isNotEmpty()) { "نام کاربری را وارد کنید" }
            require(password.text.isNotEmpty()) { "رمز عبور PPP را وارد کنید" }
            require(psk.text.isNotEmpty()) { "کلید پیش‌اشتراک‌شدهٔ IPsec را وارد کنید" }
            ProfileStore.save(this, server.text.toString(), username.text.toString(), password.text.toString(), psk.text.toString())
            val currentState = prefs.getString("state", "Disconnected") ?: "Disconnected"
            if (currentState == "Connected" || currentState == "Connecting") {
                prefs.edit().putString("detail", "پروفایل ذخیره شد؛ وضعیت اتصال فعلی تغییر نکرده است").apply()
                refreshStatus()
            } else {
                setStatus("پروفایل به‌صورت رمزگذاری‌شده ذخیره شد", "Saved")
            }
            return true
        } catch (e: Exception) { setStatus(e.message ?: "ذخیره ناموفق بود", "Error"); return false }
    }

    private fun requestConnect() {
        try {
            if (!saveProfile()) return
            val permissionIntent = VpnService.prepare(this)
            if (permissionIntent != null) startActivityForResult(permissionIntent, 902)
            else startVpnService()
        } catch (e: Exception) { setStatus(e.message ?: "امکان شروع اتصال نیست", "Error") }
    }

    @Deprecated("Legacy activity result is kept for Android 7 compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 902) {
            if (resultCode == RESULT_OK) startVpnService() else setStatus("مجوز اتصال VPN رد شد", "Disconnected")
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, VpnTunnelService::class.java).setAction(VpnTunnelService.ACTION_CONNECT)
        if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }
    private fun stopVpn() { startService(Intent(this, VpnTunnelService::class.java).setAction(VpnTunnelService.ACTION_DISCONNECT)) }

    private fun refreshStatus() {
        status.text = "وضعیت: ${prefs.getString("state", "Disconnected") ?: "Disconnected"}\n${prefs.getString("detail", "") ?: ""}"
        val tx = prefs.getLong("tx", 0); val rx = prefs.getLong("rx", 0); val since = prefs.getLong("startedAt", 0)
        val duration = if (since > 0 && prefs.getString("state", "") == "Connected") formatDuration((System.currentTimeMillis()-since)/1000) else "—"
        traffic.text = "ارسال: ${formatBytes(tx)}     دریافت: ${formatBytes(rx)}\nمدت اتصال: $duration"
        logView.text = prefs.getString("logs", "") ?: ""
    }

    private fun setStatus(detail: String, state: String) {
        prefs.edit().putString("detail", detail).putString("state", state).apply()
        refreshStatus()
    }
    private fun formatBytes(value: Long): String = when {
        value < 1024 -> "$value B"
        value < 1024L*1024 -> String.format(Locale.US, "%.1f KiB", value/1024.0)
        value < 1024L*1024*1024 -> String.format(Locale.US, "%.2f MiB", value/(1024.0*1024))
        else -> String.format(Locale.US, "%.2f GiB", value/(1024.0*1024*1024))
    }
    private fun formatDuration(seconds: Long): String = "%02d:%02d:%02d".format(seconds/3600,(seconds%3600)/60,seconds%60)
    private fun dp(n: Int): Int = (n * resources.displayMetrics.density + 0.5f).toInt()
    private fun matchWrap() = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
}
