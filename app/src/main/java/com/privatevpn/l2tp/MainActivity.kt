package com.privatevpn.l2tp

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var etServer: EditText
    private lateinit var etUsername: EditText
    private lateinit var etPassword: EditText
    private lateinit var etPsk: EditText
    private lateinit var etSecret: EditText
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvTimer: TextView
    private lateinit var tvDownload: TextView
    private lateinit var tvUpload: TextView

    private var isConnected = false
    private var baseRxBytes = 0L
    private var baseTxBytes = 0L
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L
    private var connectTimestamp = 0L

    private val handler = Handler(Looper.getMainLooper())
    private val statsUpdater = object : Runnable {
        override fun run() {
            if (isConnected) {
                val nowRx = TrafficStats.getTotalRxBytes()
                val nowTx = TrafficStats.getTotalTxBytes()

                val totalRx = (nowRx - baseRxBytes).coerceAtLeast(0L)
                val totalTx = (nowTx - baseTxBytes).coerceAtLeast(0L)

                val speedRx = (nowRx - lastRxBytes).coerceAtLeast(0L)
                val speedTx = (nowTx - lastTxBytes).coerceAtLeast(0L)

                lastRxBytes = nowRx
                lastTxBytes = nowTx

                val elapsedSec = (System.currentTimeMillis() - connectTimestamp) / 1000
                val hours = elapsedSec / 3600
                val minutes = (elapsedSec % 3600) / 60
                val seconds = elapsedSec % 60

                tvTimer.text = String.format(Locale.US, "مدت اتصال: %02d:%02d:%02d", hours, minutes, seconds)
                tvDownload.text = "⬇ دریافتی: ${formatSize(totalRx)} (${formatSize(speedRx)}/s)"
                tvUpload.text = "⬆ ارسالی: ${formatSize(totalTx)} (${formatSize(speedTx)}/s)"

                handler.postDelayed(this, 1000)
            }
        }
    }

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val state = intent?.getStringExtra("STATE") ?: return
            val msg = intent.getStringExtra("MESSAGE") ?: ""
            updateUiState(state, msg)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServer = findViewById(R.id.etServer)
        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        etPsk = findViewById(R.id.etPsk)
        etSecret = findViewById(R.id.etSecret)
        btnConnect = findViewById(R.id.btnConnect)
        tvStatus = findViewById(R.id.tvStatus)
        tvTimer = findViewById(R.id.tvTimer)
        tvDownload = findViewById(R.id.tvDownload)
        tvUpload = findViewById(R.id.tvUpload)

        loadSavedCredentials()

        btnConnect.setOnClickListener {
            if (isConnected) {
                stopVpnService()
            } else {
                val server = etServer.text.toString().trim()
                val user = etUsername.text.toString().trim()
                val pass = etPassword.text.toString()

                if (server.isEmpty() || user.isEmpty() || pass.isEmpty()) {
                    Toast.makeText(this, "لطفاً آدرس سرور، نام کاربری و رمز عبور را وارد کنید", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                saveCredentials()
                val prepareIntent = VpnService.prepare(this)
                if (prepareIntent != null) {
                    startActivityForResult(prepareIntent, 101)
                } else {
                    startVpnService()
                }
            }
        }
    }

    private fun updateUiState(state: String, message: String) {
        when (state) {
            "CONNECTING" -> {
                tvStatus.text = "وضعیت: در حال اتصال به سرور..."
                tvStatus.setTextColor(Color.parseColor("#D69E2E"))
                btnConnect.isEnabled = false
            }
            "CONNECTED" -> {
                isConnected = true
                btnConnect.isEnabled = true
                btnConnect.text = "قطع اتصال (Disconnect)"
                tvStatus.text = "وضعیت: متصل (Connected)"
                tvStatus.setTextColor(Color.parseColor("#38A169"))

                baseRxBytes = TrafficStats.getTotalRxBytes()
                baseTxBytes = TrafficStats.getTotalTxBytes()
                lastRxBytes = baseRxBytes
                lastTxBytes = baseTxBytes
                connectTimestamp = System.currentTimeMillis()

                handler.removeCallbacks(statsUpdater)
                handler.post(statsUpdater)
            }
            "DISCONNECTED" -> {
                isConnected = false
                btnConnect.isEnabled = true
                btnConnect.text = "اتصال (Connect)"
                val detail = if (message.isNotEmpty()) " ($message)" else ""
                tvStatus.text = "وضعیت: قطع شده$detail"
                tvStatus.setTextColor(Color.parseColor("#E53E3E"))
                handler.removeCallbacks(statsUpdater)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter("com.privatevpn.l2tp.STATE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnStateReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(vpnStateReceiver)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 101 && resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, L2tpVpnService::class.java).apply {
            action = "CONNECT"
            putExtra("SERVER", etServer.text.toString().trim())
            putExtra("USERNAME", etUsername.text.toString().trim())
            putExtra("PASSWORD", etPassword.text.toString())
            putExtra("PSK", etPsk.text.toString())
            putExtra("SECRET", etSecret.text.toString())
        }
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, L2tpVpnService::class.java).apply {
            action = "DISCONNECT"
        }
        startService(intent)
    }

    private fun saveCredentials() {
        getSharedPreferences("l2tp_prefs", Context.MODE_PRIVATE).edit().apply {
            putString("server", etServer.text.toString().trim())
            putString("user", etUsername.text.toString().trim())
            putString("pass", etPassword.text.toString())
            putString("psk", etPsk.text.toString())
            putString("secret", etSecret.text.toString())
            apply()
        }
    }

    private fun loadSavedCredentials() {
        val prefs = getSharedPreferences("l2tp_prefs", Context.MODE_PRIVATE)
        etServer.setText(prefs.getString("server", ""))
        etUsername.setText(prefs.getString("user", ""))
        etPassword.setText(prefs.getString("pass", ""))
        etPsk.setText(prefs.getString("psk", ""))
        etSecret.setText(prefs.getString("secret", ""))
    }

    private fun formatSize(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        val gb = mb / 1024.0
        return when {
            gb >= 1.0 -> String.format(Locale.US, "%.2f GB", gb)
            mb >= 1.0 -> String.format(Locale.US, "%.2f MB", mb)
            else -> String.format(Locale.US, "%.1f KB", kb)
        }
    }
}
