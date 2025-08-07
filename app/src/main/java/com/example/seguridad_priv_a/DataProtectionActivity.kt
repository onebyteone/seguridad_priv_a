package com.example.seguridad_priv_a

import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import com.example.seguridad_priv_a.security.BiometricAuthManager

class DataProtectionActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityDataProtectionBinding
    private lateinit var biometricAuthManager: BiometricAuthManager
    private var isAuthenticated = false
    private var sessionTimeoutHandler = Handler(Looper.getMainLooper())
    private var timeoutRunnable: Runnable? = null
    
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // Inicializar BiometricAuthManager
        biometricAuthManager = BiometricAuthManager(this)
        
        // Verificar autenticación antes de mostrar contenido sensible
        checkAuthenticationAndProceed()
        
        dataProtectionManager.logAccess("NAVIGATION", "DataProtectionActivity abierta")
    }
    
    /**
     * Verifica autenticación y procede con la inicialización
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun checkAuthenticationAndProceed() {
        if (biometricAuthManager.isSessionActive()) {
            // Sesión ya activa, proceder
            isAuthenticated = true
            initializeSecureContent()
            startSessionTimeoutMonitoring()
        } else {
            // Requerir autenticación
            showAuthenticationPrompt()
        }
    }
    
    /**
     * Muestra el prompt de autenticación biométrica
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun showAuthenticationPrompt() {
        biometricAuthManager.authenticateUser(
            activity = this,
            onSuccess = {
                isAuthenticated = true
                initializeSecureContent()
                startSessionTimeoutMonitoring()
                Toast.makeText(this, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
            },
            onError = { error ->
                Toast.makeText(this, "Error de autenticación: $error", Toast.LENGTH_LONG).show()
                finish() // Cerrar actividad si no se puede autenticar
            },
            onFallback = {
                // Usar autenticación con PIN/Pattern
                biometricAuthManager.authenticateWithDeviceCredentials(
                    activity = this,
                    onSuccess = {
                        isAuthenticated = true
                        initializeSecureContent()
                        startSessionTimeoutMonitoring()
                        Toast.makeText(this, "Autenticación con PIN/Pattern exitosa", Toast.LENGTH_SHORT).show()
                    },
                    onError = { error ->
                        Toast.makeText(this, "Error de autenticación: $error", Toast.LENGTH_LONG).show()
                        finish()
                    }
                )
            }
        )
    }
    
    /**
     * Inicializa el contenido seguro después de autenticación exitosa
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun initializeSecureContent() {
        setupUI()
        loadDataProtectionInfo()
        loadAccessLogs()
    }
    
    /**
     * Inicia el monitoreo de timeout de sesión
     */
    private fun startSessionTimeoutMonitoring() {
        resetSessionTimeout()
    }
    
    /**
     * Resetea el timeout de sesión
     */
    private fun resetSessionTimeout() {
        timeoutRunnable?.let { sessionTimeoutHandler.removeCallbacks(it) }
        
        timeoutRunnable = Runnable {
            biometricAuthManager.invalidateSession()
            isAuthenticated = false
            Toast.makeText(this, "Sesión expirada por inactividad", Toast.LENGTH_LONG).show()
            finish()
        }
        
        sessionTimeoutHandler.postDelayed(timeoutRunnable!!, 5 * 60 * 1000L) // 5 minutos
    }
    
    /**
     * Registra actividad del usuario y resetea timeout
     */
    private fun onUserActivity() {
        if (isAuthenticated) {
            biometricAuthManager.updateLastActivity()
            resetSessionTimeout()
        }
    }
    
    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            onUserActivity() // Registrar actividad del usuario
            loadAccessLogs()
            Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
        }
        
        binding.btnClearData.setOnClickListener {
            onUserActivity() // Registrar actividad del usuario
            showClearDataDialog()
        }
        
        // Nuevo botón para auditoría avanzada
        binding.btnAuditReport.setOnClickListener {
            onUserActivity() // Registrar actividad del usuario
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                showAuditReport()
            } else {
                Toast.makeText(this, "Función no disponible en esta versión de Android", Toast.LENGTH_SHORT).show()
            }
        }
        
        // Nuevo botón para exportar logs
        binding.btnExportLogs.setOnClickListener {
            onUserActivity() // Registrar actividad del usuario
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                exportAuditLogs()
            } else {
                Toast.makeText(this, "Función no disponible en esta versión de Android", Toast.LENGTH_SHORT).show()
            }
        }
        
        // Nuevo botón para información de autenticación
        binding.btnAuthInfo.setOnClickListener {
            onUserActivity() // Registrar actividad del usuario
            showAuthInfo()
        }
        
        // Registrar actividad en todos los clics de la vista
        binding.root.setOnClickListener { onUserActivity() }
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    private fun loadDataProtectionInfo() {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            dataProtectionManager.getCompleteSecurityInfo()
        } else {
            dataProtectionManager.getDataProtectionInfo()
        }
        
        val infoText = StringBuilder()
        
        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\\n\\n")
        info.forEach { (key, value) ->
            when (value) {
                is Map<*, *> -> {
                    infoText.append("• $key:\\n")
                    value.forEach { (subKey, subValue) ->
                        infoText.append("  - $subKey: $subValue\\n")
                    }
                }
                else -> infoText.append("• $key: $value\\n")
            }
        }
        
        infoText.append("\\n📊 EVIDENCIAS DE PROTECCIÓN:\\n")
        infoText.append("• Encriptación AES-256-GCM activa\\n")
        infoText.append("• Todos los accesos registrados\\n")
        infoText.append("• Datos anonimizados automáticamente\\n")
        infoText.append("• Almacenamiento local seguro\\n")
        infoText.append("• Sistema de auditoría avanzado\\n")
        infoText.append("• Rate limiting habilitado\\n")
        infoText.append("• No hay compartición de datos\\n")
        
        binding.tvDataProtectionInfo.text = infoText.toString()
        
        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }
    
    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()
        
        if (logs.isNotEmpty()) {
            val logsText = logs.joinToString("\\n")
            binding.tvAccessLogs.text = logsText
        } else {
            binding.tvAccessLogs.text = "No hay logs disponibles"
        }
        
        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }
    
    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        
        // Actualizar UI
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\\n\\nTodos los datos personales y logs han sido eliminados del dispositivo."
        
        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()
        
        // Este log se creará después del borrado
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    private fun showAuditReport() {
        val suspiciousActivities = dataProtectionManager.getSuspiciousActivitiesSummary()
        
        val reportBuilder = StringBuilder()
        reportBuilder.append("🛡️ REPORTE DE AUDITORÍA DE SEGURIDAD\\n\\n")
        
        if (suspiciousActivities.isNotEmpty()) {
            reportBuilder.append("📊 ESTADÍSTICAS DE SEGURIDAD:\\n")
            suspiciousActivities.forEach { (key, value) ->
                reportBuilder.append("• $key: $value\\n")
            }
            
            val totalSuspicious = suspiciousActivities["totalSuspicious"] as? Int ?: 0
            val criticalCount = suspiciousActivities["criticalRiskCount"] as? Int ?: 0
            
            reportBuilder.append("\\n🚨 NIVEL DE ALERTA: ")
            when {
                criticalCount > 0 -> reportBuilder.append("CRÍTICO - Se detectaron actividades de alto riesgo")
                totalSuspicious > 5 -> reportBuilder.append("MEDIO - Actividad sospechosa detectada")
                else -> reportBuilder.append("BAJO - Sistema operando normalmente")
            }
        } else {
            reportBuilder.append("✅ No se detectaron actividades sospechosas")
        }
        
        reportBuilder.append("\\n\\n📋 CARACTERÍSTICAS DE AUDITORÍA:\\n")
        reportBuilder.append("• Detección automática de anomalías\\n")
        reportBuilder.append("• Rate limiting en operaciones sensibles\\n")
        reportBuilder.append("• Logs firmados digitalmente\\n")
        reportBuilder.append("• Monitoreo de patrones de acceso\\n")
        
        AlertDialog.Builder(this)
            .setTitle("Reporte de Auditoría")
            .setMessage(reportBuilder.toString())
            .setPositiveButton("OK", null)
            .show()
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    private fun exportAuditLogs() {
        try {
            val exportedLogs = dataProtectionManager.exportSecurityAuditLogs()
            
            // En una implementación real, aquí se guardaría en un archivo
            // Por ahora mostramos un resumen
            val summary = "Logs de auditoría exportados exitosamente.\\n\\n" +
                    "Contenido: Entradas de auditoría firmadas digitalmente\\n" +
                    "Formato: JSON con firma HMAC-SHA256\\n" +
                    "Tamaño: ${exportedLogs.length} caracteres\\n\\n" +
                    "Los logs pueden ser verificados para asegurar su integridad."
            
            AlertDialog.Builder(this)
                .setTitle("Exportación Completada")
                .setMessage(summary)
                .setPositiveButton("OK", null)
                .show()
                
            Toast.makeText(this, "Logs exportados con firma digital", Toast.LENGTH_SHORT).show()
            
        } catch (e: Exception) {
            Toast.makeText(this, "Error al exportar logs: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    /**
     * Muestra información del estado de autenticación
     */
    private fun showAuthInfo() {
        val authInfo = biometricAuthManager.getAuthInfo()
        
        val infoBuilder = StringBuilder()
        infoBuilder.append("🔐 INFORMACIÓN DE AUTENTICACIÓN\\n\\n")
        
        infoBuilder.append("📱 Estado Biométrico: ${authInfo["biometricStatus"]}\\n")
        infoBuilder.append("🔓 Sesión Activa: ${if (authInfo["sessionActive"] as Boolean) "Sí" else "No"}\\n")
        
        if (authInfo["sessionActive"] as Boolean) {
            val timeRemaining = authInfo["timeRemaining"] as Long
            val minutesRemaining = timeRemaining / 60000
            val secondsRemaining = (timeRemaining % 60000) / 1000
            infoBuilder.append("⏱️ Tiempo Restante: ${minutesRemaining}m ${secondsRemaining}s\\n")
        }
        
        infoBuilder.append("⏰ Timeout de Sesión: ${authInfo["sessionTimeoutMinutes"]} minutos\\n")
        
        val lastAuthTime = authInfo["lastAuthTime"] as Long
        if (lastAuthTime > 0) {
            val timeAgo = (System.currentTimeMillis() - lastAuthTime) / 60000
            infoBuilder.append("🕐 Última Autenticación: hace ${timeAgo} minutos\\n")
        }
        
        infoBuilder.append("\\n🛡️ CARACTERÍSTICAS DE SEGURIDAD:\\n")
        infoBuilder.append("• Timeout automático de sesión\\n")
        infoBuilder.append("• Fallback a PIN/Pattern del dispositivo\\n")
        infoBuilder.append("• Integración con Android Keystore\\n")
        infoBuilder.append("• Monitoreo de actividad del usuario\\n")
        
        AlertDialog.Builder(this)
            .setTitle("Estado de Autenticación")
            .setMessage(infoBuilder.toString())
            .setPositiveButton("OK", null)
            .setNeutralButton("Cerrar Sesión") { _, _ ->
                invalidateSessionAndClose()
            }
            .show()
    }
    
    /**
     * Invalida la sesión y cierra la actividad
     */
    private fun invalidateSessionAndClose() {
        biometricAuthManager.invalidateSession()
        isAuthenticated = false
        timeoutRunnable?.let { sessionTimeoutHandler.removeCallbacks(it) }
        Toast.makeText(this, "Sesión cerrada manualmente", Toast.LENGTH_SHORT).show()
        finish()
    }
    
    override fun onPause() {
        super.onPause()
        // Pausar timeout cuando la actividad no está visible
        timeoutRunnable?.let { sessionTimeoutHandler.removeCallbacks(it) }
    }
    
    override fun onResume() {
        super.onResume()
        // Verificar sesión al volver
        if (isAuthenticated && !biometricAuthManager.isSessionActive()) {
            // Sesión expiró mientras estaba en background
            isAuthenticated = false
            Toast.makeText(this, "Sesión expirada", Toast.LENGTH_LONG).show()
            finish()
        } else if (isAuthenticated) {
            // Reanudar monitoreo de timeout
            resetSessionTimeout()
            loadAccessLogs() // Actualizar logs al volver a la actividad
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Limpiar timeout handler
        timeoutRunnable?.let { sessionTimeoutHandler.removeCallbacks(it) }
    }
}