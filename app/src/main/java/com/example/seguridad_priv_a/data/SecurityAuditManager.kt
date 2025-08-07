package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.annotation.RequiresApi
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Sistema de Auditoría Avanzado de Seguridad
 * 
 * Características:
 * - Detección de intentos de acceso sospechosos
 * - Rate limiting para operaciones sensibles
 * - Generación de alertas por patrones anómalos
 * - Exportación de logs firmados digitalmente en JSON
 */
class SecurityAuditManager(private val context: Context) {
    
    private val auditPrefs: SharedPreferences = context.getSharedPreferences("security_audit", Context.MODE_PRIVATE)
    private val accessAttempts = ConcurrentHashMap<String, MutableList<Long>>()
    private val operationCounts = ConcurrentHashMap<String, AtomicInteger>()
    private val suspiciousActivities = mutableListOf<SuspiciousActivity>()
    
    // Rate limiting configuration
    private val rateLimitRules = mapOf(
        "DATA_STORAGE" to RateLimitRule(maxAttempts = 10, timeWindowMs = 60_000), // 10 por minuto
        "DATA_ACCESS" to RateLimitRule(maxAttempts = 50, timeWindowMs = 60_000),  // 50 por minuto
        "KEY_ROTATION" to RateLimitRule(maxAttempts = 1, timeWindowMs = 3600_000), // 1 por hora
        "LOGIN_ATTEMPT" to RateLimitRule(maxAttempts = 5, timeWindowMs = 300_000), // 5 por 5 minutos
        "PERMISSION_REQUEST" to RateLimitRule(maxAttempts = 20, timeWindowMs = 300_000) // 20 por 5 minutos
    )
    
    companion object {
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val AUDIT_SALT_KEY = "audit_salt"
        private const val MAX_AUDIT_ENTRIES = 1000
        private const val SUSPICIOUS_PATTERN_THRESHOLD = 3
    }
    
    data class RateLimitRule(
        val maxAttempts: Int,
        val timeWindowMs: Long
    )
    
    data class AuditEntry(
        val timestamp: Long,
        val category: String,
        val action: String,
        val ipAddress: String = "local",
        val userAgent: String = "android-app",
        val sessionId: String,
        val riskLevel: RiskLevel,
        val metadata: Map<String, String> = emptyMap()
    )
    
    data class SuspiciousActivity(
        val timestamp: Long,
        val activityType: String,
        val description: String,
        val riskLevel: RiskLevel,
        val sourceIdentifier: String
    )
    
    enum class RiskLevel(val value: Int) {
        LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4)
    }
    
    /**
     * Registra una actividad de auditoría con detección automática de patrones sospechosos
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun logSecurityEvent(
        category: String,
        action: String,
        metadata: Map<String, String> = emptyMap(),
        sessionId: String = generateSessionId()
    ): Boolean {
        try {
            val currentTime = System.currentTimeMillis()
            
            // Verificar rate limiting
            if (!checkRateLimit(category, currentTime)) {
                logSuspiciousActivity(
                    "RATE_LIMIT_EXCEEDED",
                    "Rate limit exceeded for category: $category",
                    RiskLevel.HIGH,
                    sessionId
                )
                return false
            }
            
            // Determinar nivel de riesgo
            val riskLevel = assessRiskLevel(category, action, currentTime)
            
            // Crear entrada de auditoría
            val auditEntry = AuditEntry(
                timestamp = currentTime,
                category = category,
                action = action,
                sessionId = sessionId,
                riskLevel = riskLevel,
                metadata = metadata
            )
            
            // Guardar entrada
            saveAuditEntry(auditEntry)
            
            // Detectar patrones anómalos
            detectAnomalousPatterns(category, action, currentTime, sessionId)
            
            return true
            
        } catch (e: Exception) {
            android.util.Log.e("SecurityAuditManager", "Error logging security event: ${e.message}")
            return false
        }
    }
    
    /**
     * Verifica rate limiting para operaciones sensibles
     */
    private fun checkRateLimit(category: String, currentTime: Long): Boolean {
        val rule = rateLimitRules[category] ?: return true
        
        val attempts = accessAttempts.getOrPut(category) { mutableListOf() }
        
        // Limpiar intentos antiguos
        attempts.removeAll { currentTime - it > rule.timeWindowMs }
        
        // Verificar si se excede el límite
        if (attempts.size >= rule.maxAttempts) {
            return false
        }
        
        // Agregar intento actual
        attempts.add(currentTime)
        return true
    }
    
    /**
     * Evalúa el nivel de riesgo de una operación
     */
    private fun assessRiskLevel(category: String, action: String, timestamp: Long): RiskLevel {
        return when {
            category == "SECURITY_ERROR" || action.contains("FAILED") -> RiskLevel.HIGH
            category == "KEY_ROTATION" || category == "PERMISSION_REQUEST" -> RiskLevel.MEDIUM
            isHighFrequencyActivity(category, timestamp) -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }
    
    /**
     * Detecta si hay alta frecuencia de actividad sospechosa
     */
    private fun isHighFrequencyActivity(category: String, timestamp: Long): Boolean {
        val attempts = accessAttempts[category] ?: return false
        val recentAttempts = attempts.count { timestamp - it < 10_000 } // Últimos 10 segundos
        return recentAttempts > 5
    }
    
    /**
     * Detecta patrones anómalos en el comportamiento
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun detectAnomalousPatterns(category: String, action: String, timestamp: Long, sessionId: String) {
        // Patrón 1: Múltiples errores en secuencia
        if (category == "SECURITY_ERROR") {
            val errorCount = operationCounts.getOrPut("ERROR_COUNT") { AtomicInteger(0) }
            if (errorCount.incrementAndGet() >= SUSPICIOUS_PATTERN_THRESHOLD) {
                logSuspiciousActivity(
                    "MULTIPLE_SECURITY_ERRORS",
                    "Multiple security errors detected in sequence",
                    RiskLevel.CRITICAL,
                    sessionId
                )
                errorCount.set(0) // Reset counter
            }
        }
        
        // Patrón 2: Acceso intensivo a datos
        if (category == "DATA_ACCESS") {
            val dataAccessCount = operationCounts.getOrPut("DATA_ACCESS_COUNT") { AtomicInteger(0) }
            if (dataAccessCount.incrementAndGet() > 20) { // Más de 20 accesos
                logSuspiciousActivity(
                    "INTENSIVE_DATA_ACCESS",
                    "Unusual high frequency data access detected",
                    RiskLevel.MEDIUM,
                    sessionId
                )
            }
        }
        
        // Patrón 3: Intentos de rotación de clave frecuentes
        if (category == "KEY_ROTATION") {
            logSuspiciousActivity(
                "KEY_ROTATION_ATTEMPT",
                "Key rotation operation detected",
                RiskLevel.MEDIUM,
                sessionId
            )
        }
    }
    
    /**
     * Registra actividad sospechosa
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun logSuspiciousActivity(
        activityType: String,
        description: String,
        riskLevel: RiskLevel,
        sourceIdentifier: String
    ) {
        val suspiciousActivity = SuspiciousActivity(
            timestamp = System.currentTimeMillis(),
            activityType = activityType,
            description = description,
            riskLevel = riskLevel,
            sourceIdentifier = sourceIdentifier
        )
        
        suspiciousActivities.add(suspiciousActivity)
        
        // Mantener solo las últimas 100 actividades sospechosas
        if (suspiciousActivities.size > 100) {
            suspiciousActivities.removeAt(0)
        }
        
        // Log en sistema Android para monitoreo
        android.util.Log.w("SecurityAudit", "SUSPICIOUS: $activityType - $description (Risk: $riskLevel)")
        
        // Generar alerta crítica si es necesario
        if (riskLevel == RiskLevel.CRITICAL) {
            generateSecurityAlert(suspiciousActivity)
        }
    }
    
    /**
     * Genera alertas de seguridad críticas
     */
    private fun generateSecurityAlert(activity: SuspiciousActivity) {
        // Aquí se podría enviar notificación, email, o webhook
        android.util.Log.e("SecurityAlert", 
            "CRITICAL SECURITY ALERT: ${activity.activityType} - ${activity.description}")
        
        // Guardar alerta en preferencias para revisión posterior
        val alerts = auditPrefs.getString("security_alerts", "") ?: ""
        val newAlert = "${activity.timestamp}|${activity.activityType}|${activity.description}"
        val updatedAlerts = if (alerts.isEmpty()) newAlert else "$alerts\n$newAlert"
        
        auditPrefs.edit().putString("security_alerts", updatedAlerts).apply()
    }
    
    /**
     * Guarda entrada de auditoría
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun saveAuditEntry(entry: AuditEntry) {
        val existingEntries = getAuditEntries().toMutableList()
        existingEntries.add(entry)
        
        // Mantener solo las últimas MAX_AUDIT_ENTRIES entradas
        if (existingEntries.size > MAX_AUDIT_ENTRIES) {
            existingEntries.removeAt(0)
        }
        
        // Serializar y guardar
        val jsonArray = JSONArray()
        existingEntries.forEach { auditEntry ->
            val jsonObject = JSONObject().apply {
                put("timestamp", auditEntry.timestamp)
                put("category", auditEntry.category)
                put("action", auditEntry.action)
                put("sessionId", auditEntry.sessionId)
                put("riskLevel", auditEntry.riskLevel.name)
                put("metadata", JSONObject(auditEntry.metadata))
            }
            jsonArray.put(jsonObject)
        }
        
        auditPrefs.edit().putString("audit_entries", jsonArray.toString()).apply()
    }
    
    /**
     * Obtiene entradas de auditoría
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun getAuditEntries(): List<AuditEntry> {
        val entriesJson = auditPrefs.getString("audit_entries", null) ?: return emptyList()
        
        return try {
            val jsonArray = JSONArray(entriesJson)
            val entries = mutableListOf<AuditEntry>()
            
            for (i in 0 until jsonArray.length()) {
                val jsonObject = jsonArray.getJSONObject(i)
                val metadataJson = jsonObject.getJSONObject("metadata")
                val metadata = mutableMapOf<String, String>()
                
                metadataJson.keys().forEach { key ->
                    metadata[key] = metadataJson.getString(key)
                }
                
                entries.add(
                    AuditEntry(
                        timestamp = jsonObject.getLong("timestamp"),
                        category = jsonObject.getString("category"),
                        action = jsonObject.getString("action"),
                        sessionId = jsonObject.getString("sessionId"),
                        riskLevel = RiskLevel.valueOf(jsonObject.getString("riskLevel")),
                        metadata = metadata
                    )
                )
            }
            entries
        } catch (e: Exception) {
            android.util.Log.e("SecurityAuditManager", "Error parsing audit entries: ${e.message}")
            emptyList()
        }
    }
    
    /**
     * Exporta logs en formato JSON firmado digitalmente
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun exportSignedAuditLogs(): String {
        val auditEntries = getAuditEntries()
        val suspiciousActivitiesList = suspiciousActivities.toList()
        
        val exportData = JSONObject().apply {
            put("exportTimestamp", System.currentTimeMillis())
            put("exportVersion", "1.0")
            put("deviceInfo", getDeviceInfo())
            
            // Audit entries
            val entriesArray = JSONArray()
            auditEntries.forEach { entry ->
                val entryJson = JSONObject().apply {
                    put("timestamp", entry.timestamp)
                    put("category", entry.category)
                    put("action", entry.action)
                    put("sessionId", entry.sessionId)
                    put("riskLevel", entry.riskLevel.name)
                    put("metadata", JSONObject(entry.metadata))
                }
                entriesArray.put(entryJson)
            }
            put("auditEntries", entriesArray)
            
            // Suspicious activities
            val suspiciousArray = JSONArray()
            suspiciousActivitiesList.forEach { activity ->
                val activityJson = JSONObject().apply {
                    put("timestamp", activity.timestamp)
                    put("activityType", activity.activityType)
                    put("description", activity.description)
                    put("riskLevel", activity.riskLevel.name)
                    put("sourceIdentifier", activity.sourceIdentifier)
                }
                suspiciousArray.put(activityJson)
            }
            put("suspiciousActivities", suspiciousArray)
            
            // Statistics
            put("statistics", getAuditStatistics())
        }
        
        val jsonString = exportData.toString(2) // Pretty print with 2-space indentation
        
        // Firmar digitalmente el contenido
        val signature = generateDigitalSignature(jsonString)
        
        val signedExport = JSONObject().apply {
            put("data", exportData)
            put("signature", signature)
            put("signatureAlgorithm", "HMAC-SHA256")
            put("signedAt", System.currentTimeMillis())
        }
        
        return signedExport.toString(2)
    }
    
    /**
     * Genera estadísticas de auditoría
     */
    private fun getAuditStatistics(): JSONObject {
        val auditEntries = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getAuditEntries()
        } else {
            emptyList()
        }
        
        val categoryStats = auditEntries.groupBy { it.category }.mapValues { it.value.size }
        val riskLevelStats = auditEntries.groupBy { it.riskLevel }.mapValues { it.value.size }
        
        return JSONObject().apply {
            put("totalEntries", auditEntries.size)
            put("totalSuspiciousActivities", suspiciousActivities.size)
            put("categoryCounts", JSONObject(categoryStats))
            put("riskLevelCounts", JSONObject(riskLevelStats.mapKeys { it.key.name }))
            put("timeRange", JSONObject().apply {
                if (auditEntries.isNotEmpty()) {
                    put("earliest", auditEntries.minOf { it.timestamp })
                    put("latest", auditEntries.maxOf { it.timestamp })
                }
            })
        }
    }
    
    /**
     * Obtiene información del dispositivo
     */
    private fun getDeviceInfo(): JSONObject {
        return JSONObject().apply {
            put("model", Build.MODEL)
            put("manufacturer", Build.MANUFACTURER)
            put("androidVersion", Build.VERSION.RELEASE)
            put("sdkVersion", Build.VERSION.SDK_INT)
            put("appVersion", getAppVersion())
        }
    }
    
    /**
     * Obtiene versión de la aplicación
     */
    private fun getAppVersion(): String {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName ?: "unknown"
        } catch (e: Exception) {
            "unknown"
        }
    }
    
    /**
     * Genera firma digital HMAC para el contenido
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateDigitalSignature(content: String): String {
        val salt = getOrCreateAuditSalt()
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(salt, HMAC_ALGORITHM)
        mac.init(secretKey)
        
        val signature = mac.doFinal(content.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(signature)
    }
    
    /**
     * Obtiene o crea salt para auditoría
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun getOrCreateAuditSalt(): ByteArray {
        val existingSalt = auditPrefs.getString(AUDIT_SALT_KEY, null)
        
        return if (existingSalt != null) {
            Base64.getDecoder().decode(existingSalt)
        } else {
            val newSalt = ByteArray(32)
            SecureRandom().nextBytes(newSalt)
            auditPrefs.edit().putString(
                AUDIT_SALT_KEY,
                Base64.getEncoder().encodeToString(newSalt)
            ).apply()
            newSalt
        }
    }
    
    /**
     * Genera ID de sesión único
     */
    private fun generateSessionId(): String {
        return UUID.randomUUID().toString().take(8)
    }
    
    /**
     * Obtiene resumen de actividades sospechosas
     */
    fun getSuspiciousActivitiesSummary(): Map<String, Any> {
        val recentActivities = suspiciousActivities.filter { 
            System.currentTimeMillis() - it.timestamp < 24 * 60 * 60 * 1000 // Últimas 24 horas
        }
        
        return mapOf(
            "totalSuspicious" to suspiciousActivities.size,
            "recentSuspicious" to recentActivities.size,
            "highRiskCount" to suspiciousActivities.count { it.riskLevel == RiskLevel.HIGH },
            "criticalRiskCount" to suspiciousActivities.count { it.riskLevel == RiskLevel.CRITICAL },
            "lastActivity" to (suspiciousActivities.lastOrNull()?.timestamp ?: 0)
        )
    }
    
    /**
     * Limpia logs antiguos
     */
    fun cleanupOldLogs(maxAgeMs: Long = 30L * 24 * 60 * 60 * 1000) { // 30 días por defecto
        val currentTime = System.currentTimeMillis()
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val entries = getAuditEntries().filter { currentTime - it.timestamp <= maxAgeMs }
            
            val jsonArray = JSONArray()
            entries.forEach { entry ->
                val jsonObject = JSONObject().apply {
                    put("timestamp", entry.timestamp)
                    put("category", entry.category)
                    put("action", entry.action)
                    put("sessionId", entry.sessionId)
                    put("riskLevel", entry.riskLevel.name)
                    put("metadata", JSONObject(entry.metadata))
                }
                jsonArray.put(jsonObject)
            }
            
            auditPrefs.edit().putString("audit_entries", jsonArray.toString()).apply()
        }
        
        // Limpiar actividades sospechosas antiguas
        suspiciousActivities.removeAll { currentTime - it.timestamp > maxAgeMs }
    }
}
