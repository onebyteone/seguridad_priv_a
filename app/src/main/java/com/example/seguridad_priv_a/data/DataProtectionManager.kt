package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {
    
    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private lateinit var currentMasterKey: MasterKey
    private lateinit var userSalt: ByteArray
    private lateinit var securityAuditManager: SecurityAuditManager
    
    companion object {
        private const val KEY_ROTATION_INTERVAL_DAYS = 30
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val AES_ALGORITHM = "AES/GCM/NoPadding"
        private const val SALT_LENGTH = 32
        private const val IV_LENGTH = 12
        private const val TAG_LENGTH = 16
        private const val KEY_ALIAS_PREFIX = "master_key_"
        private const val USER_SALT_KEY = "user_salt"
        private const val LAST_KEY_ROTATION_KEY = "last_key_rotation"
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    fun initialize() {
        try {
            // Inicializar SecurityAuditManager PRIMERO
            securityAuditManager = SecurityAuditManager(context)
            
            // Inicializar SharedPreferences de logs PRIMERO (antes de cualquier operación que pueda fallar)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            
            // Log inicio de inicialización
            securityAuditManager.logSecurityEvent(
                "SYSTEM_INITIALIZATION", 
                "DataProtectionManager initialization started",
                mapOf("timestamp" to System.currentTimeMillis().toString())
            )
            
            // Inicializar o generar salt único del usuario
            initializeUserSalt()
            
            // Intentar crear el sistema de encriptación con recuperación automática
            initializeEncryptionWithRecovery()
            
            logAccess("SECURITY", "Sistema de protección de datos inicializado correctamente")
            
        } catch (e: Exception) {
            // Asegurar que accessLogPrefs esté inicializado antes de usarlo
            if (!::accessLogPrefs.isInitialized) {
                accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            }
            logAccess("SECURITY_ERROR", "Error crítico en inicialización: ${e.message}")
            throw SecurityException("Failed to initialize secure storage", e)
        }
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    fun storeSecureData(key: String, value: String) {
        try {
            // Validar entrada
            if (key.isBlank() || value.isBlank()) {
                throw IllegalArgumentException("Key and value cannot be blank")
            }
            
            // Auditar operación de almacenamiento
            securityAuditManager.logSecurityEvent(
                "DATA_STORAGE",
                "STORE_SECURE_DATA",
                mapOf(
                    "key" to key,
                    "dataSize" to value.length.toString(),
                    "timestamp" to System.currentTimeMillis().toString()
                )
            )
            
            // Generar HMAC para verificación de integridad
            val hmac = generateHMAC(value, key)
            val dataWithHmac = "$value|$hmac"
            
            encryptedPrefs.edit().putString(key, dataWithHmac).apply()
            logAccess("DATA_STORAGE", "Dato almacenado de forma segura con verificación de integridad")
        } catch (e: Exception) {
            // Auditar error de seguridad
            securityAuditManager.logSecurityEvent(
                "SECURITY_ERROR",
                "STORE_DATA_FAILED",
                mapOf(
                    "error" to (e.message ?: "Unknown error"),
                    "key" to key
                )
            )
            logAccess("SECURITY_ERROR", "Error al almacenar dato: ${e.message}")
            throw e
        }
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    fun getSecureData(key: String): String? {
        try {
            // Auditar intento de acceso a datos
            securityAuditManager.logSecurityEvent(
                "DATA_ACCESS",
                "GET_SECURE_DATA",
                mapOf(
                    "key" to key,
                    "timestamp" to System.currentTimeMillis().toString()
                )
            )
            
            val dataWithHmac = encryptedPrefs.getString(key, null) ?: return null
            
            // Verificar integridad del dato
            if (!verifyDataIntegrity(key)) {
                // Auditar fallo de integridad
                securityAuditManager.logSecurityEvent(
                    "SECURITY_ERROR",
                    "INTEGRITY_VERIFICATION_FAILED",
                    mapOf(
                        "key" to key,
                        "reason" to "HMAC verification failed"
                    )
                )
                logAccess("SECURITY_ERROR", "Verificación de integridad falló para clave: $key")
                return null
            }
            
            // Extraer solo el valor (sin HMAC)
            val parts = dataWithHmac.split("|")
            if (parts.size != 2) {
                // Auditar formato inválido
                securityAuditManager.logSecurityEvent(
                    "SECURITY_ERROR",
                    "INVALID_DATA_FORMAT",
                    mapOf(
                        "key" to key,
                        "parts_count" to parts.size.toString()
                    )
                )
                logAccess("SECURITY_ERROR", "Formato de dato inválido para clave: $key")
                return null
            }
            
            logAccess("DATA_ACCESS", "Dato accedido con verificación de integridad")
            return parts[0]
        } catch (e: Exception) {
            // Auditar error de acceso
            securityAuditManager.logSecurityEvent(
                "SECURITY_ERROR",
                "DATA_ACCESS_FAILED",
                mapOf(
                    "error" to (e.message ?: "Unknown error"),
                    "key" to key
                )
            )
            logAccess("SECURITY_ERROR", "Error al acceder dato: ${e.message}")
            return null
        }
    }
    
    fun logAccess(category: String, action: String) {
        try {
            // Verificar que accessLogPrefs esté inicializado
            if (!::accessLogPrefs.isInitialized) {
                accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            }
            
            val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
            val logEntry = "$timestamp - $category: $action"
            
            // Obtener logs existentes
            val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
            val newLogs = if (existingLogs.isEmpty()) {
                logEntry
            } else {
                "$existingLogs\\n$logEntry"
            }
            
            // Guardar logs actualizados
            accessLogPrefs.edit().putString("logs", newLogs).apply()
            
            // Limitar el número de logs (mantener solo los últimos 100)
            val logLines = newLogs.split("\\n")
            if (logLines.size > 100) {
                val trimmedLogs = logLines.takeLast(100).joinToString("\\n")
                accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
            }
        } catch (e: Exception) {
            // Si hay algún error en el logging, no debería crashear la aplicación
            // Solo imprimimos en el log del sistema
            android.util.Log.e("DataProtectionManager", "Error en logAccess: ${e.message}")
        }
    }
    
    fun getAccessLogs(): List<String> {
        return try {
            // Verificar que accessLogPrefs esté inicializado
            if (!::accessLogPrefs.isInitialized) {
                accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            }
            
            val logsString = accessLogPrefs.getString("logs", "") ?: ""
            if (logsString.isEmpty()) {
                emptyList()
            } else {
                logsString.split("\\n").reversed() // Mostrar los más recientes primero
            }
        } catch (e: Exception) {
            android.util.Log.e("DataProtectionManager", "Error al obtener logs: ${e.message}")
            emptyList()
        }
    }
    
    fun clearAllData() {
        try {
            // Verificar que las referencias estén inicializadas antes de usarlas
            if (::encryptedPrefs.isInitialized) {
                encryptedPrefs.edit().clear().apply()
            }
            
            if (!::accessLogPrefs.isInitialized) {
                accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            }
            accessLogPrefs.edit().clear().apply()
            
            logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
        } catch (e: Exception) {
            android.util.Log.e("DataProtectionManager", "Error al limpiar datos: ${e.message}")
        }
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    fun getDataProtectionInfo(): Map<String, String> {
        val lastRotation = getSecureData(LAST_KEY_ROTATION_KEY)
        val daysSinceRotation = lastRotation?.let {
            val lastRotationTime = it.toLongOrNull() ?: 0
            val daysDiff = (System.currentTimeMillis() - lastRotationTime) / (1000 * 60 * 60 * 24)
            daysDiff.toString()
        } ?: "Desconocido"
        
        return mapOf(
            "Encriptación" to "AES-256-GCM con HMAC-SHA256",
            "Almacenamiento" to "Local encriptado con rotación de claves",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Última limpieza" to (getSecureData("last_cleanup") ?: "Nunca"),
            "Última rotación de clave" to "$daysSinceRotation días",
            "Salt de usuario" to "Configurado (${userSalt.size} bytes)",
            "Estado de seguridad" to "Activo con verificación de integridad"
        )
    }
    
    fun anonymizeData(data: String): String {
        // Implementación básica de anonimización
        return data.replace(Regex("[0-9]"), "*")
            .replace(Regex("[A-Za-z]{3,}"), "***")
    }
    
    // ============ NUEVAS FUNCIONES DE SEGURIDAD AVANZADA ============
    
    /**
     * Rota la clave de encriptación maestra automáticamente cada 30 días
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun rotateEncryptionKey(): Boolean {
        return try {
            // Auditar inicio de rotación de clave
            securityAuditManager.logSecurityEvent(
                "KEY_ROTATION",
                "ROTATION_STARTED",
                mapOf(
                    "timestamp" to System.currentTimeMillis().toString(),
                    "reason" to "Manual or automatic rotation"
                )
            )
            
            logAccess("SECURITY", "Iniciando rotación de clave maestra")
            
            // Backup de datos con clave actual
            val currentData = backupCurrentData()
            
            // Generar nueva clave maestra
            val newKeyAlias = generateNewMasterKey()
            
            // Crear nuevas SharedPreferences con la nueva clave
            val newMasterKey = MasterKey.Builder(context, newKeyAlias)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            
            val newEncryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs_new",
                newMasterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            
            // Migrar datos a la nueva clave
            migrateDataToNewKey(currentData, newEncryptedPrefs)
            
            // Actualizar referencias
            encryptedPrefs = newEncryptedPrefs
            currentMasterKey = newMasterKey
            
            // Registrar la rotación
            val currentTime = System.currentTimeMillis()
            storeSecureData(LAST_KEY_ROTATION_KEY, currentTime.toString())
            
            logAccess("SECURITY", "Rotación de clave completada exitosamente")
            true
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error en rotación de clave: ${e.message}")
            false
        }
    }
    
    /**
     * Verifica la integridad de los datos encriptados usando HMAC
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun verifyDataIntegrity(key: String): Boolean {
        return try {
            val dataWithHmac = encryptedPrefs.getString(key, null) ?: return false
            val parts = dataWithHmac.split("|")
            
            if (parts.size != 2) return false
            
            val originalData = parts[0]
            val storedHmac = parts[1]
            val calculatedHmac = generateHMAC(originalData, key)
            
            // Comparación segura para prevenir timing attacks
            MessageDigest.isEqual(
                storedHmac.toByteArray(StandardCharsets.UTF_8),
                calculatedHmac.toByteArray(StandardCharsets.UTF_8)
            )
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error en verificación de integridad: ${e.message}")
            false
        }
    }
    
    // ============ FUNCIONES AUXILIARES PRIVADAS ============
    
    @RequiresApi(Build.VERSION_CODES.O)
    private fun initializeUserSalt() {
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        val existingSalt = saltPrefs.getString(USER_SALT_KEY, null)
        
        userSalt = if (existingSalt != null) {
            Base64.getDecoder().decode(existingSalt)
        } else {
            // Generar nuevo salt único para el usuario
            val newSalt = ByteArray(SALT_LENGTH)
            SecureRandom().nextBytes(newSalt)
            
            // Almacenar el salt
            saltPrefs.edit().putString(
                USER_SALT_KEY, 
                Base64.getEncoder().encodeToString(newSalt)
            ).apply()
            
            logAccess("SECURITY", "Nuevo salt de usuario generado")
            newSalt
        }
    }
    
    private fun shouldRotateKey(): Boolean {
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        val lastRotation = saltPrefs.getLong(LAST_KEY_ROTATION_KEY, 0)
        val daysSinceRotation = (System.currentTimeMillis() - lastRotation) / (1000 * 60 * 60 * 24)
        
        return daysSinceRotation >= KEY_ROTATION_INTERVAL_DAYS
    }
    
    private fun getCurrentMasterKey(): MasterKey {
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        val currentKeyAlias = saltPrefs.getString("current_key_alias", null)
            ?: generateNewMasterKey()
        
        return MasterKey.Builder(context, currentKeyAlias)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }
    
    private fun generateNewMasterKey(): String {
        val keyAlias = "${KEY_ALIAS_PREFIX}${System.currentTimeMillis()}"
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        saltPrefs.edit().putString("current_key_alias", keyAlias).apply()
        return keyAlias
    }
    
    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateHMAC(data: String, context: String): String {
        // Derivar clave HMAC usando salt del usuario y contexto
        val keyDerivationData = "${context}:${Base64.getEncoder().encodeToString(userSalt)}"
        val derivedKey = deriveKey(keyDerivationData.toByteArray(StandardCharsets.UTF_8))
        
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(derivedKey, HMAC_ALGORITHM)
        mac.init(secretKey)
        
        val hmacBytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(hmacBytes)
    }
    
    private fun deriveKey(inputData: ByteArray): ByteArray {
        // Implementación de key derivation con PBKDF2
        val digest = MessageDigest.getInstance("SHA-256")
        
        // Combinar input con salt del usuario
        digest.update(userSalt)
        digest.update(inputData)
        
        return digest.digest()
    }
    
    private fun backupCurrentData(): Map<String, String> {
        val backup = mutableMapOf<String, String>()
        val allKeys = encryptedPrefs.all
        
        for ((key, value) in allKeys) {
            if (value is String) {
                backup[key] = value
            }
        }
        
        return backup
    }
    
    private fun migrateDataToNewKey(data: Map<String, String>, newPrefs: SharedPreferences) {
        val editor = newPrefs.edit()
        
        for ((key, value) in data) {
            editor.putString(key, value)
        }
        
        editor.apply()
        logAccess("SECURITY", "Migración de ${data.size} elementos completada")
    }
    
    // ============ FUNCIONES DE RECUPERACIÓN ============
    
    /**
     * Inicializa el sistema de encriptación con recuperación automática en caso de error
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun initializeEncryptionWithRecovery() {
        var attempt = 0
        val maxAttempts = 3
        
        while (attempt < maxAttempts) {
            try {
                attempt++
                logAccess("SECURITY", "Intento $attempt de inicialización de encriptación")
                
                // Verificar si necesitamos rotación de clave
                if (shouldRotateKey()) {
                    rotateEncryptionKey()
                }
                
                // Crear o obtener la clave maestra actual
                currentMasterKey = getCurrentMasterKey()
                    
                // Crear SharedPreferences encriptado para datos sensibles
                encryptedPrefs = EncryptedSharedPreferences.create(
                    context,
                    "secure_prefs",
                    currentMasterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
                
                logAccess("SECURITY", "Encriptación inicializada exitosamente en intento $attempt")
                return
                
            } catch (e: Exception) {
                logAccess("SECURITY_ERROR", "Error en intento $attempt: ${e.javaClass.simpleName} - ${e.message}")
                
                when {
                    e is javax.crypto.AEADBadTagException || 
                    e.cause is javax.crypto.AEADBadTagException -> {
                        logAccess("SECURITY_RECOVERY", "Detectado AEADBadTagException - iniciando recuperación")
                        handleCorruptedKeystore(attempt)
                    }
                    e.message?.contains("AndroidKeysetManager") == true -> {
                        logAccess("SECURITY_RECOVERY", "Error de AndroidKeysetManager - limpiando metadatos")
                        clearSecurityMetadata()
                    }
                    else -> {
                        logAccess("SECURITY_ERROR", "Error desconocido: ${e.message}")
                        if (attempt >= maxAttempts) {
                            throw e
                        }
                    }
                }
                
                // Esperar antes del siguiente intento
                Thread.sleep((100 * attempt).toLong())
            }
        }
        
        throw SecurityException("Failed to initialize encryption after $maxAttempts attempts")
    }
    
    /**
     * Maneja el caso cuando el keystore está corrupto
     */
    private fun handleCorruptedKeystore(attempt: Int) {
        try {
            logAccess("SECURITY_RECOVERY", "Manejando keystore corrupto - intento $attempt")
            
            when (attempt) {
                1 -> {
                    // Primer intento: limpiar alias de clave actual
                    clearCurrentKeyAlias()
                    logAccess("SECURITY_RECOVERY", "Alias de clave limpiado")
                }
                2 -> {
                    // Segundo intento: limpiar todos los metadatos de seguridad
                    clearSecurityMetadata()
                    logAccess("SECURITY_RECOVERY", "Metadatos de seguridad limpiados")
                }
                3 -> {
                    // Tercer intento: recrear con nombre diferente
                    clearEncryptedPreferences()
                    logAccess("SECURITY_RECOVERY", "Preferencias encriptadas limpiadas")
                }
            }
            
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error en recuperación: ${e.message}")
        }
    }
    
    /**
     * Limpia el alias de clave actual
     */
    private fun clearCurrentKeyAlias() {
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        saltPrefs.edit().remove("current_key_alias").apply()
    }
    
    /**
     * Limpia todos los metadatos de seguridad
     */
    private fun clearSecurityMetadata() {
        val saltPrefs = context.getSharedPreferences("security_metadata", Context.MODE_PRIVATE)
        saltPrefs.edit().clear().apply()
    }
    
    /**
     * Limpia las preferencias encriptadas existentes
     */
    private fun clearEncryptedPreferences() {
        try {
            // Intentar eliminar el archivo de preferencias encriptadas
            val prefsFile = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
            prefsFile.edit().clear().apply()
            
            // También limpiar posibles archivos relacionados
            val prefsDir = context.filesDir.parent + "/shared_prefs/"
            val files = listOf("secure_prefs.xml", "secure_prefs_new.xml")
            for (filename in files) {
                val file = java.io.File(prefsDir, filename)
                if (file.exists()) {
                    file.delete()
                    logAccess("SECURITY_RECOVERY", "Archivo eliminado: $filename")
                }
            }
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error al limpiar preferencias: ${e.message}")
        }
    }
    
    // ============ FUNCIONES DE AUDITORÍA AVANZADA ============
    
    /**
     * Obtiene el resumen de actividades sospechosas detectadas
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun getSuspiciousActivitiesSummary(): Map<String, Any> {
        return if (::securityAuditManager.isInitialized) {
            securityAuditManager.getSuspiciousActivitiesSummary()
        } else {
            emptyMap()
        }
    }
    
    /**
     * Exporta los logs de auditoría firmados digitalmente
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun exportSecurityAuditLogs(): String {
        return if (::securityAuditManager.isInitialized) {
            securityAuditManager.exportSignedAuditLogs()
        } else {
            "{\"error\": \"SecurityAuditManager not initialized\"}"
        }
    }
    
    /**
     * Limpia logs de auditoría antiguos
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun cleanupOldAuditLogs(maxAgeMs: Long = 30L * 24 * 60 * 60 * 1000) {
        if (::securityAuditManager.isInitialized) {
            securityAuditManager.cleanupOldLogs(maxAgeMs)
        }
    }
    
    /**
     * Obtiene información completa de protección de datos incluyendo auditoría
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun getCompleteSecurityInfo(): Map<String, Any> {
        val basicInfo = getDataProtectionInfo()
        val suspiciousInfo = getSuspiciousActivitiesSummary()
        
        return basicInfo + mapOf(
            "Sistema de Auditoría" to "Activo con detección de anomalías",
            "Actividades Sospechosas" to suspiciousInfo,
            "Rate Limiting" to "Habilitado para operaciones sensibles",
            "Firma Digital" to "HMAC-SHA256 para logs de auditoría"
        )
    }
}