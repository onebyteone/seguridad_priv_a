package com.example.seguridad_priv_a.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Gestor de Autenticación Biométrica con Fallback y Timeout de Sesión
 * 
 * Características:
 * - Autenticación biométrica usando BiometricPrompt API
 * - Fallback automático a PIN/Pattern si biometría no disponible
 * - Timeout de sesión tras 5 minutos de inactividad
 * - Integración segura con Android Keystore
 */
class BiometricAuthManager(private val context: Context) {
    
    private val sessionPrefs: SharedPreferences = context.getSharedPreferences("biometric_session", Context.MODE_PRIVATE)
    private val keystore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    
    companion object {
        private const val KEY_NAME = "biometric_auth_key"
        private const val CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding"
        private const val SESSION_TIMEOUT_MS = 5 * 60 * 1000L // 5 minutos
        private const val LAST_AUTH_TIME_KEY = "last_auth_time"
        private const val SESSION_ACTIVE_KEY = "session_active"
    }
    
    init {
        keystore.load(null)
    }
    
    /**
     * Verifica si la autenticación biométrica está disponible en el dispositivo
     */
    fun isBiometricAvailable(): BiometricAuthStatus {
        val biometricManager = BiometricManager.from(context)
        
        return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricAuthStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAuthStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricAuthStatus.UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricAuthStatus.NOT_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricAuthStatus.SECURITY_UPDATE_REQUIRED
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> BiometricAuthStatus.UNSUPPORTED
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> BiometricAuthStatus.UNKNOWN
            else -> BiometricAuthStatus.UNKNOWN
        }
    }
    
    /**
     * Verifica si hay una sesión activa válida
     */
    fun isSessionActive(): Boolean {
        val lastAuthTime = sessionPrefs.getLong(LAST_AUTH_TIME_KEY, 0)
        val isActive = sessionPrefs.getBoolean(SESSION_ACTIVE_KEY, false)
        val currentTime = System.currentTimeMillis()
        
        return isActive && (currentTime - lastAuthTime) < SESSION_TIMEOUT_MS
    }
    
    /**
     * Actualiza el timestamp de la última actividad
     */
    fun updateLastActivity() {
        if (isSessionActive()) {
            sessionPrefs.edit()
                .putLong(LAST_AUTH_TIME_KEY, System.currentTimeMillis())
                .apply()
        }
    }
    
    /**
     * Invalida la sesión actual
     */
    fun invalidateSession() {
        sessionPrefs.edit()
            .putBoolean(SESSION_ACTIVE_KEY, false)
            .remove(LAST_AUTH_TIME_KEY)
            .apply()
    }
    
    /**
     * Marca una sesión como activa después de autenticación exitosa
     */
    private fun markSessionActive() {
        sessionPrefs.edit()
            .putBoolean(SESSION_ACTIVE_KEY, true)
            .putLong(LAST_AUTH_TIME_KEY, System.currentTimeMillis())
            .apply()
    }
    
    /**
     * Genera o recupera la clave para autenticación biométrica
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateSecretKey(): SecretKey? {
        return try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(300) // 5 minutos
                .build()
            
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            android.util.Log.e("BiometricAuthManager", "Error generating secret key: ${e.message}")
            null
        }
    }
    
    /**
     * Obtiene la clave secreta del Android Keystore
     */
    private fun getSecretKey(): SecretKey? {
        return try {
            keystore.getKey(KEY_NAME, null) as SecretKey?
        } catch (e: Exception) {
            android.util.Log.e("BiometricAuthManager", "Error retrieving secret key: ${e.message}")
            null
        }
    }
    
    /**
     * Crea el cipher para autenticación biométrica
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun getCipher(): Cipher? {
        return try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            val secretKey = getSecretKey() ?: generateSecretKey()
            
            secretKey?.let {
                cipher.init(Cipher.ENCRYPT_MODE, it)
                cipher
            }
        } catch (e: Exception) {
            android.util.Log.e("BiometricAuthManager", "Error creating cipher: ${e.message}")
            null
        }
    }
    
    /**
     * Autentica usando biometría con fallback automático
     */
    fun authenticateUser(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onFallback: () -> Unit
    ) {
        // Verificar si la sesión ya está activa
        if (isSessionActive()) {
            updateLastActivity()
            onSuccess()
            return
        }
        
        val biometricStatus = isBiometricAvailable()
        
        when (biometricStatus) {
            BiometricAuthStatus.AVAILABLE -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    performBiometricAuth(activity, onSuccess, onError, onFallback)
                } else {
                    onFallback()
                }
            }
            BiometricAuthStatus.NOT_ENROLLED -> {
                onFallback() // Usuario puede configurar PIN/Pattern
            }
            BiometricAuthStatus.NO_HARDWARE,
            BiometricAuthStatus.UNAVAILABLE,
            BiometricAuthStatus.UNSUPPORTED -> {
                onFallback() // Fallback a PIN/Pattern
            }
            else -> {
                onError("Autenticación biométrica no disponible: $biometricStatus")
            }
        }
    }
    
    /**
     * Realiza autenticación biométrica
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun performBiometricAuth(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onFallback: () -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                        // Usuario canceló, no hacer nada
                    }
                    BiometricPrompt.ERROR_LOCKOUT,
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                        onFallback() // Muchos intentos fallidos, usar PIN/Pattern
                    }
                    else -> {
                        onError("Error de autenticación biométrica: $errString")
                    }
                }
            }
            
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                markSessionActive()
                onSuccess()
            }
            
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // No hacer nada, permitir más intentos
            }
        })
        
        val cipher = getCipher()
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación Requerida")
            .setSubtitle("Use su huella dactilar o PIN/Pattern")
            .setDescription("Confirme su identidad para acceder a información sensible")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        
        if (cipher != null) {
            val cryptoObject = BiometricPrompt.CryptoObject(cipher)
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        } else {
            // Autenticación sin crypto object como fallback
            biometricPrompt.authenticate(promptInfo)
        }
    }
    
    /**
     * Autentica usando PIN/Pattern del dispositivo
     */
    fun authenticateWithDeviceCredentials(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                if (errorCode != BiometricPrompt.ERROR_USER_CANCELED) {
                    onError("Error de autenticación: $errString")
                }
            }
            
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                markSessionActive()
                onSuccess()
            }
        })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación con PIN/Pattern")
            .setSubtitle("Ingrese su PIN o patrón del dispositivo")
            .setDescription("Confirme su identidad para acceder a información sensible")
            .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    /**
     * Obtiene información del estado de autenticación
     */
    fun getAuthInfo(): Map<String, Any> {
        val biometricStatus = isBiometricAvailable()
        val sessionActive = isSessionActive()
        val lastAuthTime = sessionPrefs.getLong(LAST_AUTH_TIME_KEY, 0)
        val timeRemaining = if (sessionActive) {
            SESSION_TIMEOUT_MS - (System.currentTimeMillis() - lastAuthTime)
        } else 0
        
        return mapOf(
            "biometricStatus" to biometricStatus.name,
            "sessionActive" to sessionActive,
            "timeRemaining" to timeRemaining,
            "sessionTimeoutMinutes" to (SESSION_TIMEOUT_MS / 60000),
            "lastAuthTime" to lastAuthTime
        )
    }
    
    /**
     * Estados posibles de autenticación biométrica
     */
    enum class BiometricAuthStatus {
        AVAILABLE,
        NO_HARDWARE,
        UNAVAILABLE,
        NOT_ENROLLED,
        SECURITY_UPDATE_REQUIRED,
        UNSUPPORTED,
        UNKNOWN
    }
}
