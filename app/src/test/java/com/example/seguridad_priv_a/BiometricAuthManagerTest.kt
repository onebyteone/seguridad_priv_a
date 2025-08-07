package com.example.seguridad_priv_a

import android.content.Context
import android.content.SharedPreferences
import com.example.seguridad_priv_a.security.BiometricAuthManager
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.MockitoAnnotations

class BiometricAuthManagerTest {

    @Mock
    private lateinit var context: Context
    
    @Mock
    private lateinit var sessionPrefs: SharedPreferences
    
    @Mock
    private lateinit var prefsEditor: SharedPreferences.Editor
    
    private lateinit var biometricAuthManager: BiometricAuthManager

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        
        // Mock SharedPreferences behavior
        `when`(context.getSharedPreferences("biometric_session", Context.MODE_PRIVATE)).thenReturn(sessionPrefs)
        `when`(sessionPrefs.edit()).thenReturn(prefsEditor)
        `when`(prefsEditor.putLong(anyString(), anyLong())).thenReturn(prefsEditor)
        `when`(prefsEditor.putBoolean(anyString(), anyBoolean())).thenReturn(prefsEditor)
        `when`(prefsEditor.remove(anyString())).thenReturn(prefsEditor)
        
        biometricAuthManager = BiometricAuthManager(context)
    }

    @After
    fun tearDown() {
        // Cleanup after each test
    }

    @Test
    fun testBiometricAuthManagerCreation() {
        // Test that we can create a BiometricAuthManager and it doesn't crash
        assertNotNull("BiometricAuthManager should be created", biometricAuthManager)
        
        // Verify that it tries to access SharedPreferences
        verify(context, times(1)).getSharedPreferences("biometric_session", Context.MODE_PRIVATE)
    }

    @Test
    fun testSessionInactiveByDefault() {
        // Arrange
        `when`(sessionPrefs.getLong(anyString(), anyLong())).thenReturn(0L)
        `when`(sessionPrefs.getBoolean(anyString(), anyBoolean())).thenReturn(false)

        // Act
        val isActive = biometricAuthManager.isSessionActive()

        // Assert
        assertFalse("Session should be inactive by default", isActive)
    }

    @Test
    fun testSessionActiveWithRecentAuth() {
        // Arrange
        val currentTime = System.currentTimeMillis()
        val recentAuthTime = currentTime - 60000 // 1 minute ago
        
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(recentAuthTime)
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(true)

        // Act
        val isActive = biometricAuthManager.isSessionActive()

        // Assert
        assertTrue("Session should be active with recent authentication", isActive)
    }

    @Test
    fun testSessionExpiredWithOldAuth() {
        // Arrange
        val currentTime = System.currentTimeMillis()
        val oldAuthTime = currentTime - (6 * 60 * 1000) // 6 minutes ago (expired)
        
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(oldAuthTime)
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(true)

        // Act
        val isActive = biometricAuthManager.isSessionActive()

        // Assert
        assertFalse("Session should be expired with old authentication", isActive)
    }

    @Test
    fun testInvalidateSession() {
        // Act
        biometricAuthManager.invalidateSession()

        // Assert
        verify(sessionPrefs, times(1)).edit()
        verify(prefsEditor, times(1)).putBoolean("session_active", false)
        verify(prefsEditor, times(1)).remove("last_auth_time")
        verify(prefsEditor, times(1)).apply()
    }

    @Test
    fun testUpdateLastActivity() {
        // Arrange - Mock an active session
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(System.currentTimeMillis())
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(true)

        // Act
        biometricAuthManager.updateLastActivity()

        // Assert
        verify(sessionPrefs, atLeastOnce()).edit()
        verify(prefsEditor, atLeastOnce()).putLong(eq("last_auth_time"), anyLong())
        verify(prefsEditor, atLeastOnce()).apply()
    }

    @Test
    fun testGetAuthInfoStructure() {
        // Arrange
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(System.currentTimeMillis())
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(true)

        // Act
        val authInfo = biometricAuthManager.getAuthInfo()

        // Assert
        assertTrue("Should contain biometricStatus key", authInfo.containsKey("biometricStatus"))
        assertTrue("Should contain sessionActive key", authInfo.containsKey("sessionActive"))
        assertTrue("Should contain timeRemaining key", authInfo.containsKey("timeRemaining"))
        assertTrue("Should contain sessionTimeoutMinutes key", authInfo.containsKey("sessionTimeoutMinutes"))
        assertTrue("Should contain lastAuthTime key", authInfo.containsKey("lastAuthTime"))
        
        // Check timeout value
        val timeoutMinutes = authInfo["sessionTimeoutMinutes"] as Long
        assertEquals("Session timeout should be 5 minutes", 5L, timeoutMinutes)
    }

    @Test
    fun testBiometricAuthStatusEnum() {
        // Test that the BiometricAuthStatus enum has expected values
        val statusValues = BiometricAuthManager.BiometricAuthStatus.values()
        
        assertEquals("Should have 7 status values", 7, statusValues.size)
        assertTrue("Should contain AVAILABLE", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.AVAILABLE))
        assertTrue("Should contain NO_HARDWARE", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.NO_HARDWARE))
        assertTrue("Should contain UNAVAILABLE", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.UNAVAILABLE))
        assertTrue("Should contain NOT_ENROLLED", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.NOT_ENROLLED))
        assertTrue("Should contain SECURITY_UPDATE_REQUIRED", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.SECURITY_UPDATE_REQUIRED))
        assertTrue("Should contain UNSUPPORTED", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.UNSUPPORTED))
        assertTrue("Should contain UNKNOWN", statusValues.contains(BiometricAuthManager.BiometricAuthStatus.UNKNOWN))
    }

    @Test
    fun testTimeRemainingCalculation() {
        // Arrange
        val currentTime = System.currentTimeMillis()
        val authTime = currentTime - 120000 // 2 minutes ago
        
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(authTime)
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(true)

        // Act
        val authInfo = biometricAuthManager.getAuthInfo()
        val timeRemaining = authInfo["timeRemaining"] as Long

        // Assert
        assertTrue("Time remaining should be positive", timeRemaining > 0)
        assertTrue("Time remaining should be less than 5 minutes", timeRemaining < 5 * 60 * 1000)
        // Should be approximately 3 minutes remaining (5 - 2 = 3)
        assertTrue("Time remaining should be around 3 minutes", 
            timeRemaining > 2.5 * 60 * 1000 && timeRemaining < 3.5 * 60 * 1000)
    }

    @Test
    fun testInactiveSessionTimeRemaining() {
        // Arrange
        `when`(sessionPrefs.getLong("last_auth_time", 0)).thenReturn(0L)
        `when`(sessionPrefs.getBoolean("session_active", false)).thenReturn(false)

        // Act
        val authInfo = biometricAuthManager.getAuthInfo()
        val timeRemaining = authInfo["timeRemaining"] as Long

        // Assert
        assertEquals("Inactive session should have 0 time remaining", 0L, timeRemaining)
    }
}
