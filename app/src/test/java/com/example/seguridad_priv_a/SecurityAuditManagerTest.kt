package com.example.seguridad_priv_a

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import com.example.seguridad_priv_a.data.SecurityAuditManager
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.MockitoAnnotations

class SecurityAuditManagerTest {

    @Mock
    private lateinit var context: Context
    
    @Mock
    private lateinit var auditPrefs: SharedPreferences
    
    @Mock
    private lateinit var prefsEditor: SharedPreferences.Editor
    
    private lateinit var securityAuditManager: SecurityAuditManager

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        
        // Mock SharedPreferences behavior
        `when`(context.getSharedPreferences("security_audit", Context.MODE_PRIVATE)).thenReturn(auditPrefs)
        `when`(auditPrefs.edit()).thenReturn(prefsEditor)
        `when`(prefsEditor.putString(anyString(), anyString())).thenReturn(prefsEditor)
        `when`(prefsEditor.remove(anyString())).thenReturn(prefsEditor)
        `when`(prefsEditor.clear()).thenReturn(prefsEditor)
        `when`(auditPrefs.getString(anyString(), anyString())).thenReturn(null)
        
        securityAuditManager = SecurityAuditManager(context)
    }

    @After
    fun tearDown() {
        // Cleanup after each test
    }

    @Test
    fun testSecurityEventLoggingBasic() {
        // Test that we can create a SecurityAuditManager and it doesn't crash
        assertNotNull("SecurityAuditManager should be created", securityAuditManager)
    }

    @Test
    fun testSuspiciousActivitiesSummaryStructure() {
        // Act
        val summary = securityAuditManager.getSuspiciousActivitiesSummary()

        // Assert
        assertNotNull("Summary should not be null", summary)
        assertTrue("Should contain totalSuspicious key", summary.containsKey("totalSuspicious"))
        assertTrue("Should contain recentSuspicious key", summary.containsKey("recentSuspicious"))
        assertTrue("Should contain highRiskCount key", summary.containsKey("highRiskCount"))
        assertTrue("Should contain criticalRiskCount key", summary.containsKey("criticalRiskCount"))
        assertTrue("Should contain lastActivity key", summary.containsKey("lastActivity"))
    }

    @Test
    fun testCleanupOldLogsDoesNotCrash() {
        // Act & Assert - This test verifies the cleanup method runs without errors
        try {
            securityAuditManager.cleanupOldLogs(1000)
            // If we reach this point, no exception was thrown
            assertTrue("Cleanup should execute without throwing exceptions", true)
        } catch (e: Exception) {
            fail("Cleanup should not throw exceptions: ${e.message}")
        }
    }

    @Test
    fun testGetSuspiciousActivitiesSummaryInitialState() {
        // Act
        val summary = securityAuditManager.getSuspiciousActivitiesSummary()

        // Assert
        val totalSuspicious = summary["totalSuspicious"] as? Int ?: -1
        val recentSuspicious = summary["recentSuspicious"] as? Int ?: -1
        val highRiskCount = summary["highRiskCount"] as? Int ?: -1
        val criticalRiskCount = summary["criticalRiskCount"] as? Int ?: -1
        
        assertTrue("Total suspicious should be 0 initially", totalSuspicious == 0)
        assertTrue("Recent suspicious should be 0 initially", recentSuspicious == 0)
        assertTrue("High risk count should be 0 initially", highRiskCount == 0)
        assertTrue("Critical risk count should be 0 initially", criticalRiskCount == 0)
    }

    @Test
    fun testSecurityAuditManagerCreation() {
        // Test that SecurityAuditManager can be instantiated with mocked context
        val newManager = SecurityAuditManager(context)
        assertNotNull("New SecurityAuditManager should be created", newManager)
        
        // Verify that it tries to access SharedPreferences
        verify(context, atLeastOnce()).getSharedPreferences("security_audit", Context.MODE_PRIVATE)
    }

    @Test
    fun testRiskLevelEnumValues() {
        // Test that the RiskLevel enum has expected values
        val riskLevels = SecurityAuditManager.RiskLevel.values()
        
        assertEquals("Should have 4 risk levels", 4, riskLevels.size)
        assertTrue("Should contain LOW", riskLevels.contains(SecurityAuditManager.RiskLevel.LOW))
        assertTrue("Should contain MEDIUM", riskLevels.contains(SecurityAuditManager.RiskLevel.MEDIUM))
        assertTrue("Should contain HIGH", riskLevels.contains(SecurityAuditManager.RiskLevel.HIGH))
        assertTrue("Should contain CRITICAL", riskLevels.contains(SecurityAuditManager.RiskLevel.CRITICAL))
        
        // Test risk level values
        assertEquals("LOW should have value 1", 1, SecurityAuditManager.RiskLevel.LOW.value)
        assertEquals("MEDIUM should have value 2", 2, SecurityAuditManager.RiskLevel.MEDIUM.value)
        assertEquals("HIGH should have value 3", 3, SecurityAuditManager.RiskLevel.HIGH.value)
        assertEquals("CRITICAL should have value 4", 4, SecurityAuditManager.RiskLevel.CRITICAL.value)
    }
}
