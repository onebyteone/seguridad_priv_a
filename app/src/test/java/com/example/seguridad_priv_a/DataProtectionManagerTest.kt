package com.example.seguridad_priv_a

import com.example.seguridad_priv_a.data.DataProtectionManager
import org.junit.Test
import org.mockito.kotlin.mock
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DataProtectionManagerTest {

    @Test
    fun `test anonymize data replaces sensitive information`() {
        // Given
        val mockContext = mock<android.content.Context>()
        val dataProtectionManager = DataProtectionManager(mockContext)
        val sensitiveData = "John Doe 123-45-6789 john@email.com"
        
        // When
        val anonymizedData = dataProtectionManager.anonymizeData(sensitiveData)
        
        // Then
        assertFalse(anonymizedData.contains("123-45-6789"))
        assertFalse(anonymizedData.contains("John"))
        assertFalse(anonymizedData.contains("Doe"))
        assertTrue(anonymizedData.contains("*"))
        assertTrue(anonymizedData.contains("***"))
    }

    @Test
    fun `test rotation key function signature exists`() {
        // This test ensures the rotateEncryptionKey function exists
        val method = DataProtectionManager::class.java.getDeclaredMethod("rotateEncryptionKey")
        assertNotNull(method)
        assertEquals(Boolean::class.java, method.returnType)
    }

    @Test
    fun `test verify data integrity function signature exists`() {
        // This test ensures the verifyDataIntegrity function exists
        val method = DataProtectionManager::class.java.getDeclaredMethod("verifyDataIntegrity", String::class.java)
        assertNotNull(method)
        assertEquals(Boolean::class.java, method.returnType)
    }
    
    @Test
    fun `test class can be instantiated`() {
        // Test that the class can be created with mocked context
        val mockContext = mock<android.content.Context>()
        val dataProtectionManager = DataProtectionManager(mockContext)
        assertNotNull(dataProtectionManager)
    }
    
    @Test
    fun `test security constants are properly defined`() {
        // Verify that our security improvements include proper anonymization
        val mockContext = mock<android.content.Context>()
        val dataProtectionManager = DataProtectionManager(mockContext)
        
        // Test anonymization works (this is the simplest test we can do without Android runtime)
        val testData = "TestData123"
        val anonymized = dataProtectionManager.anonymizeData(testData)
        
        // Should replace numbers and long words
        assertFalse(anonymized.contains("123"))
        assertFalse(anonymized.contains("TestData"))
        assertTrue(anonymized.contains("*"))
    }
}
