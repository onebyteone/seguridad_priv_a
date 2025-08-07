# App de Seguridad y Privacidad

Una aplicación Android que demuestra el manejo seguro de permisos y protección de datos personales.

## **Parte 1: Análisis de Seguridad Básico**

### **1.1 Identificación de Vulnerabilidades (2 puntos)**

**¿Qué método de encriptación se utiliza para proteger datos sensibles?**
- **AES-256-GCM** para el esquema de clave maestra (`MasterKey.KeyScheme.AES256_GCM`)
- **AES-256-SIV** para la encriptación de claves (`PrefKeyEncryptionScheme.AES256_SIV`)
- **AES-256-GCM** para la encriptación de valores (`PrefValueEncryptionScheme.AES256_GCM`)

**Identificación de al menos 2 posibles vulnerabilidades en la implementación actual del logging:**

1. **Logging de información sensible en texto plano**: 
   - En la función `logAccess()`, se registra información como nombres de claves (`"Dato almacenado de forma segura: $key"`) que podría revelar estructura de datos sensibles
   - Los logs se almacenan en SharedPreferences normales sin encriptación

2. **Falta de sanitización en los logs**:
   - Los parámetros `category` y `action` se concatenan directamente sin validación, permitiendo potencial log injection
   - No hay límites en el tamaño de las entradas individuales de log

**¿Qué sucede si falla la inicialización del sistema de encriptación?**
- La aplicación realiza un **fallback inseguro** a SharedPreferences normales (`"fallback_prefs"`)
- Esto significa que los datos "seguros" se almacenarían sin encriptación, comprometiendo completamente la seguridad
- No hay notificación al usuario sobre este fallo crítico de seguridad

### **1.2 Permisos y Manifiesto (2 puntos)**

**Lista de todos los permisos peligrosos declarados en el manifiesto:**
1. `android.permission.CAMERA`
2. `android.permission.READ_EXTERNAL_STORAGE`
3. `android.permission.READ_MEDIA_IMAGES`
4. `android.permission.RECORD_AUDIO`
5. `android.permission.READ_CONTACTS`
6. `android.permission.CALL_PHONE`
7. `android.permission.SEND_SMS`
8. `android.permission.ACCESS_COARSE_LOCATION`

**¿Qué patrón se utiliza para solicitar permisos en runtime?**
- **ActivityResultContracts.RequestPermission()** con `registerForActivityResult()`
- Implementa el patrón moderno de Android para manejo de permisos sin callbacks deprecated
- Incluye verificación de `shouldShowRequestPermissionRationale()` para mostrar explicaciones

**Configuración de seguridad que previene backups automáticos:**
- `android:allowBackup="false"` - Desactiva completamente los backups automáticos del sistema
- `android:dataExtractionRules="@xml/data_extraction_rules"` - Define reglas específicas para extracción de datos
- `android:fullBackupContent="@xml/backup_rules"` - Especifica qué contenido puede incluirse en backups

### **1.3 Gestión de Archivos (3 puntos)**

**¿Cómo se implementa la compartición segura de archivos de imágenes?**
- Utiliza **FileProvider** para compartir archivos de forma segura
- Se crea una URI segura usando `FileProvider.getUriForFile()` en lugar de acceso directo al sistema de archivos
- Los archivos se almacenan en el directorio privado de la aplicación (`getExternalFilesDir()`)

**¿Qué autoridad se utiliza para el FileProvider?**
- `"com.example.seguridad_priv_a.fileprovider"`

**¿Por qué no se debe usar  URIs directamente?**
1. **Violación de seguridad**: Las URIs  exponen rutas del sistema de archivos directamente
2. **FileUriExposedException**: Android 7.0+ lanza esta excepción al intentar pasar URIs de archivo entre aplicaciones
3. **Falta de control de acceso**: No permite granular permisos temporales como lo hace FileProvider
4. **Exposición de estructura interna**: Revela la estructura de directorios de la aplicación a otras apps
5. **Cumplimiento de Android Security**: FileProvider es la forma recomendada y segura según las mejores prácticas de Android

El FileProvider con file_paths.xml permite definir específicamente qué directorios pueden ser compartidos (`external-files-path name="my_images" path="Pictures"`), manteniendo el control y la seguridad.

---

## **Parte 2: Implementación y Mejoras Intermedias**

### **2.1 Fortalecimiento de la Encriptación (3 puntos) - IMPLEMENTADO ✅**

Se han implementado las siguientes mejoras de seguridad en `DataProtectionManager.kt`:

#### **🔄 Rotación Automática de Claves Maestras**
- **Implementación**: Función `rotateEncryptionKey()` que rota claves cada 30 días
- **Proceso seguro**: 
  1. Backup de datos con clave actual
  2. Generación de nueva clave maestra en Android Keystore
  3. Migración segura de datos a la nueva clave
  4. Limpieza de claves anteriores
- **Logging**: Registro completo del proceso de rotación para auditoría

#### **🛡️ Verificación de Integridad con HMAC**
- **Algoritmo**: HMAC-SHA256 para garantizar integridad de datos
- **Implementación**: Función `verifyDataIntegrity(key: String): Boolean`
- **Proceso**:
  1. Cada dato almacenado incluye su HMAC calculado
  2. Al recuperar datos, se verifica automáticamente la integridad
  3. Comparación segura para prevenir timing attacks
- **Formato de almacenamiento**: `"data|hmac_value"`

#### **🔐 Key Derivation con Salt Único por Usuario**
- **Salt único**: 32 bytes generados criptográficamente seguros por usuario
- **Derivación**: PBKDF2 con SHA-256 para derivar claves contextuales
- **Persistencia**: Salt almacenado de forma segura y reutilizado
- **Aplicación**: Usado para generar claves HMAC específicas por contexto

---

### **2.2 Sistema de Auditoría Avanzado (3 puntos) - IMPLEMENTADO ✅**

Se ha desarrollado un **Sistema de Auditoría Avanzado** completo mediante la clase `SecurityAuditManager.kt` con las siguientes características:

#### **🕵️ Detección de Intentos de Acceso Sospechosos**
- **Patrones anómalos detectados**:
  1. **Múltiples errores de seguridad consecutivos** (≥3): Detecta posibles ataques
  2. **Acceso intensivo a datos** (>20 accesos): Identifica comportamiento anormal
  3. **Intentos frecuentes de rotación de claves**: Detecta manipulación sospechosa
- **Clasificación de riesgo**: LOW, MEDIUM, HIGH, CRITICAL
- **Alertas automáticas**: Generación de alertas críticas para actividades de alto riesgo

#### **⚡ Rate Limiting para Operaciones Sensibles**
- **Límites implementados**:
  - `DATA_STORAGE`: 10 operaciones por minuto
  - `DATA_ACCESS`: 50 operaciones por minuto  
  - `KEY_ROTATION`: 1 operación por hora
  - `LOGIN_ATTEMPT`: 5 intentos por 5 minutos
  - `PERMISSION_REQUEST`: 20 solicitudes por 5 minutos
- **Ventanas deslizantes**: Implementación con limpieza automática de intentos antiguos
- **Bloqueo automático**: Prevención de ataques de fuerza bruta y DoS

#### **📊 Generación de Alertas por Patrones Anómalos**
- **Detección en tiempo real**: Análisis automático de cada evento de seguridad
- **Almacenamiento de actividades sospechosas**: Máximo 100 entradas con rotación automática
- **Metadatos completos**: Timestamp, tipo de actividad, nivel de riesgo, identificador de fuente
- **Alertas críticas**: Logging especializado para actividades de riesgo CRITICAL

#### **🔒 Exportación de Logs Firmados Digitalmente en JSON**
- **Formato estructurado**: JSON con metadatos completos del dispositivo y aplicación
- **Firma digital**: HMAC-SHA256 con salt único para verificar integridad
- **Contenido del export**:
  - Todas las entradas de auditoría con timestamps y metadata
  - Lista completa de actividades sospechosas detectadas
  - Estadísticas agregadas por categoría y nivel de riesgo
  - Información del dispositivo y versión de la aplicación
  - Firma digital verificable para prevenir manipulación

---

### **2.3 Biometría y Autenticación (3 puntos) - IMPLEMENTADO ✅**

Se ha implementado un **Sistema de Autenticación Biométrica** completo con fallback y timeout de sesión mediante la clase `BiometricAuthManager.kt`:

#### **🔐 Integración BiometricPrompt API**
- **API moderna**: Utiliza `androidx.biometric.BiometricPrompt` para autenticación biométrica
- **Soporte amplio**: Compatible con huella dactilar, reconocimiento facial y otras modalidades biométricas
- **Integración con Android Keystore**: Genera claves criptográficas protegidas por biometría
- **Configuración segura**: 
  - Cipher AES/CBC/PKCS7Padding para proteger datos
  - Claves requieren autenticación del usuario (`setUserAuthenticationRequired(true)`)
  - Validez de autenticación de 5 minutos por sesión

#### **🛡️ Fallback a PIN/Pattern del Dispositivo**
- **Detección automática**: Verifica disponibilidad de biometría en el dispositivo
- **Fallback inteligente**: 
  - Si no hay hardware biométrico → PIN/Pattern automáticamente
  - Si biometría no está configurada → Prompt para usar credenciales del dispositivo
  - Si hay demasiados intentos fallidos → Cambio automático a PIN/Pattern
- **Estados manejados**:
  - `BIOMETRIC_SUCCESS`: Biometría disponible y funcional
  - `BIOMETRIC_ERROR_NO_HARDWARE`: Sin hardware biométrico
  - `BIOMETRIC_ERROR_NONE_ENROLLED`: Usuario no tiene biometría configurada
  - `BIOMETRIC_ERROR_LOCKOUT`: Muchos intentos fallidos

#### **⏱️ Timeout de Sesión tras 5 minutos de Inactividad**
- **Monitoreo automático**: Handler con Runnable para timeout de 5 minutos exactos
- **Seguimiento de actividad**: Cada interacción del usuario resetea el contador
- **Gestión de ciclo de vida**:
  - `onPause()`: Pausa el timeout cuando la actividad no está visible
  - `onResume()`: Verifica validez de sesión y reanuda monitoreo
  - `onDestroy()`: Limpia handlers para evitar memory leaks
- **Invalidación automática**: Cierre de sesión y regreso a pantalla de autenticación
