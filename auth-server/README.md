# Servidor de Autenticación de NexusVault

Un servicio RMI basado en Java que gestiona la autenticación y autorización para el sistema de archivos distribuido NexusVault.

## Descripción general

El Servidor de Autenticación proporciona servicios seguros de autenticación de usuarios y generación/validación de tokens JWT para todos los componentes de NexusVault, implementando un mecanismo central de control de acceso mediante tecnología Java RMI.

## Características

- **Gestión de usuarios**: Registro y validación de credenciales
- **Generación de tokens JWT**: Creación de tokens JSON Web seguros y con tiempo limitado
- **Validación de tokens**: Verificación de la integridad y expiración del token
- **Revocación de tokens**: Soporte para invalidación explícita de tokens (cerrar sesión)
- **Integración RMI**: Soporte para invocaciones remotas en arquitectura distribuida

## Requisitos

- Java 17 o superior
- Maven 3.8 o superior
- Base de datos MariaDB/MySQL

## Instalación y configuración

1. Clona el repositorio:

   ```bash
   git clone https://github.com/yourusername/nexusvault.git
   cd auth-server
   ```

2. Configura los ajustes de la base de datos en `src/main/resources/application.properties`:

   ```properties
   db.url=jdbc:mariadb://localhost:3306/nexusvault-authentication
   db.user=username
   db.password=password
   db.driver=org.mariadb.jdbc.Driver
   ```

3. Crea el esquema de la base de datos:

   ```bash
   mysql -u username -p < src/main/resources/scripts/database.sql
   ```

4. Construye el proyecto:

   ```bash
   mvn clean package
   ```

5. Ejecuta el servidor:

   ```bash
   java -jar target/nexusvault-authentication-1.0-SNAPSHOT.jar
   ```

## Referencia de la API

### Interfaz RMI

```java
public interface AuthService extends Remote {
    String authenticate(String username, String password) throws RemoteException;
    boolean validateToken(String token) throws RemoteException;
    boolean registerUser(String username, String password) throws RemoteException;
    boolean revokeToken(String token) throws RemoteException;
}
```

### Ejemplo de uso del cliente

```java
// Obtener referencia al registro RMI
Registry registry = LocateRegistry.getRegistry("localhost", 1099);
    
// Buscar el objeto remoto AuthService
AuthService authService = (AuthService) registry.lookup("AuthService");

// Usar el servicio
String token = authService.authenticate("username", "password");
boolean isValid = authService.validateToken(token);
```

## Consideraciones de seguridad

- Los tokens JWT están firmados con HMAC-SHA256
- Las contraseñas se almacenan con hash SHA-256 y sal
- La expiración de tokens está configurada a 1 hora por defecto
- Las comunicaciones RMI deben protegerse con reglas de firewall

## Esquema de la base de datos

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Desarrollo

### Estructura del proyecto

```md
src
├── main
│   ├── java
│   │   └── edu/co/upb/nexusvault
│   │       ├── auth
│   │       │   ├── client      - Interfaz cliente RMI
│   │       │   └── database    - Conectividad a base de datos
│   │       ├── NexusVaultAuthentication.java - Punto de entrada
│   │       └── AuthServiceImpl.java          - Implementación
│   └── resources
│       ├── application.properties - Configuración
│       └── scripts               - Scripts SQL
└── test
    └── java                     - Clases de prueba
```

### Ejecución del cliente de demostración

El proyecto incluye un cliente de demostración para probar el servicio de autenticación:

```bash
java -cp target/nexusvault-auth-0.0.1-SNAPSHOT.jar edu.co.upb.nexusvault.auth.client.AuthClientDemo

./mvnw exec:java -Dexec.mainClass="edu.co.upb.nexusvault.auth.client.AuthClientDemo"
```

## Contribuciones

1. Haz un fork del repositorio
2. Crea una rama de funcionalidad (`git checkout -b feature/funcionalidad-asombrosa`)
3. Realiza tus cambios (`git commit -m 'Agregar funcionalidad asombrosa'`)
4. Sube la rama (`git push origin feature/funcionalidad-asombrosa`)
5. Abre un Pull Request
