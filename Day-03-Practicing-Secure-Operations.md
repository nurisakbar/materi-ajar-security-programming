# Day 3: Practicing Secure Operations

## 📚 Tujuan Pembelajaran
Setelah menyelesaikan materi ini, peserta akan:
- Mampu mengimplementasikan OTP dan Multi-Factor Authentication (MFA)
- Memahami dan mengimplementasikan Authentication, Authorization, dan Logging yang aman
- Mampu mencegah kehilangan data dengan backup dan recovery strategies

---

## 3.1 Using OTP & MFA

### Teori

**OTP (One-Time Password)** adalah password yang hanya valid untuk satu transaksi atau sesi login.

**MFA (Multi-Factor Authentication)** adalah metode autentikasi yang memerlukan lebih dari satu faktor verifikasi.

#### Faktor Autentikasi:

1. **Something You Know** (Knowledge)
   - Password, PIN, Security Questions

2. **Something You Have** (Possession)
   - Smartphone, Hardware Token, Smart Card

3. **Something You Are** (Inherence)
   - Fingerprint, Face Recognition, Iris Scan

#### Jenis-jenis OTP:

1. **TOTP (Time-based OTP)**
   - Berdasarkan waktu (30-60 detik)
   - Contoh: Google Authenticator, Authy

2. **HOTP (HMAC-based OTP)**
   - Berdasarkan counter
   - Setiap penggunaan increment counter

3. **SMS OTP**
   - Dikirim melalui SMS
   - Kurang aman (SIM swapping attack)

4. **Email OTP**
   - Dikirim melalui email
   - Tergantung keamanan email

#### Keuntungan MFA:

- Meningkatkan keamanan akun secara signifikan
- Mengurangi risiko akibat password yang bocor
- Compliance dengan regulasi (PCI-DSS, GDPR)
- Meningkatkan kepercayaan pengguna

#### Best Practices MFA:

- Wajibkan MFA untuk akun admin
- Wajibkan MFA untuk operasi sensitif
- Berikan backup codes
- Support multiple methods
- Jangan gunakan SMS sebagai satu-satunya metode

### Praktik: Latihan 3.1

**Tujuan**: Mengimplementasikan TOTP-based MFA menggunakan Google Authenticator

**Langkah-langkah**:
1. Install library PHP untuk TOTP (PHPGangsta/GoogleAuthenticator)
2. Buat database untuk menyimpan secret keys
3. Buat sistem registrasi MFA
4. Buat sistem verifikasi MFA
5. Integrasikan dengan sistem login

**Setup Database (`mfa-setup.sql`)**:
```sql
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN backup_codes TEXT NULL;

CREATE TABLE mfa_backup_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code VARCHAR(10) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

**Install Library** (menggunakan Composer):
```bash
composer require pragmarx/google2fa
```

**File `MFAHandler.php`**:
```php
<?php
require_once 'vendor/autoload.php';
use PragmaRX\Google2FA\Google2FA;

class MFAHandler {
    private $google2fa;
    private $conn;
    
    public function __construct($databaseConnection) {
        $this->google2fa = new Google2FA();
        $this->conn = $databaseConnection;
    }
    
    /**
     * Generate secret key for user
     */
    public function generateSecret($userId) {
        $secret = $this->google2fa->generateSecretKey();
        
        // Store secret in database
        $stmt = $this->conn->prepare("UPDATE users SET mfa_secret = ? WHERE id = ?");
        $stmt->bind_param("si", $secret, $userId);
        $stmt->execute();
        $stmt->close();
        
        return $secret;
    }
    
    /**
     * Get QR code URL for Google Authenticator
     */
    public function getQRCodeUrl($email, $secret, $issuer = 'MyApp') {
        return $this->google2fa->getQRCodeUrl(
            $issuer,
            $email,
            $secret
        );
    }
    
    /**
     * Verify TOTP code
     */
    public function verifyCode($userId, $code) {
        // Get user's secret
        $stmt = $this->conn->prepare("SELECT mfa_secret FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            return false;
        }
        
        $user = $result->fetch_assoc();
        $secret = $user['mfa_secret'];
        
        $stmt->close();
        
        // Verify code (allow 1 time step window)
        $valid = $this->google2fa->verifyKey($secret, $code, 1);
        
        return $valid;
    }
    
    /**
     * Generate backup codes
     */
    public function generateBackupCodes($userId, $count = 10) {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = bin2hex(random_bytes(4)); // 8 character code
            $codes[] = $code;
            
            // Store in database
            $stmt = $this->conn->prepare("INSERT INTO mfa_backup_codes (user_id, code) VALUES (?, ?)");
            $stmt->bind_param("is", $userId, $code);
            $stmt->execute();
            $stmt->close();
        }
        
        return $codes;
    }
    
    /**
     * Verify backup code
     */
    public function verifyBackupCode($userId, $code) {
        $stmt = $this->conn->prepare("SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code = ? AND used = FALSE");
        $stmt->bind_param("is", $userId, $code);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            // Mark code as used
            $row = $result->fetch_assoc();
            $codeId = $row['id'];
            
            $updateStmt = $this->conn->prepare("UPDATE mfa_backup_codes SET used = TRUE WHERE id = ?");
            $updateStmt->bind_param("i", $codeId);
            $updateStmt->execute();
            $updateStmt->close();
            
            $stmt->close();
            return true;
        }
        
        $stmt->close();
        return false;
    }
    
    /**
     * Enable MFA for user
     */
    public function enableMFA($userId) {
        $stmt = $this->conn->prepare("UPDATE users SET mfa_enabled = TRUE WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Disable MFA for user
     */
    public function disableMFA($userId) {
        $stmt = $this->conn->prepare("UPDATE users SET mfa_enabled = FALSE WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Check if user has MFA enabled
     */
    public function isMFAEnabled($userId) {
        $stmt = $this->conn->prepare("SELECT mfa_enabled FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            $stmt->close();
            return (bool)$user['mfa_enabled'];
        }
        
        $stmt->close();
        return false;
    }
}
?>
```

**File `mfa-setup.php`** (Setup MFA untuk user):
```php
<?php
session_start();
require_once 'MFAHandler.php';
require_once 'SecureSession.php';

$conn = mysqli_connect('localhost', 'root', '', 'security_training');
$mfaHandler = new MFAHandler($conn);

SecureSession::start();

if (!SecureSession::isLoggedIn()) {
    header("Location: login.php");
    exit;
}

$userId = SecureSession::get('user_id');

// Generate secret if not exists
$stmt = $conn->prepare("SELECT mfa_secret FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (empty($user['mfa_secret'])) {
    $secret = $mfaHandler->generateSecret($userId);
} else {
    $secret = $user['mfa_secret'];
}

// Generate QR code URL
$email = SecureSession::get('username');
$qrCodeUrl = $mfaHandler->getQRCodeUrl($email, $secret, 'Security Training App');

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['verify_code'])) {
        $code = $_POST['code'];
        if ($mfaHandler->verifyCode($userId, $code)) {
            $mfaHandler->enableMFA($userId);
            $backupCodes = $mfaHandler->generateBackupCodes($userId);
            $message = "MFA berhasil diaktifkan! Simpan backup codes Anda: " . implode(', ', $backupCodes);
        } else {
            $error = "Kode tidak valid!";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Setup MFA</title>
</head>
<body>
    <h2>Setup Multi-Factor Authentication</h2>
    
    <?php if (isset($message)): ?>
        <div style="background: #d4edda; padding: 10px; margin: 10px 0;">
            <?php echo htmlspecialchars($message); ?>
        </div>
    <?php endif; ?>
    
    <?php if (isset($error)): ?>
        <div style="background: #f8d7da; padding: 10px; margin: 10px 0;">
            <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>
    
    <h3>Langkah-langkah:</h3>
    <ol>
        <li>Install Google Authenticator di smartphone Anda</li>
        <li>Scan QR code di bawah ini</li>
        <li>Masukkan kode 6 digit dari aplikasi untuk verifikasi</li>
    </ol>
    
    <div style="margin: 20px 0;">
        <img src="<?php echo $qrCodeUrl; ?>" alt="QR Code">
    </div>
    
    <p><strong>Secret Key:</strong> <?php echo $secret; ?></p>
    <p><small>Simpan secret key ini di tempat yang aman sebagai backup</small></p>
    
    <form method="POST">
        <label>Masukkan kode 6 digit dari Google Authenticator:</label><br>
        <input type="text" name="code" pattern="[0-9]{6}" maxlength="6" required>
        <button type="submit" name="verify_code">Verifikasi & Aktifkan MFA</button>
    </form>
</body>
</html>
```

**File `login-with-mfa.php`** (Login dengan MFA):
```php
<?php
session_start();
require_once 'MFAHandler.php';
require_once 'SecureSession.php';
require_once 'InputValidator.php';

$conn = mysqli_connect('localhost', 'root', '', 'security_training');
$mfaHandler = new MFAHandler($conn);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $mfaCode = $_POST['mfa_code'] ?? '';
    
    // Validate input
    if (!InputValidator::validateLength($username, 3, 50)) {
        $error = "Username tidak valid";
    } else {
        // Verify username and password
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            if (password_verify($password, $user['password'])) {
                $userId = $user['id'];
                
                // Check if MFA is enabled
                if ($mfaHandler->isMFAEnabled($userId)) {
                    // Verify MFA code
                    if (empty($mfaCode)) {
                        $_SESSION['pending_mfa_user_id'] = $userId;
                        $requireMFA = true;
                    } else {
                        // Verify TOTP code or backup code
                        if ($mfaHandler->verifyCode($userId, $mfaCode) || 
                            $mfaHandler->verifyBackupCode($userId, $mfaCode)) {
                            SecureSession::login($userId, $user['username']);
                            header("Location: dashboard.php");
                            exit;
                        } else {
                            $error = "Kode MFA tidak valid!";
                            $requireMFA = true;
                            $_SESSION['pending_mfa_user_id'] = $userId;
                        }
                    }
                } else {
                    // No MFA required
                    SecureSession::login($userId, $user['username']);
                    header("Location: dashboard.php");
                    exit;
                }
            } else {
                $error = "Username atau password salah!";
            }
        } else {
            $error = "Username atau password salah!";
        }
        
        $stmt->close();
    }
}

$requireMFA = isset($_SESSION['pending_mfa_user_id']);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    
    <?php if (isset($error)): ?>
        <div style="background: #f8d7da; padding: 10px; margin: 10px 0;">
            <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>
    
    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        
        <?php if ($requireMFA): ?>
            <label>MFA Code (6 digit dari Google Authenticator atau Backup Code):</label><br>
            <input type="text" name="mfa_code" pattern="[0-9]{6}" maxlength="10" required><br><br>
        <?php endif; ?>
        
        <button type="submit">Login</button>
    </form>
</body>
</html>
```

**File `mfa-documentation.md`**:
```markdown
# MFA Implementation Documentation

## Overview
Implementasi Multi-Factor Authentication menggunakan TOTP (Time-based OTP) dengan Google Authenticator.

## Components
1. **MFAHandler.php**: Core class untuk handling MFA
2. **mfa-setup.php**: Setup page untuk user
3. **login-with-mfa.php**: Login page dengan MFA verification

## Features
- TOTP generation dan verification
- QR code generation untuk Google Authenticator
- Backup codes generation
- Enable/disable MFA per user

## Security Considerations
- Secret keys disimpan di database (should be encrypted in production)
- Backup codes hanya bisa digunakan sekali
- TOTP code valid untuk 30 detik dengan 1 time step tolerance
- Rate limiting untuk prevent brute force

## Best Practices
- Wajibkan MFA untuk admin accounts
- Berikan backup codes saat setup
- Implement rate limiting
- Log semua MFA attempts
- Support multiple MFA methods
```

**Output yang diharapkan**: 
- Sistem MFA lengkap dengan TOTP
- Backup codes functionality
- Integrasi dengan sistem login

---

## 3.2 User Authentication, Authorization, and Logging

### Teori

**Authentication** adalah proses verifikasi identitas pengguna.

**Authorization** adalah proses menentukan apa yang boleh dilakukan pengguna setelah terautentikasi.

**Logging** adalah proses pencatatan aktivitas untuk audit dan monitoring.

#### Authentication Methods:

1. **Password-based**
   - Traditional username/password
   - Harus menggunakan password hashing (bcrypt, argon2)

2. **Token-based**
   - JWT (JSON Web Tokens)
   - API tokens
   - Session tokens

3. **Certificate-based**
   - SSL/TLS client certificates
   - Digital certificates

4. **Biometric**
   - Fingerprint, Face recognition

#### Authorization Models:

1. **RBAC (Role-Based Access Control)**
   - User memiliki role
   - Role memiliki permissions
   - Contoh: Admin, User, Guest

2. **ABAC (Attribute-Based Access Control)**
   - Berdasarkan attributes
   - Lebih fleksibel dari RBAC

3. **ACL (Access Control List)**
   - List permissions per resource
   - Fine-grained control

#### Logging Best Practices:

- **Log semua aktivitas penting**: Login, logout, perubahan data
- **Jangan log informasi sensitif**: Password, credit card numbers
- **Structured logging**: Format yang konsisten (JSON)
- **Log levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Centralized logging**: Collect logs di satu tempat
- **Log retention**: Tentukan berapa lama log disimpan
- **Log analysis**: Monitor dan analisis log

#### Security Logging:

- Failed login attempts
- Privilege escalation attempts
- Unusual access patterns
- Data modification
- Configuration changes
- Security events

### Praktik: Latihan 3.2

**Tujuan**: Membuat sistem Authentication, Authorization, dan Logging yang komprehensif

**Langkah-langkah**:
1. Buat sistem RBAC (Role-Based Access Control)
2. Buat authentication system dengan password hashing
3. Buat authorization middleware
4. Buat logging system
5. Integrasikan semua komponen

**Setup Database (`auth-setup.sql`)**:
```sql
-- Roles table
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);

-- Permissions table
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT
);

-- Role permissions (many-to-many)
CREATE TABLE role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

-- User roles (many-to-many)
CREATE TABLE user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Activity logs table
CREATE TABLE activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NULL,
    resource_id INT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    details TEXT NULL,
    status VARCHAR(20) NOT NULL, -- SUCCESS, FAILED, ERROR
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
('admin', 'Administrator dengan akses penuh'),
('user', 'User biasa dengan akses terbatas'),
('guest', 'Guest dengan akses sangat terbatas');

-- Insert default permissions
INSERT INTO permissions (name, description) VALUES
('user.create', 'Membuat user baru'),
('user.read', 'Melihat data user'),
('user.update', 'Mengupdate data user'),
('user.delete', 'Menghapus user'),
('post.create', 'Membuat post'),
('post.read', 'Membaca post'),
('post.update', 'Mengupdate post'),
('post.delete', 'Menghapus post'),
('admin.access', 'Akses ke admin panel');

-- Assign permissions to roles
-- Admin gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- User gets basic permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 2, id FROM permissions WHERE name IN ('post.create', 'post.read', 'post.update', 'user.read');

-- Guest gets read-only
INSERT INTO role_permissions (role_id, permission_id)
SELECT 3, id FROM permissions WHERE name IN ('post.read', 'user.read');
```

**File `AuthHandler.php`**:
```php
<?php
require_once 'SecureSession.php';

class AuthHandler {
    private $conn;
    
    public function __construct($databaseConnection) {
        $this->conn = $databaseConnection;
    }
    
    /**
     * Register new user
     */
    public function register($username, $email, $password) {
        // Validate input
        if (empty($username) || empty($email) || empty($password)) {
            return ['success' => false, 'message' => 'Semua field harus diisi'];
        }
        
        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'Password minimal 8 karakter'];
        }
        
        // Check if username or email exists
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $stmt->close();
            return ['success' => false, 'message' => 'Username atau email sudah digunakan'];
        }
        $stmt->close();
        
        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        
        // Insert user
        $stmt = $this->conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashedPassword);
        
        if ($stmt->execute()) {
            $userId = $stmt->insert_id;
            $stmt->close();
            
            // Assign default role (user)
            $this->assignRole($userId, 2); // role_id 2 = user
            
            // Log registration
            $this->logActivity($userId, 'user.register', 'user', $userId, 'SUCCESS');
            
            return ['success' => true, 'message' => 'Registrasi berhasil', 'user_id' => $userId];
        } else {
            $stmt->close();
            return ['success' => false, 'message' => 'Gagal registrasi'];
        }
    }
    
    /**
     * Login user
     */
    public function login($username, $password) {
        $stmt = $this->conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            if (password_verify($password, $user['password'])) {
                // Check for account lockout (after 5 failed attempts)
                $failedAttempts = $this->getFailedLoginAttempts($user['id']);
                if ($failedAttempts >= 5) {
                    $this->logActivity($user['id'], 'user.login', 'user', $user['id'], 'FAILED', 'Account locked due to too many failed attempts');
                    return ['success' => false, 'message' => 'Akun terkunci karena terlalu banyak percobaan login gagal'];
                }
                
                SecureSession::login($user['id'], $user['username']);
                
                // Reset failed attempts
                $this->resetFailedLoginAttempts($user['id']);
                
                // Log successful login
                $this->logActivity($user['id'], 'user.login', 'user', $user['id'], 'SUCCESS');
                
                $stmt->close();
                return ['success' => true, 'message' => 'Login berhasil'];
            } else {
                // Increment failed attempts
                $this->incrementFailedLoginAttempts($user['id']);
                $this->logActivity($user['id'], 'user.login', 'user', $user['id'], 'FAILED', 'Invalid password');
            }
        } else {
            $this->logActivity(null, 'user.login', null, null, 'FAILED', 'User not found: ' . $username);
        }
        
        $stmt->close();
        return ['success' => false, 'message' => 'Username atau password salah'];
    }
    
    /**
     * Assign role to user
     */
    public function assignRole($userId, $roleId) {
        $stmt = $this->conn->prepare("INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)");
        $stmt->bind_param("ii", $userId, $roleId);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Check if user has permission
     */
    public function hasPermission($userId, $permissionName) {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as count
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = ? AND p.name = ?
        ");
        $stmt->bind_param("is", $userId, $permissionName);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['count'] > 0;
    }
    
    /**
     * Get user roles
     */
    public function getUserRoles($userId) {
        $stmt = $this->conn->prepare("
            SELECT r.id, r.name, r.description
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $roles = [];
        while ($row = $result->fetch_assoc()) {
            $roles[] = $row;
        }
        
        $stmt->close();
        return $roles;
    }
    
    /**
     * Log activity
     */
    public function logActivity($userId, $action, $resource = null, $resourceId = null, $status = 'SUCCESS', $details = null) {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        
        $stmt = $this->conn->prepare("
            INSERT INTO activity_logs (user_id, action, resource, resource_id, ip_address, user_agent, details, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("ississss", $userId, $action, $resource, $resourceId, $ipAddress, $userAgent, $details, $status);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Get failed login attempts (simplified - in production use separate table)
     */
    private function getFailedLoginAttempts($userId) {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as count
            FROM activity_logs
            WHERE user_id = ? 
            AND action = 'user.login' 
            AND status = 'FAILED'
            AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['count'];
    }
    
    private function incrementFailedLoginAttempts($userId) {
        // Already logged in logActivity
    }
    
    private function resetFailedLoginAttempts($userId) {
        // Could implement separate table for this
    }
}
?>
```

**File `AuthorizationMiddleware.php`**:
```php
<?php
require_once 'AuthHandler.php';
require_once 'SecureSession.php';

class AuthorizationMiddleware {
    private $authHandler;
    
    public function __construct($databaseConnection) {
        $this->authHandler = new AuthHandler($databaseConnection);
    }
    
    /**
     * Require authentication
     */
    public function requireAuth() {
        SecureSession::start();
        
        if (!SecureSession::isLoggedIn()) {
            header("Location: login.php");
            exit;
        }
    }
    
    /**
     * Require specific permission
     */
    public function requirePermission($permissionName) {
        $this->requireAuth();
        
        $userId = SecureSession::get('user_id');
        
        if (!$this->authHandler->hasPermission($userId, $permissionName)) {
            $this->authHandler->logActivity($userId, 'authorization.denied', 'permission', null, 'FAILED', "Attempted to access: $permissionName");
            http_response_code(403);
            die("Access Denied: You don't have permission to access this resource");
        }
    }
    
    /**
     * Require any of the specified permissions
     */
    public function requireAnyPermission($permissions) {
        $this->requireAuth();
        
        $userId = SecureSession::get('user_id');
        
        foreach ($permissions as $permission) {
            if ($this->authHandler->hasPermission($userId, $permission)) {
                return true;
            }
        }
        
        $this->authHandler->logActivity($userId, 'authorization.denied', 'permission', null, 'FAILED', "Attempted to access any of: " . implode(', ', $permissions));
        http_response_code(403);
        die("Access Denied");
    }
    
    /**
     * Require specific role
     */
    public function requireRole($roleName) {
        $this->requireAuth();
        
        $userId = SecureSession::get('user_id');
        $userRoles = $this->authHandler->getUserRoles($userId);
        
        foreach ($userRoles as $role) {
            if ($role['name'] === $roleName) {
                return true;
            }
        }
        
        $this->authHandler->logActivity($userId, 'authorization.denied', 'role', null, 'FAILED', "Attempted to access role: $roleName");
        http_response_code(403);
        die("Access Denied: Required role: $roleName");
    }
}
?>
```

**File `admin-panel.php`** (Contoh penggunaan authorization):
```php
<?php
require_once 'AuthorizationMiddleware.php';

$conn = mysqli_connect('localhost', 'root', '', 'security_training');
$auth = new AuthorizationMiddleware($conn);

// Require admin access
$auth->requirePermission('admin.access');

// Log access
$authHandler = new AuthHandler($conn);
$authHandler->logActivity($_SESSION['user_id'], 'admin.panel.access', 'admin', null, 'SUCCESS');
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
</head>
<body>
    <h2>Admin Panel</h2>
    <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</p>
    
    <h3>User Management</h3>
    <?php
    // Check permission before showing action
    $authHandler = new AuthHandler($conn);
    if ($authHandler->hasPermission($_SESSION['user_id'], 'user.read')) {
        // Show user list
        $result = mysqli_query($conn, "SELECT id, username, email FROM users");
        echo "<table border='1'>";
        echo "<tr><th>ID</th><th>Username</th><th>Email</th><th>Actions</th></tr>";
        while ($row = mysqli_fetch_assoc($result)) {
            echo "<tr>";
            echo "<td>" . htmlspecialchars($row['id']) . "</td>";
            echo "<td>" . htmlspecialchars($row['username']) . "</td>";
            echo "<td>" . htmlspecialchars($row['email']) . "</td>";
            echo "<td>";
            
            if ($authHandler->hasPermission($_SESSION['user_id'], 'user.update')) {
                echo "<a href='edit-user.php?id=" . $row['id'] . "'>Edit</a> ";
            }
            
            if ($authHandler->hasPermission($_SESSION['user_id'], 'user.delete')) {
                echo "<a href='delete-user.php?id=" . $row['id'] . "'>Delete</a>";
            }
            
            echo "</td>";
            echo "</tr>";
        }
        echo "</table>";
    }
    ?>
    
    <h3>Activity Logs</h3>
    <?php
    $result = mysqli_query($conn, "
        SELECT al.*, u.username 
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 50
    ");
    
    echo "<table border='1'>";
    echo "<tr><th>Time</th><th>User</th><th>Action</th><th>Status</th><th>IP</th></tr>";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($row['created_at']) . "</td>";
        echo "<td>" . htmlspecialchars($row['username'] ?? 'N/A') . "</td>";
        echo "<td>" . htmlspecialchars($row['action']) . "</td>";
        echo "<td>" . htmlspecialchars($row['status']) . "</td>";
        echo "<td>" . htmlspecialchars($row['ip_address']) . "</td>";
        echo "</tr>";
    }
    echo "</table>";
    ?>
</body>
</html>
```

**File `logging-best-practices.md`**:
```markdown
# Logging Best Practices

## What to Log

### Authentication Events
- Successful logins
- Failed login attempts
- Logout events
- Password changes
- Account lockouts

### Authorization Events
- Permission denied attempts
- Role changes
- Access to sensitive resources

### Data Operations
- Create, update, delete operations
- Data exports
- Bulk operations

### Security Events
- Suspicious activities
- Unusual access patterns
- Configuration changes
- Security policy violations

## What NOT to Log
- Passwords (even hashed)
- Credit card numbers
- Social security numbers
- Full authentication tokens
- Sensitive personal data

## Log Format
Use structured logging (JSON format):
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "user_id": 123,
  "action": "user.login",
  "status": "SUCCESS",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0..."
}
```

## Log Retention
- Security logs: Minimum 1 year
- Application logs: 30-90 days
- Debug logs: 7-30 days
- Compliance requirements may vary

## Log Analysis
- Real-time monitoring
- Alert on suspicious patterns
- Regular log review
- Automated log analysis tools
```

**Output yang diharapkan**: 
- Sistem RBAC lengkap
- Authentication dengan password hashing
- Authorization middleware
- Activity logging system
- Admin panel dengan permission checks

---

## 3.3 Preventing Data Loss

### Teori

**Data Loss Prevention (DLP)** adalah strategi dan teknologi untuk mencegah kehilangan, kebocoran, atau kerusakan data.

#### Penyebab Data Loss:

1. **Human Error**
   - Accidental deletion
   - Wrong operations
   - Misconfiguration

2. **Hardware Failure**
   - Disk failure
   - Server crash
   - Network issues

3. **Software Issues**
   - Bugs
   - Corrupted files
   - Database corruption

4. **Security Breaches**
   - Ransomware
   - Data theft
   - Malicious deletion

5. **Natural Disasters**
   - Fire, flood, earthquake
   - Power outages

#### Strategi Pencegahan Data Loss:

1. **Backup Strategy**
   - Regular automated backups
   - Multiple backup locations
   - Backup testing and verification
   - 3-2-1 Rule: 3 copies, 2 different media, 1 offsite

2. **Version Control**
   - Git for code
   - Database versioning
   - File versioning

3. **Replication**
   - Database replication
   - File replication
   - Real-time sync

4. **Access Control**
   - Least privilege principle
   - Audit logs
   - Change tracking

5. **Monitoring**
   - Disk space monitoring
   - Health checks
   - Alert systems

#### Backup Types:

1. **Full Backup**
   - Complete backup of all data
   - Slow, but complete restore

2. **Incremental Backup**
   - Only changes since last backup
   - Faster, but slower restore

3. **Differential Backup**
   - Changes since last full backup
   - Balance between speed and restore time

#### Recovery Strategies:

- **RTO (Recovery Time Objective)**: Maximum acceptable downtime
- **RPO (Recovery Point Objective)**: Maximum acceptable data loss
- **Disaster Recovery Plan**: Step-by-step recovery procedures

### Praktik: Latihan 3.3

**Tujuan**: Membuat sistem backup dan recovery untuk database dan files

**Langkah-langkah**:
1. Buat script backup database
2. Buat script backup files
3. Buat script restore
4. Buat monitoring system
5. Buat automation dengan cron

**File `DatabaseBackup.php`**:
```php
<?php
class DatabaseBackup {
    private $host;
    private $username;
    private $password;
    private $database;
    private $backupDir;
    
    public function __construct($host, $username, $password, $database, $backupDir) {
        $this->host = $host;
        $this->username = $username;
        $this->password = $password;
        $this->database = $database;
        $this->backupDir = rtrim($backupDir, '/') . '/';
        
        // Create backup directory if not exists
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
    }
    
    /**
     * Create database backup
     */
    public function backup($compress = true) {
        $filename = $this->database . '_' . date('Y-m-d_His') . '.sql';
        $filepath = $this->backupDir . $filename;
        
        // Use mysqldump
        $command = sprintf(
            'mysqldump -h %s -u %s -p%s %s > %s',
            escapeshellarg($this->host),
            escapeshellarg($this->username),
            escapeshellarg($this->password),
            escapeshellarg($this->database),
            escapeshellarg($filepath)
        );
        
        exec($command, $output, $returnVar);
        
        if ($returnVar !== 0) {
            throw new Exception("Backup failed: " . implode("\n", $output));
        }
        
        // Compress if requested
        if ($compress && file_exists($filepath)) {
            $compressedFile = $filepath . '.gz';
            exec("gzip " . escapeshellarg($filepath));
            $filepath = $compressedFile;
        }
        
        // Log backup
        $this->logBackup($filepath, 'SUCCESS');
        
        return $filepath;
    }
    
    /**
     * Restore database from backup
     */
    public function restore($backupFile) {
        if (!file_exists($backupFile)) {
            throw new Exception("Backup file not found: $backupFile");
        }
        
        // Decompress if needed
        $sqlFile = $backupFile;
        if (pathinfo($backupFile, PATHINFO_EXTENSION) === 'gz') {
            $sqlFile = str_replace('.gz', '', $backupFile);
            exec("gunzip -c " . escapeshellarg($backupFile) . " > " . escapeshellarg($sqlFile));
        }
        
        // Restore database
        $command = sprintf(
            'mysql -h %s -u %s -p%s %s < %s',
            escapeshellarg($this->host),
            escapeshellarg($this->username),
            escapeshellarg($this->password),
            escapeshellarg($this->database),
            escapeshellarg($sqlFile)
        );
        
        exec($command, $output, $returnVar);
        
        // Clean up temporary file
        if ($sqlFile !== $backupFile && file_exists($sqlFile)) {
            unlink($sqlFile);
        }
        
        if ($returnVar !== 0) {
            throw new Exception("Restore failed: " . implode("\n", $output));
        }
        
        $this->logBackup($backupFile, 'RESTORED');
        
        return true;
    }
    
    /**
     * List available backups
     */
    public function listBackups() {
        $backups = [];
        $files = glob($this->backupDir . $this->database . '_*.sql*');
        
        foreach ($files as $file) {
            $backups[] = [
                'filename' => basename($file),
                'filepath' => $file,
                'size' => filesize($file),
                'created' => date('Y-m-d H:i:s', filemtime($file))
            ];
        }
        
        // Sort by creation time (newest first)
        usort($backups, function($a, $b) {
            return strtotime($b['created']) - strtotime($a['created']);
        });
        
        return $backups;
    }
    
    /**
     * Clean old backups (keep last N backups)
     */
    public function cleanOldBackups($keepCount = 10) {
        $backups = $this->listBackups();
        
        if (count($backups) > $keepCount) {
            $toDelete = array_slice($backups, $keepCount);
            
            foreach ($toDelete as $backup) {
                if (unlink($backup['filepath'])) {
                    $this->logBackup($backup['filepath'], 'DELETED');
                }
            }
            
            return count($toDelete);
        }
        
        return 0;
    }
    
    /**
     * Log backup operations
     */
    private function logBackup($filepath, $status) {
        $logFile = $this->backupDir . 'backup.log';
        $logEntry = sprintf(
            "[%s] %s: %s\n",
            date('Y-m-d H:i:s'),
            $status,
            $filepath
        );
        
        file_put_contents($logFile, $logEntry, FILE_APPEND);
    }
}
?>
```

**File `FileBackup.php`**:
```php
<?php
class FileBackup {
    private $sourceDir;
    private $backupDir;
    
    public function __construct($sourceDir, $backupDir) {
        $this->sourceDir = rtrim($sourceDir, '/') . '/';
        $this->backupDir = rtrim($backupDir, '/') . '/';
        
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
    }
    
    /**
     * Create file backup (tar.gz)
     */
    public function backup($excludePatterns = []) {
        $filename = 'files_' . date('Y-m-d_His') . '.tar.gz';
        $filepath = $this->backupDir . $filename;
        
        // Build tar command
        $command = "tar -czf " . escapeshellarg($filepath) . " -C " . escapeshellarg(dirname($this->sourceDir)) . " " . escapeshellarg(basename($this->sourceDir));
        
        // Add exclude patterns
        foreach ($excludePatterns as $pattern) {
            $command .= " --exclude=" . escapeshellarg($pattern);
        }
        
        exec($command, $output, $returnVar);
        
        if ($returnVar !== 0) {
            throw new Exception("File backup failed: " . implode("\n", $output));
        }
        
        $this->logBackup($filepath, 'SUCCESS');
        
        return $filepath;
    }
    
    /**
     * Restore files from backup
     */
    public function restore($backupFile, $targetDir = null) {
        if (!file_exists($backupFile)) {
            throw new Exception("Backup file not found: $backupFile");
        }
        
        $targetDir = $targetDir ?: $this->sourceDir;
        
        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0755, true);
        }
        
        // Extract backup
        $command = "tar -xzf " . escapeshellarg($backupFile) . " -C " . escapeshellarg($targetDir);
        
        exec($command, $output, $returnVar);
        
        if ($returnVar !== 0) {
            throw new Exception("Restore failed: " . implode("\n", $output));
        }
        
        $this->logBackup($backupFile, 'RESTORED');
        
        return true;
    }
    
    /**
     * List available backups
     */
    public function listBackups() {
        $backups = [];
        $files = glob($this->backupDir . 'files_*.tar.gz');
        
        foreach ($files as $file) {
            $backups[] = [
                'filename' => basename($file),
                'filepath' => $file,
                'size' => filesize($file),
                'created' => date('Y-m-d H:i:s', filemtime($file))
            ];
        }
        
        usort($backups, function($a, $b) {
            return strtotime($b['created']) - strtotime($a['created']);
        });
        
        return $backups;
    }
    
    /**
     * Log backup operations
     */
    private function logBackup($filepath, $status) {
        $logFile = $this->backupDir . 'backup.log';
        $logEntry = sprintf(
            "[%s] %s: %s\n",
            date('Y-m-d H:i:s'),
            $status,
            $filepath
        );
        
        file_put_contents($logFile, $logEntry, FILE_APPEND);
    }
}
?>
```

**File `backup-scheduler.php`** (Cron job script):
```php
<?php
/**
 * Backup Scheduler
 * Run this script via cron: 0 2 * * * /usr/bin/php /path/to/backup-scheduler.php
 */

require_once 'DatabaseBackup.php';
require_once 'FileBackup.php';

// Configuration
$dbConfig = [
    'host' => 'localhost',
    'username' => 'root',
    'password' => '',
    'database' => 'security_training'
];

$backupConfig = [
    'db_backup_dir' => __DIR__ . '/backups/database/',
    'file_backup_dir' => __DIR__ . '/backups/files/',
    'source_dir' => __DIR__ . '/uploads/',
    'keep_backups' => 30 // Keep last 30 backups
];

try {
    // Database backup
    echo "Starting database backup...\n";
    $dbBackup = new DatabaseBackup(
        $dbConfig['host'],
        $dbConfig['username'],
        $dbConfig['password'],
        $dbConfig['database'],
        $backupConfig['db_backup_dir']
    );
    
    $dbBackupFile = $dbBackup->backup(true); // Compress
    echo "Database backup created: $dbBackupFile\n";
    
    // Clean old database backups
    $deleted = $dbBackup->cleanOldBackups($backupConfig['keep_backups']);
    echo "Deleted $deleted old database backups\n";
    
    // File backup
    echo "Starting file backup...\n";
    $fileBackup = new FileBackup(
        $backupConfig['source_dir'],
        $backupConfig['file_backup_dir']
    );
    
    $fileBackupFile = $fileBackup->backup(['*.tmp', '*.log']);
    echo "File backup created: $fileBackupFile\n";
    
    // Clean old file backups
    $fileBackups = $fileBackup->listBackups();
    if (count($fileBackups) > $backupConfig['keep_backups']) {
        $toDelete = array_slice($fileBackups, $backupConfig['keep_backups']);
        foreach ($toDelete as $backup) {
            unlink($backup['filepath']);
            echo "Deleted old file backup: {$backup['filename']}\n";
        }
    }
    
    echo "Backup completed successfully!\n";
    
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    // Send alert email or notification
    error_log("Backup failed: " . $e->getMessage());
    exit(1);
}
?>
```

**File `backup-manager.php`** (Web interface untuk manage backups):
```php
<?php
session_start();
require_once 'AuthorizationMiddleware.php';
require_once 'DatabaseBackup.php';
require_once 'FileBackup.php';

$conn = mysqli_connect('localhost', 'root', '', 'security_training');
$auth = new AuthorizationMiddleware($conn);

// Require admin access
$auth->requirePermission('admin.access');

$dbBackup = new DatabaseBackup('localhost', 'root', '', 'security_training', __DIR__ . '/backups/database/');
$fileBackup = new FileBackup(__DIR__ . '/uploads/', __DIR__ . '/backups/files/');

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        try {
            switch ($_POST['action']) {
                case 'backup_db':
                    $file = $dbBackup->backup(true);
                    $message = "Database backup created: " . basename($file);
                    break;
                    
                case 'backup_files':
                    $file = $fileBackup->backup();
                    $message = "File backup created: " . basename($file);
                    break;
                    
                case 'restore_db':
                    if (isset($_POST['backup_file'])) {
                        $dbBackup->restore($_POST['backup_file']);
                        $message = "Database restored successfully";
                    }
                    break;
                    
                case 'restore_files':
                    if (isset($_POST['backup_file'])) {
                        $fileBackup->restore($_POST['backup_file']);
                        $message = "Files restored successfully";
                    }
                    break;
                    
                case 'delete_backup':
                    if (isset($_POST['backup_file']) && file_exists($_POST['backup_file'])) {
                        unlink($_POST['backup_file']);
                        $message = "Backup deleted";
                    }
                    break;
            }
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
}

$dbBackups = $dbBackup->listBackups();
$fileBackups = $fileBackup->listBackups();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Backup Manager</title>
</head>
<body>
    <h2>Backup Manager</h2>
    
    <?php if (isset($message)): ?>
        <div style="background: #d4edda; padding: 10px;"><?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>
    
    <?php if (isset($error)): ?>
        <div style="background: #f8d7da; padding: 10px;"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    
    <h3>Database Backups</h3>
    <form method="POST" style="margin-bottom: 20px;">
        <input type="hidden" name="action" value="backup_db">
        <button type="submit">Create Database Backup</button>
    </form>
    
    <table border="1">
        <tr>
            <th>Filename</th>
            <th>Size</th>
            <th>Created</th>
            <th>Actions</th>
        </tr>
        <?php foreach ($dbBackups as $backup): ?>
        <tr>
            <td><?php echo htmlspecialchars($backup['filename']); ?></td>
            <td><?php echo number_format($backup['size'] / 1024, 2); ?> KB</td>
            <td><?php echo htmlspecialchars($backup['created']); ?></td>
            <td>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="restore_db">
                    <input type="hidden" name="backup_file" value="<?php echo htmlspecialchars($backup['filepath']); ?>">
                    <button type="submit" onclick="return confirm('Are you sure? This will overwrite current database!')">Restore</button>
                </form>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="delete_backup">
                    <input type="hidden" name="backup_file" value="<?php echo htmlspecialchars($backup['filepath']); ?>">
                    <button type="submit" onclick="return confirm('Are you sure?')">Delete</button>
                </form>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
    
    <h3>File Backups</h3>
    <form method="POST" style="margin-bottom: 20px;">
        <input type="hidden" name="action" value="backup_files">
        <button type="submit">Create File Backup</button>
    </form>
    
    <table border="1">
        <tr>
            <th>Filename</th>
            <th>Size</th>
            <th>Created</th>
            <th>Actions</th>
        </tr>
        <?php foreach ($fileBackups as $backup): ?>
        <tr>
            <td><?php echo htmlspecialchars($backup['filename']); ?></td>
            <td><?php echo number_format($backup['size'] / 1024 / 1024, 2); ?> MB</td>
            <td><?php echo htmlspecialchars($backup['created']); ?></td>
            <td>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="restore_files">
                    <input type="hidden" name="backup_file" value="<?php echo htmlspecialchars($backup['filepath']); ?>">
                    <button type="submit" onclick="return confirm('Are you sure? This will overwrite current files!')">Restore</button>
                </form>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="delete_backup">
                    <input type="hidden" name="backup_file" value="<?php echo htmlspecialchars($backup['filepath']); ?>">
                    <button type="submit" onclick="return confirm('Are you sure?')">Delete</button>
                </form>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
</body>
</html>
```

**File `data-loss-prevention-guide.md`**:
```markdown
# Data Loss Prevention Guide

## Backup Strategy: 3-2-1 Rule
- **3 copies** of your data
- **2 different media** types
- **1 offsite** backup

## Backup Schedule
- **Database**: Daily (full) + Hourly (incremental)
- **Files**: Daily
- **Configuration**: Weekly
- **Code**: Version control (Git)

## Backup Testing
- Test restore monthly
- Verify backup integrity
- Document restore procedures
- Train staff on restore process

## Monitoring
- Disk space alerts
- Backup failure alerts
- Backup age monitoring
- Storage capacity planning

## Recovery Procedures
1. Assess the situation
2. Identify what needs to be restored
3. Select appropriate backup
4. Restore to test environment first
5. Verify data integrity
6. Restore to production
7. Document the incident

## Prevention Measures
- Access controls
- Change tracking
- Version control
- Regular health checks
- Disaster recovery plan
```

**Output yang diharapkan**: 
- Sistem backup database dan files
- Script restore
- Automation dengan cron
- Web interface untuk manage backups
- Dokumentasi DLP strategy

---

## 🎯 Proyek Akhir Day 3

**Tujuan**: Mengintegrasikan semua komponen secure operations

**Deliverables**:
1. Sistem MFA dengan TOTP
2. Sistem Authentication, Authorization, dan Logging
3. Sistem Backup dan Recovery
4. Integrasi semua komponen
5. Dokumentasi lengkap

**Struktur Proyek Final**:
```
day-03-project/
├── README.md
├── includes/
│   ├── MFAHandler.php
│   ├── AuthHandler.php
│   ├── AuthorizationMiddleware.php
│   ├── DatabaseBackup.php
│   └── FileBackup.php
├── applications/
│   ├── mfa-setup.php
│   ├── login-with-mfa.php
│   ├── admin-panel.php
│   └── backup-manager.php
├── scripts/
│   └── backup-scheduler.php
├── database/
│   └── auth-setup.sql
└── docs/
    ├── mfa-documentation.md
    ├── logging-best-practices.md
    └── data-loss-prevention-guide.md
```

---

## 📝 Ringkasan Day 3

### Key Takeaways:
1. MFA meningkatkan keamanan akun secara signifikan
2. RBAC memberikan kontrol akses yang fleksibel
3. Logging penting untuk audit dan monitoring
4. Backup strategy harus mengikuti 3-2-1 rule
5. Test restore procedures secara berkala

### Next Steps:
- Review semua implementasi
- Test semua fitur security
- Siapkan environment untuk Day 4 (Server Security)

---

## 📚 Referensi Tambahan
- OWASP Authentication Cheat Sheet
- OWASP Authorization Cheat Sheet
- OWASP Logging Cheat Sheet
- NIST Backup and Recovery Guidelines
- PCI-DSS Backup Requirements

---

**Selamat! Anda telah menyelesaikan Day 3 🎉**

