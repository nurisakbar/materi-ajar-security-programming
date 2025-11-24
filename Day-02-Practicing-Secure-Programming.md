# Day 2: Practicing Secure Programming

## 📚 Tujuan Pembelajaran
Setelah menyelesaikan materi ini, peserta akan:
- Mampu memvalidasi dan menyanitasi input pengguna
- Mencegah serangan SQL Injection
- Mencegah serangan Cross-Site Scripting (XSS)
- Mencegah Session Hijacking
- Mencegah Remote Code Execution

---

## 2.1 Validating and Sanitizing User Input

### Teori

**Input Validation** adalah proses memverifikasi bahwa data yang diterima sesuai dengan format dan aturan yang diharapkan.

**Input Sanitization** adalah proses membersihkan data dari karakter atau konten yang berbahaya.

#### Prinsip Input Validation:

1. **Whitelist Approach** (Lebih Aman)
   - Hanya mengizinkan karakter/format yang diizinkan
   - Menolak semua yang tidak ada dalam whitelist

2. **Blacklist Approach** (Kurang Aman)
   - Menolak karakter/format yang diketahui berbahaya
   - Masih rentan terhadap teknik baru

#### Teknik Validasi:

- **Type Validation**: Memastikan tipe data sesuai (string, integer, email)
- **Length Validation**: Membatasi panjang input
- **Format Validation**: Memastikan format sesuai (regex, email format)
- **Range Validation**: Memastikan nilai dalam rentang yang diizinkan
- **Business Logic Validation**: Validasi sesuai aturan bisnis

#### Teknik Sanitization:

- **HTML Encoding**: Mengencode karakter HTML khusus
- **SQL Escaping**: Escape karakter khusus SQL
- **Path Traversal Prevention**: Membersihkan path characters
- **Command Injection Prevention**: Membersihkan shell characters

### Praktik: Latihan 2.1

**Tujuan**: Membuat library validasi dan sanitasi input

**Langkah-langkah**:
1. Buat direktori `day-02-project/input-validation/`
2. Buat file `InputValidator.php` dengan class untuk validasi
3. Buat file `InputSanitizer.php` dengan class untuk sanitasi
4. Buat file `test-validation.php` untuk testing

**Implementasi `InputValidator.php`**:
```php
<?php
class InputValidator {
    
    /**
     * Validate email format
     */
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Validate integer
     */
    public static function validateInteger($value, $min = null, $max = null) {
        $options = [];
        if ($min !== null) $options['min_range'] = $min;
        if ($max !== null) $options['max_range'] = $max;
        
        return filter_var($value, FILTER_VALIDATE_INT, ['options' => $options]) !== false;
    }
    
    /**
     * Validate string length
     */
    public static function validateLength($string, $min = 0, $max = null) {
        $length = strlen($string);
        if ($length < $min) return false;
        if ($max !== null && $length > $max) return false;
        return true;
    }
    
    /**
     * Validate alphanumeric (whitelist approach)
     */
    public static function validateAlphanumeric($string) {
        return preg_match('/^[a-zA-Z0-9]+$/', $string) === 1;
    }
    
    /**
     * Validate against regex pattern
     */
    public static function validatePattern($string, $pattern) {
        return preg_match($pattern, $string) === 1;
    }
}
?>
```

**Implementasi `InputSanitizer.php`**:
```php
<?php
class InputSanitizer {
    
    /**
     * Sanitize string (remove HTML tags)
     */
    public static function sanitizeString($string) {
        return filter_var($string, FILTER_SANITIZE_STRING);
    }
    
    /**
     * Sanitize email
     */
    public static function sanitizeEmail($email) {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }
    
    /**
     * Sanitize integer
     */
    public static function sanitizeInteger($value) {
        return filter_var($value, FILTER_SANITIZE_NUMBER_INT);
    }
    
    /**
     * HTML encode (prevent XSS)
     */
    public static function htmlEncode($string) {
        return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
    }
    
    /**
     * Remove path traversal characters
     */
    public static function sanitizePath($path) {
        $path = str_replace('..', '', $path);
        $path = str_replace('/', '', $path);
        $path = str_replace('\\', '', $path);
        return $path;
    }
    
    /**
     * Sanitize for SQL (use with prepared statements)
     */
    public static function sanitizeForSQL($string) {
        // Note: This is a basic sanitization
        // Always use prepared statements instead
        return addslashes($string);
    }
}
?>
```

**File `test-validation.php`**:
```php
<?php
require_once 'InputValidator.php';
require_once 'InputSanitizer.php';

// Test cases
$testEmail = "user@example.com";
$testInvalidEmail = "invalid-email";
$testXSS = "<script>alert('XSS')</script>";
$testSQL = "admin' OR '1'='1";

echo "=== Input Validation Tests ===\n";
echo "Email validation: " . (InputValidator::validateEmail($testEmail) ? "PASS" : "FAIL") . "\n";
echo "Invalid email: " . (!InputValidator::validateEmail($testInvalidEmail) ? "PASS" : "FAIL") . "\n";

echo "\n=== Input Sanitization Tests ===\n";
echo "XSS sanitization: " . InputSanitizer::htmlEncode($testXSS) . "\n";
echo "SQL sanitization: " . InputSanitizer::sanitizeForSQL($testSQL) . "\n";
?>
```

**Output yang diharapkan**: Library validasi dan sanitasi yang dapat digunakan kembali

---

## 2.2 Preventing SQL Injection

### Teori

**SQL Injection** adalah teknik serangan di mana penyerang menyuntikkan kode SQL berbahaya ke dalam query database.

#### Cara Kerja SQL Injection:

1. **Union-based**: Menggunakan UNION untuk menggabungkan query
2. **Error-based**: Memanfaatkan error message untuk mendapatkan informasi
3. **Boolean-based Blind**: Menggunakan kondisi true/false
4. **Time-based Blind**: Menggunakan delay untuk menentukan kondisi

#### Contoh Vulnerable Code:
```php
// VULNERABLE - JANGAN GUNAKAN!
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);
```

#### Cara Pencegahan:

1. **Prepared Statements** (Paling Aman)
   - Menggunakan parameterized queries
   - Database memisahkan data dari kode SQL

2. **Input Validation**
   - Validasi dan sanitasi input
   - Whitelist approach

3. **Least Privilege**
   - Database user dengan privilege minimum
   - Tidak menggunakan root/administrator

4. **Error Handling**
   - Jangan expose error message ke user
   - Log error secara internal

### Praktik: Latihan 2.2

**Tujuan**: Membuat aplikasi login yang aman dari SQL Injection

**Langkah-langkah**:
1. Buat database dan tabel users
2. Buat file `vulnerable-login.php` (untuk demonstrasi)
3. Buat file `secure-login.php` (menggunakan prepared statements)
4. Buat file `test-sql-injection.php` untuk testing

**Setup Database (`setup-db.sql`)**:
```sql
CREATE DATABASE security_training;
USE security_training;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test user (password: test123, hashed)
INSERT INTO users (username, password, email) 
VALUES ('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com');
```

**File `vulnerable-login.php` (UNTUK DEMONSTRASI SAJA)**:
```php
<?php
// VULNERABLE CODE - JANGAN GUNAKAN DI PRODUKSI!
session_start();
$conn = mysqli_connect('localhost', 'root', '', 'security_training');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // VULNERABLE: Direct string concatenation
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = mysqli_query($conn, $query);
    
    if (mysqli_num_rows($result) > 0) {
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        echo "Login berhasil!";
    } else {
        echo "Login gagal!";
    }
}
?>

<form method="POST">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <button type="submit">Login</button>
</form>
```

**File `secure-login.php` (IMPLEMENTASI AMAN)**:
```php
<?php
session_start();
require_once 'InputValidator.php';
require_once 'InputSanitizer.php';

$conn = mysqli_connect('localhost', 'root', '', 'security_training');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Validate input
    if (!InputValidator::validateLength($username, 3, 50)) {
        die("Username tidak valid");
    }
    
    if (!InputValidator::validateLength($password, 6, 100)) {
        die("Password tidak valid");
    }
    
    // Sanitize input
    $username = InputSanitizer::sanitizeString($username);
    
    // SECURE: Use prepared statements
    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Verify password hash
        if (password_verify($password, $user['password'])) {
            $_SESSION['logged_in'] = true;
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            echo "Login berhasil!";
        } else {
            echo "Username atau password salah!";
        }
    } else {
        echo "Username atau password salah!";
    }
    
    $stmt->close();
}
?>

<form method="POST">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    <button type="submit">Login</button>
</form>
```

**File `test-sql-injection.php`**:
```php
<?php
// Test SQL Injection attempts
$testCases = [
    "admin' OR '1'='1",
    "admin'--",
    "admin'/*",
    "' UNION SELECT * FROM users--",
    "'; DROP TABLE users--"
];

echo "=== SQL Injection Test Cases ===\n";
foreach ($testCases as $test) {
    echo "Testing: $test\n";
    // Test dengan vulnerable code (dalam environment terisolasi)
    // Test dengan secure code (harusnya aman)
}
?>
```

**Output yang diharapkan**: 
- Aplikasi login yang aman dari SQL Injection
- Dokumentasi perbandingan vulnerable vs secure code

---

## 2.3 Preventing Cross-Site Scripting (XSS)

### Teori

**Cross-Site Scripting (XSS)** adalah serangan di mana penyerang menyuntikkan script berbahaya ke dalam halaman web yang dilihat oleh pengguna lain.

#### Jenis-jenis XSS:

1. **Stored XSS (Persistent)**
   - Script disimpan di database
   - Dieksekusi setiap kali halaman diakses
   - Contoh: Comment box, forum post

2. **Reflected XSS (Non-Persistent)**
   - Script direfleksikan dari input user
   - Tidak disimpan di database
   - Contoh: Search results, error messages

3. **DOM-based XSS**
   - Script dieksekusi di client-side
   - Manipulasi DOM tree
   - Tidak melibatkan server

#### Contoh Serangan XSS:
```html
<!-- Stored XSS -->
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">

<!-- Reflected XSS -->
http://example.com/search.php?q=<script>alert('XSS')</script>
```

#### Cara Pencegahan:

1. **Output Encoding**
   - HTML encoding: `htmlspecialchars()`, `htmlentities()`
   - JavaScript encoding untuk JavaScript context
   - URL encoding untuk URL context

2. **Content Security Policy (CSP)**
   - Header HTTP yang membatasi sumber script
   - Mencegah eksekusi inline script

3. **Input Validation**
   - Validasi dan sanitasi input
   - Whitelist approach

4. **HttpOnly Cookies**
   - Mencegah JavaScript mengakses cookies
   - Mengurangi risiko session hijacking

### Praktik: Latihan 2.3

**Tujuan**: Membuat aplikasi komentar yang aman dari XSS

**Langkah-langkah**:
1. Buat database untuk komentar
2. Buat file `vulnerable-comments.php` (untuk demonstrasi)
3. Buat file `secure-comments.php` (dengan output encoding)
4. Implementasi CSP header

**Setup Database (`comments.sql`)**:
```sql
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**File `vulnerable-comments.php` (UNTUK DEMONSTRASI)**:
```php
<?php
// VULNERABLE CODE - JANGAN GUNAKAN DI PRODUKSI!
$conn = mysqli_connect('localhost', 'root', '', 'security_training');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $comment = $_POST['comment'];
    
    // VULNERABLE: No output encoding
    $stmt = $conn->prepare("INSERT INTO comments (name, comment) VALUES (?, ?)");
    $stmt->bind_param("ss", $name, $comment);
    $stmt->execute();
}

$result = mysqli_query($conn, "SELECT * FROM comments ORDER BY created_at DESC");
?>

<h2>Komentar</h2>
<form method="POST">
    Nama: <input type="text" name="name"><br>
    Komentar: <textarea name="comment"></textarea><br>
    <button type="submit">Kirim</button>
</form>

<hr>
<?php while ($row = mysqli_fetch_assoc($result)): ?>
    <div>
        <strong><?php echo $row['name']; ?></strong>
        <p><?php echo $row['comment']; ?></p> <!-- VULNERABLE: No encoding -->
    </div>
<?php endwhile; ?>
```

**File `secure-comments.php` (IMPLEMENTASI AMAN)**:
```php
<?php
session_start();
require_once 'InputValidator.php';
require_once 'InputSanitizer.php';

// Set Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");

$conn = mysqli_connect('localhost', 'root', '', 'security_training');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? '';
    $comment = $_POST['comment'] ?? '';
    
    // Validate input
    if (!InputValidator::validateLength($name, 1, 100)) {
        die("Nama tidak valid");
    }
    
    if (!InputValidator::validateLength($comment, 1, 1000)) {
        die("Komentar tidak valid");
    }
    
    // Sanitize input
    $name = InputSanitizer::sanitizeString($name);
    $comment = InputSanitizer::sanitizeString($comment);
    
    // Store in database
    $stmt = $conn->prepare("INSERT INTO comments (name, comment) VALUES (?, ?)");
    $stmt->bind_param("ss", $name, $comment);
    $stmt->execute();
    $stmt->close();
    
    header("Location: secure-comments.php");
    exit;
}

$result = mysqli_query($conn, "SELECT * FROM comments ORDER BY created_at DESC");
?>

<!DOCTYPE html>
<html>
<head>
    <title>Komentar Aman</title>
</head>
<body>
    <h2>Komentar</h2>
    <form method="POST">
        Nama: <input type="text" name="name" required maxlength="100"><br>
        Komentar: <textarea name="comment" required maxlength="1000"></textarea><br>
        <button type="submit">Kirim</button>
    </form>

    <hr>
    <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <div>
            <strong><?php echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'); ?></strong>
            <p><?php echo htmlspecialchars($row['comment'], ENT_QUOTES, 'UTF-8'); ?></p>
            <!-- SECURE: Output encoding dengan htmlspecialchars -->
        </div>
    <?php endwhile; ?>
</body>
</html>
```

**File `xss-test-cases.md`**:
```markdown
# XSS Test Cases

## Stored XSS Tests
- `<script>alert('XSS')</script>`
- `<img src=x onerror="alert('XSS')">`
- `<svg onload="alert('XSS')">`
- `<body onload="alert('XSS')">`
- `<iframe src="javascript:alert('XSS')">`

## Reflected XSS Tests
- `http://example.com/search.php?q=<script>alert('XSS')</script>`
- `http://example.com/error.php?msg=<img src=x onerror="alert('XSS')">`

## Expected Behavior
- Vulnerable code: Script akan dieksekusi
- Secure code: Script akan ditampilkan sebagai teks (encoded)
```

**Output yang diharapkan**: 
- Aplikasi komentar yang aman dari XSS
- Implementasi CSP header
- Dokumentasi test cases XSS

---

## 2.4 Preventing Session Hijacking

### Teori

**Session Hijacking** adalah serangan di mana penyerang mencuri session ID pengguna untuk mengakses akun mereka.

#### Metode Session Hijacking:

1. **Session Sniffing**
   - Menangkap session ID melalui network sniffing
   - Session ID dikirim melalui HTTP (tidak aman)

2. **XSS Attack**
   - Mencuri session ID melalui JavaScript
   - `document.cookie` dapat diakses jika tidak HttpOnly

3. **Session Fixation**
   - Memaksa korban menggunakan session ID yang diketahui penyerang
   - Penyerang sudah mengetahui session ID

4. **Man-in-the-Middle (MITM)**
   - Menyadap komunikasi antara client dan server
   - Session ID dicuri dari komunikasi

#### Cara Pencegahan:

1. **Secure Session Management**
   - Regenerate session ID setelah login
   - Gunakan session ID yang kuat (random, panjang)
   - Set session timeout

2. **HTTPS Only**
   - Selalu gunakan HTTPS untuk session cookies
   - Set Secure flag pada cookies

3. **HttpOnly Cookies**
   - Mencegah JavaScript mengakses cookies
   - Mengurangi risiko XSS-based session hijacking

4. **SameSite Attribute**
   - Mencegah CSRF attacks
   - SameSite=Strict atau SameSite=Lax

5. **IP Validation**
   - Validasi IP address (dapat bermasalah dengan proxy/mobile)
   - User-Agent validation

6. **Session Timeout**
   - Set waktu kadaluarsa session
   - Logout otomatis setelah idle

### Praktik: Latihan 2.4

**Tujuan**: Membuat sistem session management yang aman

**Langkah-langkah**:
1. Buat file `SecureSession.php` untuk mengelola session dengan aman
2. Buat file `session-demo.php` untuk demonstrasi
3. Buat dokumentasi best practices

**File `SecureSession.php`**:
```php
<?php
class SecureSession {
    
    /**
     * Start secure session
     */
    public static function start() {
        // Configure session settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1); // Only over HTTPS
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_samesite', 'Strict');
        
        // Set session name
        session_name('SECURE_SESSION');
        
        // Start session
        session_start();
        
        // Regenerate session ID periodically
        if (!isset($_SESSION['created'])) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        } else if (time() - $_SESSION['created'] > 1800) {
            // Regenerate every 30 minutes
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
        
        // Set session timeout (1 hour)
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity'] > 3600)) {
            self::destroy();
            return false;
        }
        
        $_SESSION['last_activity'] = time();
        
        // Validate session fingerprint
        if (!self::validateFingerprint()) {
            self::destroy();
            return false;
        }
        
        return true;
    }
    
    /**
     * Create session fingerprint
     */
    private static function createFingerprint() {
        $fingerprint = $_SERVER['HTTP_USER_AGENT'] ?? '';
        // Note: IP validation can be problematic with proxies/mobile
        // $fingerprint .= $_SERVER['REMOTE_ADDR'] ?? '';
        return hash('sha256', $fingerprint);
    }
    
    /**
     * Validate session fingerprint
     */
    private static function validateFingerprint() {
        if (!isset($_SESSION['fingerprint'])) {
            $_SESSION['fingerprint'] = self::createFingerprint();
            return true;
        }
        
        return $_SESSION['fingerprint'] === self::createFingerprint();
    }
    
    /**
     * Set session data
     */
    public static function set($key, $value) {
        $_SESSION[$key] = $value;
    }
    
    /**
     * Get session data
     */
    public static function get($key, $default = null) {
        return $_SESSION[$key] ?? $default;
    }
    
    /**
     * Check if user is logged in
     */
    public static function isLoggedIn() {
        return isset($_SESSION['user_id']) && isset($_SESSION['logged_in']);
    }
    
    /**
     * Login user
     */
    public static function login($userId, $username) {
        // Regenerate session ID on login
        session_regenerate_id(true);
        
        $_SESSION['logged_in'] = true;
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = time();
        $_SESSION['fingerprint'] = self::createFingerprint();
    }
    
    /**
     * Logout user
     */
    public static function logout() {
        self::destroy();
    }
    
    /**
     * Destroy session
     */
    public static function destroy() {
        $_SESSION = array();
        
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 3600, '/');
        }
        
        session_destroy();
    }
}
?>
```

**File `session-demo.php`**:
```php
<?php
require_once 'SecureSession.php';

SecureSession::start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'login') {
        // Simulate login
        SecureSession::login(1, 'testuser');
        echo "Login berhasil!";
    } elseif ($_POST['action'] === 'logout') {
        SecureSession::logout();
        echo "Logout berhasil!";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Session Management Demo</title>
</head>
<body>
    <h2>Session Management Demo</h2>
    
    <?php if (SecureSession::isLoggedIn()): ?>
        <p>Status: Logged in</p>
        <p>User ID: <?php echo SecureSession::get('user_id'); ?></p>
        <p>Username: <?php echo SecureSession::get('username'); ?></p>
        <p>Login Time: <?php echo date('Y-m-d H:i:s', SecureSession::get('login_time')); ?></p>
        
        <form method="POST">
            <input type="hidden" name="action" value="logout">
            <button type="submit">Logout</button>
        </form>
    <?php else: ?>
        <p>Status: Not logged in</p>
        <form method="POST">
            <input type="hidden" name="action" value="login">
            <button type="submit">Login</button>
        </form>
    <?php endif; ?>
    
    <hr>
    <h3>Session Information</h3>
    <pre>
Session ID: <?php echo session_id(); ?>
Session Name: <?php echo session_name(); ?>
Session Cookie Params:
<?php print_r(session_get_cookie_params()); ?>
    </pre>
</body>
</html>
```

**File `session-security-checklist.md`**:
```markdown
# Session Security Checklist

## Configuration
- [ ] Use HttpOnly flag for session cookies
- [ ] Use Secure flag (HTTPS only)
- [ ] Set SameSite attribute (Strict or Lax)
- [ ] Use strong session ID generation
- [ ] Set appropriate session timeout

## Implementation
- [ ] Regenerate session ID on login
- [ ] Regenerate session ID periodically
- [ ] Validate session fingerprint
- [ ] Implement session timeout
- [ ] Proper logout functionality

## Testing
- [ ] Test session hijacking prevention
- [ ] Test session fixation prevention
- [ ] Test session timeout
- [ ] Test concurrent sessions
```

**Output yang diharapkan**: 
- Library session management yang aman
- Dokumentasi best practices session security

---

## 2.5 Preventing Remote Code Execution

### Teori

**Remote Code Execution (RCE)** adalah serangan di mana penyerang dapat mengeksekusi kode secara remote pada server target.

#### Vektor Serangan RCE:

1. **Command Injection**
   - Eksekusi command shell melalui input user
   - Fungsi seperti `exec()`, `system()`, `shell_exec()`

2. **File Inclusion**
   - Local File Inclusion (LFI)
   - Remote File Inclusion (RFI)

3. **Deserialization Vulnerabilities**
   - Eksekusi kode melalui deserialization
   - Object injection

4. **Template Injection**
   - Server-Side Template Injection (SSTI)
   - Eksekusi kode melalui template engine

#### Contoh Vulnerable Code:
```php
// VULNERABLE: Command Injection
$filename = $_GET['file'];
exec("cat " . $filename); // Dangerous!

// VULNERABLE: File Inclusion
include($_GET['page'] . '.php'); // Dangerous!

// VULNERABLE: Deserialization
$data = unserialize($_POST['data']); // Dangerous!
```

#### Cara Pencegahan:

1. **Avoid Dangerous Functions**
   - Jangan gunakan `eval()`, `exec()`, `system()`
   - Gunakan alternatif yang lebih aman

2. **Input Validation**
   - Whitelist approach untuk file names
   - Validasi path traversal

3. **Safe File Operations**
   - Gunakan basename() untuk file names
   - Validasi file extensions
   - Jangan include file dari user input

4. **Safe Deserialization**
   - Hindari deserialization dari user input
   - Gunakan JSON instead of serialize()
   - Validasi sebelum deserialization

5. **Least Privilege**
   - Web server dengan privilege minimum
   - Disable dangerous PHP functions

### Praktik: Latihan 2.5

**Tujuan**: Membuat aplikasi file manager yang aman dari RCE

**Langkah-langkah**:
1. Buat file `vulnerable-file-manager.php` (untuk demonstrasi)
2. Buat file `secure-file-manager.php` (implementasi aman)
3. Buat dokumentasi prevention techniques

**File `vulnerable-file-manager.php` (UNTUK DEMONSTRASI)**:
```php
<?php
// VULNERABLE CODE - JANGAN GUNAKAN DI PRODUKSI!

// VULNERABLE: Command Injection
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>";
    system($cmd); // DANGEROUS!
    echo "</pre>";
}

// VULNERABLE: File Inclusion
if (isset($_GET['page'])) {
    include($_GET['page'] . '.php'); // DANGEROUS!
}
?>
```

**File `secure-file-manager.php` (IMPLEMENTASI AMAN)**:
```php
<?php
require_once 'InputValidator.php';
require_once 'InputSanitizer.php';

/**
 * Secure File Manager
 * Demonstrates safe file operations
 */
class SecureFileManager {
    
    private $baseDir;
    private $allowedExtensions = ['txt', 'pdf', 'jpg', 'png'];
    
    public function __construct($baseDir) {
        // Ensure base directory is absolute and within allowed path
        $this->baseDir = realpath($baseDir);
        if ($this->baseDir === false) {
            throw new Exception("Invalid base directory");
        }
    }
    
    /**
     * List files in directory (safe)
     */
    public function listFiles($subDir = '') {
        // Sanitize subdirectory
        $subDir = $this->sanitizePath($subDir);
        $fullPath = $this->baseDir . DIRECTORY_SEPARATOR . $subDir;
        
        // Prevent directory traversal
        $realPath = realpath($fullPath);
        if ($realPath === false || strpos($realPath, $this->baseDir) !== 0) {
            throw new Exception("Invalid path");
        }
        
        $files = [];
        if (is_dir($realPath)) {
            $items = scandir($realPath);
            foreach ($items as $item) {
                if ($item !== '.' && $item !== '..') {
                    $filePath = $realPath . DIRECTORY_SEPARATOR . $item;
                    if (is_file($filePath)) {
                        $files[] = [
                            'name' => $item,
                            'size' => filesize($filePath),
                            'extension' => pathinfo($item, PATHINFO_EXTENSION)
                        ];
                    }
                }
            }
        }
        
        return $files;
    }
    
    /**
     * Read file content (safe)
     */
    public function readFile($filename) {
        // Validate filename
        if (!InputValidator::validatePattern($filename, '/^[a-zA-Z0-9._-]+$/')) {
            throw new Exception("Invalid filename");
        }
        
        // Get file extension
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // Check if extension is allowed
        if (!in_array($extension, $this->allowedExtensions)) {
            throw new Exception("File type not allowed");
        }
        
        $filePath = $this->baseDir . DIRECTORY_SEPARATOR . basename($filename);
        
        // Prevent directory traversal
        $realPath = realpath($filePath);
        if ($realPath === false || strpos($realPath, $this->baseDir) !== 0) {
            throw new Exception("Invalid file path");
        }
        
        // Read file
        if (is_file($realPath)) {
            return file_get_contents($realPath);
        }
        
        throw new Exception("File not found");
    }
    
    /**
     * Sanitize path to prevent directory traversal
     */
    private function sanitizePath($path) {
        // Remove directory traversal characters
        $path = str_replace('..', '', $path);
        $path = str_replace('/', '', $path);
        $path = str_replace('\\', '', $path);
        return $path;
    }
}

// Usage example
try {
    $fileManager = new SecureFileManager(__DIR__ . '/files');
    
    if (isset($_GET['action'])) {
        if ($_GET['action'] === 'list') {
            $files = $fileManager->listFiles();
            echo json_encode($files);
        } elseif ($_GET['action'] === 'read' && isset($_GET['file'])) {
            $content = $fileManager->readFile($_GET['file']);
            echo htmlspecialchars($content);
        }
    }
} catch (Exception $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
}
?>
```

**File `rce-prevention-guide.md`**:
```markdown
# Remote Code Execution Prevention Guide

## Dangerous PHP Functions to Avoid
- `eval()` - Execute PHP code from string
- `exec()` - Execute system command
- `system()` - Execute system command
- `shell_exec()` - Execute shell command
- `passthru()` - Execute system command
- `popen()` - Open process file pointer
- `proc_open()` - Execute command and open file descriptors
- `file_get_contents()` with user input URLs (RFI)
- `include()` / `require()` with user input (LFI/RFI)
- `unserialize()` with user input

## Safe Alternatives
- Use whitelist for file operations
- Use `basename()` for file names
- Validate file extensions
- Use `realpath()` and check against base directory
- Use JSON instead of serialize/unserialize
- Use prepared statements instead of command execution

## Best Practices
1. Disable dangerous functions in php.ini
2. Use least privilege for web server user
3. Validate and sanitize all inputs
4. Use whitelist approach
5. Implement proper error handling
6. Log all file operations
```

**File `php.ini-security-config.md`**:
```markdown
# PHP Security Configuration

## Disable Dangerous Functions
```ini
disable_functions = eval,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

## Other Security Settings
```ini
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
display_errors = Off
log_errors = On
```

## Session Security
```ini
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_only_cookies = 1
```
```

**Output yang diharapkan**: 
- File manager yang aman dari RCE
- Dokumentasi prevention techniques
- Security configuration guide

---

## 🎯 Proyek Akhir Day 2

**Tujuan**: Membuat aplikasi web sederhana yang mengimplementasikan semua teknik secure programming

**Deliverables**:
1. Library input validation dan sanitization
2. Aplikasi login yang aman dari SQL Injection
3. Aplikasi komentar yang aman dari XSS
4. Sistem session management yang aman
5. File manager yang aman dari RCE
6. Dokumentasi lengkap semua teknik

**Struktur Proyek Final**:
```
day-02-project/
├── README.md
├── includes/
│   ├── InputValidator.php
│   ├── InputSanitizer.php
│   └── SecureSession.php
├── applications/
│   ├── secure-login.php
│   ├── secure-comments.php
│   └── secure-file-manager.php
├── database/
│   ├── setup-db.sql
│   └── comments.sql
├── docs/
│   ├── sql-injection-prevention.md
│   ├── xss-prevention.md
│   ├── session-security.md
│   └── rce-prevention.md
└── tests/
    ├── test-validation.php
    ├── test-sql-injection.php
    └── xss-test-cases.md
```

---

## 📝 Ringkasan Day 2

### Key Takeaways:
1. Selalu validasi dan sanitasi input pengguna
2. Gunakan prepared statements untuk mencegah SQL Injection
3. Encode output untuk mencegah XSS
4. Implementasi session management yang aman
5. Hindari fungsi berbahaya dan validasi semua file operations

### Next Steps:
- Review semua kode yang telah dibuat
- Test semua aplikasi dengan berbagai attack vectors
- Siapkan environment untuk Day 3 (OTP, Authentication, Data Loss Prevention)

---

## 📚 Referensi Tambahan
- OWASP Input Validation Cheat Sheet
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
- OWASP Session Management Cheat Sheet
- PHP Security Best Practices

---

**Selamat! Anda telah menyelesaikan Day 2 🎉**

