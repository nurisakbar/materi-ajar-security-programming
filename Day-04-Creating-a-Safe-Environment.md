# Day 4: Creating a Safe Environment

## 📚 Tujuan Pembelajaran
Setelah menyelesaikan materi ini, peserta akan:
- Mampu mengamankan sistem Linux
- Mampu mengamankan database
- Memahami dan mengimplementasikan enkripsi
- Mampu mengamankan koneksi jaringan dengan SSL dan SSH
- Mampu mengamankan web server

---

## 4.1 Securing Linux

### Teori

**Linux Security** melibatkan berbagai aspek untuk melindungi sistem dari ancaman internal dan eksternal.

#### Prinsip Keamanan Linux:

1. **Principle of Least Privilege**
   - User hanya memiliki akses yang diperlukan
   - Gunakan sudo untuk administrative tasks

2. **Defense in Depth**
   - Multiple layers of security
   - Firewall, IDS/IPS, antivirus

3. **Regular Updates**
   - Patch security vulnerabilities
   - Update system packages

4. **Monitoring and Logging**
   - Monitor system activities
   - Log semua aktivitas penting

#### Area Keamanan Linux:

1. **User Management**
   - Strong passwords
   - User account policies
   - Disable unused accounts

2. **File Permissions**
   - Proper file ownership
   - Correct permissions (chmod)
   - SetUID/SetGID bits

3. **Network Security**
   - Firewall configuration
   - Disable unnecessary services
   - SSH hardening

4. **System Hardening**
   - Disable root login via SSH
   - Configure fail2ban
   - Set up intrusion detection

5. **Logging and Monitoring**
   - System logs (syslog)
   - Audit logs (auditd)
   - Log rotation

### Praktik: Latihan 4.1

**Tujuan**: Mengamankan sistem Linux dengan berbagai teknik hardening

**Langkah-langkah**:
1. Buat script untuk audit keamanan sistem
2. Buat script untuk hardening dasar
3. Konfigurasi firewall
4. Setup fail2ban
5. Konfigurasi SSH yang aman

**File `linux-security-audit.sh`**:
```bash
#!/bin/bash

# Linux Security Audit Script
# Run as root or with sudo

echo "=========================================="
echo "Linux Security Audit Report"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "=========================================="
echo ""

# 1. Check for root login via SSH
echo "1. SSH Configuration Check"
if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "   [WARNING] Root login via SSH is enabled"
else
    echo "   [OK] Root login via SSH is disabled"
fi

if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "   [INFO] Password authentication is enabled"
else
    echo "   [OK] Password authentication is disabled (key-based only)"
fi

echo ""

# 2. Check for unnecessary services
echo "2. Running Services Check"
echo "   Active services:"
systemctl list-units --type=service --state=running | grep -v "systemd\|dbus\|NetworkManager" | awk '{print "   - " $1}'

echo ""

# 3. Check for world-writable files
echo "3. File Permissions Check"
WORLD_WRITABLE=$(find / -xdev -type f -perm -0002 2>/dev/null | head -10)
if [ -z "$WORLD_WRITABLE" ]; then
    echo "   [OK] No world-writable files found"
else
    echo "   [WARNING] Found world-writable files:"
    echo "$WORLD_WRITABLE" | sed 's/^/   /'
fi

echo ""

# 4. Check for files with SUID/SGID
echo "4. SUID/SGID Files Check"
SUID_FILES=$(find / -xdev -type f -perm -4000 2>/dev/null | head -10)
echo "   SUID files found:"
echo "$SUID_FILES" | sed 's/^/   /'

echo ""

# 5. Check password policy
echo "5. Password Policy Check"
if [ -f /etc/login.defs ]; then
    PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    PASS_MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    PASS_MIN_LEN=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
    
    echo "   Password max days: $PASS_MAX_DAYS"
    echo "   Password min days: $PASS_MIN_DAYS"
    echo "   Password min length: $PASS_MIN_LEN"
fi

echo ""

# 6. Check for users with empty passwords
echo "6. User Accounts Check"
EMPTY_PASS=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$EMPTY_PASS" ]; then
    echo "   [OK] No users with empty passwords"
else
    echo "   [CRITICAL] Users with empty passwords:"
    echo "$EMPTY_PASS" | sed 's/^/   /'
fi

echo ""

# 7. Check firewall status
echo "7. Firewall Status"
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | head -1)
    echo "   $UFW_STATUS"
elif command -v firewall-cmd &> /dev/null; then
    FIREWALLD_STATUS=$(firewall-cmd --state 2>/dev/null)
    echo "   Firewalld: $FIREWALLD_STATUS"
elif command -v iptables &> /dev/null; then
    IPTABLES_RULES=$(iptables -L | wc -l)
    echo "   iptables rules: $IPTABLES_RULES"
else
    echo "   [WARNING] No firewall detected"
fi

echo ""

# 8. Check for failed login attempts
echo "8. Failed Login Attempts (last 24 hours)"
if [ -f /var/log/auth.log ]; then
    FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | wc -l)
    echo "   Failed login attempts: $FAILED_LOGINS"
elif [ -f /var/log/secure ]; then
    FAILED_LOGINS=$(grep "Failed password" /var/log/secure | grep "$(date +%b\ %d)" | wc -l)
    echo "   Failed login attempts: $FAILED_LOGINS"
fi

echo ""

# 9. Check disk space
echo "9. Disk Space Check"
df -h | grep -E "^/dev" | awk '{printf "   %s: %s used (%s available)\n", $1, $5, $4}'

echo ""

# 10. Check for system updates
echo "10. System Updates Check"
if command -v apt &> /dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
    echo "   Available updates: $((UPDATES - 1))"
elif command -v yum &> /dev/null; then
    UPDATES=$(yum check-update 2>/dev/null | wc -l)
    echo "   Available updates: $UPDATES"
fi

echo ""
echo "=========================================="
echo "Audit completed"
echo "=========================================="
```

**File `linux-hardening.sh`**:
```bash
#!/bin/bash

# Linux Hardening Script
# Run as root or with sudo
# WARNING: Review and test before running in production

set -e

echo "Starting Linux Hardening..."
echo ""

# 1. Update system
echo "1. Updating system packages..."
if command -v apt &> /dev/null; then
    apt update && apt upgrade -y
elif command -v yum &> /dev/null; then
    yum update -y
fi

# 2. Configure SSH
echo "2. Hardening SSH..."
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_BACKUP="/etc/ssh/sshd_config.backup.$(date +%Y%m%d)"

# Backup original config
cp "$SSH_CONFIG" "$SSH_BACKUP"

# Apply secure SSH settings
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSH_CONFIG"
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG" 2>/dev/null || true

# Add secure settings
if ! grep -q "^Protocol 2" "$SSH_CONFIG"; then
    echo "Protocol 2" >> "$SSH_CONFIG"
fi

if ! grep -q "^MaxAuthTries" "$SSH_CONFIG"; then
    echo "MaxAuthTries 3" >> "$SSH_CONFIG"
fi

if ! grep -q "^ClientAliveInterval" "$SSH_CONFIG"; then
    echo "ClientAliveInterval 300" >> "$SSH_CONFIG"
    echo "ClientAliveCountMax 2" >> "$SSH_CONFIG"
fi

echo "   SSH configuration updated. Backup saved to: $SSH_BACKUP"
echo "   Restart SSH service: systemctl restart sshd"

# 3. Configure firewall
echo "3. Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo "   UFW firewall configured"
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    echo "   Firewalld configured"
fi

# 4. Install and configure fail2ban
echo "4. Installing fail2ban..."
if command -v apt &> /dev/null; then
    apt install -y fail2ban
elif command -v yum &> /dev/null; then
    yum install -y fail2ban
fi

# Configure fail2ban for SSH
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

systemctl enable fail2ban
systemctl start fail2ban
echo "   fail2ban installed and configured"

# 5. Set password policy
echo "5. Setting password policy..."
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs
    echo "   Password policy updated"
fi

# 6. Disable unnecessary services
echo "6. Disabling unnecessary services..."
SERVICES_TO_DISABLE=("telnet" "rsh" "rlogin" "rexec" "ftp")
for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        systemctl disable "$service"
        systemctl stop "$service"
        echo "   Disabled: $service"
    fi
done

# 7. Configure automatic security updates
echo "7. Configuring automatic security updates..."
if command -v apt &> /dev/null; then
    apt install -y unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    systemctl enable unattended-upgrades
elif command -v yum &> /dev/null; then
    yum install -y yum-cron
    sed -i 's/update_cmd = default/update_cmd = security/' /etc/yum/yum-cron.conf
    systemctl enable yum-cron
    systemctl start yum-cron
fi

# 8. Set up log rotation
echo "8. Configuring log rotation..."
if [ ! -f /etc/logrotate.d/security ]; then
    cat > /etc/logrotate.d/security <<EOF
/var/log/security.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF
    echo "   Log rotation configured"
fi

# 9. Set file permissions
echo "9. Setting secure file permissions..."
# Remove world-writable permissions from critical files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
echo "   File permissions updated"

# 10. Enable auditd (if available)
echo "10. Configuring audit daemon..."
if command -v auditd &> /dev/null; then
    systemctl enable auditd
    systemctl start auditd
    echo "   Audit daemon enabled"
fi

echo ""
echo "=========================================="
echo "Hardening completed!"
echo "=========================================="
echo ""
echo "IMPORTANT:"
echo "1. Review SSH configuration before restarting SSH service"
echo "2. Test SSH access before closing current session"
echo "3. Review firewall rules"
echo "4. Check fail2ban status: fail2ban-client status"
echo ""
```

**File `ssh-secure-config.md`**:
```markdown
# SSH Secure Configuration Guide

## Recommended SSH Configuration (/etc/ssh/sshd_config)

```bash
# Protocol version
Protocol 2

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
PubkeyAuthentication yes

# Limit authentication attempts
MaxAuthTries 3
LoginGraceTime 60

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding (if not needed)
X11Forwarding no

# Set idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Limit users/groups
AllowUsers user1 user2
# AllowGroups sshusers

# Disable unused features
UsePAM yes
UseDNS no

# Strong ciphers only
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256,hmac-sha2-512
```

## Generate SSH Key Pair

```bash
# Generate key pair
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# Copy public key to server
ssh-copy-id user@server

# Or manually
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

## Test SSH Configuration

```bash
# Test configuration before applying
sshd -t

# Reload SSH service
systemctl reload sshd
```

## Security Checklist
- [ ] Root login disabled
- [ ] Password authentication disabled
- [ ] SSH keys configured
- [ ] Strong ciphers configured
- [ ] Fail2ban configured
- [ ] Firewall allows only necessary ports
```

**File `fail2ban-setup.md`**:
```markdown
# Fail2ban Setup Guide

## Installation

```bash
# Ubuntu/Debian
apt install fail2ban

# CentOS/RHEL
yum install fail2ban
```

## Configuration (/etc/fail2ban/jail.local)

```ini
[DEFAULT]
# Ban time in seconds (1 hour)
bantime = 3600

# Time window to count failures (10 minutes)
findtime = 600

# Maximum failures before ban
maxretry = 3

# Email notifications (optional)
destemail = admin@example.com
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
bantime = 86400

[php-url-fopen]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
maxretry = 2
```

## Commands

```bash
# Start fail2ban
systemctl start fail2ban
systemctl enable fail2ban

# Check status
fail2ban-client status

# Check specific jail
fail2ban-client status sshd

# Unban IP
fail2ban-client set sshd unbanip 192.168.1.100

# Reload configuration
fail2ban-client reload
```
```

**Output yang diharapkan**: 
- Script audit keamanan Linux
- Script hardening Linux
- Konfigurasi SSH yang aman
- Setup fail2ban
- Dokumentasi best practices

---

## 4.2 Securing Database

### Teori

**Database Security** melindungi database dari akses tidak sah, modifikasi data, dan serangan lainnya.

#### Ancaman Database:

1. **SQL Injection**
   - Sudah dibahas di Day 2
   - Gunakan prepared statements

2. **Unauthorized Access**
   - Weak passwords
   - Default credentials
   - Network exposure

3. **Privilege Escalation**
   - Excessive user privileges
   - Misconfigured roles

4. **Data Exposure**
   - Unencrypted data
   - Unauthorized backups
   - Log files containing sensitive data

#### Prinsip Keamanan Database:

1. **Least Privilege**
   - User hanya memiliki privilege yang diperlukan
   - Pisahkan application user dan admin user

2. **Encryption**
   - Encrypt data at rest
   - Encrypt data in transit
   - Encrypt backups

3. **Access Control**
   - Strong authentication
   - Network restrictions
   - IP whitelisting

4. **Auditing**
   - Log semua aktivitas penting
   - Monitor suspicious activities
   - Regular audit reviews

5. **Regular Updates**
   - Patch security vulnerabilities
   - Update database software

### Praktik: Latihan 4.2

**Tujuan**: Mengamankan database MySQL/MariaDB

**Langkah-langkah**:
1. Hardening MySQL installation
2. Konfigurasi user privileges
3. Setup encryption
4. Konfigurasi logging dan auditing
5. Network security

**File `mysql-secure-installation.sh`**:
```bash
#!/bin/bash

# MySQL Secure Installation Script
# Run as root

set -e

echo "MySQL Security Hardening"
echo ""

# 1. Run mysql_secure_installation (interactive)
echo "1. Running mysql_secure_installation..."
mysql_secure_installation

# 2. Create secure configuration
echo "2. Creating secure MySQL configuration..."

MYSQL_CONFIG="/etc/mysql/mysql.conf.d/mysqld.cnf"
MYSQL_CONFIG_BACKUP="${MYSQL_CONFIG}.backup.$(date +%Y%m%d)"

if [ -f "$MYSQL_CONFIG" ]; then
    cp "$MYSQL_CONFIG" "$MYSQL_CONFIG_BACKUP"
    
    # Add secure settings
    cat >> "$MYSQL_CONFIG" <<EOF

# Security Settings
bind-address = 127.0.0.1
skip-networking = 0
local-infile = 0
symbolic-links = 0
secure-file-priv = /var/lib/mysql-files/

# Logging
general_log = 1
general_log_file = /var/log/mysql/mysql.log
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2

# Connection limits
max_connections = 100
max_connect_errors = 10
wait_timeout = 600
interactive_timeout = 600
EOF

    echo "   Configuration updated. Backup: $MYSQL_CONFIG_BACKUP"
fi

# 3. Create log directory
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

# 4. Set secure file permissions
chmod 600 /etc/mysql/my.cnf
chmod 600 /etc/mysql/debian.cnf 2>/dev/null || true

echo ""
echo "MySQL hardening completed!"
echo "Restart MySQL: systemctl restart mysql"
```

**File `mysql-user-management.sql`**:
```sql
-- MySQL User Management and Security
-- Run as root user

-- 1. Create application user with minimal privileges
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON security_training.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;

-- 2. Create read-only user for reporting
CREATE USER 'readonly_user'@'localhost' IDENTIFIED BY 'ReadOnlyPassword123!';
GRANT SELECT ON security_training.* TO 'readonly_user'@'localhost';
FLUSH PRIVILEGES;

-- 3. Create backup user
CREATE USER 'backup_user'@'localhost' IDENTIFIED BY 'BackupPassword123!';
GRANT SELECT, LOCK TABLES, RELOAD ON *.* TO 'backup_user'@'localhost';
FLUSH PRIVILEGES;

-- 4. Remove anonymous users
DELETE FROM mysql.user WHERE User='';
FLUSH PRIVILEGES;

-- 5. Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;

-- 6. Check user privileges
SELECT User, Host, authentication_string FROM mysql.user;

-- 7. Show grants for specific user
SHOW GRANTS FOR 'app_user'@'localhost';

-- 8. Revoke unnecessary privileges (example)
-- REVOKE ALL PRIVILEGES ON *.* FROM 'app_user'@'localhost';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON security_training.* TO 'app_user'@'localhost';

-- 9. Set password expiration policy
ALTER USER 'app_user'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;
ALTER USER 'backup_user'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;

-- 10. Enable password validation plugin (if available)
-- INSTALL PLUGIN validate_password SONAME 'validate_password.so';
-- SET GLOBAL validate_password.policy = STRONG;
-- SET GLOBAL validate_password.length = 12;
```

**File `mysql-audit-setup.sql`**:
```sql
-- MySQL Audit Setup
-- Requires MySQL Enterprise Audit plugin or Percona Audit Plugin

-- For Percona Server / MariaDB
-- Install audit plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Configure audit log
SET GLOBAL audit_log_policy = 'ALL';
SET GLOBAL audit_log_format = 'JSON';
SET GLOBAL audit_log_file = '/var/log/mysql/audit.log';

-- Or use general log for basic auditing
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/mysql.log';

-- Enable slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow-query.log';

-- Create audit table for custom logging
CREATE TABLE IF NOT EXISTS db_audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    table_name VARCHAR(100),
    query_text TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_name),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB;

-- Create trigger for INSERT operations (example)
DELIMITER //
CREATE TRIGGER audit_insert_users
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO db_audit_log (user_name, action, table_name, query_text, ip_address)
    VALUES (USER(), 'INSERT', 'users', CONCAT('INSERT INTO users (id, username) VALUES (', NEW.id, ', ', NEW.username, ')'), CONNECTION_ID());
END//
DELIMITER ;

-- Create trigger for UPDATE operations
DELIMITER //
CREATE TRIGGER audit_update_users
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO db_audit_log (user_name, action, table_name, query_text, ip_address)
    VALUES (USER(), 'UPDATE', 'users', CONCAT('UPDATE users SET username=', NEW.username, ' WHERE id=', NEW.id), CONNECTION_ID());
END//
DELIMITER ;

-- Create trigger for DELETE operations
DELIMITER //
CREATE TRIGGER audit_delete_users
AFTER DELETE ON users
FOR EACH ROW
BEGIN
    INSERT INTO db_audit_log (user_name, action, table_name, query_text, ip_address)
    VALUES (USER(), 'DELETE', 'users', CONCAT('DELETE FROM users WHERE id=', OLD.id), CONNECTION_ID());
END//
DELIMITER ;
```

**File `mysql-encryption-setup.sql`**:
```sql
-- MySQL Encryption Setup
-- For MySQL 5.7+ or MariaDB 10.1+

-- 1. Enable encryption for InnoDB tables
-- Set encryption key (store securely!)
SET GLOBAL innodb_default_encryption_key_id = 1;

-- Create encrypted table
CREATE TABLE encrypted_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    encrypted_data VARBINARY(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB
ENCRYPTION='Y';

-- 2. Encrypt specific columns using AES_ENCRYPT
-- Note: Store encryption key securely, not in code!
CREATE TABLE users_encrypted (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email_encrypted VARBINARY(255),
    phone_encrypted VARBINARY(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Insert encrypted data (example - use secure key management in production)
INSERT INTO users_encrypted (username, email_encrypted, phone_encrypted)
VALUES (
    'testuser',
    AES_ENCRYPT('user@example.com', 'encryption_key_here'),
    AES_ENCRYPT('1234567890', 'encryption_key_here')
);

-- Decrypt data
SELECT 
    id,
    username,
    AES_DECRYPT(email_encrypted, 'encryption_key_here') AS email,
    AES_DECRYPT(phone_encrypted, 'encryption_key_here') AS phone
FROM users_encrypted;

-- 3. Enable SSL for connections
-- Check SSL status
SHOW VARIABLES LIKE '%ssl%';

-- Require SSL for specific user
ALTER USER 'app_user'@'localhost' REQUIRE SSL;

-- Require SSL and specific cipher
ALTER USER 'app_user'@'localhost' 
REQUIRE SSL 
CIPHER 'ECDHE-RSA-AES256-SHA384';

-- 4. Enable binary log encryption (MySQL 8.0+)
SET GLOBAL binlog_encryption = ON;

-- 5. Enable redo log encryption
SET GLOBAL innodb_redo_log_encrypt = ON;
```

**File `database-security-checklist.md`**:
```markdown
# Database Security Checklist

## Installation & Configuration
- [ ] Run mysql_secure_installation
- [ ] Remove anonymous users
- [ ] Remove test database
- [ ] Change root password
- [ ] Disable remote root login
- [ ] Bind to localhost only (if not needed remotely)
- [ ] Set secure file permissions

## User Management
- [ ] Create application-specific users
- [ ] Use strong passwords
- [ ] Apply principle of least privilege
- [ ] Set password expiration policy
- [ ] Remove unused users
- [ ] Regular privilege audits

## Network Security
- [ ] Use firewall to restrict access
- [ ] Use SSH tunnel for remote access
- [ ] Enable SSL/TLS for connections
- [ ] Whitelist IP addresses
- [ ] Disable network access if not needed

## Encryption
- [ ] Encrypt data at rest
- [ ] Encrypt data in transit (SSL/TLS)
- [ ] Encrypt backups
- [ ] Use encrypted connections

## Logging & Auditing
- [ ] Enable general log (if needed)
- [ ] Enable slow query log
- [ ] Enable error log
- [ ] Set up audit logging
- [ ] Monitor failed login attempts
- [ ] Regular log review

## Backup Security
- [ ] Encrypt backups
- [ ] Secure backup storage
- [ ] Test restore procedures
- [ ] Limit backup access

## Maintenance
- [ ] Regular security updates
- [ ] Regular privilege reviews
- [ ] Monitor for suspicious activities
- [ ] Regular backup testing
```

**Output yang diharapkan**: 
- Script hardening MySQL
- SQL scripts untuk user management
- Setup encryption
- Audit logging configuration
- Security checklist

---

## 4.3 Using Encryption

### Teori

**Encryption** adalah proses mengubah data menjadi format yang tidak dapat dibaca tanpa kunci dekripsi.

#### Jenis-jenis Encryption:

1. **Symmetric Encryption**
   - Satu kunci untuk encrypt dan decrypt
   - Cepat dan efisien
   - Contoh: AES, DES, 3DES

2. **Asymmetric Encryption**
   - Dua kunci: public key dan private key
   - Lebih aman tapi lebih lambat
   - Contoh: RSA, ECC, DSA

3. **Hashing**
   - One-way function
   - Tidak dapat di-decrypt
   - Contoh: SHA-256, MD5 (deprecated), bcrypt

#### Use Cases Encryption:

1. **Data at Rest**
   - Encrypt files di disk
   - Encrypt database
   - Encrypt backups

2. **Data in Transit**
   - HTTPS/TLS
   - VPN
   - Encrypted email

3. **Password Storage**
   - Hash passwords (bcrypt, argon2)
   - Jangan gunakan MD5 atau SHA-1 untuk passwords

#### Encryption Best Practices:

- Gunakan strong encryption algorithms (AES-256, RSA-2048+)
- Manage keys securely
- Rotate encryption keys regularly
- Use proper key derivation functions
- Don't store keys with encrypted data

### Praktik: Latihan 4.3

**Tujuan**: Mengimplementasikan berbagai jenis enkripsi dalam aplikasi

**Langkah-langkah**:
1. Buat class untuk symmetric encryption
2. Buat class untuk asymmetric encryption
3. Implementasi password hashing
4. File encryption
5. Database encryption

**File `EncryptionHandler.php`**:
```php
<?php
/**
 * Encryption Handler
 * Provides symmetric and asymmetric encryption methods
 */

class EncryptionHandler {
    
    /**
     * Symmetric encryption using AES-256-CBC
     */
    public static function encrypt($data, $key) {
        // Generate random IV
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        
        // Encrypt data
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        // Prepend IV to encrypted data
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Symmetric decryption using AES-256-CBC
     */
    public static function decrypt($encryptedData, $key) {
        $data = base64_decode($encryptedData);
        
        // Extract IV (first 16 bytes)
        $ivLength = openssl_cipher_iv_length('AES-256-CBC');
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }
    
    /**
     * Generate encryption key
     */
    public static function generateKey($length = 32) {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }
    
    /**
     * Hash password using bcrypt
     */
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
    
    /**
     * Verify password
     */
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Generate RSA key pair
     */
    public static function generateRSAKeyPair($keySize = 2048) {
        $config = [
            "digest_alg" => "sha256",
            "private_key_bits" => $keySize,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        
        $resource = openssl_pkey_new($config);
        
        // Get private key
        openssl_pkey_export($resource, $privateKey);
        
        // Get public key
        $publicKey = openssl_pkey_get_details($resource);
        $publicKey = $publicKey["key"];
        
        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey
        ];
    }
    
    /**
     * Encrypt with RSA public key
     */
    public static function encryptRSA($data, $publicKey) {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }
    
    /**
     * Decrypt with RSA private key
     */
    public static function decryptRSA($encryptedData, $privateKey) {
        $data = base64_decode($encryptedData);
        openssl_private_decrypt($data, $decrypted, $privateKey);
        return $decrypted;
    }
    
    /**
     * Encrypt file
     */
    public static function encryptFile($inputFile, $outputFile, $key) {
        $data = file_get_contents($inputFile);
        $encrypted = self::encrypt($data, $key);
        file_put_contents($outputFile, $encrypted);
        return true;
    }
    
    /**
     * Decrypt file
     */
    public static function decryptFile($inputFile, $outputFile, $key) {
        $encrypted = file_get_contents($inputFile);
        $decrypted = self::decrypt($encrypted, $key);
        file_put_contents($outputFile, $decrypted);
        return true;
    }
    
    /**
     * Generate secure random token
     */
    public static function generateToken($length = 32) {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }
    
    /**
     * Hash data using SHA-256
     */
    public static function hash($data) {
        return hash('sha256', $data);
    }
    
    /**
     * HMAC (Hash-based Message Authentication Code)
     */
    public static function hmac($data, $key) {
        return hash_hmac('sha256', $data, $key);
    }
}
?>
```

**File `encryption-demo.php`**:
```php
<?php
require_once 'EncryptionHandler.php';

echo "=== Encryption Demo ===\n\n";

// 1. Symmetric Encryption
echo "1. Symmetric Encryption (AES-256-CBC)\n";
$key = EncryptionHandler::generateKey();
$originalData = "Sensitive data that needs encryption";
echo "Original: $originalData\n";

$encrypted = EncryptionHandler::encrypt($originalData, $key);
echo "Encrypted: $encrypted\n";

$decrypted = EncryptionHandler::decrypt($encrypted, $key);
echo "Decrypted: $decrypted\n";
echo "Match: " . ($originalData === $decrypted ? "Yes" : "No") . "\n\n";

// 2. Password Hashing
echo "2. Password Hashing (bcrypt)\n";
$password = "MySecurePassword123!";
$hash = EncryptionHandler::hashPassword($password);
echo "Password: $password\n";
echo "Hash: $hash\n";
echo "Verify: " . (EncryptionHandler::verifyPassword($password, $hash) ? "Valid" : "Invalid") . "\n\n";

// 3. RSA Encryption
echo "3. RSA Encryption\n";
$keyPair = EncryptionHandler::generateRSAKeyPair();
$rsaData = "Data encrypted with RSA";
echo "Original: $rsaData\n";

$rsaEncrypted = EncryptionHandler::encryptRSA($rsaData, $keyPair['public_key']);
echo "Encrypted: $rsaEncrypted\n";

$rsaDecrypted = EncryptionHandler::decryptRSA($rsaEncrypted, $keyPair['private_key']);
echo "Decrypted: $rsaDecrypted\n";
echo "Match: " . ($rsaData === $rsaDecrypted ? "Yes" : "No") . "\n\n";

// 4. File Encryption
echo "4. File Encryption\n";
$testFile = 'test.txt';
file_put_contents($testFile, "This is a test file for encryption");
echo "Created test file: $testFile\n";

EncryptionHandler::encryptFile($testFile, 'test.encrypted', $key);
echo "File encrypted: test.encrypted\n";

EncryptionHandler::decryptFile('test.encrypted', 'test.decrypted', $key);
echo "File decrypted: test.decrypted\n";
echo "Content: " . file_get_contents('test.decrypted') . "\n\n";

// 5. HMAC
echo "5. HMAC (Message Authentication)\n";
$message = "Important message";
$hmacKey = EncryptionHandler::generateKey();
$hmac = EncryptionHandler::hmac($message, $hmacKey);
echo "Message: $message\n";
echo "HMAC: $hmac\n";
echo "Verify HMAC: " . (EncryptionHandler::hmac($message, $hmacKey) === $hmac ? "Valid" : "Invalid") . "\n\n";

// Cleanup
unlink($testFile);
unlink('test.encrypted');
unlink('test.decrypted');
?>
```

**File `secure-password-storage.php`**:
```php
<?php
require_once 'EncryptionHandler.php';

/**
 * Secure Password Storage Example
 * Demonstrates best practices for storing passwords
 */

class SecurePasswordStorage {
    
    /**
     * Store user password securely
     */
    public static function storePassword($userId, $password) {
        // Hash password (never store plaintext!)
        $hashedPassword = EncryptionHandler::hashPassword($password);
        
        // Store hash in database
        // In real application, use prepared statements
        $conn = mysqli_connect('localhost', 'root', '', 'security_training');
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->bind_param("si", $hashedPassword, $userId);
        $stmt->execute();
        $stmt->close();
        
        return true;
    }
    
    /**
     * Verify password
     */
    public static function verifyPassword($userId, $password) {
        $conn = mysqli_connect('localhost', 'root', '', 'security_training');
        $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            $stmt->close();
            
            // Verify password hash
            return EncryptionHandler::verifyPassword($password, $user['password']);
        }
        
        $stmt->close();
        return false;
    }
    
    /**
     * Generate password reset token
     */
    public static function generatePasswordResetToken($userId) {
        // Generate secure random token
        $token = EncryptionHandler::generateToken(32);
        
        // Hash token before storing (defense in depth)
        $tokenHash = EncryptionHandler::hash($token);
        
        // Store token hash with expiration (1 hour)
        $conn = mysqli_connect('localhost', 'root', '', 'security_training');
        $expires = date('Y-m-d H:i:s', time() + 3600);
        
        // Create password_reset_tokens table if not exists
        $conn->query("
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                token_hash VARCHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ");
        
        $stmt = $conn->prepare("INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
        $stmt->bind_param("iss", $userId, $tokenHash, $expires);
        $stmt->execute();
        $stmt->close();
        
        // Return plain token (only shown once to user)
        return $token;
    }
    
    /**
     * Verify password reset token
     */
    public static function verifyPasswordResetToken($token) {
        $tokenHash = EncryptionHandler::hash($token);
        
        $conn = mysqli_connect('localhost', 'root', '', 'security_training');
        $stmt = $conn->prepare("
            SELECT user_id FROM password_reset_tokens 
            WHERE token_hash = ? 
            AND expires_at > NOW() 
            AND used = FALSE
        ");
        $stmt->bind_param("s", $tokenHash);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $row = $result->fetch_assoc();
            $userId = $row['user_id'];
            $stmt->close();
            
            // Mark token as used
            $updateStmt = $conn->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE token_hash = ?");
            $updateStmt->bind_param("s", $tokenHash);
            $updateStmt->execute();
            $updateStmt->close();
            
            return $userId;
        }
        
        $stmt->close();
        return false;
    }
}
?>
```

**File `encryption-best-practices.md`**:
```markdown
# Encryption Best Practices

## Key Management
- Never store encryption keys in code
- Use environment variables or key management services
- Rotate keys regularly
- Use different keys for different purposes
- Store keys securely (encrypted, access-controlled)

## Algorithm Selection
- Use AES-256 for symmetric encryption
- Use RSA-2048+ or ECC-256+ for asymmetric encryption
- Use bcrypt or argon2 for password hashing
- Use SHA-256 or SHA-3 for hashing
- Avoid deprecated algorithms (MD5, SHA-1, DES)

## Password Storage
- Never store passwords in plaintext
- Always hash passwords (bcrypt, argon2)
- Use salt (automatically handled by bcrypt)
- Never use MD5 or SHA-1 for passwords
- Consider password complexity requirements

## Data Encryption
- Encrypt sensitive data at rest
- Encrypt data in transit (HTTPS/TLS)
- Encrypt backups
- Use proper IV for each encryption
- Never reuse encryption keys

## Implementation
- Use established libraries (OpenSSL, libsodium)
- Don't implement encryption yourself
- Validate encrypted data before decryption
- Handle errors gracefully
- Log encryption operations (without keys)

## Key Rotation
- Plan for key rotation
- Support multiple key versions during rotation
- Archive old keys securely
- Update encryption keys regularly
```

**Output yang diharapkan**: 
- Encryption library dengan berbagai metode
- Password storage yang aman
- File encryption functionality
- Dokumentasi best practices

---

## 4.4 Securing Network Connection: SSL and SSH

### Teori

**SSL/TLS** (Secure Sockets Layer/Transport Layer Security) mengamankan komunikasi melalui jaringan.

**SSH** (Secure Shell) adalah protokol untuk akses remote yang aman.

#### SSL/TLS:

- **Encryption**: Mengenkripsi data yang ditransmisikan
- **Authentication**: Memverifikasi identitas server (dan client)
- **Integrity**: Memastikan data tidak diubah

#### SSL/TLS Certificates:

1. **Self-Signed Certificate**
   - Untuk development/testing
   - Browser akan menampilkan warning

2. **CA-Signed Certificate**
   - Dikeluarkan oleh Certificate Authority
   - Dipercaya oleh browser
   - Contoh: Let's Encrypt (gratis), DigiCert, Comodo

#### SSH Security:

- Key-based authentication (lebih aman dari password)
- Disable root login
- Change default port (optional)
- Use strong ciphers
- Implement fail2ban

### Praktik: Latihan 4.4

**Tujuan**: Setup SSL/TLS dan konfigurasi SSH yang aman

**Langkah-langkah**:
1. Generate self-signed SSL certificate
2. Konfigurasi Apache/Nginx dengan SSL
3. Setup Let's Encrypt certificate
4. Konfigurasi SSH yang aman
5. Setup SSH key-based authentication

**File `generate-ssl-certificate.sh`**:
```bash
#!/bin/bash

# Generate Self-Signed SSL Certificate
# For production, use Let's Encrypt or commercial CA

DOMAIN="localhost"
DAYS=365
KEY_SIZE=2048

echo "Generating SSL certificate for $DOMAIN..."

# Create directory for certificates
mkdir -p /etc/ssl/private
mkdir -p /etc/ssl/certs

# Generate private key
openssl genrsa -out /etc/ssl/private/${DOMAIN}.key $KEY_SIZE
chmod 600 /etc/ssl/private/${DOMAIN}.key

# Generate certificate signing request
openssl req -new -key /etc/ssl/private/${DOMAIN}.key -out /tmp/${DOMAIN}.csr <<EOF
US
State
City
Organization
Organizational Unit
${DOMAIN}
admin@${DOMAIN}
.
.
EOF

# Generate self-signed certificate
openssl x509 -req -days $DAYS -in /tmp/${DOMAIN}.csr -signkey /etc/ssl/private/${DOMAIN}.key -out /etc/ssl/certs/${DOMAIN}.crt

# Cleanup
rm /tmp/${DOMAIN}.csr

echo "Certificate generated:"
echo "  Private Key: /etc/ssl/private/${DOMAIN}.key"
echo "  Certificate: /etc/ssl/certs/${DOMAIN}.crt"
echo ""
echo "For Apache, add to VirtualHost:"
echo "  SSLEngine on"
echo "  SSLCertificateFile /etc/ssl/certs/${DOMAIN}.crt"
echo "  SSLCertificateKeyFile /etc/ssl/private/${DOMAIN}.key"
```

**File `apache-ssl-config.conf`**:
```apache
# Apache SSL Configuration
# Add to your VirtualHost or create new SSL VirtualHost

<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html
    
    # Enable SSL
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    
    # SSL Protocol Configuration
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    
    # HSTS (HTTP Strict Transport Security)
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    
    # Redirect HTTP to HTTPS
    RewriteEngine on
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
    
    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

**File `nginx-ssl-config.conf`**:
```nginx
# Nginx SSL Configuration

server {
    listen 443 ssl http2;
    server_name example.com;
    root /var/www/html;
    index index.php index.html;

    # SSL Certificate
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

**File `letsencrypt-setup.sh`**:
```bash
#!/bin/bash

# Let's Encrypt SSL Certificate Setup
# Using Certbot

DOMAIN="example.com"
EMAIL="admin@example.com"
WEBROOT="/var/www/html"

echo "Setting up Let's Encrypt SSL certificate for $DOMAIN"

# Install certbot
if command -v apt &> /dev/null; then
    apt update
    apt install -y certbot python3-certbot-apache  # For Apache
    # apt install -y certbot python3-certbot-nginx  # For Nginx
elif command -v yum &> /dev/null; then
    yum install -y certbot python3-certbot-apache
fi

# Obtain certificate
certbot --apache -d $DOMAIN -d www.$DOMAIN --email $EMAIL --agree-tos --non-interactive

# Or for standalone mode (if web server is stopped)
# certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Test auto-renewal
certbot renew --dry-run

# Setup auto-renewal cron job
(crontab -l 2>/dev/null; echo "0 0,12 * * * certbot renew --quiet") | crontab -

echo ""
echo "Certificate installed!"
echo "Certificate location: /etc/letsencrypt/live/$DOMAIN/"
echo "Auto-renewal configured"
```

**File `ssh-key-setup.sh`**:
```bash
#!/bin/bash

# SSH Key Setup Script
# Run on client machine

USERNAME="your_username"
SERVER="your_server.com"
SSH_PORT="22"

echo "SSH Key Setup"
echo ""

# 1. Generate SSH key pair (if not exists)
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "Generating SSH key pair..."
    ssh-keygen -t rsa -b 4096 -C "$(whoami)@$(hostname)"
    echo ""
fi

# 2. Copy public key to server
echo "Copying public key to server..."
ssh-copy-id -p $SSH_PORT $USERNAME@$SERVER

# Or manually:
# cat ~/.ssh/id_rsa.pub | ssh -p $SSH_PORT $USERNAME@$SERVER "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# 3. Test SSH connection
echo ""
echo "Testing SSH connection..."
ssh -p $SSH_PORT $USERNAME@$SERVER "echo 'SSH key authentication successful!'"

# 4. Configure SSH client (optional)
cat >> ~/.ssh/config <<EOF

Host $SERVER
    HostName $SERVER
    User $USERNAME
    Port $SSH_PORT
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

chmod 600 ~/.ssh/config

echo ""
echo "SSH key setup completed!"
echo "You can now connect using: ssh $USERNAME@$SERVER"
```

**File `ssl-ssh-security-guide.md`**:
```markdown
# SSL/TLS and SSH Security Guide

## SSL/TLS Best Practices

### Certificate Management
- Use Let's Encrypt for free certificates
- Use commercial CA for production (if needed)
- Enable auto-renewal
- Monitor certificate expiration
- Use strong key sizes (2048+ bits)

### Configuration
- Disable old protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
- Use TLSv1.2 and TLSv1.3 only
- Use strong cipher suites
- Enable HSTS (HTTP Strict Transport Security)
- Redirect HTTP to HTTPS

### Testing
- Test SSL configuration: https://www.ssllabs.com/ssltest/
- Check certificate validity
- Verify cipher suite strength
- Test HSTS implementation

## SSH Best Practices

### Authentication
- Use key-based authentication
- Disable password authentication
- Use strong key sizes (4096 bits)
- Protect private keys with passphrase

### Configuration
- Disable root login
- Change default port (optional)
- Use strong ciphers
- Limit authentication attempts
- Set idle timeout

### Key Management
- Use different keys for different servers
- Rotate keys regularly
- Revoke compromised keys immediately
- Use SSH agent for key management

### Monitoring
- Monitor failed login attempts
- Use fail2ban for brute force protection
- Log all SSH access
- Review access logs regularly
```

**Output yang diharapkan**: 
- Script untuk generate SSL certificate
- Konfigurasi Apache/Nginx dengan SSL
- Setup Let's Encrypt
- SSH key setup script
- Dokumentasi security guide

---

## 4.5 Securing Web Server

### Teori

**Web Server Security** melindungi web server dari berbagai ancaman.

#### Ancaman Web Server:

1. **DDoS Attacks**
   - Overwhelm server dengan traffic
   - Mitigation: Rate limiting, CDN, firewall

2. **Directory Traversal**
   - Akses file di luar web root
   - Prevention: Proper file permissions, input validation

3. **Server Misconfiguration**
   - Default settings yang tidak aman
   - Prevention: Security hardening, regular audits

4. **Information Disclosure**
   - Error messages yang terlalu informatif
   - Prevention: Custom error pages, disable server signature

5. **Outdated Software**
   - Known vulnerabilities
   - Prevention: Regular updates, security patches

#### Web Server Hardening:

1. **Remove Unnecessary Modules**
2. **Disable Directory Listing**
3. **Set Proper File Permissions**
4. **Configure Security Headers**
5. **Enable Logging**
6. **Rate Limiting**
7. **WAF (Web Application Firewall)**

### Praktik: Latihan 4.5

**Tujuan**: Mengamankan web server Apache/Nginx

**Langkah-langkah**:
1. Hardening Apache/Nginx configuration
2. Setup security headers
3. Konfigurasi rate limiting
4. Setup logging dan monitoring
5. Konfigurasi WAF (ModSecurity)

**File `apache-hardening.conf`**:
```apache
# Apache Security Hardening Configuration

# Disable server signature
ServerTokens Prod
ServerSignature Off

# Hide Apache version
<IfModule mod_headers.c>
    Header unset Server
    Header always unset X-Powered-By
</IfModule>

# Disable directory listing
Options -Indexes

# Prevent access to hidden files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Prevent access to backup files
<FilesMatch "\.(bak|backup|old|orig|save|swp|tmp)$">
    Require all denied
</FilesMatch>

# Security Headers
<IfModule mod_headers.c>
    # XSS Protection
    Header set X-XSS-Protection "1; mode=block"
    
    # Prevent MIME sniffing
    Header set X-Content-Type-Options "nosniff"
    
    # Prevent clickjacking
    Header set X-Frame-Options "DENY"
    
    # Referrer Policy
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Content Security Policy
    Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # Permissions Policy
    Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# Disable TRACE and TRACK methods
TraceEnable off

# Limit request size
LimitRequestBody 10485760  # 10MB

# Timeout settings
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# Disable server status (or restrict access)
# <Location /server-status>
#     SetHandler server-status
#     Require ip 127.0.0.1
# </Location>

# Custom error pages (don't expose information)
ErrorDocument 404 /error/404.html
ErrorDocument 500 /error/500.html

# PHP Security
<IfModule mod_php7.c>
    php_flag display_errors Off
    php_flag log_errors On
    php_value error_log /var/log/apache2/php_errors.log
    php_flag expose_php Off
</IfModule>

# Logging
LogLevel warn
CustomLog /var/log/apache2/access.log combined
ErrorLog /var/log/apache2/error.log
```

**File `nginx-hardening.conf`**:
```nginx
# Nginx Security Hardening Configuration

# Hide Nginx version
server_tokens off;

# Disable directory listing
autoindex off;

# Security Headers
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Remove server header
more_set_headers 'Server: ';

# Limit request size
client_max_body_size 10M;

# Timeout settings
client_body_timeout 10;
client_header_timeout 10;
keepalive_timeout 5 5;
send_timeout 10;

# Rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# Prevent access to hidden files
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# Prevent access to backup files
location ~ \.(bak|backup|old|orig|save|swp|tmp)$ {
    deny all;
    access_log off;
    log_not_found off;
}

# Custom error pages
error_page 404 /error/404.html;
error_page 500 502 503 504 /error/50x.html;

# PHP Security
location ~ \.php$ {
    fastcgi_param PHP_VALUE "display_errors=Off \n log_errors=On";
    fastcgi_param PHP_ADMIN_VALUE "expose_php=Off";
}

# Logging
access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log warn;
```

**File `rate-limiting-config.php`**:
```php
<?php
/**
 * Rate Limiting Implementation
 * Prevents abuse and DDoS attacks
 */

class RateLimiter {
    private $conn;
    
    public function __construct($databaseConnection) {
        $this->conn = $databaseConnection;
        
        // Create rate limit table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                attempts INT DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ip_endpoint (ip_address, endpoint),
                INDEX idx_window (window_start)
            ) ENGINE=InnoDB
        ");
    }
    
    /**
     * Check rate limit
     */
    public function checkRateLimit($endpoint, $maxAttempts = 10, $windowSeconds = 60) {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        
        // Clean old entries
        $this->cleanOldEntries($windowSeconds);
        
        // Get current attempts
        $stmt = $this->conn->prepare("
            SELECT attempts, window_start 
            FROM rate_limits 
            WHERE ip_address = ? AND endpoint = ?
        ");
        $stmt->bind_param("ss", $ipAddress, $endpoint);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $row = $result->fetch_assoc();
            $attempts = $row['attempts'];
            $windowStart = strtotime($row['window_start']);
            
            // Check if within time window
            if (time() - $windowStart < $windowSeconds) {
                if ($attempts >= $maxAttempts) {
                    $stmt->close();
                    return [
                        'allowed' => false,
                        'remaining' => 0,
                        'reset_at' => $windowStart + $windowSeconds
                    ];
                }
                
                // Increment attempts
                $stmt->close();
                $updateStmt = $this->conn->prepare("
                    UPDATE rate_limits 
                    SET attempts = attempts + 1 
                    WHERE ip_address = ? AND endpoint = ?
                ");
                $updateStmt->bind_param("ss", $ipAddress, $endpoint);
                $updateStmt->execute();
                $updateStmt->close();
                
                return [
                    'allowed' => true,
                    'remaining' => $maxAttempts - $attempts - 1,
                    'reset_at' => $windowStart + $windowSeconds
                ];
            } else {
                // Reset window
                $stmt->close();
                $this->resetWindow($ipAddress, $endpoint);
                return [
                    'allowed' => true,
                    'remaining' => $maxAttempts - 1,
                    'reset_at' => time() + $windowSeconds
                ];
            }
        } else {
            // First attempt
            $stmt->close();
            $this->createEntry($ipAddress, $endpoint);
            return [
                'allowed' => true,
                'remaining' => $maxAttempts - 1,
                'reset_at' => time() + $windowSeconds
            ];
        }
    }
    
    private function createEntry($ipAddress, $endpoint) {
        $stmt = $this->conn->prepare("
            INSERT INTO rate_limits (ip_address, endpoint, attempts) 
            VALUES (?, ?, 1)
        ");
        $stmt->bind_param("ss", $ipAddress, $endpoint);
        $stmt->execute();
        $stmt->close();
    }
    
    private function resetWindow($ipAddress, $endpoint) {
        $stmt = $this->conn->prepare("
            UPDATE rate_limits 
            SET attempts = 1, window_start = CURRENT_TIMESTAMP 
            WHERE ip_address = ? AND endpoint = ?
        ");
        $stmt->bind_param("ss", $ipAddress, $endpoint);
        $stmt->execute();
        $stmt->close();
    }
    
    private function cleanOldEntries($windowSeconds) {
        $this->conn->query("
            DELETE FROM rate_limits 
            WHERE window_start < DATE_SUB(NOW(), INTERVAL $windowSeconds SECOND)
        ");
    }
}

// Usage example
$rateLimiter = new RateLimiter($conn);
$result = $rateLimiter->checkRateLimit('/api/login', 5, 300); // 5 attempts per 5 minutes

if (!$result['allowed']) {
    http_response_code(429);
    header('Retry-After: ' . ($result['reset_at'] - time()));
    die(json_encode(['error' => 'Too many requests. Please try again later.']));
}

header('X-RateLimit-Limit: 5');
header('X-RateLimit-Remaining: ' . $result['remaining']);
header('X-RateLimit-Reset: ' . $result['reset_at']);
?>
```

**File `web-server-security-checklist.md`**:
```markdown
# Web Server Security Checklist

## Apache/Nginx Configuration
- [ ] Hide server version
- [ ] Disable directory listing
- [ ] Set proper file permissions
- [ ] Disable unnecessary modules
- [ ] Configure security headers
- [ ] Set up custom error pages
- [ ] Enable logging
- [ ] Configure timeouts

## SSL/TLS
- [ ] Enable HTTPS
- [ ] Use strong cipher suites
- [ ] Enable HSTS
- [ ] Redirect HTTP to HTTPS
- [ ] Valid SSL certificate
- [ ] Auto-renewal configured

## Access Control
- [ ] Restrict admin access by IP
- [ ] Use strong authentication
- [ ] Implement rate limiting
- [ ] Configure firewall rules
- [ ] Block malicious IPs

## PHP Security
- [ ] Disable dangerous functions
- [ ] Set proper php.ini settings
- [ ] Hide PHP version
- [ ] Disable error display
- [ ] Enable error logging
- [ ] Use latest PHP version

## Monitoring
- [ ] Set up log monitoring
- [ ] Monitor failed login attempts
- [ ] Set up alerts
- [ ] Regular log review
- [ ] Monitor disk space

## Updates
- [ ] Keep server software updated
- [ ] Keep PHP updated
- [ ] Keep modules updated
- [ ] Security patches applied
- [ ] Regular security audits
```

**Output yang diharapkan**: 
- Konfigurasi Apache/Nginx yang hardened
- Rate limiting implementation
- Security headers configuration
- Security checklist
- Dokumentasi best practices

---

## 🎯 Proyek Akhir Day 4

**Tujuan**: Mengintegrasikan semua komponen secure environment

**Deliverables**:
1. Linux security audit dan hardening scripts
2. Database security configuration
3. Encryption implementation
4. SSL/TLS dan SSH setup
5. Web server hardening
6. Dokumentasi lengkap

**Struktur Proyek Final**:
```
day-04-project/
├── README.md
├── linux-security/
│   ├── linux-security-audit.sh
│   ├── linux-hardening.sh
│   ├── ssh-secure-config.md
│   └── fail2ban-setup.md
├── database-security/
│   ├── mysql-secure-installation.sh
│   ├── mysql-user-management.sql
│   ├── mysql-audit-setup.sql
│   ├── mysql-encryption-setup.sql
│   └── database-security-checklist.md
├── encryption/
│   ├── EncryptionHandler.php
│   ├── encryption-demo.php
│   ├── secure-password-storage.php
│   └── encryption-best-practices.md
├── ssl-ssh/
│   ├── generate-ssl-certificate.sh
│   ├── apache-ssl-config.conf
│   ├── nginx-ssl-config.conf
│   ├── letsencrypt-setup.sh
│   ├── ssh-key-setup.sh
│   └── ssl-ssh-security-guide.md
└── web-server/
    ├── apache-hardening.conf
    ├── nginx-hardening.conf
    ├── rate-limiting-config.php
    └── web-server-security-checklist.md
```

---

## 📝 Ringkasan Day 4

### Key Takeaways:
1. Linux security memerlukan multiple layers of defense
2. Database security melibatkan access control, encryption, dan auditing
3. Encryption harus digunakan untuk data at rest dan in transit
4. SSL/TLS dan SSH mengamankan komunikasi jaringan
5. Web server hardening mengurangi attack surface

### Next Steps:
- Review semua konfigurasi security
- Test semua implementasi
- Dokumentasikan environment production
- Setup monitoring dan alerting
- Regular security audits

---

## 📚 Referensi Tambahan
- CIS Benchmarks (Center for Internet Security)
- NIST Cybersecurity Framework
- OWASP Server Security Guide
- Linux Security Documentation
- MySQL Security Best Practices
- SSL Labs SSL Test
- Let's Encrypt Documentation

---

**Selamat! Anda telah menyelesaikan Day 4 dan seluruh program pelatihan! 🎉**

## 🏆 Final Project Integration

Setelah menyelesaikan semua 4 hari, integrasikan semua komponen menjadi satu aplikasi web yang aman:

1. **Day 1**: Dokumentasi dan threat model
2. **Day 2**: Secure programming practices
3. **Day 3**: Authentication, authorization, logging, backup
4. **Day 4**: Server hardening, encryption, SSL/SSH

**Buat aplikasi web lengkap yang mengimplementasikan semua security best practices!**

