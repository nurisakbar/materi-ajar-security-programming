# Day 1: The Importance of Security

## 📚 Tujuan Pembelajaran
Setelah menyelesaikan materi ini, peserta akan:
- Memahami konsep ethical hacking dan metodologinya
- Mengenal berbagai jenis serangan berdasarkan OWASP Top 10
- Memahami dasar-dasar keamanan komputer
- Menerapkan secure programming dalam SDLC

---

## 1.1 Overview of Ethical Hacking

### Teori

**Ethical Hacking** adalah praktik menguji sistem komputer, jaringan, atau aplikasi untuk menemukan kerentanan keamanan sebelum penyerang jahat menemukannya. Ethical hacker menggunakan teknik yang sama dengan hacker jahat, tetapi dengan izin dan untuk tujuan yang baik.

#### Karakteristik Ethical Hacker:
1. **Legal Authorization**: Memiliki izin tertulis untuk melakukan testing
2. **Ethical Purpose**: Tujuan untuk meningkatkan keamanan, bukan merusak
3. **Responsible Disclosure**: Melaporkan temuan dengan cara yang bertanggung jawab
4. **Professional Standards**: Mengikuti standar dan kode etik profesional

#### Perbedaan Ethical Hacker vs Malicious Hacker:
- **White Hat Hacker**: Ethical hacker yang bekerja legal
- **Black Hat Hacker**: Hacker jahat yang melakukan aktivitas ilegal
- **Gray Hat Hacker**: Hacker yang berada di antara keduanya

### Praktik: Latihan 1.1

**Tujuan**: Membuat dokumentasi perbedaan jenis hacker dan peran ethical hacking

**Langkah-langkah**:
1. Buat file `ethical-hacking-overview.md`
2. Dokumentasikan perbedaan White Hat, Black Hat, dan Gray Hat hacker
3. Buat tabel perbandingan karakteristik masing-masing
4. Tuliskan contoh kasus ethical hacking yang berhasil mencegah serangan

**Output yang diharapkan**:
```markdown
# Ethical Hacking Overview

## Jenis-jenis Hacker
| Jenis | Tujuan | Legalitas | Contoh Aktivitas |
|-------|--------|-----------|------------------|
| White Hat | Meningkatkan keamanan | Legal | Penetration testing, Bug bounty |
| Black Hat | Keuntungan pribadi | Ilegal | Data theft, Ransomware |
| Gray Hat | Campuran | Ambigu | Unauthorized testing lalu melaporkan |

## Contoh Kasus Ethical Hacking
[Isi dengan contoh nyata]
```

---

## 1.2 Methodological of Ethical Hacking

### Teori

**Metodologi Ethical Hacking** mengikuti pendekatan sistematis untuk menguji keamanan sistem. Metodologi standar yang umum digunakan:

#### 1. **Reconnaissance (Pengintaian)**
- Mengumpulkan informasi tentang target
- Passive: Menggunakan informasi publik
- Active: Berinteraksi langsung dengan target

#### 2. **Scanning**
- Mengidentifikasi sistem yang hidup
- Port scanning
- Service enumeration
- Vulnerability scanning

#### 3. **Gaining Access**
- Eksploitasi kerentanan yang ditemukan
- Privilege escalation
- Maintaining access

#### 4. **Maintaining Access**
- Membuat backdoor
- Menjaga akses yang telah diperoleh

#### 5. **Covering Tracks**
- Menghapus log
- Menyembunyikan aktivitas (untuk ethical hacking, ini dilakukan untuk dokumentasi)

#### 6. **Reporting**
- Dokumentasi temuan
- Rekomendasi perbaikan
- Risk assessment

### Praktik: Latihan 1.2

**Tujuan**: Membuat checklist metodologi ethical hacking untuk proyek

**Langkah-langkah**:
1. Buat file `hacking-methodology-checklist.md`
2. Buat checklist untuk setiap fase metodologi
3. Untuk setiap fase, buat sub-checklist aktivitas yang harus dilakukan
4. Tambahkan tools yang digunakan untuk setiap fase

**Output yang diharapkan**:
```markdown
# Ethical Hacking Methodology Checklist

## Phase 1: Reconnaissance
- [ ] Passive information gathering
- [ ] Active information gathering
- [ ] Tools: Google dorking, WHOIS, DNS lookup

## Phase 2: Scanning
- [ ] Port scanning (Nmap)
- [ ] Service enumeration
- [ ] Vulnerability scanning (Nessus, OpenVAS)

## Phase 3: Gaining Access
- [ ] Exploit identified vulnerabilities
- [ ] Attempt privilege escalation
- [ ] Document access methods

## Phase 4: Maintaining Access
- [ ] Test persistence mechanisms
- [ ] Document backdoor creation (for testing)

## Phase 5: Covering Tracks
- [ ] Document log manipulation techniques
- [ ] Test detection evasion

## Phase 6: Reporting
- [ ] Document all findings
- [ ] Risk assessment
- [ ] Provide remediation recommendations
```

---

## 1.3 Kinds of Attacks Based on Top 10 OWASP

### Teori

**OWASP Top 10** adalah daftar 10 risiko keamanan aplikasi web yang paling kritis, dikeluarkan oleh Open Web Application Security Project (OWASP).

#### OWASP Top 10 (2021):

1. **A01:2021 – Broken Access Control**
   - Pengguna dapat mengakses data/fungsi yang tidak seharusnya
   - Contoh: IDOR (Insecure Direct Object Reference)

2. **A02:2021 – Cryptographic Failures**
   - Data sensitif tidak terenkripsi dengan benar
   - Contoh: Password dalam plaintext, SSL/TLS misconfiguration

3. **A03:2021 – Injection**
   - SQL Injection, NoSQL Injection, Command Injection
   - Data tidak divalidasi dan disanitasi

4. **A04:2021 – Insecure Design**
   - Desain aplikasi yang tidak aman dari awal
   - Missing security controls

5. **A05:2021 – Security Misconfiguration**
   - Konfigurasi default yang tidak aman
   - Error messages yang terlalu informatif

6. **A06:2021 – Vulnerable and Outdated Components**
   - Menggunakan library/framework yang outdated
   - Komponen dengan known vulnerabilities

7. **A07:2021 – Identification and Authentication Failures**
   - Weak authentication mechanisms
   - Session management yang buruk

8. **A08:2021 – Software and Data Integrity Failures**
   - CI/CD pipeline yang tidak aman
   - Update mechanism yang tidak terverifikasi

9. **A09:2021 – Security Logging and Monitoring Failures**
   - Logging yang tidak memadai
   - Monitoring yang tidak efektif

10. **A10:2021 – Server-Side Request Forgery (SSRF)**
    - Aplikasi membuat request ke URL yang tidak terpercaya
    - Bypass firewall dan access internal resources

### Praktik: Latihan 1.3

**Tujuan**: Membuat dokumentasi dan contoh serangan OWASP Top 10

**Langkah-langkah**:
1. Buat direktori `owasp-top10-examples/`
2. Untuk setiap kategori OWASP Top 10, buat file contoh:
   - `A01-broken-access-control.md`
   - `A02-cryptographic-failures.md`
   - `A03-injection.md`
   - dll.
3. Setiap file berisi:
   - Penjelasan serangan
   - Contoh kode vulnerable
   - Contoh exploit
   - Cara pencegahan

**Contoh struktur file `A03-injection.md`**:
```markdown
# A03:2021 - Injection

## Penjelasan
Injection terjadi ketika data tidak divalidasi dan memungkinkan eksekusi kode berbahaya.

## Contoh Vulnerable Code (PHP)
```php
<?php
$username = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);
?>
```

## Contoh Exploit
```
http://example.com/login.php?username=admin' OR '1'='1
```

## Cara Pencegahan
- Gunakan prepared statements
- Input validation dan sanitization
- Parameterized queries
```

**Output yang diharapkan**: Direktori dengan 10 file dokumentasi OWASP Top 10

---

## 1.4 Introduction to Computer Security

### Teori

**Computer Security** adalah perlindungan sistem komputer dari akses tidak sah, kerusakan, atau pencurian informasi.

#### Tiga Pilar Keamanan (CIA Triad):

1. **Confidentiality (Kerahasiaan)**
   - Data hanya dapat diakses oleh pihak yang berwenang
   - Teknik: Encryption, Access Control

2. **Integrity (Integritas)**
   - Data tidak diubah oleh pihak yang tidak berwenang
   - Teknik: Hashing, Digital Signatures

3. **Availability (Ketersediaan)**
   - Data dan sistem tersedia saat dibutuhkan
   - Teknik: Redundancy, Backup, DDoS Protection

#### Konsep Keamanan Tambahan:

- **Authentication**: Verifikasi identitas pengguna
- **Authorization**: Penentuan hak akses pengguna
- **Non-repudiation**: Tidak dapat menyangkal tindakan yang dilakukan
- **Accountability**: Dapat dilacak siapa yang melakukan apa

#### Threat Model:
- **Threats**: Potensi bahaya terhadap sistem
- **Vulnerabilities**: Kelemahan dalam sistem
- **Risks**: Kombinasi threat dan vulnerability
- **Countermeasures**: Tindakan untuk mengurangi risiko

### Praktik: Latihan 1.4

**Tujuan**: Membuat threat model untuk aplikasi web sederhana

**Langkah-langkah**:
1. Buat file `threat-model.md`
2. Pilih aplikasi web sederhana (misalnya: sistem login)
3. Identifikasi:
   - Assets (data yang perlu dilindungi)
   - Threats (ancaman yang mungkin terjadi)
   - Vulnerabilities (kelemahan yang ada)
   - Risks (risiko yang dihadapi)
   - Countermeasures (tindakan pencegahan)

**Template**:
```markdown
# Threat Model: [Nama Aplikasi]

## Assets
- User credentials (username, password)
- User personal data
- Session tokens
- Database records

## Threats
| Threat | Description | Likelihood | Impact |
|--------|-------------|------------|--------|
| SQL Injection | Attacker injects SQL code | High | High |
| XSS | Attacker injects malicious scripts | Medium | Medium |
| Session Hijacking | Attacker steals session token | Medium | High |

## Vulnerabilities
- No input validation
- SQL queries without prepared statements
- Session tokens in URL

## Risks
[Risk assessment matrix]

## Countermeasures
- Implement input validation
- Use prepared statements
- Secure session management
```

**Output yang diharapkan**: File threat model yang lengkap

---

## 1.5 Implementation of Secure Programming in The SDLC

### Teori

**Secure SDLC (Software Development Life Cycle)** mengintegrasikan praktik keamanan ke dalam setiap fase pengembangan perangkat lunak.

#### Fase SDLC dengan Security Integration:

1. **Planning & Requirements**
   - Security requirements gathering
   - Threat modeling
   - Security architecture design

2. **Design**
   - Secure design principles
   - Security architecture review
   - Data flow analysis

3. **Development**
   - Secure coding practices
   - Code reviews dengan fokus security
   - Static Application Security Testing (SAST)

4. **Testing**
   - Security testing
   - Dynamic Application Security Testing (DAST)
   - Penetration testing
   - Vulnerability scanning

5. **Deployment**
   - Secure configuration
   - Environment hardening
   - Security monitoring setup

6. **Maintenance**
   - Patch management
   - Security updates
   - Incident response

#### Secure Coding Principles:

1. **Defense in Depth**: Multiple layers of security
2. **Least Privilege**: Minimum access yang diperlukan
3. **Fail Secure**: Sistem gagal dalam kondisi aman
4. **Input Validation**: Selalu validasi input
5. **Output Encoding**: Encode output untuk mencegah injection
6. **Error Handling**: Jangan expose informasi sensitif dalam error
7. **Secure Defaults**: Konfigurasi default yang aman

### Praktik: Latihan 1.5

**Tujuan**: Membuat secure SDLC checklist dan implementasi dalam proyek

**Langkah-langkah**:
1. Buat file `secure-sdlc-checklist.md`
2. Buat checklist untuk setiap fase SDLC
3. Buat file `secure-coding-guidelines.md` dengan best practices
4. Buat struktur proyek sederhana yang mengikuti secure SDLC:
   ```
   secure-project/
   ├── requirements/
   │   └── security-requirements.md
   ├── design/
   │   └── security-architecture.md
   ├── src/
   │   └── [code files]
   ├── tests/
   │   └── security-tests/
   └── docs/
       └── security-documentation.md
   ```

**Contoh `secure-coding-guidelines.md`**:
```markdown
# Secure Coding Guidelines

## Input Validation
- [ ] Validate all user inputs
- [ ] Use whitelist approach when possible
- [ ] Sanitize inputs before processing
- [ ] Validate on both client and server side

## Authentication & Authorization
- [ ] Use strong password policies
- [ ] Implement multi-factor authentication
- [ ] Use secure session management
- [ ] Implement proper access controls

## Data Protection
- [ ] Encrypt sensitive data at rest
- [ ] Encrypt data in transit (HTTPS)
- [ ] Never store passwords in plaintext
- [ ] Use parameterized queries

## Error Handling
- [ ] Don't expose system information in errors
- [ ] Log errors securely
- [ ] Provide generic error messages to users
```

**Output yang diharapkan**: 
- Checklist secure SDLC
- Secure coding guidelines
- Struktur proyek yang mengikuti secure SDLC

---

## 🎯 Proyek Akhir Day 1

**Tujuan**: Mengintegrasikan semua materi Day 1 ke dalam satu proyek dokumentasi

**Deliverables**:
1. Dokumentasi lengkap tentang ethical hacking
2. Metodologi ethical hacking dengan checklist
3. Dokumentasi OWASP Top 10 dengan contoh
4. Threat model untuk aplikasi web
5. Secure SDLC checklist dan guidelines
6. Struktur proyek yang siap untuk development

**Struktur Proyek Final**:
```
day-01-project/
├── README.md
├── ethical-hacking/
│   ├── overview.md
│   └── methodology-checklist.md
├── owasp-top10/
│   ├── A01-broken-access-control.md
│   ├── A02-cryptographic-failures.md
│   ├── A03-injection.md
│   └── [7 files lainnya]
├── security-fundamentals/
│   ├── computer-security-intro.md
│   └── threat-model.md
└── secure-sdlc/
    ├── checklist.md
    ├── guidelines.md
    └── project-structure/
```

---

## 📝 Ringkasan Day 1

### Key Takeaways:
1. Ethical hacking adalah praktik legal untuk meningkatkan keamanan
2. Metodologi ethical hacking mengikuti pendekatan sistematis
3. OWASP Top 10 memberikan framework untuk memahami risiko keamanan web
4. CIA Triad (Confidentiality, Integrity, Availability) adalah dasar keamanan
5. Secure SDLC mengintegrasikan keamanan ke dalam setiap fase development

### Next Steps:
- Review semua dokumentasi yang telah dibuat
- Siapkan environment untuk praktik Day 2
- Install tools yang diperlukan (PHP, MySQL, text editor)

---

## 📚 Referensi Tambahan
- OWASP Foundation: https://owasp.org/
- OWASP Top 10 2021: https://owasp.org/Top10/
- NIST Cybersecurity Framework
- ISO/IEC 27001

---

**Selamat! Anda telah menyelesaikan Day 1 🎉**

