# Slide Presentasi - Training Security Programming

## 📋 Deskripsi

Slide presentasi menggunakan RevealJS untuk program pelatihan Security Programming & Server Security selama 4 hari.

## 🚀 Cara Menggunakan

### 1. Menggunakan Web Server Lokal

Buka slide melalui web server (XAMPP, Apache, atau web server lainnya):

```
http://localhost/traning%20security%20programming/slides/index.html
```

### 2. Menggunakan Python Simple Server

Jika tidak menggunakan XAMPP, bisa menggunakan Python:

```bash
cd slides
python3 -m http.server 8000
```

Kemudian buka browser:
```
http://localhost:8000/index.html
```

### 3. Membuka Langsung di Browser

Bisa juga membuka file HTML langsung di browser, namun beberapa fitur mungkin tidak berfungsi dengan baik.

## 📁 Struktur File

```
slides/
├── index.html          # Menu utama dan navigasi
├── day-01.html         # Day 1: The Importance of Security
├── day-02.html         # Day 2: Practicing Secure Programming
├── day-03.html         # Day 3: Practicing Secure Operations
├── day-04.html         # Day 4: Creating a Safe Environment
└── README.md           # File ini
```

## 🎮 Kontrol Presentasi

### Navigasi Keyboard

- **Arrow Keys** atau **Space**: Navigasi slide berikutnya
- **Shift + Arrow Keys**: Navigasi slide sebelumnya
- **F**: Fullscreen mode
- **Esc**: Overview mode (lihat semua slide)
- **S**: Speaker notes (jika ada)
- **B**: Pause/Black screen

### Navigasi Mouse

- Klik panah di pojok kiri/bawah
- Scroll mouse untuk navigasi
- Klik progress bar di bawah

## 📝 Fitur Slide

- **Responsive Design**: Dapat digunakan di desktop, tablet, dan mobile
- **Code Highlighting**: Syntax highlighting untuk code blocks
- **Interactive Navigation**: Navigasi yang mudah antar slide
- **Progress Indicator**: Menampilkan progress presentasi
- **Slide Numbers**: Menampilkan nomor slide saat ini

## 🎨 Tema dan Styling

Slide menggunakan tema **White** dari RevealJS dengan custom styling:
- Warna utama: #2c3e50
- Code blocks: Dark theme (#2d2d2d)
- Warning boxes: Red border
- Success boxes: Green border
- Info boxes: Blue border

## 📚 Konten Slide

### Day 1: The Importance of Security
- Overview of Ethical Hacking
- Methodological of Ethical Hacking
- OWASP Top 10
- Introduction to Computer Security
- Secure Programming in SDLC

### Day 2: Practicing Secure Programming
- Validating and Sanitizing User Input
- Preventing SQL Injection
- Preventing XSS
- Preventing Session Hijacking
- Preventing Remote Code Execution

### Day 3: Practicing Secure Operations
- Using OTP & MFA
- Authentication, Authorization, and Logging
- Preventing Data Loss

### Day 4: Creating a Safe Environment
- Securing Linux
- Securing Database
- Using Encryption
- Securing Network Connection (SSL & SSH)
- Securing Web Server

## 🔧 Customization

Untuk mengubah tema atau styling, edit bagian `<style>` di setiap file HTML atau gunakan tema RevealJS lainnya:

- `white` (default)
- `black`
- `league`
- `beige`
- `sky`
- `night`
- `serif`
- `simple`
- `solarized`
- `blood`
- `moon`

Ubah di bagian:
```html
<link rel="stylesheet" href=".../theme/white.css">
```

## 📖 Referensi

- [RevealJS Documentation](https://revealjs.com/)
- [RevealJS GitHub](https://github.com/hakimel/reveal.js)

## 💡 Tips Presentasi

1. **Gunakan Fullscreen Mode**: Tekan `F` untuk fullscreen
2. **Gunakan Overview Mode**: Tekan `Esc` untuk melihat semua slide
3. **Speaker Notes**: Bisa ditambahkan dengan tag `<aside class="notes">`
4. **Practice**: Latih navigasi sebelum presentasi
5. **Backup**: Siapkan backup jika internet tidak tersedia (CDN RevealJS)

## 🐛 Troubleshooting

### Slide tidak muncul
- Pastikan koneksi internet tersedia (untuk CDN RevealJS)
- Atau download RevealJS lokal dan ubah path di HTML

### Code tidak ter-highlight
- Pastikan menggunakan format code block yang benar
- Check browser console untuk error

### Navigasi tidak berfungsi
- Pastikan JavaScript enabled di browser
- Check browser console untuk error

## 📝 Catatan

- Slide menggunakan CDN untuk RevealJS, pastikan koneksi internet tersedia
- Untuk offline use, download RevealJS dan ubah path di HTML
- Slide ini adalah companion untuk materi lengkap di file `.md`

---

**Selamat Presentasi! 🎉**

