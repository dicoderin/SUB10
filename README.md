# SUB10 - Dokumentasi

![SUB10 Logo](https://i.imgur.com/gSPsw4r.jpeg)

SUB10 adalah alat multifungsi yang menyediakan 10 fitur keamanan dan reconnaissance dalam satu paket lengkap. Dibangun untuk membantu profesional keamanan, bug bounty hunters, dan administrator sistem dalam melakukan pengujian keamanan dasar dan pengumpulan informasi.

## Fitur Utama

SUB10 menawarkan 10 fitur utama:

1. **Reverse Subdomain** - Mengumpulkan subdomain dari target domain
2. **Header Status Check** - Memeriksa status HTTP dan header server
3. **Port Scanner** - Memindai port umum (21,22,80,443,8080,8443)
4. **IP Converter** - Mendapatkan alamat IPv4 dan IPv6
5. **Down Detector** - Mendeteksi domain yang tidak responsif
6. **XSS Scanner** - Mendeteksi kerentanan XSS dasar
7. **Subdomain Takeover** - Mendeteksi kemungkinan subdomain takeover
8. **HTTP Logger** - Mencatat detail permintaan HTTP
9. **SQLi Detector** - Mendeteksi kerentanan SQL injection
10. **Domain Recon** - Mengumpulkan informasi DNS dan WHOIS

## Instalasi

### Prasyarat
- Python 3.6+
- pip (Python package manager)

### Langkah Instalasi
1. Clone repositori:
```bash
git clone https://github.com/dicoderin/sub10.git
cd sub10
```

2. Instal dependensi:
```bash
pip install -r requirements.txt
```

3. Jalankan program:
```bash
python main.py
```

### Contoh Penggunaan
1. **Mengumpulkan subdomain**:
   - Pilih opsi 1
   - Masukkan domain target (contoh: `example.com`)
   - Hasil akan disimpan di `list.txt`

2. **Memeriksa status header**:
   - Pastikan file `list.txt` sudah ada
   - Pilih opsi 2
   - Hasil akan disimpan di `list-header.txt`

## File Output

| Fitur | File Output | Deskripsi |
|-------|-------------|-----------|
| Reverse Subdomain | `list.txt` | Daftar subdomain |
| Header Check | `list-header.txt` | Status HTTP dan header server |
| Port Scanner | `list-port.txt` | Status port terbuka/tertutup |
| IP Converter | `list-ip.txt` | Alamat IPv4 dan IPv6 |
| Down Detector | `list-down.txt` | Domain yang tidak responsif |
| XSS Scanner | `list-xss.txt` | Domain yang rentan terhadap XSS |
| Subdomain Takeover | `list-take.txt` | Potensi subdomain takeover |
| HTTP Logger | `list-log.txt` | Log permintaan HTTP |
| SQLi Detector | `list-sqli.txt` | Domain yang rentan terhadap SQLi |
| Domain Recon | `list-recon.txt` | Informasi DNS dan WHOIS |

## Penafian

SUB10 dirancang untuk tujuan pengujian keamanan yang sah. Pengguna bertanggung jawab penuh atas penggunaan alat ini. Pengembang tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh alat ini. 

**Gunakan hanya pada sistem yang Anda miliki izin eksplisit untuk diuji!**

## Kontribusi

Kontribusi dipersilakan! Silakan buka issue atau pull request untuk:
- Melaporkan bug
- Menyarankan fitur baru
- Meningkatkan dokumentasi
- Meningkatkan kode

## Dukungan

Untuk masalah atau pertanyaan, silakan buka issue di repositori GitHub.

---
