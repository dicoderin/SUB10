import os
import re
import socket
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

# Fungsi bantuan
def baca_file(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def simpan_hasil(filename, data, mode='a'):
    with open(filename, mode) as f:
        f.write(data + "\n")

# 1. Reverse Subdomain
def reverse_subdomain(domain):
    print(f"\n[+] Memulai reverse subdomain untuk {domain}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            unik = set()
            for entry in data:
                sub = entry['name_value'].lower()
                # Hilangkan wildcard dan whitespace
                sub = sub.replace("*.", "").strip()
                # Hanya ambil yang berakhiran domain target
                if sub.endswith(domain) and sub not in unik:
                    unik.add(sub)
            
            # Simpan hasil ke file
            with open("list.txt", "w") as f:
                for subdomain in sorted(unik):
                    f.write(subdomain + "\n")
            
            print(f"[+] {len(unik)} subdomain ditemukan dan disimpan di list.txt")
            if len(unik) > 0:
                print(f"    Contoh: {list(unik)[:3]}")
        else:
            print(f"[!] Error: API merespon dengan status {resp.status_code}")
    except Exception as e:
        print(f"[!] Error: {str(e)}")

# 2. Check Header Status
def check_header():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa header untuk {len(domains)} domain")
    # Kosongkan file hasil sebelumnya
    open("list-header.txt", "w").close()
    
    def process(domain):
        try:
            if not domain.startswith(('http://', 'https://')):
                url = f"http://{domain}"
            else:
                url = domain
                
            resp = requests.head(
                url, 
                timeout=10, 
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (SUB10 by Eyren)'}
            )
            server = resp.headers.get('Server', 'Unknown')
            hasil = f"{domain} | Status: {resp.status_code} | Server: {server}"
            simpan_hasil("list-header.txt", hasil)
            return f"✓ {domain}"
        except Exception as e:
            simpan_hasil("list-header.txt", f"{domain} | ERROR: {str(e)}")
            return f"✗ {domain}"

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(process, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-header.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 3. Check Port
def check_port():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa port untuk {len(domains)} domain")
    # Port yang akan di-scan
    ports = [21, 22, 80, 443, 8080, 8443]
    
    def scan_domain(domain):
        try:
            ip = socket.gethostbyname(domain)
            hasil_port = []
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                status = "OPEN" if result == 0 else "CLOSED"
                hasil_port.append(f"{port}({status})")
                sock.close()
            
            hasil = f"{domain} | IP: {ip} | Port: {' '.join(hasil_port)}"
            simpan_hasil("list-port.txt", hasil)
            return f"✓ {domain}"
        except Exception as e:
            simpan_hasil("list-port.txt", f"{domain} | ERROR: {str(e)}")
            return f"✗ {domain}"

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(scan_domain, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-port.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 4. Convert ke IP
def convert_to_ip():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Mengkonversi {len(domains)} domain ke IP")
    
    def resolve(domain):
        try:
            # IPv4
            ipv4 = socket.gethostbyname(domain)
            
            # IPv6 (jika ada)
            ipv6 = "N/A"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                aaaa = resolver.resolve(domain, 'AAAA')
                ipv6 = aaaa[0].address if aaaa else "N/A"
            except:
                pass
            
            hasil = f"{domain} | IPv4: {ipv4} | IPv6: {ipv6}"
            simpan_hasil("list-ip.txt", hasil)
            return f"✓ {domain} → {ipv4}"
        except Exception as e:
            simpan_hasil("list-ip.txt", f"{domain} | ERROR: {str(e)}")
            return f"✗ {domain}"

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(resolve, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-ip.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 5. Check Domain Down
def check_down():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa status down untuk {len(domains)} domain")
    # Kosongkan file hasil sebelumnya
    open("list-down.txt", "w").close()
    
    def check(domain):
        try:
            # Coba akses dengan HTTP
            response = requests.head(
                f"http://{domain}", 
                timeout=5,
                allow_redirects=True
            )
            # Jika status 200-399 dianggap up
            if response.status_code < 400:
                return f"✓ {domain} (UP)"
            else:
                simpan_hasil("list-down.txt", domain)
                return f"✗ {domain} (DOWN {response.status_code})"
        except:
            simpan_hasil("list-down.txt", domain)
            return f"✗ {domain} (ERROR)"

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check, domains))
    
    print(f"[+] Selesai! Domain down disimpan di list-down.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 6. XSS Exploiter
def xss_exploit():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa kerentanan XSS untuk {len(domains)} domain")
    payload = "<script>alert('XSS_by_SUB10')</script>"
    
    def scan(domain):
        try:
            url = f"http://{domain}/search?q={payload}"
            response = requests.get(url, timeout=10)
            if payload in response.text:
                simpan_hasil("list-xss.txt", f"{domain} | VULNERABLE | Payload: {payload}")
                return f"✓ {domain} (VULNERABLE)"
            else:
                return f"✗ {domain} (Not Vulnerable)"
        except Exception as e:
            return f"✗ {domain} (ERROR: {str(e)})"

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(scan, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-xss.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 7. Subdomain Takeover
def subdomain_takeover():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa subdomain takeover untuk {len(domains)} domain")
    
    def check_takeover(domain):
        try:
            response = requests.get(
                f"http://{domain}", 
                timeout=8,
                allow_redirects=False
            )
            content = response.text
            
            # Deteksi layanan populer
            service = None
            if "NoSuchBucket" in content or "Specified bucket does not exist" in content:
                service = "AWS S3"
            elif "github.io" in content and "There isn't a GitHub Pages site here" in content:
                service = "GitHub Pages"
            elif "herokucdn.com" in content and "No such app" in content:
                service = "Heroku"
            elif "error code: 1001" in content:
                service = "Cloudflare"
            elif "The requested URL was not found on this server" in content and "AmazonS3" in response.headers.get('Server', ''):
                service = "AWS S3"
            
            if service:
                hasil = f"{domain} | VULNERABLE | Service: {service}"
                simpan_hasil("list-take.txt", hasil)
                return f"✓ {domain} (VULNERABLE: {service})"
            else:
                return f"✗ {domain} (Not Vulnerable)"
        except Exception as e:
            return f"✗ {domain} (ERROR: {str(e)})"

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(check_takeover, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-take.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 8. HTTP Request Logger
def http_logger():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Logging HTTP request untuk {len(domains)} domain")
    
    def log_request(domain):
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=10,
                headers={'User-Agent': 'SUB10-HTTP-Logger/1.0'}
            )
            
            log_data = (
                f"===== {domain} =====\n"
                f"URL: {response.url}\n"
                f"Status Code: {response.status_code}\n"
                "Headers:\n"
            )
            
            for header, value in response.headers.items():
                log_data += f"  {header}: {value}\n"
            
            log_data += f"\nBody (first 200 chars):\n{response.text[:200]}...\n\n"
            simpan_hasil("list-log.txt", log_data)
            return f"✓ {domain} ({response.status_code})"
        except Exception as e:
            simpan_hasil("list-log.txt", f"[{domain}] ERROR: {str(e)}\n")
            return f"✗ {domain} (ERROR)"

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(log_request, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-log.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 9. SQLi Exploiter
def sqli_exploit():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Memeriksa kerentanan SQLi untuk {len(domains)} domain")
    payload = "' OR '1'='1'-- -"
    
    def test_sqli(domain):
        try:
            # Coba di parameter umum
            test_urls = [
                f"http://{domain}/product?id=1{payload}",
                f"http://{domain}/item?code=123{payload}",
                f"http://{domain}/details.php?id=1{payload}"
            ]
            
            for url in test_urls:
                response = requests.get(url, timeout=8)
                errors = [
                    "syntax error",
                    "unclosed quotation mark",
                    "unexpected end",
                    "SQL syntax",
                    "mysql_fetch",
                    "Warning: mysql"
                ]
                
                if any(error in response.text.lower() for error in errors):
                    hasil = f"{domain} | VULNERABLE | Payload: {payload} | URL: {url}"
                    simpan_hasil("list-sqli.txt", hasil)
                    return f"✓ {domain} (VULNERABLE)"
            
            return f"✗ {domain} (Not Vulnerable)"
        except Exception as e:
            return f"✗ {domain} (ERROR: {str(e)})"

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(test_sqli, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-sqli.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# 10. Domain Recon
def domain_recon():
    domains = baca_file("list.txt")
    if not domains:
        print("[!] File list.txt kosong atau tidak ditemukan")
        return
    
    print(f"\n[+] Melakukan recon untuk {len(domains)} domain")
    
    def recon(domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            info = f"===== {domain} =====\n"
            
            # DNS Records
            records = ['A', 'NS', 'MX', 'TXT', 'CNAME']
            for record in records:
                try:
                    answers = resolver.resolve(domain, record)
                    info += f"{record} Records:\n"
                    for rdata in answers:
                        info += f"  {rdata}\n"
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                except Exception as e:
                    info += f"  ERROR: {str(e)}\n"
            
            # WHOIS lookup sederhana
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(("whois.verisign-grs.com", 43))
                    s.send(f"{domain}\r\n".encode())
                    response = b""
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                whois_data = response.decode()[:500]  # Ambil 500 karakter pertama
                info += f"\nWHOIS Data:\n{whois_data}\n"
            except:
                info += "\nWHOIS Data: Tidak tersedia\n"
            
            simpan_hasil("list-recon.txt", info)
            return f"✓ {domain}"
        except Exception as e:
            simpan_hasil("list-recon.txt", f"[{domain}] ERROR: {str(e)}\n")
            return f"✗ {domain} (ERROR)"

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(recon, domains))
    
    print(f"[+] Selesai! Hasil disimpan di list-recon.txt")
    print("    " + "\n    ".join(results[:5]) + ("\n    ..." if len(results) > 5 else ""))

# Main Menu
def main():
    print("""

 ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░   ░▒▓█▓▒░▒▓████████▓▒░      
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████▓▒░▒▓█▓▒░░▒▓█▓▒░      
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      
░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░   ░▒▓█▓▒░▒▓████████▓▒░      
                                                                    
                                                                    

 SUB10 by Eyren - 10 Tools dalam 1
    """)
    
    while True:
        print("\n" + "="*50)
        print(" MENU UTAMA")
        print("="*50)
        print("1. Reverse Subdomain (Simpan ke list.txt)")
        print("2. Check Header Status (list.txt -> list-header.txt)")
        print("3. Check Port (list.txt -> list-port.txt)")
        print("4. Convert ke IP (list.txt -> list-ip.txt)")
        print("5. Check Domain Down (list.txt -> list-down.txt)")
        print("6. XSS Exploiter (list.txt -> list-xss.txt)")
        print("7. Subdomain Takeover (list.txt -> list-take.txt)")
        print("8. HTTP Request Logger (list.txt -> list-log.txt)")
        print("9. SQLi Exploiter (list.txt -> list-sqli.txt)")
        print("10. Domain Recon (list.txt -> list-recon.txt)")
        print("11. Exit")
        print("="*50)
        
        choice = input("Pilih fitur (1-11): ").strip()
        
        if choice == "1":
            domain = input("Masukkan domain target (contoh: example.com): ").strip()
            if domain:
                reverse_subdomain(domain)
            else:
                print("[!] Domain tidak boleh kosong!")
        
        elif choice == "2":
            check_header()
        
        elif choice == "3":
            check_port()
        
        elif choice == "4":
            convert_to_ip()
        
        elif choice == "5":
            check_down()
        
        elif choice == "6":
            xss_exploit()
        
        elif choice == "7":
            subdomain_takeover()
        
        elif choice == "8":
            http_logger()
        
        elif choice == "9":
            sqli_exploit()
        
        elif choice == "10":
            domain_recon()
        
        elif choice == "11":
            print("\n[+] Terima kasih telah menggunakan SUB10 by Eyren!")
            break
        
        else:
            print("[!] Pilihan tidak valid. Silakan pilih 1-11.")

if __name__ == "__main__":
    main()
