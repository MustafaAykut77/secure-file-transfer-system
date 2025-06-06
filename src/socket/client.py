import socket  # ağ bağlantıları için
import zlib    # CRC32 checksum hesaplama için
import hashlib # SHA256 hash hesaplama için
import sys     # sistem parametrelerine erişim için
import time    # zaman ölçümü ve bekleme için
from pathlib import Path                    # dosya yolu işlemleri için
from Crypto.PublicKey import RSA            # RSA şifreleme için
from Crypto.Cipher import AES, PKCS1_OAEP   # AES ve RSA şifreleme için
from Crypto.Util.Padding import pad         # AES padding için
from Crypto.Random import get_random_bytes  # güvenli rastgele byte üretimi için

# =============================================================================
# VARSAYILAN AYARLAR
# =============================================================================
DEFAULT_CONFIG = {
    'HOST': '127.0.0.1',                    # varsayılan hedef IP adresi (localhost)
    'TCP_PORT': 5001,                       # TCP portu
    'UDP_PORT': 5002,                       # UDP portu
    'PASSWORD': b"gizli_sifre",             # kimlik doğrulama parolası
    'FILENAME': "deneme.txt",               # varsayılan gönderilecek dosya
    'PACKET_SIZE': 1024,                    # paket boyutu (byte)
    'SEND_COUNT': 1,                        # dosyanın kaç kez gönderileceği
    'TIMEOUT': 5.0,                         # bağlantı timeout süresi (saniye)
    'LATENCY_THRESHOLD': 50.0,              # hibrit mod için gecikme eşiği (ms)
    'PUBLIC_KEY_PATH': "../keys/public.pem" # RSA public key dosya yolu
}

# =============================================================================
# GÜVENLİ DOSYA TRANSFER İSTEMCİSİ SINIFI
# =============================================================================
class SecureFileTransferClient:
    def __init__(self, config=None):
        # Konfigürasyon ayarlarını yükle (özel ayar yoksa varsayılanları kullan)
        self.config = config or DEFAULT_CONFIG.copy()
        self.rsa_public_key = None  # RSA public key objesi
    
    # RSA public key'i dosyadan yükleyen fonksiyon
    def load_rsa_public_key(self):
        try:
            # Key dosyasının yolunu al
            key_path = Path(self.config['PUBLIC_KEY_PATH'])
            
            # Dosya varlığını kontrol et
            if not key_path.exists():
                raise FileNotFoundError(f"Public key dosyası bulunamadı: {key_path}")
                
            # RSA key'i dosyadan yükle
            with open(key_path, "rb") as f:
                self.rsa_public_key = RSA.import_key(f.read())
            
            print(f"[+] RSA public key yüklendi: {key_path}")
            
        except Exception as e:
            raise Exception(f"RSA key yükleme hatası: {e}")
    
    # Dosya verisini şifreleyen fonksiyon
    def encrypt_file_data(self, file_data, filename):
        # Güvenli rastgele anahtar ve IV oluştur
        aes_key = get_random_bytes(32)  # 256-bit AES anahtarı
        iv = get_random_bytes(16)       # 128-bit başlangıç vektörü
        
        # Dosya hash'i hesapla (bütünlük kontrolü için)
        file_hash = hashlib.sha256(file_data).digest()
        
        # Dosya adını bytes formatına çevir
        filename_bytes = filename.encode('utf-8')
        filename_length = len(filename_bytes).to_bytes(2, 'big')  # big-endian format
        
        # Veri paketini oluştur: hash + dosya_adı_uzunluğu + dosya_adı + dosya_verisi
        data_package = file_hash + filename_length + filename_bytes + file_data
        
        # AES ile veriyi şifrele (CBC modu)
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        encrypted_data = aes_cipher.encrypt(pad(data_package, AES.block_size))
        
        # AES anahtarını RSA ile şifrele (OAEP padding ile)
        rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        
        return encrypted_data, encrypted_aes_key, iv
    
    # Ağ gecikmesini ölçen fonksiyon
    def measure_network_latency(self):
        try:
            # Zaman ölçümü başlat
            start_time = time.perf_counter()
            
            # UDP ping paketi gönder
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)  # 2 saniye timeout
                sock.sendto(b"PING", (self.config['HOST'], self.config['UDP_PORT']))
                
                try:
                    sock.recv(64)  # sunucudan pong yanıtını bekle
                except socket.timeout:
                    print("[!] Ping yanıtı alınamadı, varsayılan gecikme kullanılıyor")
                    return 100.0  # timeout durumunda yüksek gecikme döndür
            
            # Zaman ölçümü bitir
            end_time = time.perf_counter()
            latency = (end_time - start_time) * 1000  # milisaniyeye çevir
            
            return latency
            
        except Exception as e:
            print(f"[!] Gecikme ölçüm hatası: {e}")
            return 100.0  # hata durumunda varsayılan yüksek gecikme
    
    # TCP bağlantısı için kimlik doğrulama işlemi
    def authenticate_tcp_connection(self, sock):
        try:
            # Parolanın SHA256 hash'ini hesapla
            password_hash = hashlib.sha256(self.config['PASSWORD']).digest()
            
            # Hash'i sunucuya gönder
            sock.sendall(password_hash)
            
            # Sunucudan yanıt bekle
            response = sock.recv(2)
            
            if response == b"OK":
                print("[+] Kimlik doğrulama başarılı")
                return True
            else:
                print(f"[!] Kimlik doğrulama başarısız: {response}")
                return False
                
        except Exception as e:
            print(f"[!] Kimlik doğrulama hatası: {e}")
            return False
    
    # TCP protokolü ile güvenli dosya gönderimi
    def send_file_tcp(self, host, port, packet_size, send_count, filename):
        print(f"[MODE] TCP - Dosya: {filename}")
        
        # Dosya varlığını kontrol et
        if not Path(filename).exists():
            print(f"[!] Dosya bulunamadı: {filename}")
            return False
        
        client_socket = None
        try:
            # TCP socket oluştur ve bağlan
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(self.config['TIMEOUT'])  # timeout ayarla
            client_socket.connect((host, port))
            print(f"[+] {host}:{port} adresine bağlandı")
            
            # Kimlik doğrulama işlemi
            if not self.authenticate_tcp_connection(client_socket):
                return False
            
            # Dosyayı binary modda oku
            with open(filename, "rb") as f:
                file_data = f.read()
            
            print(f"[+] Dosya okundu: {len(file_data)} bytes")
            
            # Dosyayı şifrele
            encrypted_data, encrypted_aes_key, iv = self.encrypt_file_data(
                file_data, Path(filename).name
            )
            
            # Şifrelenmiş AES anahtarını ve IV'yi gönder
            client_socket.sendall(encrypted_aes_key)  # RSA ile şifrelenmiş AES key
            client_socket.sendall(iv)                 # AES başlangıç vektörü
            
            print(f"[+] Şifreleme anahtarları gönderildi")
            
            # Toplam paket sayısını hesapla
            total_packets = len(encrypted_data) // packet_size + (1 if len(encrypted_data) % packet_size else 0)
            
            # Belirtilen sayıda gönderim turu yap
            for send_round in range(send_count):
                print(f"[*] Gönderim turu: {send_round + 1}/{send_count}")
                
                # Şifrelenmiş veriyi paketler halinde gönder
                for i in range(0, len(encrypted_data), packet_size):
                    packet_data = encrypted_data[i:i + packet_size]  # mevcut paket verisi
                    packet_number = i // packet_size + 1             # paket numarası
                    
                    # CRC32 checksum hesapla (veri bütünlüğü için)
                    crc = zlib.crc32(packet_data) & 0xffffffff
                    
                    # Paket başlığı oluştur: boyut (4 byte) + CRC (4 byte)
                    header = len(packet_data).to_bytes(4, 'big') + crc.to_bytes(4, 'big')
                    
                    # Paket gönderimi ve yeniden deneme mantığı
                    max_retries = 3      # maksimum deneme sayısı
                    retry_count = 0      # mevcut deneme sayacı
                    
                    # Paket başarılı gönderilene kadar dene
                    while retry_count < max_retries:
                        try:
                            # Paket başlığı + veriyi gönder
                            client_socket.sendall(header + packet_data)
                            
                            # Sunucudan yanıt bekle
                            response = client_socket.recv(5)
                            
                            if response == b"RETRY":
                                # Paket bozulmuş, yeniden gönder
                                retry_count += 1
                                print(f"[!] Paket {packet_number} yeniden gönderiliyor ({retry_count}/{max_retries})")
                                time.sleep(0.1)  # kısa bekleme
                                continue
                            elif response == b"OK":
                                # Paket başarıyla alındı
                                break
                            else:
                                print(f"[!] Beklenmeyen yanıt: {response}")
                                break
                                
                        except socket.timeout:
                            retry_count += 1
                            print(f"[!] Timeout - Paket {packet_number} yeniden gönderiliyor")
                            continue
                    
                    # Maksimum deneme sayısı aşıldıysa hata ver
                    if retry_count >= max_retries:
                        print(f"[!] Paket {packet_number} gönderilemedi, maksimum deneme sayısı aşıldı")
                        return False
                    
                    # İlerleme göstergesi (her 10 pakette bir veya son pakette)
                    if packet_number % 10 == 0 or packet_number == total_packets:
                        print(f"[*] İlerleme: {packet_number}/{total_packets} paket gönderildi")
            
            print(f"[+] TCP ile {filename} dosyası başarıyla gönderildi")
            return True
            
        except Exception as e:
            print(f"[!] TCP gönderim hatası: {e}")
            return False
            
        finally:
            # Socket'i kapat
            if client_socket:
                client_socket.close()
    
    # UDP protokolü ile güvenli dosya gönderimi
    def send_file_udp(self, host, port, packet_size, send_count, filename):
        print(f"[MODE] UDP - Dosya: {filename}")
        
        # Dosya varlığını kontrol et
        if not Path(filename).exists():
            print(f"[!] Dosya bulunamadı: {filename}")
            return False
        
        client_socket = None
        try:
            # UDP socket oluştur
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Dosyayı binary modda oku
            with open(filename, "rb") as f:
                file_data = f.read()
            
            print(f"[+] Dosya okundu: {len(file_data)} bytes")
            
            # Dosyayı şifrele
            encrypted_data, encrypted_aes_key, iv = self.encrypt_file_data(
                file_data, Path(filename).name
            )
            
            # Kurulum paketini oluştur (şifrelenmiş AES key + IV)
            setup_packet = encrypted_aes_key + iv
            client_socket.sendto(setup_packet, (host, port))
            time.sleep(0.1)  # sunucunun kurulum paketini işlemesi için bekle
            
            print(f"[+] Kurulum paketi gönderildi")
            
            # Toplam paket sayısını hesapla
            total_packets = len(encrypted_data) // packet_size + (1 if len(encrypted_data) % packet_size else 0)
            
            # Belirtilen sayıda gönderim turu yap
            for send_round in range(send_count):
                print(f"[*] Gönderim turu: {send_round + 1}/{send_count}")
                
                # Şifrelenmiş veriyi paketler halinde gönder
                for i in range(0, len(encrypted_data), packet_size):
                    packet_data = encrypted_data[i:i + packet_size]  # mevcut paket verisi
                    packet_number = i // packet_size + 1             # paket numarası
                    
                    # CRC32 checksum hesapla (veri bütünlüğü için)
                    crc = zlib.crc32(packet_data) & 0xffffffff
                    
                    # Paket başlığı oluştur: boyut (4 byte) + CRC (4 byte)
                    header = len(packet_data).to_bytes(4, 'big') + crc.to_bytes(4, 'big')
                    
                    # Paket gönder (UDP connectionless)
                    client_socket.sendto(header + packet_data, (host, port))
                    
                    # UDP için küçük bekleme (ağ yoğunluğunu önlemek için)
                    time.sleep(0.001)  # 1 milisaniye
                    
                    # İlerleme göstergesi (her 10 pakette bir veya son pakette)
                    if packet_number % 10 == 0 or packet_number == total_packets:
                        print(f"[*] İlerleme: {packet_number}/{total_packets} paket gönderildi")
            
            # Bitirme sinyali gönder (dosya gönderiminin tamamlandığını belirt)
            time.sleep(0.1)
            client_socket.sendto(b'FIN', (host, port))
            
            print(f"[+] UDP ile {filename} dosyası başarıyla gönderildi")
            return True
            
        except Exception as e:
            print(f"[!] UDP gönderim hatası: {e}")
            return False
            
        finally:
            # Socket'i kapat
            if client_socket:
                client_socket.close()
    
    # Hibrit mod - ağ koşullarına göre TCP veya UDP kullanarak dosya gönderir
    def send_file_hybrid(self, host, tcp_port, udp_port, packet_size, send_count, filename):
        print("[MODE] HYBRID - Ağ koşulları analiz ediliyor...")
        
        # Ağ gecikmesini ölç
        latency = self.measure_network_latency()
        print(f"[*] Ölçülen gecikme: {latency:.2f} ms")
        
        # Gecikme eşiğine göre protokol seç
        if latency < self.config['LATENCY_THRESHOLD']:
            # Düşük gecikme - UDP daha verimli
            print(f"[*] Düşük gecikme ({latency:.2f} ms < {self.config['LATENCY_THRESHOLD']} ms) - UDP kullanılıyor")
            return self.send_file_udp(host, udp_port, packet_size, send_count, filename)
        else:
            # Yüksek gecikme - TCP daha güvenilir
            print(f"[*] Yüksek gecikme ({latency:.2f} ms >= {self.config['LATENCY_THRESHOLD']} ms) - TCP kullanılıyor")
            return self.send_file_tcp(host, tcp_port, packet_size, send_count, filename)
    
    # Ana çalışma fonksiyonu - mod, host, port, paket boyutu, gönderim sayısı ve dosya adını alır
    def run(self, mode, host, port, packet_size, send_count, filename):
        print(f"[*] Güvenli Dosya Transfer İstemcisi Başlatılıyor...")
        print(f"[*] Mod: {mode}, Hedef: {host}:{port}")
        print(f"[*] Paket boyutu: {packet_size}, Gönderim sayısı: {send_count}")
        
        try:
            # RSA public key'i yükle (şifreleme için gerekli)
            self.load_rsa_public_key()
            
            # Seçilen moda göre ilgili metodu çağır
            if mode == "TCP":
                return self.send_file_tcp(host, port, packet_size, send_count, filename)
            elif mode == "UDP":
                return self.send_file_udp(host, port, packet_size, send_count, filename)
            elif mode == "HYBRID":
                # Hibrit mod için hem TCP hem UDP portları gerekli
                tcp_port = self.config['TCP_PORT']
                udp_port = self.config['UDP_PORT']
                return self.send_file_hybrid(host, tcp_port, udp_port, packet_size, send_count, filename)
            else:
                print(f"[!] Geçersiz mod: {mode}")
                print("[*] Geçerli modlar: TCP, UDP, HYBRID")
                return False
                
        except Exception as e:
            print(f"[!] Kritik hata: {e}")
            return False

# =============================================================================
# KULLANIM KILAVUZU FONKSİYONU
# =============================================================================
def print_usage():
    print("\n=== Güvenli Dosya Transfer İstemcisi ===")
    print("Kullanım:")
    print("  python client.py [mod] [host] [port] [paket_boyutu] [gönderim_sayısı] [dosya_adı]")
    print("\nParametreler:")
    print("  mod             : TCP, UDP veya HYBRID")
    print("  host            : Hedef IP adresi")
    print("  port            : Hedef port numarası")
    print("  paket_boyutu    : Paket boyutu (bytes)")
    print("  gönderim_sayısı : Dosyanın kaç kez gönderileceği")
    print("  dosya_adı       : Gönderilecek dosyanın adı")
    print("\nÖrnekler:")
    print("  python client.py TCP 192.168.1.100 5001 1024 1 test.txt")
    print("  python client.py UDP 127.0.0.1 5002 512 3 document.pdf")
    print("  python client.py HYBRID 10.0.0.1 5001 2048 1 video.mp4")
    print("\nVarsayılan değerler kullanmak için parametresiz çalıştırın:")
    print("  python client.py")

# =============================================================================
# ANA PROGRAM
# =============================================================================
def main():
    # Komut satırı argümanlarının sayısını kontrol et
    if len(sys.argv) == 1:
        # Parametre verilmemiş - varsayılan değerlerle çalıştır
        mode = "TCP"
        host = DEFAULT_CONFIG['HOST']
        port = DEFAULT_CONFIG['TCP_PORT']
        packet_size = DEFAULT_CONFIG['PACKET_SIZE']
        send_count = DEFAULT_CONFIG['SEND_COUNT']
        filename = DEFAULT_CONFIG['FILENAME']
        
        print("[*] Varsayılan ayarlarla çalıştırılıyor...")
        
    elif len(sys.argv) == 7:
        # Tüm parametreler verilmiş - parse et ve doğrula
        try:
            mode = sys.argv[1].upper()          # mod adını büyük harfe çevir
            host = sys.argv[2]                  # hedef IP adresi
            port = int(sys.argv[3])             # port numarasını integer'a çevir
            packet_size = int(sys.argv[4])      # paket boyutunu integer'a çevir
            send_count = int(sys.argv[5])       # gönderim sayısını integer'a çevir
            filename = sys.argv[6]              # dosya adı
            
            # Parametrelerin geçerliliğini kontrol et
            if mode not in ["TCP", "UDP", "HYBRID"]:
                raise ValueError(f"Geçersiz mod: {mode}")
            if port < 1 or port > 65535:
                raise ValueError(f"Geçersiz port: {port}")
            if packet_size < 64 or packet_size > 65507:
                raise ValueError(f"Geçersiz paket boyutu: {packet_size}")
            if send_count < 1:
                raise ValueError(f"Geçersiz gönderim sayısı: {send_count}")
                
        except (ValueError, IndexError) as e:
            print(f"[!] Parametre hatası: {e}")
            print_usage()
            sys.exit(1)  # hata kodu ile çık
    else:
        # Yanlış parametre sayısı
        print("[!] Hatalı parametre sayısı")
        print_usage()
        sys.exit(1)
    
    # İstemci nesnesini oluştur ve çalıştır
    client = SecureFileTransferClient()
    success = client.run(mode, host, port, packet_size, send_count, filename)
    
    # Sonuca göre çıkış kodu belirle
    if success:
        print(f"\n[+] Transfer başarıyla tamamlandı!")
        sys.exit(0)  # başarı kodu
    else:
        print(f"\n[!] Transfer başarısız!")
        sys.exit(1)  # hata kodu

# =============================================================================
# PROGRAMIN BAŞLANGIÇ NOKTASI
# =============================================================================
if __name__ == "__main__":
    main()