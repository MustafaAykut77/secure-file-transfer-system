import socket         # ağ bağlantıları için
import zlib           # veri sıkıştırma ve CRC hesaplama için
import hashlib        # hash fonksiyonları için
import threading      # çoklu thread desteği için
import time           # zaman işlemleri için
import signal         # sinyal yakalama için
import sys            # sistem işlemleri için
from pathlib import Path                   # dosya yolu işlemleri için
from datetime import datetime              # tarih ve saat işlemleri için
from Crypto.PublicKey import RSA           # RSA anahtar işlemleri için
from Crypto.Cipher import AES, PKCS1_OAEP  # AES ve RSA şifreleme için
from Crypto.Util.Padding import unpad      # padding kaldırma için

# =============================================================================
# VARSAYILAN AYARLAR
# =============================================================================
DEFAULT_CONFIG = {
    'HOST': '0.0.0.0',                    # tüm ağ arayüzlerini dinle
    'TCP_PORT': 5001,                     # TCP portu
    'UDP_PORT': 5002,                     # UDP portu
    'PASSWORD': b"gizli_sifre",           # kimlik doğrulama parolası (üretim ortamında güçlü parola kullanın)
    'PRIVATE_KEY_PATH': "../keys/private.pem",  # RSA private key dosya yolu
    'RECEIVED_FILES_DIR': "./received_files",   # alınan dosyaların kaydedileceği dizin
    'SESSION_TIMEOUT': 30.0,              # UDP oturum timeout (saniye)
    'MAX_PACKET_SIZE': 2048,              # maksimum paket boyutu
    'MAX_CONNECTIONS': 10,                # maksimum eşzamanlı bağlantı sayısı
    'CLEANUP_INTERVAL': 5.0,              # temizleme döngüsü (saniye)
    'LOG_LEVEL': 'INFO'                   # log seviyesi (DEBUG, INFO, WARNING, ERROR)
}

# =============================================================================
# GÜVENLİ DOSYA TRANSFER SUNUCUSU
# =============================================================================
class SecureFileTransferServer:
    def __init__(self, config=None):
        # Konfigürasyon ayarlarını yükle
        self.config = config or DEFAULT_CONFIG.copy()
        
        # RSA private key'i saklamak için
        self.rsa_private_key = None
        
        # UDP oturum yönetimi için sözlük
        self.udp_sessions = {}
        
        # TCP bağlantı yönetimi için sözlük
        self.tcp_connections = {}
        
        # Sunucu çalışma durumu
        self.running = True
        
        # İstatistik verileri
        self.stats = {
            'tcp_connections': 0,     # toplam TCP bağlantı sayısı
            'udp_sessions': 0,        # toplam UDP oturum sayısı
            'files_received': 0,      # alınan dosya sayısı
            'bytes_received': 0,      # alınan toplam byte sayısı
            'errors': 0               # hata sayısı
        }
        
        # Temizleme thread'i için thread lock
        self.sessions_lock = threading.Lock()
        
        # Alınan dosyalar için dizin oluştur
        self.setup_directories()
        
        # Sinyal işleyicilerini ayarla (sadece ana thread'de)
        if threading.current_thread() == threading.main_thread():
            self.setup_signal_handlers()
    
    # Gerekli dizinleri oluşturur
    def setup_directories(self):
        try:
            # Alınan dosyalar dizinini oluştur
            received_dir = Path(self.config['RECEIVED_FILES_DIR'])
            received_dir.mkdir(parents=True, exist_ok=True)  # üst dizinleri de oluştur
            self.log(f"Alınan dosyalar dizini: {received_dir.absolute()}", 'INFO')
        except Exception as e:
            self.log(f"Dizin oluşturma hatası: {e}", 'ERROR')
            sys.exit(1)  # kritik hata, programı sonlandır
    
    # Sinyal yakalama ve işleme fonksiyonlarını ayarlar
    def setup_signal_handlers(self):
        def signal_handler(signum, frame):
            """Sinyal yakalandığında çalışacak fonksiyon"""
            self.log(f"Sinyal alındı: {signum}. Sunucu kapatılıyor...", 'INFO')
            self.shutdown()
            sys.exit(0)
        
        # SIGINT (Ctrl+C) sinyalini yakala
        signal.signal(signal.SIGINT, signal_handler)
        # SIGTERM sinyalini yakala
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Log mesajlarını formatlar ve yazdırır
    def log(self, message, level='INFO'):
        # Zaman damgası oluştur
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Formatlanmış log mesajını yazdır
        print(f"[{timestamp}] [{level}] {message}")
    
    # RSA private key'i dosyadan yükler
    def load_rsa_private_key(self):
        try:
            # Key dosyasının yolunu al
            key_path = Path(self.config['PRIVATE_KEY_PATH'])
            
            # Dosyanın var olup olmadığını kontrol et
            if not key_path.exists():
                raise FileNotFoundError(f"Private key dosyası bulunamadı: {key_path}")
            
            # Dosyayı oku ve RSA anahtarını yükle
            with open(key_path, "rb") as f:
                self.rsa_private_key = RSA.import_key(f.read())
            
            self.log(f"RSA private key yüklendi: {key_path}", 'INFO')
            
        except Exception as e:
            self.log(f"RSA key yükleme hatası: {e}", 'ERROR')
            raise  # hatayı yukarı aktar
    
    # Şifrelenmiş veriyi çözer ve dosyaya kaydeder
    def decrypt_and_save_file(self, encrypted_data, client_info="unknown"):
        # Boş veri kontrolü
        if not encrypted_data:
            self.log(f"[{client_info}] Çözülecek veri alınmadı", 'WARNING')
            return False
        
        try:
            # AES padding'ini kaldır
            plaintext = unpad(encrypted_data, AES.block_size)
            
            # Veri formatını parse et: hash(32) + filename_length(2) + filename + file_content
            if len(plaintext) < 34:  # minimum boyut kontrolü (32+2)
                raise ValueError("Veri formatı geçersiz - çok kısa")
            
            # İlk 32 byte SHA-256 hash
            received_hash = plaintext[:32]
            
            # Sonraki 2 byte dosya adı uzunluğu
            filename_length = int.from_bytes(plaintext[32:34], 'big')
            
            # Dosya adı uzunluğu güvenlik kontrolü
            if filename_length > 255 or filename_length == 0:
                raise ValueError(f"Geçersiz dosya adı uzunluğu: {filename_length}")
            
            # Toplam veri uzunluğu kontrolü
            if len(plaintext) < 34 + filename_length:
                raise ValueError("Veri formatı geçersiz - dosya adı eksik")
            
            # Dosya adını çıkar
            filename = plaintext[34:34+filename_length].decode('utf-8')
            
            # Dosya içeriğini çıkar
            file_content = plaintext[34+filename_length:]
            
            # Dosya adı güvenlik kontrolü
            if not self.is_safe_filename(filename):
                raise ValueError(f"Güvenli olmayan dosya adı: {filename}")
            
            # SHA-256 hash doğrulaması
            calculated_hash = hashlib.sha256(file_content).digest()
            if calculated_hash != received_hash:
                raise ValueError("SHA-256 hash doğrulaması başarısız")
            
            # Dosyayı kaydet
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')  # zaman damgası
            safe_filename = f"{timestamp}_{filename}"             # güvenli dosya adı
            save_path = Path(self.config['RECEIVED_FILES_DIR']) / safe_filename
            
            # Dosyayı diske yaz
            with open(save_path, "wb") as f:
                f.write(file_content)
            
            # İstatistikleri güncelle
            self.stats['files_received'] += 1
            self.stats['bytes_received'] += len(file_content)
            
            self.log(f"[{client_info}] Dosya başarıyla kaydedildi: {save_path} ({len(file_content)} bytes)", 'INFO')
            return True
            
        except Exception as e:
            self.log(f"[{client_info}] Veri çözme hatası: {e}", 'ERROR')
            self.stats['errors'] += 1
            return False
    
    # Güvenli dosya adlarını kontrol eder
    def is_safe_filename(self, filename):
        # Boş veya çok uzun dosya adı kontrolü
        if not filename or len(filename) > 255:
            return False
        
        # Tehlikeli karakterleri kontrol et
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        for char in dangerous_chars:
            if char in filename:
                return False
        
        # Windows sistem dosya adlarını kontrol et
        system_names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
        if filename.upper() in system_names:
            return False
        
        return True
    
    # TCP istemcisini kimlik doğrulama işlemi
    def authenticate_tcp_client(self, client_socket, client_addr):
        try:
            # İstemciden parola hash'ini al (32 byte SHA-256)
            received_hash = client_socket.recv(32)
            if len(received_hash) != 32:
                self.log(f"[TCP-{client_addr}] Geçersiz hash boyutu", 'WARNING')
                return False
            
            # Beklenen parola hash'ini hesapla
            expected_hash = hashlib.sha256(self.config['PASSWORD']).digest()
            
            # Hash'leri karşılaştır
            if received_hash != expected_hash:
                self.log(f"[TCP-{client_addr}] Kimlik doğrulama başarısız", 'WARNING')
                client_socket.sendall(b"NO")  # başarısız yanıtı gönder
                return False
            
            # Başarılı yanıt gönder
            client_socket.sendall(b"OK")
            self.log(f"[TCP-{client_addr}] Kimlik doğrulama başarılı", 'INFO')
            return True
            
        except Exception as e:
            self.log(f"[TCP-{client_addr}] Kimlik doğrulama hatası: {e}", 'ERROR')
            return False
    
    # TCP istemci bağlantısını işler
    def handle_tcp_client(self, client_socket, client_addr):
        client_info = f"TCP-{client_addr}"
        decrypted_data = b""  # çözülmüş veriyi biriktirmek için
        
        try:
            # Önce kimlik doğrulaması yap
            if not self.authenticate_tcp_client(client_socket, client_addr):
                return
            
            # RSA ile şifrelenmiş AES anahtarını al (256 byte)
            encrypted_aes_key = client_socket.recv(256)
            if len(encrypted_aes_key) != 256:
                raise ValueError("Geçersiz AES anahtar boyutu")
            
            # AES IV'sini al (16 byte)
            iv = client_socket.recv(16)
            if len(iv) != 16:
                raise ValueError("Geçersiz IV boyutu")
            
            # RSA ile AES anahtarını çöz
            rsa_cipher = PKCS1_OAEP.new(self.rsa_private_key)
            aes_key = rsa_cipher.decrypt(encrypted_aes_key)
            
            # AES cipher'ı başlat (CBC modu)
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            
            self.log(f"[{client_info}] Şifreleme anahtarları alındı", 'INFO')
            
            # Veri paketlerini sürekli al
            packet_count = 0
            while self.running:
                try:
                    # Paket boyutunu al (4 byte big-endian)
                    size_data = client_socket.recv(4)
                    if not size_data or len(size_data) != 4:
                        break  # bağlantı kapandı
                    
                    packet_size = int.from_bytes(size_data, 'big')
                    
                    # Paket boyutu güvenlik kontrolü
                    if packet_size > self.config['MAX_PACKET_SIZE'] or packet_size <= 0:
                        self.log(f"[{client_info}] Geçersiz paket boyutu: {packet_size}", 'WARNING')
                        client_socket.sendall(b"RETRY")  # tekrar gönder talebi
                        continue
                    
                    # CRC değerini al (4 byte)
                    crc_data = client_socket.recv(4)
                    if len(crc_data) != 4:
                        break
                    
                    expected_crc = int.from_bytes(crc_data, 'big')
                    
                    # Paketi tamamen al
                    packet = b""
                    while len(packet) < packet_size:
                        chunk = client_socket.recv(packet_size - len(packet))
                        if not chunk:
                            break
                        packet += chunk
                    
                    # Paket tam alınmadıysa
                    if len(packet) != packet_size:
                        self.log(f"[{client_info}] Eksik paket alındı", 'WARNING')
                        client_socket.sendall(b"RETRY")
                        continue
                    
                    # CRC kontrolü yap
                    calculated_crc = zlib.crc32(packet) & 0xffffffff
                    if calculated_crc != expected_crc:
                        self.log(f"[{client_info}] CRC hatası (beklenen: {expected_crc}, " +
                                  "hesaplanan: {calculated_crc})", 'WARNING')
                        client_socket.sendall(b"RETRY")
                        continue
                    
                    # Paketi AES ile çöz ve biriktir
                    decrypted_packet = aes_cipher.decrypt(packet)
                    decrypted_data += decrypted_packet
                    
                    packet_count += 1
                    client_socket.sendall(b"OK")  # başarılı yanıt gönder
                    
                    # Her 10 pakette bir ilerleme logu
                    if packet_count % 10 == 0:
                        self.log(f"[{client_info}] {packet_count} paket alındı", 'DEBUG')
                    
                except socket.timeout:
                    self.log(f"[{client_info}] Paket alma timeout", 'WARNING')
                    break
                except Exception as e:
                    self.log(f"[{client_info}] Paket işleme hatası: {e}", 'ERROR')
                    break
            
            self.log(f"[{client_info}] Toplam {packet_count} paket alındı", 'INFO')
            
        except Exception as e:
            self.log(f"[{client_info}] İstemci işleme hatası: {e}", 'ERROR')
            self.stats['errors'] += 1
            
        finally:
            # Socket'i kapat
            try:
                client_socket.close()
            except:
                pass
            
            # Bağlantı listesinden çıkar
            with self.sessions_lock:
                if client_addr in self.tcp_connections:
                    del self.tcp_connections[client_addr]
            
            # Toplanan veriyi çöz ve kaydet
            if decrypted_data:
                self.decrypt_and_save_file(decrypted_data, client_info)
    
    # UDP paketlerini işler
    def handle_udp_packet(self, data, client_addr, udp_socket):
        client_info = f"UDP-{client_addr}"
        
        try:
            # PING paketini yanıtla (bağlantı testi için)
            if data == b"PING":
                udp_socket.sendto(b"PONG", client_addr)
                return
            
            with self.sessions_lock:
                # Yeni oturum kurulumu
                if client_addr not in self.udp_sessions:
                    # Minimum paket boyutu kontrolü (256 RSA + 16 IV)
                    if len(data) < 272:
                        self.log(f"[{client_info}] Geçersiz kurulum paketi boyutu", 'WARNING')
                        return
                    
                    self.log(f"[{client_info}] Yeni UDP oturumu başlatılıyor", 'INFO')
                    
                    # RSA ile şifrelenmiş AES anahtarını ve IV'yi ayır
                    encrypted_aes_key = data[:256]  # ilk 256 byte
                    iv = data[256:272]              # sonraki 16 byte
                    
                    # RSA ile AES anahtarını çöz
                    rsa_cipher = PKCS1_OAEP.new(self.rsa_private_key)
                    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
                    
                    # Yeni oturum oluştur
                    self.udp_sessions[client_addr] = {
                        "cipher": AES.new(aes_key, AES.MODE_CBC, iv),  # AES cipher objesi
                        "data": b"",                                   # biriktirilen veri
                        "last_seen": time.time(),                      # son görülme zamanı
                        "packet_count": 0                              # alınan paket sayısı
                    }
                    
                    self.stats['udp_sessions'] += 1
                    return
                
                # Mevcut oturum işlemi
                session = self.udp_sessions[client_addr]
                session["last_seen"] = time.time()  # son görülme zamanını güncelle
                
                # Oturum bitirme paketi
                if data == b'FIN':
                    self.log(f"[{client_info}] UDP oturumu tamamlandı ({session['packet_count']} paket)", 'INFO')
                    # Biriktirilen veriyi çöz ve kaydet
                    self.decrypt_and_save_file(session["data"], client_info)
                    del self.udp_sessions[client_addr]  # oturumu sil
                    return
                
                # Veri paketi işlemi
                if len(data) < 8:  # minimum header boyutu (4+4)
                    self.log(f"[{client_info}] Geçersiz paket boyutu", 'WARNING')
                    return
                
                # Paket başlığını parse et
                packet_size = int.from_bytes(data[0:4], 'big')    # paket boyutu
                expected_crc = int.from_bytes(data[4:8], 'big')   # beklenen CRC
                
                # Paket boyutu güvenlik kontrolü
                if packet_size > self.config['MAX_PACKET_SIZE'] or packet_size <= 0:
                    self.log(f"[{client_info}] Geçersiz paket boyutu: {packet_size}", 'WARNING')
                    return
                
                # Paket verisi tam mı?
                if len(data) < 8 + packet_size:
                    self.log(f"[{client_info}] Eksik paket verisi", 'WARNING')
                    return
                
                # Paket verisini çıkar
                packet = data[8:8+packet_size]
                
                # CRC kontrolü yap
                calculated_crc = zlib.crc32(packet) & 0xffffffff
                if calculated_crc != expected_crc:
                    self.log(f"[{client_info}] CRC hatası, paket atlandı", 'WARNING')
                    return
                
                # Paketi AES ile çöz ve biriktir
                decrypted_packet = session["cipher"].decrypt(packet)
                session["data"] += decrypted_packet
                session["packet_count"] += 1
                
                # Her 10 pakette bir ilerleme logu
                if session["packet_count"] % 10 == 0:
                    self.log(f"[{client_info}] {session['packet_count']} paket alındı", 'DEBUG')
                
        except Exception as e:
            self.log(f"[{client_info}] UDP paket işleme hatası: {e}", 'ERROR')
            self.stats['errors'] += 1
    
    # Süresi dolmuş UDP oturumlarını temizler
    def cleanup_expired_sessions(self):
        while self.running:
            try:
                # Temizleme aralığı kadar bekle
                time.sleep(self.config['CLEANUP_INTERVAL'])
                
                current_time = time.time()
                expired_sessions = []  # süresi dolmuş oturumlar
                
                # Süresi dolmuş oturumları tespit et
                with self.sessions_lock:
                    for addr, session in self.udp_sessions.items():
                        # Son görülme zamanından bu yana geçen süre
                        if current_time - session["last_seen"] > self.config['SESSION_TIMEOUT']:
                            expired_sessions.append(addr)
                
                # Süresi dolmuş oturumları işle
                for addr in expired_sessions:
                    with self.sessions_lock:
                        if addr in self.udp_sessions:
                            session = self.udp_sessions[addr]
                            self.log(f"[UDP-{addr}] Oturum zaman aşımına uğradı ({session['packet_count']} paket)", 'WARNING')
                            
                            # Kısmi veri varsa kaydetmeyi dene
                            if session["data"]:
                                self.decrypt_and_save_file(session["data"], f"UDP-{addr}")
                            
                            del self.udp_sessions[addr]  # oturumu sil
                
                # Temizleme istatistiği
                if expired_sessions:
                    self.log(f"Temizlenen oturum sayısı: {len(expired_sessions)}", 'INFO')
                
            except Exception as e:
                self.log(f"Oturum temizleme hatası: {e}", 'ERROR')
    
    # TCP sunucusunu başlatır ve bağlantıları kabul eder
    def tcp_server(self):
        try:
            self.log(f"TCP sunucusu başlatılıyor: {self.config['HOST']}:{self.config['TCP_PORT']}", 'INFO')
            
            # TCP socket oluştur
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # adres yeniden kullanımı
            tcp_socket.bind((self.config['HOST'], self.config['TCP_PORT']))   # adres ve porta bağla
            tcp_socket.listen(self.config['MAX_CONNECTIONS'])                 # dinlemeye başla
            tcp_socket.settimeout(1.0)                                        # timeout ayarla
            
            # Ana bağlantı kabul döngüsü
            while self.running:
                try:
                    # Yeni bağlantı kabul et
                    client_socket, client_addr = tcp_socket.accept()
                    
                    # Bağlantı limiti kontrolü
                    with self.sessions_lock:
                        if len(self.tcp_connections) >= self.config['MAX_CONNECTIONS']:
                            self.log(f"TCP bağlantı limiti aşıldı, bağlantı reddedildi: {client_addr}", 'WARNING')
                            client_socket.close()
                            continue
                        
                        # Yeni bağlantıyı kaydet
                        self.tcp_connections[client_addr] = {
                            'socket': client_socket,
                            'start_time': time.time()
                        }
                    
                    self.log(f"Yeni TCP bağlantısı: {client_addr}", 'INFO')
                    self.stats['tcp_connections'] += 1
                    
                    # İstemciyi ayrı thread'de işle
                    client_thread = threading.Thread(
                        target=self.handle_tcp_client,
                        args=(client_socket, client_addr),
                        daemon=True  # ana program kapandığında thread'i de kapat
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue  # timeout olursa devam et
                except Exception as e:
                    if self.running:
                        self.log(f"TCP sunucu hatası: {e}", 'ERROR')
                        
        except Exception as e:
            self.log(f"TCP sunucu başlatma hatası: {e}", 'ERROR')
        finally:
            # Socket'i kapat
            try:
                tcp_socket.close()
            except:
                pass
    
    # UDP sunucusunu başlatır ve paketleri alır
    def udp_server(self):
            try:
                # Sunucu başlatma mesajını logla
                self.log(f"UDP sunucusu başlatılıyor: {self.config['HOST']}:{self.config['UDP_PORT']}", 'INFO')
                
                # UDP socket oluştur (SOCK_DGRAM = UDP protokolü)
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind((self.config['HOST'], self.config['UDP_PORT']))  # adres ve porta bağla
                udp_socket.settimeout(1.0)                                       # timeout ayarla (1 saniye)
                
                # Ana paket alma döngüsü - sunucu çalıştığı sürece devam eder
                while self.running:
                    try:
                        # UDP paketini al (bloklanır, timeout ile sınırlı)
                        data, client_addr = udp_socket.recvfrom(self.config['MAX_PACKET_SIZE'])
                        
                        # Paketi ayrı thread'de işle (ana döngünün bloklanmasını önlemek için)
                        packet_thread = threading.Thread(
                            target=self.handle_udp_packet,                      # çalıştırılacak fonksiyon
                            args=(data, client_addr, udp_socket),               # fonksiyona gönderilecek parametreler
                            daemon=True  # ana program kapandığında bu thread'i de otomatik kapat
                        )
                        packet_thread.start()  # thread'i başlat
                        
                    except socket.timeout:
                        # Timeout durumunda döngüye devam et (normal davranış)
                        continue
                    except Exception as e:
                        # Diğer hatalar için log kaydet (eğer sunucu hala çalışıyorsa)
                        if self.running:
                            self.log(f"UDP paket alma hatası: {e}", 'ERROR')
                            
            except Exception as e:
                # Sunucu başlatma hatalarını logla
                self.log(f"UDP sunucu başlatma hatası: {e}", 'ERROR')
            finally:
                # Her durumda socket'i güvenli şekilde kapat
                try:
                    udp_socket.close()
                except:
                    pass  # kapatma hatalarını yoksay
    
    # İstatistikleri yazdırır (aktif bağlantı sayıları, alınan dosyalar vs.)
    def print_stats(self):
        # Sunucu çalıştığı sürece istatistik yazdırmaya devam et
        while self.running:
            try:
                time.sleep(30)  # 30 saniyede bir istatistik yazdır
                
                # Thread-safe şekilde aktif bağlantı sayılarını al
                with self.sessions_lock:
                    active_tcp = len(self.tcp_connections)    # aktif TCP bağlantı sayısı
                    active_udp = len(self.udp_sessions)       # aktif UDP oturum sayısı
                
                # İstatistikleri logla
                self.log(f"--- İSTATİSTİKLER ---", 'INFO')
                self.log(f"Aktif TCP bağlantıları: {active_tcp}", 'INFO')
                self.log(f"Aktif UDP oturumları: {active_udp}", 'INFO')
                self.log(f"Toplam TCP bağlantıları: {self.stats['tcp_connections']}", 'INFO')
                self.log(f"Toplam UDP oturumları: {self.stats['udp_sessions']}", 'INFO')
                self.log(f"Alınan dosya sayısı: {self.stats['files_received']}", 'INFO')
                self.log(f"Alınan toplam veri: {self.stats['bytes_received']} bytes", 'INFO')
                self.log(f"Hata sayısı: {self.stats['errors']}", 'INFO')
                self.log(f"--- İSTATİSTİKLER ---", 'INFO')
                
            except Exception as e:
                # İstatistik yazdırma hatalarını logla
                self.log(f"İstatistik yazdırma hatası: {e}", 'ERROR')
    
    # Sunucuyu başlatır ve gerekli thread'leri oluşturur
    def start(self):
        try:
            # Başlatma mesajını logla
            self.log("Güvenli Dosya Transfer Sunucusu başlatılıyor...", 'INFO')
            
            # RSA private key'i dosyadan yükle (şifre çözme için gerekli)
            self.load_rsa_private_key()
            
            # Sunucu thread'lerini oluştur (her biri farklı görev için)
            tcp_thread = threading.Thread(target=self.tcp_server, daemon=True)                    # TCP bağlantıları için
            udp_thread = threading.Thread(target=self.udp_server, daemon=True)                    # UDP paketleri için
            cleanup_thread = threading.Thread(target=self.cleanup_expired_sessions, daemon=True)  # süresi geçmiş oturumları temizle
            stats_thread = threading.Thread(target=self.print_stats, daemon=True)                 # istatistik yazdırma için
            
            # Tüm thread'leri başlat
            tcp_thread.start()
            udp_thread.start()
            cleanup_thread.start()
            stats_thread.start()
            
            # Başarılı başlatma mesajları
            self.log("Sunucu başarıyla başlatıldı. TCP ve UDP dinleniyor...", 'INFO')
            self.log(f"TCP Port: {self.config['TCP_PORT']}", 'INFO')
            self.log(f"UDP Port: {self.config['UDP_PORT']}", 'INFO')
            self.log("Durdurmak için Ctrl+C tuşlayın.", 'INFO')
            
            # Ana thread'i canlı tut (diğer thread'ler daemon olduğu için gerekli)
            while self.running:
                time.sleep(1)  # CPU kullanımını azaltmak için kısa bekleme
                
        except Exception as e:
            # Sunucu başlatma hatalarını logla ve kapat
            self.log(f"Sunucu başlatma hatası: {e}", 'ERROR')
            self.shutdown()
    
    # Sunucuyu güvenli şekilde kapatır
    def shutdown(self):
        # Kapatma mesajını logla
        self.log("Sunucu kapatılıyor...", 'INFO')
        self.running = False  # ana döngüleri durdurmak için flag'i false yap
        
        # Aktif bağlantıları güvenli şekilde kapat
        with self.sessions_lock:
            # Tüm TCP bağlantılarını kapat
            for addr, conn_info in self.tcp_connections.items():
                try:
                    conn_info['socket'].close()  # socket'i kapat
                except:
                    pass  # kapatma hatalarını yoksay
            
            # Kalan UDP oturumlarındaki verileri işle (veri kaybını önlemek için)
            for addr, session in self.udp_sessions.items():
                if session["data"]:  # eğer oturumda veri varsa
                    # Veriyi şifre çöz ve dosya olarak kaydet
                    self.decrypt_and_save_file(session["data"], f"UDP-{addr}")
        
        # Başarılı kapatma mesajını logla
        self.log("Sunucu başarıyla kapatıldı.", 'INFO')

# =============================================================================
# ANA PROGRAM
# =============================================================================
def main():
    # Program başlık mesajı
    print("=== Güvenli Dosya Transfer Sunucusu ===")
    
    # Konfigürasyonu özelleştir (varsayılan değerleri kopyala)
    config = DEFAULT_CONFIG.copy()
    
    # Komut satırı argümanlarını kontrol et
    if len(sys.argv) > 1:
        # Eğer parametre verilmişse kullanım bilgisini göster
        print("Kullanım: python server.py")
        print("Tüm ayarlar kod içinde DEFAULT_CONFIG'de tanımlanmıştır.")
        sys.exit(1)  # hata kodu ile çık
    
    # Sunucu nesnesini oluştur ve başlat
    server = SecureFileTransferServer(config)
    server.start()

# =============================================================================
# PROGRAMIN BAŞLANGIÇ NOKTASI
# ==============================================================================
if __name__ == "__main__":
    main()