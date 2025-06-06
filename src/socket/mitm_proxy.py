import socket     # ağ bağlantıları için
import threading  # çoklu thread işlemleri için
from datetime import datetime  # zaman damgası oluşturmak için

# =============================================================================
# MITM (MAN IN THE MIDDLE) PROXY SINIFI
# =============================================================================
class MITMProxy:
    def __init__(self, listen_port=8080, target_host='127.0.0.1', target_port=5001):
        self.listen_port = listen_port        # proxy'nin dinleyeceği port
        self.target_host = target_host        # hedef sunucunun IP adresi
        self.target_port = target_port        # hedef sunucunun port numarası
        self.intercepted_data = []            # yakalanan veri listesi (opsiyonel)

    # Ağ trafiğini loglamak için yardımcı fonksiyon 
    def log_traffic(self, direction, data, client_addr=None):
        # Zaman damgası oluştur (milisaniye hassasiyetinde)
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Client adresi varsa dahil et, yoksa sadece yön ve veri boyutu göster
        if client_addr:
            print(f"[{timestamp}] {direction} from {client_addr}: {len(data)} bytes")
        else:
            print(f"[{timestamp}] {direction}: {len(data)} bytes")
        
        # Verinin ilk 100 byte'ını hexadecimal formatında göster
        hex_data = data[:100].hex()
        print(f"         Data (hex): {hex_data}")
        
        # Veriyi UTF-8 text olarak decode etmeye çalış
        try:
            text_data = data.decode('utf-8', errors='ignore')[:100]  # ilk 100 karakter
            if text_data.strip():  # boş değilse göster
                print(f"         Data (text): {text_data}")
        except:
            # Decode hatası durumunda sessizce geç
            pass
        
        # Ayırıcı çizgi ekle (okunabilirlik için)
        print("-" * 60)
    
    # Client bağlantısını işleyen ana fonksiyon
    def handle_client(self, client_socket, client_addr):
        server_socket = None
        try:
            # Hedef sunucuya bağlantı oluştur
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.target_host, self.target_port))
            
            # Başarılı MITM bağlantısı mesajı
            print(f"[+] MITM bağlantısı kuruldu: {client_addr} <-> Proxy <-> {self.target_host}:{self.target_port}")
            
            # İki yönlü veri aktarımı için thread'ler oluştur
            client_to_server = threading.Thread(
                target=self.relay_data,                           # çalıştırılacak fonksiyon
                args=(client_socket, server_socket, "CLIENT->SERVER", client_addr)  # fonksiyon parametreleri
            )
            server_to_client = threading.Thread(
                target=self.relay_data,                           # çalıştırılacak fonksiyon
                args=(server_socket, client_socket, "SERVER->CLIENT", client_addr)  # fonksiyon parametreleri
            )
            
            # Thread'leri daemon olarak ayarla (ana program kapandığında otomatik kapansın)
            client_to_server.daemon = True
            server_to_client.daemon = True
            
            # Her iki thread'i de başlat
            client_to_server.start()
            server_to_client.start()
            
            # Thread'lerin bitmesini bekle (bağlantı kesilene kadar)
            client_to_server.join()
            server_to_client.join()
            
        except Exception as e:
            # Bağlantı hataları için log kaydet
            print(f"[!] MITM proxy hatası: {e}")
        finally:
            # Her durumda socket'leri güvenli şekilde kapat
            try:
                if client_socket:
                    client_socket.close()
                if server_socket:
                    server_socket.close()
            except:
                pass  # kapatma hatalarını yoksay
    
    # İki socket arasında veri aktarımı yapan fonksiyon
    def relay_data(self, source, destination, direction, client_addr):
        try:
            # Sürekli veri aktarım döngüsü
            while True:
                # Kaynaktan veri al (maksimum 4096 byte)
                data = source.recv(4096)
                
                # Veri yoksa bağlantı kesilmiş demektir
                if not data:
                    break
                    
                # Yakalanan trafiği logla
                self.log_traffic(direction, data, client_addr)
                
                # Değiştirilmiş (veya orijinal) veriyi hedef tarafa gönder
                destination.send(data)
                
        except Exception as e:
            # Veri aktarım hatalarını logla
            print(f"[!] Relay hatası ({direction}): {e}")
    
    # MITM Proxy'yi başlatan ana fonksiyon
    def start_proxy(self):
        # TCP socket oluştur
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Socket ayarları: adresi yeniden kullanmaya izin ver
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Tüm network interface'lerden gelen bağlantıları kabul et
        proxy_socket.bind(('0.0.0.0', self.listen_port))
        
        # Maksimum 5 bekleyen bağlantıya izin ver
        proxy_socket.listen(5)
        
        # Başlatma mesajları
        print(f"[*] MITM Proxy başlatıldı: 0.0.0.0:{self.listen_port}")
        print(f"[*] Hedef sunucu: {self.target_host}:{self.target_port}")
        print(f"[*] Client'ları {self.listen_port} portuna yönlendirin")
        print("-" * 60)
        
        try:
            # Ana bağlantı kabul döngüsü
            while True:
                # Yeni client bağlantısını kabul et
                client_socket, client_addr = proxy_socket.accept()
                print(f"[+] Yeni bağlantı: {client_addr}")
                
                # Her client için ayrı thread oluştur (paralel işlem için)
                client_thread = threading.Thread(
                    target=self.handle_client,              # çalıştırılacak fonksiyon
                    args=(client_socket, client_addr)       # fonksiyon parametreleri
                )
                client_thread.daemon = True                 # daemon thread olarak ayarla
                client_thread.start()                       # thread'i başlat
                
        except KeyboardInterrupt:
            # Ctrl+C ile durdurulduğunda temizlik yap
            print("\n[!] MITM Proxy durduruldu.")
        finally:
            # Proxy socket'ini kapat
            proxy_socket.close()

# =============================================================================
# ANA PROGRAM FONKSİYONU
# =============================================================================
if __name__ == "__main__":
    # Program tanıtım mesajları
    print("=== MITM PROXY ===")
    
    # MITM proxy nesnesini oluştur
    mitm = MITMProxy(
        listen_port=8080,          # Client'ların bağlanacağı proxy portu
        target_host='127.0.0.1',   # Gerçek sunucunun IP adresi (localhost)
        target_port=5001           # Gerçek sunucunun port numarası
    )
    
    # Proxy'yi başlat
    mitm.start_proxy()

