import socket   # ağ bağlantıları için
import zlib     # CRC32 checksum hesaplama için
import time     # zamanlama işlemleri için
import hashlib  # SHA256 hash hesaplama için
from Crypto.PublicKey import RSA            # RSA anahtarları için
from Crypto.Cipher import AES, PKCS1_OAEP   # AES ve RSA şifreleme için
from Crypto.Random import get_random_bytes  # rastgele baytlar üretmek için
from Crypto.Util.Padding import pad         # AES için veriyi doldurmak için

# =============================================================================
# SUNUCU BİLGİLERİ
# =============================================================================
IP = '127.0.0.1'
PORT = 5002

# =============================================================================
# RSA GENEL ANAHTARINI YÜKLEME
# =============================================================================
def load_server_pubkey():
    with open("../keys/public.pem", "rb") as f:
        return RSA.import_key(f.read())

# =============================================================================
# SAHTE OTURUM GÖNDERME FONKSİYONU
# =============================================================================
def send_fake_session():
    # UDP soketi oluştur
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Rastgele AES anahtarı ve IV (Initialization Vector) oluştur
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # RSA genel anahtarını yükle ve AES anahtarını şifrele
    rsa_key = load_server_pubkey()
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Kurulum paketi: encrypted_aes_key (256 byte) + iv (16 byte)
    setup_packet = encrypted_aes_key + iv
    sock.sendto(setup_packet, (IP, PORT))
    print("[*] Kurulum paketi gönderildi.")
    
    # Sunucunun kurulum paketini işlemesi için bekleme
    time.sleep(0.05)

    # Sahte dosya içeriği ve bilgileri (güncellenmiş formata uygun)
    fake_file_content = b"ENJEKTE_EDILMIS_DOSYA_ICERIGI"
    fake_filename = "injected_packet.txt"
    
    # Dosya hash'ini hesapla
    file_hash = hashlib.sha256(fake_file_content).digest()  # 32 byte
    
    # Dosya adı bilgilerini hazırla
    filename_bytes = fake_filename.encode('utf-8')
    filename_length = len(filename_bytes).to_bytes(2, 'big')  # 2 byte uzunluk
    
    # Güncellenmiş format: hash(32) + filename_length(2) + filename + file_content
    data_with_info = file_hash + filename_length + filename_bytes + fake_file_content
    
    # Veriyi şifrele
    padded_payload = pad(data_with_info, AES.block_size)
    encrypted_data = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(padded_payload)

    #  Veri paketini hazırla: size (4 byte) + crc (4 byte) + encrypted_data
    size = len(encrypted_data).to_bytes(4, 'big')
    crc = zlib.crc32(encrypted_data).to_bytes(4, 'big')
    packet = size + crc + encrypted_data

    # Veri paketini gönder
    sock.sendto(packet, (IP, PORT))
    print(f"[*] Sahte dosya paketi gönderildi: {fake_filename}")
    
    # Oturumu sonlandır
    time.sleep(0.1)
    sock.sendto(b'FIN', (IP, PORT))
    print("[*] Sahte oturum sonlandırıldı.")
    
    sock.close()

# =============================================================================
# PROGRAMIN BAŞLANGIÇ NOKTASI
# =============================================================================
if __name__ == "__main__":
    # Sahte oturumu başlat
    send_fake_session()