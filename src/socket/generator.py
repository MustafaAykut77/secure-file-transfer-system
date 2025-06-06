import os  # dosya ve klasör işlemleri için
from Crypto.PublicKey import RSA  # RSA anahtar oluşturma için

# =============================================================================
# RSA ANAHTAR ÇİFTİ OLUŞTURMA
# =============================================================================
def create_rsa_key_pair(key_size=2048, output_dir="keys"):
    # Çıktı klasörünün varlığını kontrol et ve gerekirse oluştur
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)  # klasörü oluştur (alt klasörler dahil)
        print(f"'{output_dir}' klasörü oluşturuldu.")
    
    try:
        # RSA anahtar çifti oluşturma işlemini başlat
        print(f"{key_size} bit RSA anahtar çifti oluşturuluyor...")
        key = RSA.generate(key_size)  # belirtilen uzunlukta RSA anahtarı oluştur
        
        # Anahtarların kaydedileceği dosya yollarını belirle
        private_key_path = os.path.join(output_dir, "private.pem")  # özel anahtar dosya yolu
        public_key_path = os.path.join(output_dir, "public.pem")    # genel anahtar dosya yolu
        
        # Özel anahtarı PEM formatında dosyaya kaydet
        with open(private_key_path, "wb") as private_file:
            private_file.write(key.export_key('PEM'))  # PEM formatında dışa aktar ve yaz
        
        # Genel anahtarı PEM formatında dosyaya kaydet
        with open(public_key_path, "wb") as public_file:
            public_file.write(key.publickey().export_key('PEM'))  # genel anahtarı al, PEM formatında dışa aktar
        
        # Başarılı oluşturma mesajını göster
        print(f"RSA anahtar çifti başarıyla oluşturuldu:")
        print(f"  - Özel anahtar: {private_key_path}")
        print(f"  - Genel anahtar: {public_key_path}")
        
        # Dosya yollarını tuple olarak döndür
        return private_key_path, public_key_path
        
    except Exception as e:
        # Hata durumunda hata mesajını göster ve None değerleri döndür
        print(f"Hata oluştu: {e}")
        return None, None

# =============================================================================
# ANA FONKSİYON
# =============================================================================
def main():
    # Varsayılan ayarlarla anahtar çiftini oluştur
    private_path, public_path = create_rsa_key_pair()
    
    # Anahtar oluşturma başarılı olduysa güvenlik uyarılarını göster
    if private_path and public_path:
        print("\nGÜVENLİK UYARISI:")
        print("- Özel anahtarınızı (private.pem) güvenli bir yerde saklayın")
        print("- Özel anahtarınızı asla paylaşmayın")
        print("- Genel anahtarı (public.pem) güvenle paylaşabilirsiniz")

# =============================================================================
# PROGRAMIN BAŞLANGIÇ NOKTASI
# =============================================================================
if __name__ == "__main__":
    main()