# Güvenli Dosya Transfer Sistemi

TCP/UDP protokolleri, hibrit geçiş, şifreleme ve ağ analizi yetenekleri içeren kapsamlı bir güvenli dosya transfer sistemi.

## 🚀 Özellikler

### Temel İşlevsellik
- **Güvenli Dosya Transferi**: Veri iletimi için AES/RSA hibrit şifreleme
- **Protokol Desteği**: TCP, UDP ve ağ koşullarına göre akıllı hibrit geçiş
- **Kimlik Doğrulama**: Parola tabanlı istemci kimlik doğrulaması
- **Dosya Bütünlüğü**: SHA-256 hash doğrulaması
- **GUI Arayüzü**: Kolay kullanım için kullanıcı dostu grafik arayüz

### Güvenlik Özellikleri
- **Hibrit Şifreleme**: Veri şifreleme için AES, anahtar şifreleme için RSA
- **MITM Koruması**: Ortadaki Adam saldırılarına karşı yerleşik direnç
- **Paket Enjeksiyon Savunması**: Kötü amaçlı paket enjeksiyonuna karşı koruma
- **Güvenli Dosya Adı Doğrulaması**: Dizin geçişi saldırılarının önlenmesi

### Ağ Analizi
- **Gecikme Ölçümü**: Gerçek zamanlı ağ gecikme analizi
- **Bant Genişliği Testi**: iPerf3 kullanarak ağ verim ölçümü
- **Paket Kaybı Simülasyonu**: Ağ durumu testleri
- **Performans İzleme**: Kapsamlı ağ istatistikleri

### Gelişmiş Özellikler
- **Alt Seviye Paket Manipülasyonu**: Scapy kullanarak IP başlığı değiştirme
- **Paket Parçalama**: Manuel paket bölme ve birleştirme
- **Ağ Adli Tıp**: Trafik yakalama ve analiz yetenekleri
- **Çoklu İş Parçacığı**: Eşzamanlı istemci işleme

## 📁 Proje Yapısı

```
/
├── keys/
│   ├── private.pem          # RSA özel anahtar
│   └── public.pem           # RSA genel anahtar
├── socket/
│   ├── iperf3/
│   │   └── iperf3.exe       # Bant genişliği test aracı
│   ├── client.py            # Dosya transfer istemcisi
│   ├── server.py            # Dosya transfer sunucusu
│   ├── generator.py         # RSA anahtar çifti oluşturucu
│   ├── network_analysis.py  # Ağ performans analizörü
│   ├── mitm_proxy.py        # MITM saldırı simülatörü
│   ├── packet_injection.py  # Paket enjeksiyon testi
│   └── secure_transfer_gui.py # Grafik kullanıcı arayüzü
└── scapy/
    ├── receiver_scapy.py    # Paket parça alıcısı
    └── sender_scapy.py      # Paket parça göndericisi
```

## 🛠️ Kurulum

### Gereksinimler
- Python 3.7+
- Gerekli Python paketleri:
  ```bash
  pip install pycryptodome scapy tkinter
  ```
- iPerf3 (bant genişliği testi için)

### Kurulum Adımları
1. Repoyu klonlayın
2. RSA anahtar çiftlerini oluşturun:
   ```bash
   python socket/generator.py
   ```
3. GUI uygulamasını çalıştırın:
   ```bash
   python socket/secure_transfer_gui.py
   ```

## 🖥️ Kullanım

### GUI Modu (Önerilen)
1. GUI'yi başlatın: `python socket/secure_transfer_gui.py`
2. Arayüzü kullanarak transfer edilecek dosyaları seçin
3. Transfer protokolünü seçin (TCP/UDP/Hibrit)
4. Transfer ilerlemesini gerçek zamanlı izleyin

### Komut Satırı Modu

#### Sunucu
```bash
python socket/server.py
```

#### İstemci
```bash
python socket/client.py --file <dosyaadi> --protocol <tcp/udp/hybrid>
```

### Ağ Analizi
```bash
python socket/network_analysis.py
```

## 📊 Ağ Analiz Araçları

### Gecikme Testi
- Ping tabanlı RTT ölçümü
- Min/Maks/Ortalama gecikme hesaplama
- Paket kaybı tespiti

### Bant Genişliği Testi
- iPerf3 entegrasyonu
- Yükleme/İndirme hızı ölçümü
- Gerçek zamanlı verim izleme

### Protokol Testi
- TCP güvenilirlik testi
- UDP performans testi
- Hibrit geçiş optimizasyonu

## 🧪 Güvenlik Testi

### MITM Simülasyonu
```bash
python socket/mitm_proxy.py
```

### Paket Enjeksiyon Testi
```bash
python socket/packet_injection.py
```

### Alt Seviye Paket Analizi
```bash
python scapy/sender_scapy.py    # Parçalanmış paket gönder
python scapy/receiver_scapy.py  # Yakala ve birleştir
```

## ⚡ Performans

### Hibrit Mod
- Ağ koşullarına göre otomatik protokol seçimi
- Düşük gecikme: UDP tercih edilir
- Yüksek gecikme/paket kaybı: TCP tercih edilir
- Gerçek zamanlı geçiş yeteneği

### Optimizasyon
- Çok iş parçacıklı sunucu mimarisi
- Verimli paket parçalama
- Bellek optimize edilmiş şifreleme
- Bağlantı havuzlaması

## 🚧 Kısıtlamalar

- Scapy bileşenleri socket bileşenlerinden bağımsız çalışır
- AI tabanlı ağ durumu analizi yok (gelecek geliştirme potansiyeli)
- Yerel ağ test senaryolarıyla sınırlı

## 🔮 Gelecek Geliştirmeler

- Scapy paket manipülasyonunun socket işlemleriyle entegrasyonu
- AI tabanlı protokol seçim algoritmaları
- Gerçek zamanlı ağ görselleştirmeli gelişmiş GUI
- Çoklu dosya transfer desteği
- Gelişmiş adli tıp yetenekleri

## 📝 Lisans

Bu proje Bilgisayar Ağları dersi için eğitim amaçlı geliştirilmiştir.

## 🤝 Katkıda Bulunma

Bu akademik bir projedir. İyileştirmeler veya öneriler için lütfen bir issue oluşturun veya pull request gönderin.

## 📞 Destek

Sorular veya destek için lütfen proje dokümantasyonuna bakın veya repoda bir issue oluşturun.

---

**Geliştiren**: Mustafa AYKUT (22360859028)  
**Ders**: Bilgisayar Ağları - Dönem Projesi
