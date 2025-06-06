import subprocess  # sistem komutlarını çalıştırmak için
import platform    # işletim sistemi bilgilerini almak için
import time        # zaman ölçümleri ve bekleme için
import statistics  # istatistiksel hesaplamalar için
import shutil      # dosya ve sistem araç kontrolü için
import re          # düzenli ifadeler (regex) için
import os          # dosya sistemi işlemleri için
import sys         # sistem parametreleri ve çıkış kodları için

# =============================================================================
# VARSAYILAN AYARLAR
# =============================================================================
HOST = "google.com"                    # ping testi için varsayılan hedef
IPERF_SERVER = "127.0.0.1"             # iPerf sunucu adresi (localhost)
SOCKET_SERVER_HOST = "127.0.0.1"       # socket sunucu IP adresi
SOCKET_SERVER_PORT = 9999              # socket sunucu port numarası
IPERF_CMD = None                       # iPerf komut yolu (dinamik olarak belirlenir)

# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

# Başlık yazdırma fonksiyonu
def print_header(title):
    print(f"\n{'='*50}")
    print(f"[{title}]")
    print(f"{'='*50}")

# Bağımlılıkları kontrol etme fonksiyonu
def check_dependencies():
    print("Bağımlılıklar kontrol ediliyor...")
    
    # Socket test dosyalarının varlığını kontrol et
    if not os.path.exists("server.py"):
        print("server.py bulunamadı!")
        return False
    if not os.path.exists("client.py"):
        print("client.py bulunamadı!")
        return False
        
    # iPerf3 aracını farklı konumlarda ara - sistem PATH'i ve yerel dizin
    global IPERF_CMD
    iperf_paths = ["./iperf3/iperf3", "iperf3", "iperf"]  # olası yollar listesi
    iperf_found = False
    
    # Her olası yolu kontrol et
    for path in iperf_paths:
        if shutil.which(path) or os.path.exists(path):  # sistem PATH'inde veya dosya olarak mevcut mu?
            IPERF_CMD = path
            iperf_found = True
            break
    
    # iPerf bulunamazsa uyarı ver ama devam et
    if not iperf_found:
        print("iPerf3 bulunamadı, bant genişliği testi atlanacak")
    else:
        print(f"iPerf3 bulundu: {IPERF_CMD}")
        
    print("Socket dosyaları bulundu")
    return True

# =============================================================================
# PING GECİKME ÖLÇÜM FONKSİYONU
# =============================================================================
def measure_latency(host=HOST, count=10):
    print_header("PING GECİKME ÖLÇÜMÜ")
    print(f"Hedef: {host}")
    print(f"Paket sayısı: {count}")
    
    try:
        # İşletim sistemine göre ping komutunu ayarla
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", str(count), host]    # Windows: -n parametresi
        else:
            cmd = ["ping", "-c", str(count), host]    # Linux/macOS: -c parametresi
        
        print(f"Ping başlatılıyor...")
        start_time = time.time()                      # toplam süre ölçümü için
        output = subprocess.check_output(cmd, universal_newlines=True, timeout=30)
        total_time = time.time() - start_time
        
        # Ping çıktısından zaman değerlerini çıkar - platform bazlı regex
        if platform.system().lower() == "windows":
            times = re.findall(r"time[=<]([0-9.]+)ms", output)      # Windows formatı
            loss_match = re.search(r"\(([0-9]+)% loss\)", output)   # paket kaybı
        else:
            times = re.findall(r"time=([0-9.]+) ms", output)        # Unix formatı
            loss_match = re.search(r"([0-9.]+)% packet loss", output)
        
        # String değerleri sayısal değerlere çevir
        times = [float(t) for t in times]
        packet_loss = float(loss_match.group(1)) if loss_match else 0
        
        if times:
            # İstatistiksel değerleri hesapla
            min_rtt = min(times)                      # minimum gecikme
            max_rtt = max(times)                      # maksimum gecikme
            avg_rtt = statistics.mean(times)          # ortalama gecikme
            median_rtt = statistics.median(times)     # medyan gecikme
            stddev_rtt = statistics.stdev(times) if len(times) > 1 else 0  # standart sapma
            
            # Sonuçları detaylı şekilde yazdır
            print(f"\nPING SONUÇLARI:")
            print(f"   Gönderilen: {count} paket")
            print(f"   Alınan: {len(times)} paket")
            print(f"   Kayıp: %{packet_loss:.1f}")
            print(f"   Min RTT: {min_rtt:.2f} ms")
            print(f"   Max RTT: {max_rtt:.2f} ms")
            print(f"   Ortalama RTT: {avg_rtt:.2f} ms")
            print(f"   Medyan RTT: {median_rtt:.2f} ms")
            print(f"   Standart Sapma: {stddev_rtt:.2f} ms")
            print(f"   Toplam süre: {total_time:.2f} saniye")
            
            # Sonuçları dictionary olarak döndür (diğer fonksiyonlarda kullanım için)
            return {
                'min': min_rtt, 'max': max_rtt, 'avg': avg_rtt,
                'median': median_rtt, 'stddev': stddev_rtt,
                'packet_loss': packet_loss, 'total_time': total_time
            }
        else:
            print("Ping sonuçlarında zaman bilgisi bulunamadı")
            return None
            
    except subprocess.TimeoutExpired:
        # Timeout durumu - hedef ulaşılamaz veya çok yavaş
        print("Ping timeout - hedef yanıt vermiyor")
        return None
    except subprocess.CalledProcessError as e:
        # Ping komutu başarısız - ağ hatası veya geçersiz hedef
        print(f"Ping komutu başarısız: {e}")
        return None
    except Exception as e:
        # Beklenmeyen hatalar için genel yakalama
        print(f"Gecikme ölçümünde hata: {e}")
        return None

# =============================================================================
# SOCKET SUNUCU YÖNETİM FONKSİYONU
# =============================================================================
def start_socket_server():
    print_header("SOCKET SUNUCUSU")
    try:
        print("Socket sunucusu başlatılıyor...")
        # Ayrı bir Python süreci olarak sunucuyu başlat
        process = subprocess.Popen([
            sys.executable, "server.py"           # mevcut Python interpreter'ı kullan
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Sunucunun tamamen başlaması için bekleme süresi
        
        # Sunucunun düzgün çalışıp çalışmadığını kontrol et
        if process.poll() is None:  # None = hala çalışıyor
            print("Socket sunucusu başarıyla başlatıldı")
            return process  # process handle'ını döndür (sonra kapatmak için)
        else:
            # Sunucu başlatılamadıysa hata mesajını al
            _, stderr = process.communicate()
            print(f"Socket sunucusu başlatılamadı: {stderr.decode()}")
            return None
            
    except Exception as e:
        print(f"Socket sunucusu hatası: {e}")
        return None

# =============================================================================
# PAKET ZAMANLAMA TEST FONKSİYONU
# =============================================================================
def measure_packet_timing():
    print_header("PAKET ZAMANLAMA TESTİ")
    
    packet_sizes = [64, 512, 1024]  # Farklı paket boyutları (byte) - küçük/orta/büyük
    results = {}                     # test sonuçlarını sakla
    test_count = 5                   # Her boyut için tekrar sayısı (güvenilirlik için)
    
    # Her paket boyutu için ayrı test döngüsü
    for size in packet_sizes:
        print(f"\n{size} byte paket testi ({test_count} test):")
        times = []  # bu boyut için ölçülen süreler
        
        try:
            # Belirtilen sayıda test tekrarı yap
            for i in range(test_count):
                # Her paket gönderimi için hassas zamanlama
                start_time = time.time()
                
                # Client'ı tek paket göndermek için çalıştır
                result = subprocess.run([
                    sys.executable, "client.py"
                ], capture_output=True, text=True, timeout=10)
                
                end_time = time.time()
                
                # Client başarılı olursa süreyi kaydet
                if result.returncode == 0:
                    # Paket gönderme süresini milisaniye cinsinden hesapla
                    packet_time = (end_time - start_time) * 1000
                    times.append(packet_time)
                    print(f"   Test {i+1}: {packet_time:.3f} ms")
                else:
                    print(f"   Test {i+1}: Başarısız - {result.stderr.strip()}")
            
            # Başarılı testlerin istatistiklerini hesapla ve kaydet
            if times:
                results[size] = {
                    'times': times,                                    # ham veriler
                    'min': min(times),                                # minimum süre
                    'max': max(times),                                # maksimum süre
                    'avg': statistics.mean(times),                    # ortalama süre
                    'median': statistics.median(times),               # medyan süre
                    'stddev': statistics.stdev(times) if len(times) > 1 else 0,  # standart sapma
                    'count': len(times),                              # başarılı test sayısı
                    'success_rate': (len(times) / test_count) * 100  # başarı oranı
                }
                
                # Bu boyut için özet istatistikleri yazdır
                print(f"   Sonuçlar:")
                print(f"      Min/Avg/Max: {min(times):.3f}/{statistics.mean(times):.3f}/{max(times):.3f} ms")
                print(f"      Medyan: {statistics.median(times):.3f} ms")
                print(f"      Std Sapma: {statistics.stdev(times) if len(times) > 1 else 0:.3f} ms")
                print(f"      Başarı Oranı: %{(len(times) / test_count) * 100:.1f}")
            else:
                print("   Hiçbir test başarılı olmadı")
                
        except Exception as e:
            print(f"{size} byte test hatası: {e}")
    
    return results  # tüm boyutlar için sonuçları döndür

# =============================================================================
# IPERF SUNUCU YÖNETİM FONKSİYONU
# =============================================================================
def start_iperf_server():
    if IPERF_CMD is None:  # iPerf bulunamadıysa işlem yapma
        return None
        
    print_header("IPERF3 SUNUCUSU")
    try:
        print("iPerf3 sunucusu başlatılıyor...")
        # iPerf sunucusunu başlat (-s = server modu, -p = port)
        process = subprocess.Popen([
            IPERF_CMD, "-s", "-p", "5201"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # çıktıları gizle
        
        time.sleep(3)  # Sunucunun tamamen başlaması için yeterli bekleme
        print("iPerf3 sunucusu başlatıldı")
        return process  # process handle'ını döndür
        
    except Exception as e:
        print(f"iPerf3 sunucusu hatası: {e}")
        return None

# =============================================================================
# BANT GENİŞLİĞİ ÖLÇÜM FONKSİYONU
# =============================================================================
def measure_bandwidth():
    if IPERF_CMD is None:  # iPerf yoksa test yapılamaz
        print("iPerf3 bulunamadı, bant genişliği testi atlandı")
        return None
        
    print_header("BANT GENİŞLİĞİ TESTİ")
    
    try:
        print("Bant genişliği ölçülüyor (10 saniye)...")
        # iPerf client modunda çalıştır (-c = client, -t = süre, -f = format)
        result = subprocess.run([
            IPERF_CMD, "-c", IPERF_SERVER, "-t", "10", "-f", "M"  # 10 saniye, MBytes formatı
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("Bant genişliği testi tamamlandı")
            print("\nSONUÇLAR:")
            
            # iPerf çıktısını filtrele ve önemli satırları göster
            lines = result.stdout.split('\n')
            for line in lines:
                # Sadece bant genişliği bilgisi içeren satırları göster
                if ('Mbits/sec' in line or 'sender' in line or 'receiver' in line) and line.strip().startswith('['):
                    print(f"   {line.strip()}")
            
            # Özet bilgiyi parse et ve daha okunabilir hale getir
            summary_lines = [line for line in lines if 'sender' in line or 'receiver' in line]
            results = []  # Sonuçları saklamak için liste

            if summary_lines:
                print(f"\nBant genişliği sonucu:")
                # Son iki satır genellikle sender/receiver özetleridir
                for line in summary_lines[-2:]:
                    if 'MBytes/sec' in line:
                        parts = line.split()
                        # Hız değerini bul ve ayıkla
                        for i, part in enumerate(parts):
                            if 'MBytes/sec' in part and i > 0:
                                try:
                                    speed = parts[i-1]
                                    direction = 'Gönderme' if 'sender' in line else 'Alma'
                                    result_text = f"{direction}: {speed} MBytes/sn"
                                    print(f"   {result_text}")
                                    results.append(result_text)  # Sonucu listeye ekle
                                    break
                                except IndexError:
                                    continue
                                
            return results  # sonuçları döndür
        else:
            print(f"Bant genişliği testi başarısız:")
            print(result.stderr)
            return None
            
    except subprocess.TimeoutExpired:
        # Test çok uzun sürerse timeout
        print("Bant genişliği testi timeout")
        return None
    except Exception as e:
        print(f"Bant genişliği testi hatası: {e}")
        return None

# =============================================================================
# PAKET KAYBI SİMÜLASYON FONKSİYONU 
# =============================================================================
def simulate_packet_loss():
    if platform.system().lower() != "linux":
        print("\nPaket kaybı simülasyonu sadece Linux'ta desteklenir")
        return
        
    print_header("PAKET KAYBI SİMÜLASYONU")
    
    try:
        print("🔧 %10 paket kaybı simüle ediliyor...")
        
        # Linux tc (traffic control) komutuyla paket kaybı ekle
        subprocess.run([
            "", "tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "10%"
        ], check=True)
        
        print("Paket kaybı simülasyonu aktif")
        print("5 saniye test süresi...")
        
        # Paket kaybı ile localhost'a ping testi yap
        test_result = measure_latency(host="127.0.0.1", count=5)
        
        time.sleep(5)  # Simülasyonun etkisini gözlemlemek için bekle
        
        # tc kuralını temizle (ağ ayarlarını eski haline getir)
        subprocess.run([
            "sudo", "tc", "qdisc", "del", "dev", "lo", "root"
        ], check=True)
        
        print("Paket kaybı simülasyonu temizlendi")
        return test_result
        
    except subprocess.CalledProcessError as e:
        print(f"tc komutu başarısız: {e}")
        print("sudo yetkisi gerekebilir veya tc kurulu olmayabilir")
        return None
    except Exception as e:
        print(f"Simülasyon hatası: {e}")
        return None

# =============================================================================
# SÜREÇ TEMİZLEME FONKSİYONU
# =============================================================================
def cleanup_processes(processes):
    print("\nSüreçler temizleniyor...")
    for process in processes:
        if process and process.poll() is None:  # süreç hala çalışıyorsa
            try:
                # Önce nazikçe sonlandırmayı dene
                process.terminate()
                process.wait(timeout=5)  # 5 saniye bekle
                print("Süreç temizlendi")
            except subprocess.TimeoutExpired:
                try:
                    # Nazik sonlandırma işe yaramazsa zorla öldür
                    process.kill()
                    process.wait(timeout=2)  # 2 saniye bekle
                    print("Süreç zorla sonlandırıldı")
                except:
                    print("Süreç temizlenemedi")
            except:
                print("Süreç temizleme hatası")

# =============================================================================
# ÖZET RAPOR FONKSİYONU
# =============================================================================
def print_summary(ping_result, socket_result, bandwidth_result):
    print_header("TEST ÖZETİ")
    
    # Ping testi sonuçları
    if ping_result:
        print(f"Ping Gecikme: {ping_result['avg']:.2f} ms (min: {ping_result['min']:.2f}, max: {ping_result['max']:.2f})")
        print(f"   Paket Kaybı: %{ping_result['packet_loss']:.1f}")
    else:
        print("Ping Gecikme: Test başarısız")
    
    # Socket testi sonuçları
    if socket_result:
        print(f"Socket Testleri:")
        for size, data in socket_result.items():
            print(f"   {size} byte: {data['avg']:.3f} ms ortalama ({data['count']}/{data.get('count', 0)} başarılı)")
            print(f"              Min/Max: {data['min']:.3f}/{data['max']:.3f} ms")
    else:
        print("Socket Testleri: Test başarısız")
    
    # Bant genişliği testi sonuçları
    if bandwidth_result:
        print(f"Bant Genişliği Testi:")
        print(f"{bandwidth_result[0]}")
        print(f"{bandwidth_result[1]}")
    else:
        print("Bant Genişliği: Test başarısız veya atlandı")
    
    # Test tamamlanma zamanı
    print(f"\nTest tamamlanma zamanı: {time.strftime('%Y-%m-%d %H:%M:%S')}")

# =============================================================================
# ANA PROGRAM FONKSİYONU
# =============================================================================
def main():
    print("Gelişmiş Ağ Performans Analizi Başlatılıyor...")
    print(f"Sistem: {platform.system()} {platform.release()}")
    
    # Gerekli dosya ve araçları kontrol et
    if not check_dependencies():
        print("Gerekli dosyalar bulunamadı, çıkılıyor...")
        return 1  # hata kodu ile çık
    
    running_processes = []  # çalışan süreçleri takip et (temizlik için)
    
    try:
        # 1. Ağ gecikmesi testi (internet bağlantısı gerekli)
        ping_result = measure_latency()
        
        # 2. Socket sunucusunu başlat ve paket zamanlaması test et
        socket_server = start_socket_server()
        if socket_server:
            running_processes.append(socket_server)  # temizlik listesine ekle
            socket_result = measure_packet_timing()
        else:
            socket_result = None
        
        # 3. iPerf bant genişliği testi (localhost üzerinde)
        iperf_server = start_iperf_server()
        if iperf_server:
            running_processes.append(iperf_server)   # temizlik listesine ekle
            bandwidth_result = measure_bandwidth()
        else:
            bandwidth_result = None
        
        # 4. Paket kaybı simülasyonu (şu anda kapalı - Linux gerektirir)
        # simulate_packet_loss()
        
        # 5. Tüm test sonuçlarının özet raporu
        print_summary(ping_result, socket_result, bandwidth_result)
        
        return 0  # başarılı çıkış kodu
        
    except KeyboardInterrupt:
        # Kullanıcı Ctrl+C ile durdurursa
        print("\nTest kullanıcı tarafından durduruldu")
        return 1  # hata kodu ile çık
    except Exception as e:
        # Beklenmeyen hatalar için genel yakalama
        print(f"\nBeklenmeyen hata: {e}")
        return 1  # hata kodu ile çık
    finally:
        # Her durumda çalışan süreçleri temizle (kaynak sızıntısını önle)
        cleanup_processes(running_processes)
        print("\nAğ analizi tamamlandı")

# =============================================================================
# PROGRAM GİRİŞ NOKTASI
# =============================================================================
if __name__ == "__main__":
    # Ana fonksiyonu çalıştır ve çıkış kodunu al
    exit_code = main()
    # Sistem çıkış kodunu ayarla (işletim sistemi için)
    sys.exit(exit_code)