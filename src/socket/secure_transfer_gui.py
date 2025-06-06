import tkinter as tk                                           # GUI framework'ü
from tkinter import ttk, filedialog, messagebox, scrolledtext  # GUI bileşenleri
import threading                                               # çoklu thread işlemleri için
import subprocess                                              # dış komutları çalıştırmak için
import sys                                                     # sistem fonksiyonları
import os                                                      # işletim sistemi işlemleri
from pathlib import Path                                       # dosya yolu işlemleri
import time                                                    # zaman işlemleri

# =============================================================================
# ANA GUI SINIFI
# =============================================================================
class FileTransferUI:
    def __init__(self):
        # Ana pencereyi oluştur
        self.root = tk.Tk()
        self.root.title("Güvenli Dosya Transfer")  # pencere başlığı
        self.root.geometry("800x700")  # pencere boyutu
        self.root.configure(bg="#2b2b2b")  # arka plan rengi (karanlık tema)
        
        # Karanlık tema stillerini ayarla
        self.setup_style()
        
        # Ana GUI bileşenlerini başlat
        self.server_process = None  # sunucu process referansı
        self.analysis_process = None  # ağ analizi process referansı
        self.mitm_process = None  # MITM proxy process referansı
        self.selected_file = tk.StringVar()  # seçilen dosya yolu
        self.mitm_target_file = tk.StringVar()  # MITM test dosyası yolu
        self.host = tk.StringVar(value="127.0.0.1")  # hedef sunucu adresi
        self.tcp_port = tk.StringVar(value="5001")  # TCP port numarası
        self.udp_port = tk.StringVar(value="5002")  # UDP port numarası
        self.packet_size = tk.StringVar(value="1024")  # paket boyutu (byte)
        self.transmission_count = tk.StringVar(value="1")  # gönderim sayısı
        self.mode = tk.StringVar(value="TCP")  # transfer protokolü (TCP/UDP/HYBRID)
        
        # GUI bileşenlerini oluştur
        self.create_widgets()
        
    # Setup fonksiyonu - GUI stillerini ayarlar
    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')  # temel tema
        
        # Karanlık tema renk tanımlamaları
        style.configure('.', background='#2b2b2b', foreground='#ffffff')  # genel ayarlar
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')  # etiketler
        style.configure('TButton', background='#404040', foreground='#ffffff')  # butonlar
        style.map('TButton', background=[('active', '#505050')])  # buton hover efekti
        style.configure('TEntry', background='#404040', foreground='#ffffff', 
                       insertcolor='#ffffff', fieldbackground='#404040')  # metin kutuları
        style.configure('TCombobox', background='#404040', foreground='#ffffff',
                       fieldbackground='#404040', selectbackground='#505050')  # açılır listeler
        style.map('TCombobox', fieldbackground=[('readonly', '#404040')])  # combo hover
        style.configure('TFrame', background='#2b2b2b')  # çerçeveler
        style.configure('TNotebook', background='#2b2b2b')  # sekme konteyner
        style.configure('TNotebook.Tab', background='#404040', foreground='#ffffff')  # sekmeler
        style.map('TNotebook.Tab', background=[('selected', '#505050')])  # aktif sekme

    # Ana GUI bileşenlerini oluşturur  
    def create_widgets(self):
        # Ana sekme konteynerini oluştur
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Sunucu sekmesi - dosya alımı için
        server_frame = ttk.Frame(notebook)
        notebook.add(server_frame, text="Sunucu")
        self.create_server_tab(server_frame)
        
        # İstemci sekmesi - dosya gönderimi için
        client_frame = ttk.Frame(notebook)
        notebook.add(client_frame, text="İstemci")
        self.create_client_tab(client_frame)

        # Ağ analizi sekmesi - performans testleri için
        analysis_frame = ttk.Frame(notebook)
        notebook.add(analysis_frame, text="Ağ Analizi") 
        self.create_analysis_tab(analysis_frame)

        # MITM Proxy sekmesi - güvenlik testleri için
        mitm_frame = ttk.Frame(notebook)
        notebook.add(mitm_frame, text="MITM Proxy")
        self.create_mitm_tab(mitm_frame)

        # Packet Injection sekmesi - sızma testleri için
        injection_frame = ttk.Frame(notebook)
        notebook.add(injection_frame, text="Packet Injection")
        self.create_injection_tab(injection_frame)
    
    # Sunucu sekmesini oluşturur
    def create_server_tab(self, parent):
        # Ana içerik çerçevesi
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık etiketi
        ttk.Label(content_frame, text="Dosya Transfer Sunucusu", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Port bilgileri (sabit değerler - sunucu yapılandırması)
        port_frame = ttk.Frame(content_frame)
        port_frame.pack(pady=10)
        
        ttk.Label(port_frame, text="TCP Port: 5001", font=('Arial', 10)).pack(side='left', padx=20)
        ttk.Label(port_frame, text="UDP Port: 5002", font=('Arial', 10)).pack(side='left', padx=20)
        
        # Sunucu kontrol butonları
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(pady=20)
        
        # Sunucu başlat/durdur butonu
        self.server_btn = ttk.Button(button_frame, text="Sunucuyu Başlat", 
                                   command=self.toggle_server)
        self.server_btn.pack(side='left', padx=10)
        
        # Alınan dosyalar klasörünü açma butonu
        ttk.Button(button_frame, text="Alınan Dosyalar", 
                  command=self.open_received_folder).pack(side='left', padx=10)
        
        # Sunucu durumu göstergesi
        self.server_status = ttk.Label(content_frame, text="Sunucu: Durduruldu", 
                                     foreground='#ff6b6b')
        self.server_status.pack(pady=10)
        
        # Sunucu log alanını oluştur
        self.create_log_section(content_frame, "server")
    
    # İstemci sekmesini oluşturur
    def create_client_tab(self, parent):
        # Ana içerik çerçevesi
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık etiketi
        ttk.Label(content_frame, text="Dosya Gönder", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Dosya seçme bölümü
        file_frame = ttk.Frame(content_frame)
        file_frame.pack(pady=10, fill='x', padx=20)
        
        ttk.Label(file_frame, text="Dosya:").pack(anchor='w')
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(fill='x', pady=5)
        
        # Seçilen dosya yolunu gösteren salt okunur metin kutusu
        ttk.Entry(file_select_frame, textvariable=self.selected_file, 
                 state='readonly').pack(side='left', fill='x', expand=True)
        # Dosya seçme butonu
        ttk.Button(file_select_frame, text="Seç", 
                  command=self.select_file).pack(side='right', padx=(5,0))
        
        # Taşımları ve ayarları içeren çerçeve
        settings_frame = ttk.Frame(content_frame)
        settings_frame.pack(pady=20, fill='x', padx=20)
        
        # Host ve protokol ayarları (birinci satır)
        row1 = ttk.Frame(settings_frame)
        row1.pack(fill='x', pady=5)
        
        # Hedef sunucu adresi
        ttk.Label(row1, text="Host:").pack(side='left')
        ttk.Entry(row1, textvariable=self.host, width=15).pack(side='left', padx=(5,20))
        
        # Protokol seçimi (TCP/UDP/HYBRID)
        ttk.Label(row1, text="Mod:").pack(side='left')
        mode_combo = ttk.Combobox(row1, textvariable=self.mode, 
                                values=['TCP', 'UDP', 'HYBRID'], 
                                width=8, state='readonly')
        mode_combo.pack(side='left', padx=5)
        mode_combo.set('TCP')  # varsayılan protokol
        
        # Port numarası göstergesi (otomatik güncellenir)
        ttk.Label(row1, text="Port:").pack(side='left', padx=(20,5))
        self.port_label = ttk.Label(row1, text="5001")
        self.port_label.pack(side='left')
        
        # Protokol değiştiğinde port numarasını güncelle
        mode_combo.bind('<<ComboboxSelected>>', self.update_port_display)
        
        # Paket boyutu ve gönderim sayısı ayarları (ikinci satır)
        row2 = ttk.Frame(settings_frame)
        row2.pack(fill='x', pady=5)
        
        # Paket boyutu seçimi (byte cinsinden)
        ttk.Label(row2, text="Paket Boyutu:").pack(side='left')
        size_combo = ttk.Combobox(row2, textvariable=self.packet_size, 
                                values=['64', '256', '512', '1024'], 
                                width=10, state='readonly')
        size_combo.pack(side='left', padx=5)
        size_combo.set('1024')  # varsayılan paket boyutu
        
        # Tekrar gönderim sayısı (güvenilirlik için)
        ttk.Label(row2, text="Gönderim Sayısı:").pack(side='left', padx=(20,5))
        count_combo = ttk.Combobox(row2, textvariable=self.transmission_count, 
                                 values=['1', '2', '3', '4', '5'], 
                                 width=5, state='readonly')
        count_combo.pack(side='left', padx=5)
        count_combo.set('1')  # varsayılan gönderim sayısı
        
        # Dosya gönderme butonu
        self.send_btn = ttk.Button(content_frame, text="Dosya Gönder", 
                                 command=self.send_file)
        self.send_btn.pack(pady=20)
        
        # İstemci durumu göstergesi
        self.client_status = ttk.Label(content_frame, text="Hazır", 
                                     foreground='#51cf66')
        self.client_status.pack(pady=10)
        
        # İstemci log alanını oluştur
        self.create_log_section(content_frame, "client")

    # Ağ analizi sekmesini oluşturur
    def create_analysis_tab(self, parent):
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık etiketi
        ttk.Label(content_frame, text="Ağ Performans Analizi", 
                font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Kontrol butonları
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(pady=20)
        
        # Analiz başlatma/durdurma butonu
        self.analysis_btn = ttk.Button(button_frame, text="Analizi Başlat", 
                                    command=self.start_analysis)
        self.analysis_btn.pack(side='left', padx=10)
        
        # Analiz durumu göstergesi
        self.analysis_status = ttk.Label(content_frame, text="Hazır", 
                                        foreground='#51cf66')
        self.analysis_status.pack(pady=10)
        
        # Analiz log alanını oluştur
        self.create_log_section(content_frame, "analysis")

    # Log oluşturma fonksiyonu 
    def create_log_section(self, parent, log_type):
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill='both', expand=True, pady=(10,0))
        
        # Log başlığı
        ttk.Label(log_frame, text="Loglar", font=('Arial', 11, 'bold')).pack(anchor='w')
        
        # Scrollable log metin alanı oluştur
        log_text = scrolledtext.ScrolledText(
            log_frame, 
            height=8,  # görünür satır sayısı
            bg='#1a1a1a',  # arka plan rengi (koyu)
            fg='#ffffff',  # metin rengi (beyaz)
            insertbackground='#ffffff',  # cursor rengi
            font=('Courier', 9)  # monospace font (log için uygun)
        )
        log_text.pack(fill='both', expand=True, pady=5)
        
        # Log text referansını ilgili değişkende sakla
        if log_type == "server":
            self.server_log_text = log_text
        elif log_type == "client":
            self.client_log_text = log_text
        elif log_type == "analysis":
            self.analysis_log_text = log_text
        elif log_type == "mitm":
            self.mitm_log_text = log_text
        elif log_type == "injection":
            self.injection_log_text = log_text
        else:
            raise ValueError("Geçersiz log türü: {}".format(log_type))
        
        # Log temizleme butonu
        clear_btn = ttk.Button(log_frame, text="Logları Temizle", 
                              command=lambda: self.clear_logs(log_type))
        clear_btn.pack(pady=5)

    # Proxy test sekmesini oluşturur
    def create_mitm_tab(self, parent):
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık etiketi
        ttk.Label(content_frame, text="MITM Proxy Testi", 
                font=('Arial', 14, 'bold')).pack(pady=10)
               
        # Test dosyası seçme bölümü
        file_frame = ttk.Frame(content_frame)
        file_frame.pack(pady=10, fill='x', padx=20)
        
        ttk.Label(file_frame, text="Test Dosyası:").pack(anchor='w')
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(fill='x', pady=5)
        
        # Test dosyası yolu gösterimi
        ttk.Entry(file_select_frame, textvariable=self.mitm_target_file, 
                state='readonly').pack(side='left', fill='x', expand=True)
        # Test dosyası seçme butonu
        ttk.Button(file_select_frame, text="Seç", 
                command=self.select_mitm_file).pack(side='right', padx=(5,0))
        
        # Proxy yapılandırma bilgileri
        info_frame = ttk.Frame(content_frame)
        info_frame.pack(pady=10, fill='x', padx=20)
        
        # MITM proxy yapılandırma açıklaması
        info_text = """MITM Proxy Ayarları:
        • Proxy Port: 8080 (Client'ların bağlanacağı port)
        • Hedef Sunucu: 127.0.0.1:5001 (TCP Server)
        • Test Komutu: client.py TCP 127.0.0.1 8080 1024 1 [dosya]"""
        
        ttk.Label(info_frame, text=info_text, font=('Courier', 9)).pack(anchor='w')
        
        # Kontrol butonları
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(pady=20)
        
        # MITM test başlatma butonu
        self.mitm_start_btn = ttk.Button(button_frame, text="MITM Testi Başlat", 
                                    command=self.start_mitm_test)
        self.mitm_start_btn.pack(side='left', padx=10)
        
        # MITM test durdurma butonu
        self.mitm_stop_btn = ttk.Button(button_frame, text="MITM Testi Durdur", 
                                    command=self.stop_mitm_test, state='disabled')
        self.mitm_stop_btn.pack(side='left', padx=10)
        
        # Test durumu göstergesi
        self.mitm_status = ttk.Label(content_frame, text="Hazır", 
                                foreground='#51cf66')
        self.mitm_status.pack(pady=10)
        
        # MITM log alanını oluştur
        self.create_log_section(content_frame, "mitm")

    # Packet Injection sekmesini oluşturur
    def create_injection_tab(self, parent):
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık etiketi
        ttk.Label(content_frame, text="Packet Injection Testi", 
                font=('Arial', 14, 'bold')).pack(pady=10)
               
        # Injection yapılandırma bölümü
        info_frame = ttk.Frame(content_frame)
        info_frame.pack(pady=10, fill='x', padx=20)
        
        # Packet injection yapılandırma açıklaması
        info_text = """Packet Injection Ayarları:
        • Hedef: 127.0.0.1:5002 (UDP Server)
        • Sahte dosya: injected_test.txt
        • Bu test UDP sunucusuna sahte paketler gönderir
        • Paket göndermek için önce UDP sunucusunun çalışıyor olması gerekir."""
        
        ttk.Label(info_frame, text=info_text, font=('Courier', 9)).pack(anchor='w')
        
        # Kontrol butonları
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(pady=20)
        
        # Tek injection çalıştırma butonu
        ttk.Button(button_frame, text="Tek Injection Çalıştır", 
                command=self.run_packet_injection).pack(side='left', padx=10)
    
        # Injection durumu göstergesi
        self.injection_status = ttk.Label(content_frame, text="Hazır", 
                                        foreground='#51cf66')
        self.injection_status.pack(pady=10)
        
        # Injection log alanını oluştur
        self.create_log_section(content_frame, "injection")
        
    # =============================================================================
    # YARDIMCI FONKSİYONLAR
    # =============================================================================
    
    # Protokol seçimine göre port numarasını günceller
    def update_port_display(self, event=None):
        mode = self.mode.get()
        if mode == "TCP":
            self.port_label.config(text="5001")
        elif mode == "UDP":
            self.port_label.config(text="5002")
        else:  # HYBRID - TCP portu kullanır, ağ durumuna göre protokol seçer
            self.port_label.config(text="5001")

    # Gönderilecek dosyayı seçme dialog'unu açar        
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Gönderilecek dosyayı seçin",
            filetypes=[("Tüm dosyalar", "*.*")]  # tüm dosya türlerini kabul et
        )
        if filename:  # dosya seçildiyse
            self.selected_file.set(filename)

    # MITM testi için test dosyasını seçme dialog'unu açar        
    def select_mitm_file(self):
        filename = filedialog.askopenfilename(
            title="Test dosyasını seçin",
            filetypes=[("Tüm dosyalar", "*.*")]
        )
        if filename:
            self.mitm_target_file.set(filename)
            
    # =============================================================================
    # SUNUCU YÖNETİMİ FONKSİYONLARI
    # =============================================================================

    # Sunucu başlatma/durdurma işlemini toggle eder        
    def toggle_server(self):
        if self.server_process is None:  # sunucu çalışmıyorsa
            self.start_server()
        else:  # sunucu çalışıyorsa
            self.stop_server()

    # Dosya transfer sunucusunu başlatır        
    def start_server(self):
        try:
            # server.py dosyasının varlığını kontrol et
            if not Path("server.py").exists():
                messagebox.showerror("Hata", "server.py dosyası bulunamadı!")
                return
                
            # Sunucu başlat - unbuffered output için (-u parametresi)
            self.server_process = subprocess.Popen(
                [sys.executable, "-u", "server.py"],  # Python unbuffered
                stdout=subprocess.PIPE,  # çıktıyı yakala
                stderr=subprocess.STDOUT,  # hataları da çıktıya yönlendir
                universal_newlines=True,  # string çıktı
                bufsize=0  # tampon yok (anlık çıktı)
            )
            
            # Sunucu log okuma thread'ini başlat
            threading.Thread(target=self.read_server_logs, daemon=True).start()
            
            # GUI güncellemeleri
            self.server_btn.config(text="Sunucuyu Durdur")
            self.server_status.config(text="Sunucu: Çalışıyor", foreground='#51cf66')
            self.log("Sunucu başlatıldı", "server")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucu başlatılamadı: {e}")

    # Çalışan sunucuyu durdurur        
    def stop_server(self):
        if self.server_process:
            self.server_process.terminate()  # process'i sonlandır
            self.server_process = None
            
        # GUI güncellemeleri
        self.server_btn.config(text="Sunucuyu Başlat")
        self.server_status.config(text="Sunucu: Durduruldu", foreground='#ff6b6b')
        self.log("Sunucu durduruldu", "server")

    # Sunucu loglarını okur ve GUI'ye yazar
    def read_server_logs(self):
        try:
            # Process çalıştığı sürece çıktıları oku
            while self.server_process and self.server_process.poll() is None:
                line = self.server_process.stdout.readline()  # bir satır oku
                if line:
                    # GUI thread'inde log eklemek için after kullan (thread-safe)
                    self.root.after(0, lambda msg=line.strip(): self.log(f"[SERVER] {msg}", "server"))
        except Exception as e:
            self.root.after(0, lambda: self.log(f"[SERVER] Log okuma hatası: {e}", "server"))

    # Dosya gönderme fonksiyonu
    def send_file(self):
        # Dosya seçilip seçilmediğini kontrol et
        if not self.selected_file.get():
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return
            
        # client.py dosyasının varlığını kontrol et
        if not Path("client.py").exists():
            messagebox.showerror("Hata", "client.py dosyası bulunamadı!")
            return
            
        # Port belirleme işlemi - HYBRID mod da TCP portu kullanır
        mode = self.mode.get()
        if mode == "UDP":
            port = "5002"  # UDP için port numarası
        else:  # TCP veya HYBRID modları için
            port = "5001"  # TCP için port numarası
        
        # İstemci çalıştırma fonksiyonu
        def run_client():
            try:
                # Kullanıcı arayüzü durumunu güncelle
                self.client_status.config(text="Gönderiliyor...", foreground='#ffd43b')
                self.send_btn.config(state='disabled')  # gönder butonunu devre dışı bırak
                
                # Client.py parametrelerine uygun komut oluşturma
                cmd = [
                    sys.executable, "client.py",  # python executable ve script adı
                    mode,                         # bağlantı modu (TCP/UDP/HYBRID)
                    self.host.get(),             # hedef IP adresi
                    port,                        # hedef port numarası
                    self.packet_size.get(),      # paket boyutu
                    self.transmission_count.get(), # gönderim sayısı
                    self.selected_file.get()     # gönderilecek dosya yolu
                ]
                
                # Gönderim başlangıç loglarını kaydet
                self.log(f"[CLIENT] Gönderim başlatılıyor: {Path(self.selected_file.get()).name}", "client")
                self.log(f"[CLIENT] Parametreler: {mode} {self.host.get()}:{port} paket:{self.packet_size.get()} sayı:{self.transmission_count.get()}", "client")
                
                # İstemci scriptini çalıştır ve sonucu yakala
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Gönderim sonucunu kontrol et ve kullanıcıya bildir
                if result.returncode == 0:
                    # Başarılı gönderim durumu
                    self.log(f"[CLIENT] Dosya başarıyla gönderildi: {Path(self.selected_file.get()).name}", "client")
                    if result.stdout:
                        self.log(f"[CLIENT] Çıktı: {result.stdout.strip()}", "client")
                    self.client_status.config(text="Gönderim başarılı!", foreground='#51cf66')
                else:
                    # Başarısız gönderim durumu
                    self.log(f"[CLIENT] Hata: {result.stderr if result.stderr else 'Bilinmeyen hata'}", "client")
                    if result.stdout:
                        self.log(f"[CLIENT] Çıktı: {result.stdout.strip()}", "client")
                    self.client_status.config(text="Gönderim başarısız!", foreground='#ff6b6b')
                    
            except Exception as e:
                # Hata durumunda log kaydet ve kullanıcıyı bilgilendir
                self.log(f"[CLIENT] İstemci hatası: {e}", "client")
                self.client_status.config(text="Hata oluştu!", foreground='#ff6b6b')
            finally:
                # İşlem bittiğinde gönder butonunu tekrar etkinleştir
                self.send_btn.config(state='normal')
                
        # İstemci işlemini ayrı thread'de çalıştır (UI donmasını önlemek için)
        threading.Thread(target=run_client, daemon=True).start()

    # Ağ analizi başlatma fonksiyonu
    def start_analysis(self):
        """Ağ analizini başlat"""
        # network_analysis.py dosyasının varlığını kontrol et
        if not Path("network_analysis.py").exists():
            messagebox.showerror("Hata", "network_analysis.py dosyası bulunamadı!")
            return
            
        # Zaten çalışan analiz varsa durdur
        if hasattr(self, 'analysis_process') and self.analysis_process and self.analysis_process.poll() is None:
            self.analysis_process.terminate()  # süreci sonlandır
            self.analysis_process = None
            self.analysis_btn.config(text="Analizi Başlat")  # buton metnini güncelle
            self.analysis_status.config(text="Analiz durduruldu", foreground='#ff6b6b')
            return
            
        # Analiz çalıştırma fonksiyonu
        def run_analysis():
            try:
                # Kullanıcı arayüzü durumunu güncelle
                self.analysis_status.config(text="Analiz çalışıyor...", foreground='#ffd43b')
                self.analysis_btn.config(text="Analizi Durdur")
                
                # network_analysis.py'yi unbuffered olarak çalıştır (anlık log için)
                self.analysis_process = subprocess.Popen(
                    [sys.executable, "-u", "network_analysis.py"],  # -u parametresi buffering'i kapatır
                    stdout=subprocess.PIPE,    # çıktıyı yakala
                    stderr=subprocess.STDOUT,  # hataları da stdout'a yönlendir
                    universal_newlines=True,   # metin modunda çalış
                    bufsize=1                  # satır bazında tamponlama
                )
                
                # Anlık log okuma thread'ini başlat
                threading.Thread(target=self.read_analysis_logs, daemon=True).start()
                
                # Sürecin bitmesini bekle
                self.analysis_process.wait()
                
                # Analiz sonucuna göre durumu güncelle
                if self.analysis_process.returncode == 0:
                    self.root.after(0, lambda: self.analysis_status.config(
                        text="Analiz tamamlandı", foreground='#51cf66'))
                else:
                    self.root.after(0, lambda: self.analysis_status.config(
                        text="Analiz başarısız!", foreground='#ff6b6b'))
                        
            except Exception as e:
                # Hata durumunda kullanıcıyı bilgilendir
                self.root.after(0, lambda: self.log(f"Analiz hatası: {e}", "analysis"))
                self.root.after(0, lambda: self.analysis_status.config(
                    text="Hata oluştu!", foreground='#ff6b6b'))
            finally:
                # İşlem bittiğinde değişkenleri sıfırla ve buton metnini güncelle
                self.analysis_process = None
                self.root.after(0, lambda: self.analysis_btn.config(text="Analizi Başlat"))
        
        # Analiz işlemini ayrı thread'de çalıştır
        threading.Thread(target=run_analysis, daemon=True).start()

    # Ağ analizi loglarını okur ve GUI'ye yazar
    def read_analysis_logs(self):
        try:
            # Süreç aktif olduğu sürece logları oku
            while self.analysis_process and self.analysis_process.poll() is None:
                line = self.analysis_process.stdout.readline()
                if line:
                    # UI thread'inde log eklemek için after kullan (thread safety için)
                    self.root.after(0, lambda msg=line.strip(): self.log(f"{msg}", "analysis"))
            
            # Süreç bittikten sonra kalan çıktıları da oku
            if self.analysis_process:
                remaining_output = self.analysis_process.stdout.read()
                if remaining_output:
                    for line in remaining_output.strip().split('\n'):
                        if line.strip():
                            self.root.after(0, lambda msg=line.strip(): self.log(f"{msg}", "analysis"))
                            
        except Exception as e:
            # Log okuma hatası durumunda bilgilendir
            self.root.after(0, lambda: self.log(f"Log okuma hatası: {e}", "analysis"))

    # MITM testi için gerekli dosyaları seçme dialogunu açar
    def select_mitm_file(self):
        # Dosya seçim dialogunu aç
        filename = filedialog.askopenfilename(
            title="Test dosyasını seçin",  # dialog başlığı
            filetypes=[("Tüm dosyalar", "*.*")]  # dosya türü filtresi
        )
        if filename:
            self.mitm_target_file.set(filename)  # seçilen dosyayı değişkene ata

    # MITM testi başlatma fonksiyonu
    def start_mitm_test(self):
        # Test dosyasının seçilip seçilmediğini kontrol et
        if not self.mitm_target_file.get():
            messagebox.showwarning("Uyarı", "Lütfen bir test dosyası seçin!")
            return
            
        # Gerekli dosyaların varlığını kontrol et
        if not Path("mitm_proxy.py").exists():
            messagebox.showerror("Hata", "mitm_proxy.py dosyası bulunamadı!")
            return
            
        if not Path("server.py").exists():
            messagebox.showerror("Hata", "server.py dosyası bulunamadı!")
            return
            
        if not Path("client.py").exists():
            messagebox.showerror("Hata", "client.py dosyası bulunamadı!")
            return
        
        # MITM testi çalıştırma fonksiyonu
        def run_mitm_test():
            try:
                # Kullanıcı arayüzü durumunu güncelle
                self.mitm_status.config(text="MITM testi başlatılıyor...", foreground='#ffd43b')
                self.mitm_start_btn.config(state='disabled')  # başlat butonunu devre dışı bırak
                self.mitm_stop_btn.config(state='normal')     # durdur butonunu etkinleştir
                
                # 1. Server başlatma işlemi (arka planda, log gösterme)
                self.log("1. Server başlatılıyor (port 5001)...", "mitm")
                server_process = subprocess.Popen(
                    [sys.executable, "-u", "server.py"],
                    stdout=subprocess.DEVNULL,  # çıktıyı gösterme
                    stderr=subprocess.DEVNULL   # hataları gösterme
                )
                time.sleep(2)  # Server'ın başlaması için bekleme süresi
                
                # 2. MITM Proxy başlatma işlemi (sadece proxy loglarını göster)
                self.log("2. MITM Proxy başlatılıyor (port 8080)...", "mitm")
                mitm_process = subprocess.Popen(
                    [sys.executable, "-u", "mitm_proxy.py"],
                    stdout=subprocess.PIPE,     # çıktıyı yakala
                    stderr=subprocess.STDOUT,   # hataları stdout'a yönlendir
                    universal_newlines=True,    # metin modunda çalış
                    bufsize=1                   # satır bazında tamponlama
                )
                time.sleep(2)  # Proxy'nin başlaması için bekleme süresi
                
                # Süreç referanslarını sakla (daha sonra durdurmak için)
                self.mitm_server_process = server_process
                self.mitm_proxy_process = mitm_process
                
                # Sadece MITM proxy loglarını okumak için thread başlat
                threading.Thread(target=self.read_mitm_proxy_logs, daemon=True).start()
                
                # 3. Client ile test dosyasını gönderme işlemi (arka planda)
                self.log("3. Test dosyası gönderiliyor (proxy üzerinden)...", "mitm")
                time.sleep(1)  # Kısa bekleme süresi
                
                # Client komutunu hazırla
                client_cmd = [
                    sys.executable, "client.py",  # python executable ve script
                    "TCP", "127.0.0.1", "8080",   # TCP modu, localhost, proxy portu
                    "1024", "1",                   # paket boyutu, gönderim sayısı
                    self.mitm_target_file.get()    # test dosyası yolu
                ]
                
                # Client'ı çalıştır ve sonucu kontrol et
                client_result = subprocess.run(client_cmd, capture_output=True, text=True)
                
                # Client sonucuna göre log kaydet
                if client_result.returncode == 0:
                    self.log("✓ Test dosyası başarıyla gönderildi!", "mitm")
                else:
                    self.log(f"✗ Client hatası: {client_result.stderr}", "mitm")
                    
                # Test tamamlama durumunu güncelle
                self.mitm_status.config(text="MITM testi tamamlandı", foreground='#51cf66')
                self.log("\n=== MITM TESİ TAMAMLANDI ===", "mitm")
                self.log("MITM Proxy trafiği yukarıda görüntülendi.", "mitm")
                
            except Exception as e:
                # Hata durumunda kullanıcıyı bilgilendir
                self.log(f"MITM testi hatası: {e}", "mitm")
                self.mitm_status.config(text="Test başarısız!", foreground='#ff6b6b')
            finally:
                # İşlem bittiğinde butonları güncelle
                self.root.after(0, lambda: self.mitm_start_btn.config(state='normal'))
        
        # MITM testini ayrı thread'de çalıştır
        threading.Thread(target=run_mitm_test, daemon=True).start()

    # MITM testi durdurma fonksiyonu
    def stop_mitm_test(self):
        try:
            # Server sürecini durdur
            if hasattr(self, 'mitm_server_process') and self.mitm_server_process:
                self.mitm_server_process.terminate()  # süreci sonlandır
                self.mitm_server_process = None       # referansı temizle
                
            # Proxy sürecini durdur
            if hasattr(self, 'mitm_proxy_process') and self.mitm_proxy_process:
                self.mitm_proxy_process.terminate()   # süreci sonlandır
                self.mitm_proxy_process = None        # referansı temizle
                
            # Durdurma işlemini logla ve durumu güncelle
            self.log("MITM testi durduruldu", "mitm")
            self.mitm_status.config(text="Test durduruldu", foreground='#ff6b6b')
            
        except Exception as e:
            # Durdurma hatası durumunda bilgilendir
            self.log(f"Durdurma hatası: {e}", "mitm")
        finally:
            # Buton durumlarını sıfırla
            self.mitm_start_btn.config(state='normal')   # başlat butonunu etkinleştir
            self.mitm_stop_btn.config(state='disabled')  # durdur butonunu devre dışı bırak

    # MITM proxy loglarını okur ve GUI'ye yazar
    def read_mitm_proxy_logs(self):
        try:
            # Proxy süreci aktif olduğu sürece logları oku
            while (hasattr(self, 'mitm_proxy_process') and 
                self.mitm_proxy_process and 
                self.mitm_proxy_process.poll() is None):
                line = self.mitm_proxy_process.stdout.readline()  # bir satır oku
                if line:
                    # UI thread'inde log eklemek için after kullan
                    self.root.after(0, lambda msg=line.strip(): 
                                self.log(f"[PROXY] {msg}", "mitm"))
        except Exception as e:
            # Proxy log okuma hatası durumunda bilgilendir
            self.root.after(0, lambda: self.log(f"Proxy log hatası: {e}", "mitm"))

    # Packet injection fonksiyonu
    def run_packet_injection(self):
        # packet_injection.py dosyasının varlığını kontrol et
        if not Path("packet_injection.py").exists():
            messagebox.showerror("Hata", "packet_injection.py dosyası bulunamadı!")
            return
            
        # Injection çalıştırma fonksiyonu
        def run_injection():
            try:
                # Kullanıcı arayüzü durumunu güncelle
                self.injection_status.config(text="Injection çalışıyor...", foreground='#ffd43b')
                self.log("[INJECTION] Tek injection başlatılıyor...", "injection")
                
                # packet_injection.py scriptini çalıştır (30 saniye timeout ile)
                result = subprocess.run(
                    [sys.executable, "packet_injection.py"],
                    capture_output=True,  # çıktı ve hataları yakala
                    text=True,           # metin modunda çalış
                    timeout=30           # maksimum çalışma süresi
                )
                
                # Injection sonucunu kontrol et ve kullanıcıya bildir
                if result.returncode == 0:
                    # Başarılı injection durumu
                    self.log("[INJECTION] Tek injection tamamlandı!", "injection")
                    if result.stdout:
                        # Stdout çıktısını satır satır logla
                        for line in result.stdout.strip().split('\n'):
                            if line.strip():
                                self.log(f"[OUTPUT] {line}", "injection")
                    self.injection_status.config(text="Injection tamamlandı", foreground='#51cf66')
                else:
                    # Başarısız injection durumu
                    self.log(f"[INJECTION] Hata: {result.stderr if result.stderr else 'Bilinmeyen hata'}", "injection")
                    if result.stdout:
                        self.log(f"[OUTPUT] {result.stdout}", "injection")
                    self.injection_status.config(text="Injection başarısız!", foreground='#ff6b6b')
                    
            except subprocess.TimeoutExpired:
                # Timeout durumunda bilgilendir
                self.log("[INJECTION] Injection timeout oldu (30s)", "injection")
                self.injection_status.config(text="Timeout!", foreground='#ff6b6b')
            except Exception as e:
                # Genel hata durumunda bilgilendir
                self.log(f"[INJECTION] Çalıştırma hatası: {e}", "injection")
                self.injection_status.config(text="Hata oluştu!", foreground='#ff6b6b')
                
        # Injection işlemini ayrı thread'de çalıştır
        threading.Thread(target=run_injection, daemon=True).start()

    # Alınan dosyalar klasörünü açma fonksiyonu
    def open_received_folder(self):
        # Hedef klasörü belirle ve gerekirse oluştur
        folder = Path("./received_files")
        folder.mkdir(exist_ok=True)  # klasör yoksa oluştur
        
        # İşletim sistemine göre klasör açma komutu çalıştır
        if sys.platform == "win32":
            os.startfile(folder)  # Windows için
        elif sys.platform == "darwin":
            subprocess.run(["open", folder])  # macOS için
        else:
            subprocess.run(["xdg-open", folder])  # Linux için
            
    # Log kaydetme fonksiyonu
    def log(self, message, log_type="server"):
        # Zaman damgası oluşturma işlemi
        from datetime import datetime
        timestamp = datetime.now().strftime('%H:%M:%S')  # saat:dakika:saniye formatı
        
        # Log türüne göre doğru log alanını seçme işlemi
        if log_type == "server":
            log_text = self.server_log_text      # server log alanı
        elif log_type == "client": 
            log_text = self.client_log_text      # client log alanı
        elif log_type == "analysis":
            log_text = self.analysis_log_text    # analiz log alanı
        elif log_type == "mitm":
            log_text = self.mitm_log_text        # mitm log alanı
        elif log_type == "injection":
            log_text = self.injection_log_text   # injection log alanı
        else:
            return  # Geçersiz log türü için işlemi sonlandır
            
        # Mesajı zaman damgası ile birlikte log alanına ekleme
        log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        log_text.see(tk.END)  # Son eklenen mesajı görüntülemek için kaydır
        
    # Log temizleme fonksiyonu
    def clear_logs(self, log_type):
        # Log türüne göre temizlenecek log alanını belirle
        if log_type == "server":
            log_text = self.server_log_text      # server logları
        elif log_type == "client":
            log_text = self.client_log_text      # client logları
        elif log_type == "analysis":
            log_text = self.analysis_log_text    # analiz logları
        elif log_type == "mitm":    
            log_text = self.mitm_log_text        # mitm logları
        elif log_type == "injection":
            log_text = self.injection_log_text   # injection logları
        log_text.delete(1.0, tk.END)  # tüm log içeriğini sil
        
    # Pencere kapatma olayını yakalar ve gerekli temizlik işlemlerini yapar
    def on_closing(self):
        # Server sürecini durdur
        if self.server_process:
            self.stop_server()
        # Analiz sürecini durdur
        if hasattr(self, 'analysis_process') and self.analysis_process:
            self.analysis_process.terminate()
        # MITM server sürecini durdur
        if hasattr(self, 'mitm_server_process') and self.mitm_server_process:
            self.mitm_server_process.terminate()
        # MITM proxy sürecini durdur
        if hasattr(self, 'mitm_proxy_process') and self.mitm_proxy_process:
            self.mitm_proxy_process.terminate()
        # Ana pencereyi kapat
        self.root.destroy()
        
    # Uygulamayı başlatma fonksiyonu
    def run(self):
        # Pencere kapatma olayını yakala
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        # Ana döngüyü başlat
        self.root.mainloop()

# =============================================================================
# PROGRAMIN BAŞLANGIÇ NOKTASI
# =============================================================================
if __name__ == "__main__":
    app = FileTransferUI()  # uygulama örneğini oluştur
    app.run()               # uygulamayı çalıştır