from scapy.all import sniff, IP

fragment_data = {}
TARGET_ID = 12345  # Sadece gönderdiğin paket ID'si ile filtreleme yap

def extract_text_from_combined(data):
    for i in range(len(data)):
        try:
            return data[i:].decode("utf-8")
        except UnicodeDecodeError:
            continue
    return "[!] Metin çözülemedi."

# Her paketi işle
def process_packet(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        if ip.id != TARGET_ID:
            return  # Başka paketleri geç
        ident = ip.id
        offset = ip.frag
        mf_flag = ip.flags.MF
        length = ip.len
        print(f"[+] IP Packet: ID={ident}, Offset={offset}, MF={mf_flag}, Len={length}, Checksum={ip.chksum}")
        if ident not in fragment_data:
            fragment_data[ident] = []
        fragment_data[ident].append((offset, bytes(ip.payload)))

# Sniff işlemini başlat ve fragment'ları birleştir
def analyze_fragments(timeout=5):
    print("[*] Sadece ID=12345 olan IP fragmentlar dinleniyor...")
    try:
        sniff(prn=process_packet, timeout=timeout, store=False, iface="\\Device\\NPF_Loopback")
    except PermissionError:
        print("[!] Yönetici olarak çalıştırılmalı!")

    print("\n[*] Fragment birleştirme sonucu:")
    for ident, frags in fragment_data.items():
        sorted_frags = sorted(frags, key=lambda x: x[0])
        combined = b"".join(frag[1] for frag in sorted_frags)
        print(f"[✓] ID={ident} - {len(frags)} fragment birleştirildi - Toplam boyut: {len(combined)} byte")

        print("[📦] Mesaj içeriği:", extract_text_from_combined(combined))

if __name__ == "__main__":
    analyze_fragments()
