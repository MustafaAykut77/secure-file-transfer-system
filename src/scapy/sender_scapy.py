from scapy.all import IP, UDP, Raw, fragment, send
import time

DST_IP = "127.0.0.1"  # Alıcı IP
DST_PORT = 5001        # Hedef port

# IP/UDP paketi oluştur ve fragment'lara ayır
def create_and_fragment_packet():
    data = b"Bu, IP fragment testi icin gonderilen bir mesajdir." * 2
    ip = IP(dst=DST_IP, id=12345, flags=1, ttl=128)  # TTL, ID ve MF flag ayarlandı
    udp = UDP(sport=40000, dport=DST_PORT)
    pkt = ip / udp / Raw(load=data)
    pkt = IP(bytes(pkt))  # checksum hesapla
    fragments = fragment(pkt, fragsize=48)  # 48 baytlık fragment'lara böl
    return fragments

# Fragment'ları gönder
def send_fragments():
    frags = create_and_fragment_packet()
    print(f"[*] {len(frags)} fragment gönderiliyor...")
    for i, frag in enumerate(frags):
        print(f"[>] Fragment {i+1}: Offset={frag[IP].frag}, MF={frag[IP].flags.MF}, TTL={frag[IP].ttl}, Checksum={frag[IP].chksum}")
        send(frag, verbose=0)
        time.sleep(0.05)

if __name__ == "__main__":
    print("[*] Sender başlatılıyor...")
    send_fragments()
