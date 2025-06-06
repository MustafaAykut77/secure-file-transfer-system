# Secure File Transfer System

A comprehensive secure file transfer system with TCP/UDP protocols, hybrid switching, encryption, and network analysis capabilities.

## 🚀 Features

### Core Functionality
- **Secure File Transfer**: AES/RSA hybrid encryption for data transmission
- **Protocol Support**: TCP, UDP, and intelligent hybrid switching based on network conditions
- **Authentication**: Password-based client authentication
- **File Integrity**: SHA-256 hash verification
- **GUI Interface**: User-friendly graphical interface for easy operation

### Security Features
- **Hybrid Encryption**: AES for data encryption, RSA for key encryption
- **MITM Protection**: Built-in resistance against Man-in-the-Middle attacks
- **Packet Injection Defense**: Protection against malicious packet injection
- **Safe Filename Validation**: Prevention of directory traversal attacks

### Network Analysis
- **Latency Measurement**: Real-time network latency analysis
- **Bandwidth Testing**: Network throughput measurement using iPerf3
- **Packet Loss Simulation**: Network condition testing
- **Performance Monitoring**: Comprehensive network statistics

### Advanced Features
- **Low-level Packet Manipulation**: IP header modification using Scapy
- **Packet Fragmentation**: Manual packet splitting and reassembly
- **Network Forensics**: Traffic capture and analysis capabilities
- **Multi-threading**: Concurrent client handling

## 📁 Project Structure

```
/
├── keys/
│   ├── private.pem          # RSA private key
│   └── public.pem           # RSA public key
├── socket/
│   ├── iperf3/
│   │   └── iperf3.exe       # Bandwidth testing tool
│   ├── client.py            # File transfer client
│   ├── server.py            # File transfer server
│   ├── generator.py         # RSA key pair generator
│   ├── network_analysis.py  # Network performance analyzer
│   ├── mitm_proxy.py        # MITM attack simulator
│   ├── packet_injection.py  # Packet injection testing
│   └── secure_transfer_gui.py # Graphical user interface
└── scapy/
    ├── receiver_scapy.py    # Packet fragment receiver
    └── sender_scapy.py      # Packet fragment sender
```

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- Required Python packages:
  ```bash
  pip install pycryptodome scapy tkinter
  ```
- iPerf3 (for bandwidth testing)

### Setup
1. Clone the repository
2. Generate RSA key pairs:
   ```bash
   python socket/generator.py
   ```
3. Run the GUI application:
   ```bash
   python socket/secure_transfer_gui.py
   ```

## 🖥️ Usage

### GUI Mode (Recommended)
1. Launch the GUI: `python socket/secure_transfer_gui.py`
2. Select files to transfer using the interface
3. Choose transfer protocol (TCP/UDP/Hybrid)
4. Monitor transfer progress in real-time

### Command Line Mode

#### Server
```bash
python socket/server.py
```

#### Client
```bash
python socket/client.py --file <filename> --protocol <tcp/udp/hybrid>
```

### Network Analysis
```bash
python socket/network_analysis.py
```

## 📊 Network Analysis Tools

### Latency Testing
- Ping-based RTT measurement
- Min/Max/Average latency calculation
- Packet loss detection

### Bandwidth Testing
- iPerf3 integration
- Upload/Download speed measurement
- Real-time throughput monitoring

### Protocol Testing
- TCP reliability testing
- UDP performance testing
- Hybrid switching optimization

## 🧪 Security Testing

### MITM Simulation
```bash
python socket/mitm_proxy.py
```

### Packet Injection Testing
```bash
python socket/packet_injection.py
```

### Low-level Packet Analysis
```bash
python scapy/sender_scapy.py    # Send fragmented packets
python scapy/receiver_scapy.py  # Capture and reassemble
```

## ⚡ Performance

### Hybrid Mode
- Automatic protocol selection based on network conditions
- Low latency: UDP preferred
- High latency/packet loss: TCP preferred
- Real-time switching capability

### Optimization
- Multi-threaded server architecture
- Efficient packet chunking
- Memory-optimized encryption
- Connection pooling

## 🚧 Limitations

- Scapy components work independently from socket components
- No AI-based network condition analysis (potential future enhancement)
- Limited to local network testing scenarios

## 🔮 Future Enhancements

- Integration of Scapy packet manipulation with socket operations
- AI-based protocol selection algorithms
- Enhanced GUI with real-time network visualization
- Support for multiple file transfers
- Advanced forensics capabilities

## 📝 License

This project is developed for educational purposes in Computer Networks course.

## 🤝 Contributing

This is an academic project. For improvements or suggestions, please create an issue or submit a pull request.

## 📞 Support

For questions or support, please refer to the project documentation or create an issue in the repository.

---

**Developed by**: Mustafa AYKUT (22360859028)  
**Course**: Computer Networks - Term Project
