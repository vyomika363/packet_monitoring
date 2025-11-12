# Packet Monitor

🔍 **eBPF-based packet monitoring tool with web dashboard**

A powerful network packet drop monitoring system that uses eBPF (Extended Berkeley Packet Filter) to capture and analyze dropped packets at the kernel level, with a real-time web dashboard for visualization.

## Features

- **Kernel-level monitoring** using eBPF kprobes on `kfree_skb`
- **Zero-copy data transfer** via BPF ring buffers
- **Real-time packet drop detection** with metadata extraction
- **Web-based dashboard** with live updates using WebSockets
- **Multiple interfaces**: C (libbpf) and Python (BCC) implementations
- **Low overhead** monitoring without packet injection

## Architecture

```
packet-monitor/
├── src/
│   ├── bpf/
│   │   ├── packet_monitor.bpf.c       # eBPF kernel-side code
│   │   └── vmlinux.h                   # Kernel type definitions
│   ├── packet_monitor.c                # Userspace C program (libbpf)
│   ├── packet_monitor.h                # Shared header
│   └── packet_monitor_cli.py           # Python CLI wrapper (BCC version)
├── dashboard/
│   ├── app.py                          # Flask web dashboard
│   ├── static/
│   │   └── dashboard.js                # Frontend JavaScript
│   └── templates/
│       └── index.html                  # Dashboard UI
├── Makefile
├── requirements.txt
└── README.md
```

## Prerequisites

### System Requirements
- Linux kernel 5.4+ with BTF (BPF Type Format) support
- Root/sudo privileges (required for eBPF programs)

### Dependencies

**For C implementation (libbpf):**
```bash
sudo apt-get install clang llvm libelf-dev libbpf-dev bpftool
```

**For Python implementation (BCC):**
```bash
sudo apt-get install python3 python3-pip bpfcc-tools python3-bpfcc
```

**For Web Dashboard:**
```bash
pip3 install -r requirements.txt
```

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/Destructor169/packet-monitor.git
cd packet-monitor
```

### 2. Generate vmlinux.h (required for libbpf)
```bash
make generate-vmlinux
```

### 3. Build the C implementation
```bash
make all
```

### 4. Install Python dependencies (for dashboard)
```bash
pip3 install -r requirements.txt
```

## Usage

### Option 1: C Implementation (libbpf)

```bash
sudo ./packet_monitor
```

Output example:
```
[1234567890] PID: 1234, COMM: curl
  192.168.1.10:54321 -> 8.8.8.8:443, Proto: 6, Len: 1500
```

### Option 2: Python CLI (BCC)

```bash
sudo python3 src/packet_monitor_cli.py
```

### Option 3: Web Dashboard

1. Start the dashboard:
```bash
cd dashboard
sudo python3 app.py
```

2. Open browser to `http://localhost:5000`

3. Click **"Start Monitoring"** to begin capturing packet drops

## How It Works

### 1. eBPF Kernel Program
The eBPF program attaches to the `kfree_skb` kernel function, which is called whenever a packet is dropped. It extracts:
- Source/Destination IP addresses
- Source/Destination ports
- Protocol (TCP/UDP/etc.)
- Packet length
- Process ID and name

### 2. Userspace Program
Reads events from the BPF ring buffer and processes them for display or forwarding to the dashboard.

### 3. Web Dashboard
Provides real-time visualization using:
- **Flask** for the web server
- **Socket.IO** for real-time updates
- **JavaScript** for dynamic UI updates

## API Endpoints

- `GET /` - Dashboard UI
- `GET /api/stats` - Current statistics (JSON)
- `GET /api/events` - Recent events (JSON)
- WebSocket events:
  - `connect` - Client connection
  - `start_monitor` - Start packet monitoring
  - `stop_monitor` - Stop packet monitoring
  - `packet_event` - Real-time packet drop event

## Makefile Targets

```bash
make all              # Build eBPF program and userspace binary
make bpf              # Build eBPF program only
make user             # Build userspace binary only
make generate-vmlinux # Generate vmlinux.h from kernel BTF
make install          # Install binaries to system
make clean            # Remove build artifacts
make help             # Show available targets
```

## Troubleshooting

### Permission Denied
Ensure you're running with sudo:
```bash
sudo ./packet_monitor
```

### BTF Not Available
Check if your kernel supports BTF:
```bash
ls /sys/kernel/btf/vmlinux
```

If not available, upgrade to a newer kernel (5.4+).

### BPF Program Load Failed
Verify eBPF is enabled:
```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled
```

### Dashboard Not Connecting
Check if port 5000 is available:
```bash
sudo lsof -i :5000
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

GPL License - See source files for details.

## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf](https://github.com/libbpf/libbpf)
- [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- [Linux Kernel kfree_skb](https://www.kernel.org/doc/html/latest/networking/kfree_skb.html)

## Author

**Destructor169**

---

⚡ Built with eBPF for maximum performance and minimal overhead
