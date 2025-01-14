# Packet Sniffer in Zig

This project is a simple **network packet sniffer** written in Zig using **libpcap**. It captures packets from a specified network interface, displays the timestamp, source/destination MAC addresses, IP addresses, and the protocol type.

## Features
- Capture live network traffic using `libpcap`
- Display packet timestamps in `YYYY-MM-DD HH:MM:SS` format
- Print source and destination MAC addresses
- Parse and display IPv4 source and destination IP addresses
- Identify the protocol type (TCP/UDP/ICMP)

## Prerequisites
Ensure you have the following installed:
- **Zig** (latest stable version) [Download here](https://ziglang.org/download/)
- **libpcap** (`sudo apt install libpcap-dev` for Ubuntu, `brew install libpcap` for macOS)

## Getting Started
### Clone the repository:
```bash
git clone https://github.com/yousif-wali/packet-sniffer-zig
cd packet-sniffer-zig
```

### Build the Project:
```bash
zig build-exe main.zig -lc -lpcap
```
or
```bash
zig build main.zig -lc -lpcap
```

### Run the Packet Sniffer (with sudo if required):
```bash
sudo ./main
```

### Example Output:
```plaintext
Starting packet capture on: en0
Timestamp: 2025-01-15 15:23:45
Packet captured with length: 86
Source MAC: 7a:d2:fb:fa:58:c2
Destination MAC: 33:33:ff:12:30:ad
Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Protocol: 6
```

## How It Works
1. **Initialization:**
   - Opens the specified network interface.
2. **Packet Capture:**
   - Uses `pcap_loop` to continuously capture packets.
3. **Packet Parsing:**
   - Parses Ethernet and IPv4 headers.
4. **Timestamp Handling:**
   - Converts packet timestamps using `strftime`.

## Troubleshooting
- If you get `permission denied` errors, try running with `sudo`.
- Ensure the correct network interface is specified in the `main.zig` file.

## Contributions
Feel free to fork this repository and submit pull requests for improvements, such as:
- Adding IPv6 support
- Filtering packets by protocol
- Saving captured packets to a file

## License
This project is licensed under the MIT License.

---

**Happy Sniffing!** 🚀
