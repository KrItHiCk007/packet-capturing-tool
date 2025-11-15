# Packet Capturing Tool

A web-based packet sniffer built with Python for real-time network traffic analysis.

## About

This is a lightweight packet capturing tool that monitors network traffic through a web interface. It captures packets from loopback and wireless interfaces, displaying detailed information about each packet in real time. The captured data can be exported to JSON format for further analysis.

## Features

- Real-time packet capture and display
- Web-based user interface for easy access
- Support for multiple network interfaces (lo and wlan0)
- Captures essential packet information:
  - Source and destination IP addresses
  - MAC addresses
  - Port numbers
  - Protocol types (TCP, UDP, ICMP, etc.)
  - Timestamps
  - Raw packet data
- Export captured packets to JSON files
- Beginner-friendly interface

## Requirements

### System Requirements
- Linux, macOS, or Windows
- Root or administrator privileges (required for packet capture)

### Software Dependencies
- Python 3.x
- Flask
- Scapy

## Installation

1. Clone this repository:
```bash
git clone https://github.com/KrItHiCk007/packet-capturing-tool.git
cd packet-capturing-tool
```

2. Install required packages:
```bash
pip install flask scapy
```

3. Make sure you have the necessary permissions to capture packets on your system.

## Usage

1. Run the application with elevated privileges:
```bash
sudo python3 main.py
```

2. Open your browser and go to:
```
http://localhost:5000
```

3. Select your network interface from the available options
4. Click start to begin capturing packets
5. View captured packets in the dashboard
6. Export data if needed

## Project Structure

- main/ - Contains the main application code
- notes/ - Additional documentation and notes
- README.md - This file

## Use Cases

- Network troubleshooting and debugging
- Learning about network protocols
- Monitoring application network behavior
- Educational purposes for understanding packet structures
- Simple network security analysis

## Important Notes

- Always ensure you have permission to capture network traffic
- Only use this tool on networks you own or have explicit authorization to monitor
- Be aware of privacy and legal implications when handling network data
- Capturing packets requires root/administrator access for a reason - use responsibly

## Contributing

Feel free to fork this project and submit pull requests. All contributions are welcome.

## Author

KrItHiCk007

## Acknowledgments

This project uses Flask for the web framework and Scapy for packet manipulation. Thanks to the open source community for these great tools.

