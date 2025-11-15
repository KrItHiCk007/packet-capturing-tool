# Packet Capturing Tool

A lightweight, web-based packet capturing and analysis tool built with Python. This application provides real-time network traffic monitoring through an intuitive web dashboard, making network analysis accessible for both beginners and professionals.

## Overview

This project implements a web-based packet sniffer that captures and displays network packets from specific network interfaces (loopback and wireless) in real-time. The tool captures comprehensive packet details including source/destination IP addresses, MAC addresses, ports, protocols, timestamps, and saves the data in JSON format for further analysis.

## Features

- **Real-time Packet Capture**: Monitor network traffic as it happens
- **Web-based Dashboard**: User-friendly interface accessible from any browser
- **Multiple Interface Support**: Capture packets from loopback (lo) and wireless (wlan0) interfaces
- **Comprehensive Packet Details**: View source/destination IPs, MAC addresses, ports, protocols, and timestamps
- **JSON Export**: Automatically save captured packets in JSON format for further analysis
- **Secure Authentication**: Login system to protect access to the capture tool
- **Start/Stop Control**: Easy control over packet capturing sessions

## Prerequisites

Before installing the application, ensure you have the following:

- **Python**: Version 3.x or higher
- **Operating System**: Linux (recommended) or Windows
- **Administrator/Root Access**: Required for packet capturing
- **Web Browser**: Any modern web browser (Chrome, Firefox, Edge, etc.)

## Installation

### Linux

1. Update your system packages:
```bash
sudo apt update
sudo apt upgrade
```

2. Install Python 3 (if not already installed):
```bash
sudo apt install python3
```

3. Install required Python libraries:
```bash
sudo apt install python3-scapy
sudo apt install python3-flask
```

### Windows

1. Verify Python installation:
```cmd
python --version
```

2. If Python is not installed, download and install it from [python.org](https://www.python.org/)

3. Install required libraries using pip:
```cmd
pip install flask
pip install scapy
```

**Note**: On Windows, ensure you run the command prompt as Administrator.

## Usage

### Starting the Application

**Linux:**
```bash
cd main
sudo python3 app.py
```

**Windows:**
```cmd
cd main
python app.py
```
*Make sure to run Command Prompt as Administrator*

### Accessing the Web Interface

1. After starting the application, open your web browser
2. Navigate to the URL displayed in the terminal (typically `http://127.0.0.1:5000`)
3. Log in with the default credentials:
   - **Username**: admin
   - **Password**: admin

### Capturing Packets

1. Once logged in, you'll see the capture interface
2. Select the network interface you want to monitor
3. Click "Start Capture" to begin capturing packets
4. View real-time packet information in the dashboard
5. Click "Stop Capture" when finished

## Configuration

### Network Interface

The application defaults to specific network interfaces. You may need to adjust the interface name based on your system:

**To check your interface name:**

- **Linux**: Run `ifconfig` in the terminal
- **Windows**: Run `ipconfig` in the command prompt

Update the interface name in the application code if necessary (default is set to `wlp2s0` in the code).

## Output

Captured packets are automatically saved to `captured_packets.json` in the following format:
```json
{
  "timestamp": "YYYY-MM-DD HH:MM:SS",
  "source_ip": "xxx.xxx.xxx.xxx",
  "dest_ip": "xxx.xxx.xxx.xxx",
  "source_port": "xxxx",
  "dest_port": "xxxx",
  "source_mac": "xx:xx:xx:xx:xx:xx",
  "dest_mac": "xx:xx:xx:xx:xx:xx",
  "protocol": "x",
  "length": "xxxx",
  "details": "packet summary"
}
```

## Technology Stack

- **Backend**: Python 3.x
- **Web Framework**: Flask
- **Packet Capture**: Scapy
- **Data Format**: JSON
- **Frontend**: HTML/CSS/JavaScript

## Security Notes

- This tool requires administrator/root privileges to capture network packets
- Default credentials should be changed for production use
- Use responsibly and only on networks you own or have permission to monitor
- Packet capturing may be subject to legal restrictions in your jurisdiction

## Troubleshooting

### Permission Denied Error
- Ensure you're running the application with administrator/root privileges
- On Linux, use `sudo` before the command
- On Windows, run Command Prompt as Administrator

### Interface Not Found
- Verify your network interface name using `ifconfig` (Linux) or `ipconfig` (Windows)
- Update the interface name in the code to match your system

### Import Errors
- Ensure all required libraries are installed
- Try reinstalling the dependencies using the installation instructions above

## License

This project is available for educational and personal use.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the issues page if you want to contribute.
