from scapy.all import sniff
import json
import time
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)

# Dummy login data
users = {
    "admin": "admin"
}

# List to store captured packets
captured_packets = []
capture_thread = None
stop_capture = False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username] == password:
            return redirect(url_for('capture'))  # Redirect to capture page
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

# Function to save packets to a JSON file
def save_packets_to_json(file_name='captured_packets.json'):
    with open(file_name, 'w') as file:
        json.dump(captured_packets, file, indent=4)

# Packet callback function
def packet_callback(packet):
    packet_info = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),  # Capture time
        'source_ip': packet[0][1].src if packet.haslayer('IP') else 'N/A',
        'dest_ip': packet[0][1].dst if packet.haslayer('IP') else 'N/A',
        'source_port': packet[0][2].sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A',
        'dest_port': packet[0][2].dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A',
        'source_mac': packet[0].src if packet.haslayer('Ether') else 'N/A',
        'dest_mac': packet[0].dst if packet.haslayer('Ether') else 'N/A',
        'protocol': packet[0][1].proto if packet.haslayer('IP') else 'N/A',
        'length': len(packet),
        'details': str(packet.summary())
    }

    # Append packet data to the list
    captured_packets.append(packet_info)

    # Save packets to JSON file
    save_packets_to_json()

# Background thread to capture packets
def capture_packets(interface):
    global stop_capture
    stop_capture = False
    while not stop_capture:
        sniff(iface=interface, count=10, prn=packet_callback)
        time.sleep(3)  # Wait for 3 seconds before the next capture

@app.route('/capture')
def capture():
    return render_template('capture.html')

# Route for starting packet capture
@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_thread
    data = request.get_json()
    interface = data.get('interfaces', 'wlp2s0')  # Default to 'wlp2s0' if not provided

    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(target=capture_packets, args=(interface,))
        capture_thread.start()

    return jsonify(captured_packets)

# Route for getting captured packets
@app.route('/get_packets', methods=['GET'])
def get_packets():
    return jsonify(captured_packets)

# Route for stopping the capture process
@app.route('/stop_capture', methods=['POST'])
def stop_capture_capture():
    global stop_capture
    stop_capture = True
    return "Capture Stopped"

if __name__ == '__main__':
    app.run(debug=True)

