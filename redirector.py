import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket
import webbrowser
import os
import signal
import sys
from datetime import datetime
import random

HONEYPOT_HOST = "127.0.0.1"
HONEYPOT_PORT = 9999
HTML_FILE = "dashboard.html"

print("✅ Loading trained model and features...")
model = joblib.load("model.pkl")
selected_features = joblib.load("selected_features.pkl")

packet_log = []

# --- Extract features ---
def extract_features(packet):
    try:
        features = {
            "Flow Duration": getattr(packet, "time", 0),
            "Protocol": packet.proto if hasattr(packet, "proto") else 0
        }
        return [features.get(f, 0) for f in selected_features]
    except Exception:
        return [0] * len(selected_features)

# --- Send MALICIOUS packets to honeypot ---
def send_to_honeypot(packet, label):
    if label != "MALICIOUS":
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HONEYPOT_HOST, HONEYPOT_PORT))
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
        sport = packet.sport if hasattr(packet, "sport") else 0
        dport = packet.dport if hasattr(packet, "dport") else 0
        msg = f"MALICIOUS | Src={packet[IP].src}, Dst={packet[IP].dst}, Proto={proto}, Sport={sport}, Dport={dport}"
        s.sendall(msg.encode("utf-8", errors="ignore"))
        s.close()
    except Exception as e:
        print(f"❌ Error sending to honeypot: {e}")

# --- Classify packet ---
def classify_and_redirect(packet):
    if IP not in packet:
        return

    features = extract_features(packet)
    try:
        pred = model.predict([features])[0]
    except:
        pred = 0

    # For demo: random MALICIOUS packets
    label = "MALICIOUS" if pred == 1 or random.random() < 0.05 else "BENIGN"

    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
    sport = packet.sport if hasattr(packet, "sport") else 0
    dport = packet.dport if hasattr(packet, "dport") else 0
    timestamp = datetime.fromtimestamp(getattr(packet, "time", 0)).strftime("%Y-%m-%d %H:%M:%S.%f")
    flow_duration = round(datetime.now().timestamp() - getattr(packet, "time", datetime.now().timestamp()), 6)

    packet_log.append({
        "Timestamp": timestamp,
        "Label": label,
        "Protocol": proto,
        "SrcIP": packet[IP].src,
        "DstIP": packet[IP].dst,
        "SrcPort": sport,
        "DstPort": dport,
        "FlowDuration": flow_duration
    })

    print(f"➡️ Packet classified: {label} | {proto} {packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}")
    send_to_honeypot(packet, label)

# --- Generate HTML Dashboard ---
def generate_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Dashboard</title>
        <style>
            body {font-family: Arial; margin:10px;}
            .container {display: flex; flex-wrap: wrap; gap: 10px;}
            .box {flex: 1 1 45%; padding: 10px; border: 1px solid #ccc; border-radius:5px;}
            h2 {margin-top:0;}
            table {width:100%; border-collapse: collapse;}
            th, td {padding: 5px; text-align:center; font-size:14px;}
            th {background:#4CAF50; color:white;}
            .BENIGN td {background:#d4edda;}
            .MALICIOUS td {background:#f8d7da;}
        </style>
    </head>
    <body>
        <h1>Honeypot Traffic Dashboard</h1>
        <div class="container">
            <div class="box">
                <h2>Normal / BENIGN Packets</h2>
                <table>
                    <tr>
                        <th>Timestamp</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>SrcPort</th><th>DstPort</th><th>FlowDur</th>
                    </tr>
    """
    for pkt in packet_log:
        if pkt['Label'] == "BENIGN":
            html_content += f"<tr class='BENIGN'><td>{pkt['Timestamp']}</td><td>{pkt['SrcIP']}</td><td>{pkt['DstIP']}</td><td>{pkt['Protocol']}</td><td>{pkt['SrcPort']}</td><td>{pkt['DstPort']}</td><td>{pkt['FlowDuration']}</td></tr>"

    html_content += """
                </table>
            </div>
            <div class="box">
                <h2>Malicious Packets</h2>
                <table>
                    <tr>
                        <th>Timestamp</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>SrcPort</th><th>DstPort</th><th>FlowDur</th>
                    </tr>
    """
    for pkt in packet_log:
        if pkt['Label'] == "MALICIOUS":
            html_content += f"<tr class='MALICIOUS'><td>{pkt['Timestamp']}</td><td>{pkt['SrcIP']}</td><td>{pkt['DstIP']}</td><td>{pkt['Protocol']}</td><td>{pkt['SrcPort']}</td><td>{pkt['DstPort']}</td><td>{pkt['FlowDuration']}</td></tr>"

    html_content += """
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"🌐 Dashboard saved to {HTML_FILE}")
    webbrowser.open(f"file://{os.path.abspath(HTML_FILE)}")

# --- Stop sniffing ---
def stop_sniff(signal_received, frame):
    print("\n🛑 Packet capture stopped by user")
    generate_dashboard()
    sys.exit(0)

signal.signal(signal.SIGINT, stop_sniff)

# --- Main Sniffer ---
if __name__ == "__main__":
    print("📡 Starting packet capture... (CTRL+C to stop)")
    sniff(prn=classify_and_redirect, store=0)
