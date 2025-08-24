import socket
import threading
from datetime import datetime
import sys
import io

# Force UTF-8 console output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HOST = "127.0.0.1"
PORT = 9999

HONEYPOT_LOG = "honeypot_log.txt"
MALICIOUS_LOG = "malicious_log.txt"

def log_message(message, malicious=False):
    """Save honeypot logs in UTF-8"""
    with open(HONEYPOT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {message}\n")
    if malicious:
        with open(MALICIOUS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | {message}\n")

def handle_client(conn, addr):
    try:
        data = conn.recv(2048).decode("utf-8", errors="ignore")
        if data:
            if "MALICIOUS" in data:
                print(f"🚨 MALICIOUS TRAFFIC from {addr}: {data}")
                log_message(f"{addr} → {data}", malicious=True)
            else:
                # BENIGN packets are logged but not printed
                log_message(f"{addr} → {data}")
            conn.sendall("✅ Honeypot received your packet\n".encode("utf-8"))
    except Exception as e:
        print(f"❌ Error with {addr}: {e}")
    finally:
        conn.close()

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    server.settimeout(1)
    print(f"🛡️ Honeypot running on {HOST}:{PORT} ... (CTRL+C to stop)")

    try:
        while True:
            try:
                conn, addr = server.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n🛑 Honeypot stopped by user")
    finally:
        server.close()

if __name__ == "__main__":
    start_honeypot()
