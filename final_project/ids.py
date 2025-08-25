import time
import csv
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from rich.console import Console

console = Console()

# ==========================
# إعدادات عامة
# ==========================
SCAN_THRESHOLD = 20          # عدد المنافذ لفحص Port Scan
SCAN_WINDOW = 10             # نافذة زمنية بالثواني

SSH_ATTEMPTS = 6             # عدد محاولات SSH
SSH_WINDOW = 60              # ثانية

DOS_THRESHOLD = 100          # عدد الحزم الكلي
DOS_WINDOW = 10              # ثانية

# ==========================
# هياكل بيانات
# ==========================
scan_activity = defaultdict(lambda: deque())
ssh_activity = defaultdict(lambda: deque())
traffic_activity = defaultdict(lambda: deque())

# ==========================
# دالة تسجيل التنبيه في CSV
# ==========================
def log_alert(alert_type, src, dst, description):
    with open("alerts.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), alert_type, src, dst, description])

# ==========================
# دالة معالجة الحزم
# ==========================
def handle_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # ---- كشف Port Scan ----
        if TCP in pkt and pkt[TCP].flags == "S":
            now = time.time()
            scan_activity[src].append(now)

            while scan_activity[src] and now - scan_activity[src][0] > SCAN_WINDOW:
                scan_activity[src].popleft()

            if len(scan_activity[src]) >= SCAN_THRESHOLD:
                console.print(f"[red][ALERT][SCAN][/red] {src} → {dst} (≥{SCAN_THRESHOLD} SYN in {SCAN_WINDOW}s)")
                log_alert("SCAN", src, dst, f"{SCAN_THRESHOLD}+ SYN packets in {SCAN_WINDOW}s")

        # ---- كشف Brute Force SSH ----
        if TCP in pkt and pkt[TCP].dport == 22:
            now = time.time()
            ssh_activity[src].append(now)

            while ssh_activity[src] and now - ssh_activity[src][0] > SSH_WINDOW:
                ssh_activity[src].popleft()

            if len(ssh_activity[src]) >= SSH_ATTEMPTS:
                console.print(f"[red][ALERT][SSH-BruteForce][/red] {src} → {dst} (≥{SSH_ATTEMPTS} attempts in {SSH_WINDOW}s)")
                log_alert("SSH-BruteForce", src, dst, f"{SSH_ATTEMPTS}+ SSH attempts in {SSH_WINDOW}s")

        # ---- كشف DoS ----
        now = time.time()
        traffic_activity[src].append(now)

        while traffic_activity[src] and now - traffic_activity[src][0] > DOS_WINDOW:
            traffic_activity[src].popleft()

        if len(traffic_activity[src]) >= DOS_THRESHOLD:
            console.print(f"[red][ALERT][DoS][/red] {src} floods {dst} (≥{DOS_THRESHOLD} pkts in {DOS_WINDOW}s)")
            log_alert("DoS", src, dst, f"{DOS_THRESHOLD}+ packets in {DOS_WINDOW}s")


# ==========================
# Main
# ==========================
def main():
    console.print("[green][INFO][/green] Starting IDS ... Press Ctrl+C to stop.")
    sniff(iface="eth0", filter="ip", prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
