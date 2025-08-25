import time
import random
import logging
from datetime import datetime

# إعداد اللوج
logging.basicConfig(
    filename="access.log",
    filemode="a",
    format="%(message)s",
    level=logging.INFO
)

# بعض الـ User-Agents العادية والمشبوهة
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Chrome/120.0.0.0 Safari/537.36",
    "Firefox/115.0",
    "Safari/605.1.15"
]

SUSPICIOUS_AGENTS = [
    "sqlmap/1.6.12",      # أداة SQL Injection
    "Nmap Scripting Engine", 
    "Nikto/2.5.0",        # أداة Web Scan
    "curl/7.81.0"         # curl كثيف
]

# بعض الـ Endpoints
ENDPOINTS = [
    "/index.html",
    "/login",
    "/register",
    "/products",
    "/search?q=phone",
    "/cart",
]

# توليد عنوان IP عشوائي
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# صيغة Apache Combined Log
def format_log(ip, method, endpoint, agent, status=200):
    now = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{now}] "{method} {endpoint} HTTP/1.1" {status} {random.randint(200,5000)} "-" "{agent}"'

# محاكاة نشاط طبيعي
def normal_traffic():
    ip = random_ip()
    agent = random.choice(NORMAL_AGENTS)
    endpoint = random.choice(ENDPOINTS)
    line = format_log(ip, "GET", endpoint, agent, 200)
    logging.info(line)

# محاكاة Brute Force على /login
def brute_force():
    ip = random_ip()
    for _ in range(10):  # محاولات كثيرة
        line = format_log(ip, "POST", "/login", random.choice(NORMAL_AGENTS), 401)
        logging.info(line)
        time.sleep(0.2)

# محاكاة DoS (Burst traffic)
def dos_attack():
    ip = random_ip()
    agent = "curl/7.81.0"
    for _ in range(150):  # عدد كبير من الطلبات
        line = format_log(ip, "GET", "/index.html", agent, 200)
        logging.info(line)

# محاكاة User-Agent مشبوه
def suspicious_agent():
    ip = random_ip()
    agent = random.choice(SUSPICIOUS_AGENTS)
    endpoint = random.choice(ENDPOINTS)
    line = format_log(ip, "GET", endpoint, agent, 200)
    logging.info(line)

# ==========================
# Main
# ==========================
if __name__ == "__main__":
    print("[INFO] Generating mixed traffic into access.log ... Ctrl+C to stop")
    try:
        while True:
            choice = random.randint(1, 20)

            if choice <= 12:   # 60% ترافيك عادي
                normal_traffic()
            elif choice <= 15: # 15% brute force
                brute_force()
            elif choice <= 18: # 15% DoS
                dos_attack()
            else:              # 10% User-Agent مشبوه
                suspicious_agent()

            time.sleep(random.uniform(0.5, 2.0))

    except KeyboardInterrupt:
        print("\n[INFO] Stopped traffic generator.")
