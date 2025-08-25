import subprocess
import time
import os

# اسم الملفات
GENERATOR = "generate_access_log.py"
IDS = "ids.py"

def main():
    # تأكد أن الملفات موجودة
    if not os.path.exists(GENERATOR):
        print(f"[ERROR] {GENERATOR} غير موجود!")
        return
    if not os.path.exists(IDS):
        print(f"[ERROR] {IDS} غير موجود!")
        return

    print("[INFO] تشغيل Traffic Generator + IDS ...")

    # شغل مولّد الترافيك في الخلفية
    gen_proc = subprocess.Popen(["python3", GENERATOR])

    # انتظر شوية لحد ما يبدأ يولّد بيانات
    time.sleep(3)

    try:
        # شغل IDS (يراقب logs باستمرار)
        subprocess.run(["python3", IDS])
    except KeyboardInterrupt:
        print("\n[INFO] إيقاف IDS ...")
    finally:
        # أوقف المولد
        gen_proc.terminate()
        print("[INFO] تم إيقاف كل العمليات.")

if __name__ == "__main__":
    main()
