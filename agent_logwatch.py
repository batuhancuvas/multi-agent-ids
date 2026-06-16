# agent_logwatch.py
# LOG IZLEME AJANI (ek sinyal kaynagi).
# /var/log/auth.log dosyasini okuyup SSH'a yapilan basarisiz giris
# denemelerini ("Failed password") sayar. Bir IP'den kisa surede cok
# sayida basarisiz deneme gelirse, bunu SSH brute-force icin EK SINYAL
# olarak bildirir. Boylece saldiri hem ag trafiginden (port 22 davranisi)
# hem de sistem logundan dogrulanir -> daha guvenilir tespit.

import re
import os
from collections import defaultdict

AUTH_LOG = "/var/log/auth.log"

class LogWatchAgent:
    def __init__(self):
        # Her IP icin auth.log'da gorulen basarisiz giris sayisi
        self.failed_counts = defaultdict(int)
        self.last_position = 0   # dosyada en son okudugumuz yer
        # "Failed password for ... from <IP>" satirlarini yakalayan desen
        self.pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        # Baslangicta dosyanin sonuna git (eski kayitlari sayma)
        try:
            self.last_position = os.path.getsize(AUTH_LOG)
        except OSError:
            self.last_position = 0

    def check(self):
        """auth.log'da yeni eklenen satirlari oku, basarisiz giris say.
        Doner: {ip: basarisiz_deneme_sayisi} (sadece bu turda artanlar)."""
        new_failures = defaultdict(int)
        try:
            with open(AUTH_LOG, "r") as f:
                f.seek(self.last_position)      # en son kaldigimiz yerden oku
                for line in f:
                    m = self.pattern.search(line)
                    if m:
                        ip = m.group(1)
                        self.failed_counts[ip] += 1
                        new_failures[ip] += 1
                self.last_position = f.tell()   # yeni konumu kaydet
        except OSError:
            pass
        return new_failures

    def get_total_failures(self, ip):
        """Bir IP'nin toplam basarisiz giris sayisini dondur."""
        return self.failed_counts.get(ip, 0)