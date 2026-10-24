# Garde le service Render eveille : une requete sur l'adresse publique toutes les 5 minutes
# (Render endort un service gratuit apres 15 min sans trafic entrant).
import os, time, urllib.request
URL = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
time.sleep(60)
while True:
    if URL:
        try:
            with urllib.request.urlopen(URL + "/", timeout=20) as r:
                print("[eveil] %s -> %s" % (URL, r.status), flush=True)
        except Exception as e:
            print("[eveil] erreur %s" % e, flush=True)
    time.sleep(300)
