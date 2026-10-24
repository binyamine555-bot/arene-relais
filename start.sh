#!/bin/sh
# Relais Arene des Origines sur Render (offre gratuite).
# - WebSocket (iPhone / navigateur) sur $PORT, publie par Render en https/wss sur 443.
# - TCP brut (Android) sur 50055, publie sur Internet par un tunnel bore (bore.pub:$BORE_PORT).
# - garde_eveil.py : appelle l'adresse publique toutes les 5 min pour que Render ne mette jamais le service en veille.
PORT="${PORT:-10000}"
BORE_PORT="${BORE_PORT:-50055}"
BORE_SERVER="${BORE_SERVER:-bore.pub}"

python3 -u garde_eveil.py &

( while true; do
    bore local 50055 --to "$BORE_SERVER" --port "$BORE_PORT"
    echo "[tunnel] bore s est arrete, nouvel essai dans 5 s"
    sleep 5
  done ) &

# Le relais est le processus principal : s'il s'arrete, Render relance le conteneur.
exec python3 -u smash_relay.py --port 50055 --ws-port "$PORT" --max 800 \
     --per-ip 5000 --ip-rate 100000 --mail-file /tmp/courrier.json
