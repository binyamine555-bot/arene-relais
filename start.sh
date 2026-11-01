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
# 7o : classement du Combat du jour dans /tmp/classement (efface si Render redemarre le conteneur : le classement
# du jour repart a zero, accepte pour un classement du jour). Limites par IP desactivees : derriere bore, tous les
# Android ont la meme IP (127.0.0.1) ; restent la limite par joueur, le plafond global par minute et la signature.
# Disque persistant (offre payante) : remplacer /tmp/classement par le point de montage, ex. /var/data/classement.
exec python3 -u smash_relay.py --port 50055 --ws-port "$PORT" --max 800 \
     --per-ip 5000 --ip-rate 100000 --mail-file /tmp/courrier.json \
     --classement-dir "${CLASSEMENT_DIR:-/tmp/classement}" --classement-jours 30 \
     --classement-ip-scores 0 --classement-ip-lectures 0
