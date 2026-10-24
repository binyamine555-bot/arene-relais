#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Arene des Origines - relais en ligne (smash_relay.py)
=====================================================

A quoi il sert
--------------
Les telephones se connectent tous a ce petit serveur (TCP, port 50055 par
defaut). Il sert a :
  - savoir quels amis sont en ligne (presence) ;
  - faire passe-plat entre deux joueurs (messages, appels, paquets de jeu) ;
  - garder les messages des absents (en memoire, et dans un fichier JSON
    si on le demande avec --mail-file) ;
  - mettre deux joueurs face a face : PARTIE RAPIDE (deux joueurs en
    attente) ou SALON (un code a 5 chiffres).

Ce qu'il NE fait PAS
--------------------
Il ne lit rien de ce qu'il transporte : messages et paquets de jeu sont
chiffres de bout en bout entre les deux joueurs (cles Curve25519 derivees
des identites Ed25519). Il ne voit que des identifiants et des blocs opaques.
L'identification se fait par SIGNATURE Ed25519 d'un defi aleatoire :
impossible de se faire passer pour quelqu'un d'autre.

Protocole (une ligne JSON par message, terminee par "\n", 64 Ko max)
--------------------------------------------------------------------
  relais -> jeu  {"t":"hello","pv":2,"challenge":"<32 hex>"}
  jeu -> relais  {"t":"auth","pid":..,"pk":<b64>,"sig":<b64>,"n":<nom>}
  relais -> jeu  {"t":"auth_ok","pid":..,"pv":2,"features":["match"]}
                 ou {"t":"auth_ko","why":"id"|"sig"|"bad"|"full"}
                 (puis le courrier en attente : {"t":"from",...,"late":1})
  who    -> who_ok {"on":[...],"names":{pid:nom}}
  to     {"pid","d","store","ack"} -> chez l'autre {"t":"from","pid","n","d"}
                 et pour l'envoyeur, si ack : {"t":"sent","pid","ok",("stored")}
  quick  {"pv","pm","n"} -> queued | matched
  salon  {"code","pv","pm","n"} -> salon_ok | salon_ko {"why":"pris"|"code"}
  join   {"code","pv","pm","n"} -> matched | join_ko {"why":"inconnu"|"soi"|"version"}
  matched {"pid","n","pk","host":1|0}  (envoye aux deux joueurs)
  cancel -> cancel_ok ; ping -> pong ; stats -> stats_ok
  pair {"pid"} : (jeu -> relais) rappel de l'adversaire apres une reconnexion
  gone {"pid"} / back {"pid"} : l'adversaire de la partie en cours vient de
                 perdre / retrouver sa connexion au relais (v15.1, ignore par
                 les jeux plus anciens)
WebSocket (version navigateur, port 50056) : meme protocole, une ligne JSON
par message WebSocket (texte). En wss:// avec --ws-cert / --ws-key.
Le relais envoie aussi une ligne vide toutes les 25 s (le jeu l'ignore) :
elle garde ouvertes les connexions derriere les box et les reseaux 4G/5G.

Lancement
---------
    python3 smash_relay.py                       # port 50055
    python3 smash_relay.py --port 8080 --max 300 --ws-port 0     # sans WebSocket
    python3 smash_relay.py --ws-cert /etc/letsencrypt/live/X/fullchain.pem \
                           --ws-key /etc/letsencrypt/live/X/privkey.pem  # wss:// (iPhone)
    python3 smash_relay.py --mail-file /var/lib/smash-relay/courrier.json

Aucune dependance : uniquement la bibliotheque standard (Python 3.7+).
"""
import argparse
import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import signal
import socket
import sys
import time

PROTO = 2                    # version annoncee dans "hello" (celle du relais d'origine)
MAX_LINE = 64 * 1024         # un message ne depasse jamais cette taille (comme le jeu)
HELLO_TIMEOUT = 20.0         # secondes pour s'identifier apres la connexion
IDLE_MAX = 900.0             # deconnexion apres ce silence (option --idle)
HEARTBEAT = 25.0             # ligne vide envoyee a chaque client, en secondes
RATE_MAX = 240               # messages par seconde et par client (rafale x2)
RATE_KICK = 3000             # au-dela de ce nombre de refus en 10 s : deconnexion
WRITE_BUF_MAX = 1024 * 1024  # client qui ne lit plus : deconnecte au-dela
MAX_MAIL = 40                # messages gardes par joueur absent
MAIL_TTL = 7 * 24 * 3600     # au-dela, on oublie
MAIL_ITEM_MAX = 8 * 1024     # taille max d'un message garde
MAIL_TOTAL_MAX = 20000       # messages gardes en tout (les plus vieux partent)
MAIL_PER_SENDER_HOUR = 120   # messages qu'un joueur peut deposer par heure
SALON_TTL = 3600             # un salon ouvert reste au plus 1 h
WHO_MAX = 64
ID_LEN = 24
HEX = set('0123456789abcdef')

log = logging.getLogger('relais')


# ------------------------------------------------------------
# Verification de signature Ed25519 (le meme calcul que le jeu)
# ------------------------------------------------------------
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha(b):
    return hashlib.sha512(b).digest()


def _xrec(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_B = (_xrec(_BY) % _Q, _BY, 1, _xrec(_BY) * _BY % _Q)


def _add(P, Qp):
    A = (P[1] - P[0]) * (Qp[1] - Qp[0]) % _Q
    B = (P[1] + P[0]) * (Qp[1] + Qp[0]) % _Q
    C = 2 * P[3] * Qp[3] * _D % _Q
    Dd = 2 * P[2] * Qp[2] % _Q
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _Q, G * H % _Q, F * G % _Q, E * H % _Q)


def _mul(P, e):
    R = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            R = _add(R, P)
        P = _add(P, P)
        e >>= 1
    return R


def _enc(P):
    zi = pow(P[2], _Q - 2, _Q)
    x = P[0] * zi % _Q
    y = P[1] * zi % _Q
    return int.to_bytes((y & ~(1 << 255)) | ((x & 1) << 255), 32, 'little')


def _dec(b):
    n = int.from_bytes(b, 'little')
    y = n & ~(1 << 255)
    if y >= _Q:
        raise ValueError('y')
    x = _xrec(y)
    if x & 1 != (n >> 255) & 1:
        x = _Q - x
    P = (x, y, 1, x * y % _Q)
    if (-P[0] * P[0] + P[1] * P[1] - P[2] * P[2] - _D * P[3] * P[3]) % _Q != 0:
        raise ValueError('point')
    return P


def ed25519_verify(msg, sig, pk):
    try:
        if len(sig) != 64 or len(pk) != 32:
            return False
        R = _dec(sig[:32])
        A = _dec(pk)
        S = int.from_bytes(sig[32:], 'little')
        if S >= _L:
            return False
        k = int.from_bytes(_sha(sig[:32] + pk + msg), 'little') % _L
        return _enc(_mul(_B, S)) == _enc(_add(R, _mul(A, k)))
    except Exception:
        return False


def _b64d(txt):
    return base64.b64decode(str(txt).encode('ascii'), validate=True)


def pid_valide(p):
    return isinstance(p, str) and len(p) == ID_LEN and set(p) <= HEX


def _entier(v, defaut):
    try:
        return int(v)
    except (TypeError, ValueError):
        return defaut


def compatibles(pv_a, pm_a, pv_b, pm_b):
    """Deux jeux jouent ensemble si chacun comprend le protocole de l'autre."""
    return pv_a >= pm_b and pv_b >= pm_a


def _nom(v, defaut='?'):
    if not isinstance(v, str):
        return defaut
    v = ''.join(ch for ch in v if ch.isprintable()).strip()[:14]
    return v or defaut


# ------------------------------------------------------------
# Boite aux lettres des absents
# ------------------------------------------------------------
class Courrier(object):
    def __init__(self, chemin=None):
        self.chemin = chemin
        self.boites = {}          # pid destinataire -> [ {from, n, d, t} ]
        self.depots = {}          # pid envoyeur -> [instants des depots]
        self.sale = False
        if chemin:
            self.charger()

    def total(self):
        return sum(len(b) for b in self.boites.values())

    def charger(self):
        try:
            with open(self.chemin, 'r', encoding='utf-8') as f:
                data = json.load(f)
            boites = data.get('boites', {}) if isinstance(data, dict) else {}
            for pid, lst in boites.items():
                if pid_valide(pid) and isinstance(lst, list):
                    ok = [m for m in lst if isinstance(m, dict) and pid_valide(m.get('from'))]
                    if ok:
                        self.boites[pid] = ok[-MAX_MAIL:]
            self.purger()
            log.info('courrier charge depuis %s : %d message(s) pour %d joueur(s)',
                     self.chemin, self.total(), len(self.boites))
        except FileNotFoundError:
            log.info('courrier : %s sera cree au premier message garde', self.chemin)
        except Exception as e:
            log.warning('courrier : lecture de %s impossible (%s), on repart a vide',
                        self.chemin, e)

    def sauver(self, force=False):
        if not self.chemin or not (self.sale or force):
            return
        tmp = self.chemin + '.tmp'
        try:
            d = os.path.dirname(os.path.abspath(self.chemin))
            os.makedirs(d, exist_ok=True)
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump({'v': 1, 'boites': self.boites}, f, separators=(',', ':'))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.chemin)
            self.sale = False
        except Exception as e:
            log.warning('courrier : ecriture de %s impossible (%s)', self.chemin, e)

    def purger(self):
        lim = time.time() - MAIL_TTL
        for pid in list(self.boites):
            avant = len(self.boites[pid])
            self.boites[pid] = [m for m in self.boites[pid] if m.get('t', 0) > lim][-MAX_MAIL:]
            if len(self.boites[pid]) != avant:
                self.sale = True
            if not self.boites[pid]:
                del self.boites[pid]
        h = time.time() - 3600
        for pid in list(self.depots):
            self.depots[pid] = [x for x in self.depots[pid] if x > h]
            if not self.depots[pid]:
                del self.depots[pid]

    def deposer(self, dest, envoyeur, nom, d):
        """Garde un message pour un absent. Renvoie False si refuse."""
        try:
            taille = len(json.dumps(d, separators=(',', ':')))
        except Exception:
            return False
        if taille > MAIL_ITEM_MAX:
            return False
        h = time.time() - 3600
        dep = [x for x in self.depots.get(envoyeur, []) if x > h]
        if len(dep) >= MAIL_PER_SENDER_HOUR:
            return False
        dep.append(time.time())
        self.depots[envoyeur] = dep
        boite = self.boites.setdefault(dest, [])
        boite.append({'from': envoyeur, 'n': nom, 'd': d, 't': time.time()})
        del boite[:-MAX_MAIL]
        # plafond global : on retire les plus vieux messages, toutes boites confondues
        while self.total() > MAIL_TOTAL_MAX:
            plus_vieux = min(self.boites, key=lambda p: self.boites[p][0].get('t', 0))
            self.boites[plus_vieux].pop(0)
            if not self.boites[plus_vieux]:
                del self.boites[plus_vieux]
        self.sale = True
        return True

    def retirer_tout(self, pid):
        lst = self.boites.pop(pid, [])
        if lst:
            self.sale = True
        return lst


# ------------------------------------------------------------
# WebSocket (version navigateur : iPhone / iPad, Safari)
# ------------------------------------------------------------
# Un navigateur ne peut pas ouvrir de connexion TCP brute : la version web
# du jeu passe par un WebSocket (port 50056 par defaut, ou en wss:// avec un
# certificat, --ws-cert / --ws-key). Chaque message WebSocket porte une (ou
# plusieurs) lignes JSON du MEME protocole que le TCP : un joueur Android et
# un joueur iPhone se retrouvent sur le meme relais et jouent ensemble.
_WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def ws_trame(payload, op=1):
    n = len(payload)
    if n < 126:
        tete = bytes((0x80 | op, n))
    elif n < 65536:
        tete = bytes((0x80 | op, 126)) + n.to_bytes(2, 'big')
    else:
        tete = bytes((0x80 | op, 127)) + n.to_bytes(8, 'big')
    return tete + payload


def ws_demasquer(data, masque):
    n = len(data)
    if not n:
        return b''
    m = (masque * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'little') ^ int.from_bytes(m, 'little')).to_bytes(n, 'little')


_dumps = json.JSONEncoder(separators=(',', ':')).encode


# ------------------------------------------------------------
# Un client connecte (TCP ou WebSocket)
# ------------------------------------------------------------
class Client(object):
    __slots__ = ('tr', 'ws', 'ip', 'pid', 'pk', 'name', 'njs', 'alive', 'last',
                 'tokens', 'token_t', 'refus', 'refus_t', 'defi', 'cid', 't0', 'buf')

    def __init__(self, tr, ip, cid, ws=False):
        self.tr = tr
        self.ws = ws
        self.ip = ip
        self.cid = cid
        self.pid = None
        self.pk = ''
        self.name = '?'
        self.njs = b'"?"'
        self.alive = True
        self.last = time.monotonic()
        self.t0 = self.last
        self.tokens = float(RATE_MAX * 2)
        self.token_t = self.last
        self.refus = 0
        self.refus_t = self.last
        self.defi = secrets.token_hex(16)
        self.buf = bytearray()

    def set_nom(self, n):
        self.name = n
        self.njs = _dumps(n).encode('ascii')

    def tag(self):
        return '#%d %s%s %s' % (self.cid, self.ip, ' ws' if self.ws else '', (self.pid or '-')[:8])

    def send_line(self, data):
        """data : une ligne JSON terminee par \n (ou b'\n' seul = maintien)."""
        if not self.alive:
            return False
        tr = self.tr
        try:
            if tr.is_closing():
                self.alive = False
                return False
            if tr.get_write_buffer_size() > WRITE_BUF_MAX:
                log.warning('%s ne lit plus (tampon plein) : deconnexion', self.tag())
                self.alive = False
                tr.abort()
                return False
            if self.ws:
                if data == b'\n':
                    tr.write(b'\x89\x00')           # ping WebSocket (invisible pour le jeu)
                else:
                    tr.write(ws_trame(data[:-1] if data.endswith(b'\n') else data))
            else:
                tr.write(data)
            return True
        except Exception:
            self.alive = False
            return False

    def send(self, obj):
        try:
            data = (_dumps(obj) + '\n').encode('utf-8')
        except Exception:
            return False
        if len(data) > MAX_LINE:
            return False
        return self.send_line(data)

    def allowed(self):
        """Limite de debit : un client ne peut pas noyer le relais."""
        now = time.monotonic()
        self.tokens = min(RATE_MAX * 2.0, self.tokens + (now - self.token_t) * RATE_MAX)
        self.token_t = now
        if self.tokens < 1:
            if now - self.refus_t > 10:
                self.refus, self.refus_t = 0, now
            self.refus += 1
            return False
        self.tokens -= 1
        return True

    def close(self):
        self.alive = False
        try:
            if self.ws and not self.tr.is_closing():
                self.tr.write(b'\x88\x02\x03\xe8')   # trame de fermeture (1000)
            self.tr.close()
        except Exception:
            pass


def _regler_socket(tr):
    sock = tr.get_extra_info('socket')
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in (('TCP_KEEPIDLE', 60), ('TCP_KEEPINTVL', 15), ('TCP_KEEPCNT', 4)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
    except OSError:
        pass


class ProtoTCP(asyncio.Protocol):
    """Connexion TCP (Android, ordinateur) : une ligne JSON par message."""

    def __init__(self, relais):
        self.r = relais
        self.cl = None

    def connection_made(self, tr):
        _regler_socket(tr)
        peer = tr.get_extra_info('peername') or ('?', 0)
        self.cl = self.r.ouvrir(tr, str(peer[0]), False)

    def data_received(self, data):
        cl = self.cl
        if cl is None or not cl.alive:
            return
        buf = cl.buf
        buf += data
        debut = 0
        r = self.r
        while cl.alive:
            j = buf.find(b'\n', debut)
            if j < 0:
                break
            if j - debut > MAX_LINE:
                break
            r.ligne(cl, bytes(buf[debut:j]))
            debut = j + 1
        if debut:
            del buf[:debut]
        if len(buf) > MAX_LINE and cl.alive:
            log.warning('%s message trop long (> %d o) : deconnexion', cl.tag(), MAX_LINE)
            r.stats['rejetes'] += 1
            cl.alive = False
            cl.tr.abort()

    def connection_lost(self, exc):
        if self.cl is not None:
            self.r.fermer(self.cl)


class ProtoWS(asyncio.Protocol):
    """Connexion WebSocket (version navigateur). Meme protocole, en trames."""

    def __init__(self, relais):
        self.r = relais
        self.cl = None
        self.tr = None
        self.etat = 'http'
        self.http = bytearray()
        self.buf = bytearray()
        self.frag = None

    def connection_made(self, tr):
        self.tr = tr
        _regler_socket(tr)
        self.r.ws_attente[self] = time.monotonic()

    def _http(self, code, texte):
        corps = texte.encode('utf-8')
        try:
            self.tr.write(('HTTP/1.1 %s\r\nContent-Type: text/plain; charset=utf-8\r\n'
                           'Content-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n'
                           'Connection: close\r\n\r\n' % (code, len(corps))).encode('ascii') + corps)
            self.tr.close()
        except Exception:
            pass

    def data_received(self, data):
        if self.etat == 'ws':
            return self.trames(data)
        if self.etat != 'http':
            return
        self.http += data
        k = self.http.find(b'\r\n\r\n')
        if k < 0:
            if len(self.http) > 8192:
                self.etat = 'fini'
                self._http('431 Request Header Fields Too Large', 'trop long\n')
            return
        self.r.ws_attente.pop(self, None)
        tete = bytes(self.http[:k]).decode('latin-1').split('\r\n')
        reste = bytes(self.http[k + 4:])
        self.http = None
        entetes = {}
        for ln in tete[1:]:
            if ':' in ln:
                a, _s, b = ln.partition(':')
                entetes[a.strip().lower()] = b.strip()
        if 'websocket' not in entetes.get('upgrade', '').lower():
            # simple GET (navigateur, sonde de sante) : on repond que tout va bien
            self.etat = 'fini'
            self._http('200 OK', 'Relais Arene des Origines : OK (%d en ligne)\n' % len(self.r.clients))
            return
        cle = entetes.get('sec-websocket-key', '')
        if not cle:
            self.etat = 'fini'
            self._http('400 Bad Request', 'websocket sans cle\n')
            return
        acc = base64.b64encode(hashlib.sha1(cle.encode('ascii', 'ignore') + _WS_GUID).digest())
        self.tr.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                      b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + b'\r\n\r\n')
        self.etat = 'ws'
        peer = self.tr.get_extra_info('peername') or ('?', 0)
        ip = str(peer[0])
        if ip in ('127.0.0.1', '::1') and entetes.get('x-forwarded-for'):
            ip = entetes['x-forwarded-for'].split(',')[0].strip()[:45] or ip   # derriere un proxy local
        self.cl = self.r.ouvrir(self.tr, ip, True)
        if reste:
            self.trames(reste)

    def trames(self, data):
        cl = self.cl
        if cl is None or not cl.alive:
            return
        buf = self.buf
        buf += data
        r = self.r
        while cl.alive:
            if len(buf) < 2:
                break
            b0, b1 = buf[0], buf[1]
            op = b0 & 0x0F
            n = b1 & 0x7F
            p = 2
            if n == 126:
                if len(buf) < 4:
                    break
                n = int.from_bytes(buf[2:4], 'big')
                p = 4
            elif n == 127:
                if len(buf) < 10:
                    break
                n = int.from_bytes(buf[2:10], 'big')
                p = 10
            if n > MAX_LINE + 64:
                log.warning('%s message trop long (> %d o) : deconnexion', cl.tag(), MAX_LINE)
                r.stats['rejetes'] += 1
                cl.alive = False
                cl.tr.abort()
                return
            if not (b1 & 0x80):
                cl.close()                         # le client doit masquer (RFC 6455)
                return
            if len(buf) < p + 4 + n:
                break
            masque = bytes(buf[p:p + 4])
            charge = ws_demasquer(bytes(buf[p + 4:p + 4 + n]), masque)
            del buf[:p + 4 + n]
            if op == 8:                            # fermeture
                cl.close()
                return
            if op == 9:                            # ping -> pong
                cl.last = time.monotonic()
                try:
                    cl.tr.write(ws_trame(charge[:125], 10))
                except Exception:
                    pass
                continue
            if op == 10:
                cl.last = time.monotonic()
                continue
            if op in (1, 2):
                if b0 & 0x80:
                    self.message(charge)
                else:
                    self.frag = bytearray(charge)
            elif op == 0 and self.frag is not None:
                self.frag += charge
                if len(self.frag) > MAX_LINE:
                    cl.close()
                    return
                if b0 & 0x80:
                    m, self.frag = bytes(self.frag), None
                    self.message(m)

    def message(self, charge):
        cl = self.cl
        if b'\n' in charge:
            for ln in charge.split(b'\n'):
                if cl.alive:
                    self.r.ligne(cl, ln)
        else:
            self.r.ligne(cl, charge)

    def connection_lost(self, exc):
        self.r.ws_attente.pop(self, None)
        if self.cl is not None:
            self.r.fermer(self.cl)


# ------------------------------------------------------------
# Le relais
# ------------------------------------------------------------
class Relais(object):
    def __init__(self, args):
        self.a = args
        self.clients = {}          # pid -> Client identifie
        self.conns = set()         # toutes les connexions ouvertes
        self.par_ip = {}           # ip -> nombre de connexions ouvertes
        self.ip_rythme = {}        # ip -> [instants des connexions recentes]
        self.file = []             # partie rapide : [(pid, pv, pm, instant)]
        self.salons = {}           # code -> (pid, pv, pm, instant)
        self.paires = {}           # pid -> (pid de l'adversaire, instant) : partie en cours
        self.ws_attente = {}       # WebSocket pas encore ouverts -> instant
        self.courrier = Courrier(args.mail_file)
        self.cid = 0
        self.depuis = time.time()
        self.stats = dict(connexions=0, identifies=0, refus_auth=0, pleins=0, messages=0,
                          relayes=0, gardes=0, remis=0, appariements=0, rejetes=0, ws=0)

    # ---------- connexions ----------
    def ouvrir(self, tr, ip, ws):
        """Nouvelle connexion (TCP ou WebSocket ouvert). Renvoie le Client, ou
        None si elle est refusee (relais plein, trop de connexions par IP)."""
        self.cid += 1
        cl = Client(tr, ip, self.cid, ws)
        now = time.monotonic()
        rythme = [x for x in self.ip_rythme.get(ip, []) if now - x < 60]
        rythme.append(now)
        self.ip_rythme[ip] = rythme
        refus = None
        if len(self.conns) >= self.a.max_conn:
            refus = 'full'
        elif self.par_ip.get(ip, 0) >= self.a.per_ip:
            refus = 'full'
        elif len(rythme) > self.a.ip_rate:
            refus = 'full'
        if refus:
            # meme reponse que le relais plein : le jeu essaie le relais suivant
            self.stats['pleins'] += 1
            log.warning('connexion refusee %s (connexions=%d, cette ip=%d, %d/min)',
                        ip, len(self.conns), self.par_ip.get(ip, 0), len(rythme))
            cl.send_line(b'{"t":"auth_ko","why":"full"}\n')
            cl.close()
            return None
        self.conns.add(cl)
        self.par_ip[ip] = self.par_ip.get(ip, 0) + 1
        self.stats['connexions'] += 1
        if ws:
            self.stats['ws'] += 1
        log.debug('%s connexion', cl.tag())
        cl.send({'t': 'hello', 'pv': PROTO, 'challenge': cl.defi})
        return cl

    def ligne(self, cl, ligne):
        """Une ligne JSON recue d'un client."""
        cl.last = time.monotonic()
        if not ligne.strip():
            return
        if not cl.allowed():
            self.stats['rejetes'] += 1
            if cl.refus > RATE_KICK:
                log.warning('%s inonde le relais : deconnexion', cl.tag())
                cl.alive = False
                cl.tr.abort()
            return
        try:
            o = json.loads(ligne)
        except Exception:
            self.stats['rejetes'] += 1
            return
        if not isinstance(o, dict):
            return
        self.stats['messages'] += 1
        try:
            if self.traiter(cl, o) == 'close':
                cl.close()
        except Exception:
            log.exception('%s message %r mal traite', cl.tag(), o.get('t'))

    def fermer(self, cl):
        if cl in self.conns:
            self.conns.discard(cl)
            n = self.par_ip.get(cl.ip, 1) - 1
            if n <= 0:
                self.par_ip.pop(cl.ip, None)
            else:
                self.par_ip[cl.ip] = n
        cl.alive = False
        if cl.pid and self.clients.get(cl.pid) is cl:
            del self.clients[cl.pid]
            self.retirer(cl.pid)
            # l'adversaire de la partie en cours est prevenu tout de suite
            pr = self.paires.get(cl.pid)
            if pr:
                c2 = self.vivant(pr[0])
                if c2 is not None:
                    c2.send({'t': 'gone', 'pid': cl.pid})
            log.info('%s parti (%s) - %d en ligne', cl.tag(), cl.name, len(self.clients))
        try:
            cl.tr.close()
        except Exception:
            pass

    # ---------- mise en relation ----------
    def vivant(self, pid):
        c = self.clients.get(pid)
        return c if (c is not None and c.alive) else None

    def retirer(self, pid):
        """Sort ce joueur de la file et de ses salons."""
        if not pid:
            return
        if self.file:
            self.file[:] = [e for e in self.file if e[0] != pid]
        if self.salons:
            for code in [c for c, e in self.salons.items() if e[0] == pid]:
                del self.salons[code]

    def oublier_paire(self, pid):
        pr = self.paires.pop(pid, None)
        if pr and (self.paires.get(pr[0]) or (None,))[0] == pid:
            del self.paires[pr[0]]

    def apparier(self, a, b, comment):
        """Presente a et b l'un a l'autre. a (arrive le premier) heberge."""
        self.stats['appariements'] += 1
        now = time.time()
        self.oublier_paire(a.pid)
        self.oublier_paire(b.pid)
        self.paires[a.pid] = (b.pid, now)
        self.paires[b.pid] = (a.pid, now)
        a.send({'t': 'matched', 'pid': b.pid, 'n': b.name, 'pk': b.pk, 'host': 1})
        b.send({'t': 'matched', 'pid': a.pid, 'n': a.name, 'pk': a.pk, 'host': 0})
        log.info('face a face (%s) : %s [hote] <-> %s', comment, a.tag(), b.tag())

    # ---------- les messages ----------
    def traiter(self, cl, o):
        t = o.get('t')

        # chemin le plus frequent (paquets de jeu) en premier
        if t == 'to' and cl.pid is not None:
            dest = o.get('pid')
            if not pid_valide(dest):
                return None
            d = o.get('d')
            c2 = self.vivant(dest)
            if c2 is not None:
                try:
                    dj = _dumps(d).encode('utf-8')
                except Exception:
                    return None
                c2.send_line(b'{"t":"from","pid":"' + cl.pid.encode('ascii') + b'","n":'
                             + cl.njs + b',"d":' + dj + b'}\n')
                self.stats['relayes'] += 1
                if o.get('ack'):
                    cl.send({'t': 'sent', 'pid': dest, 'ok': 1})
            elif o.get('store'):
                ok = self.courrier.deposer(dest, cl.pid, cl.name, d)
                if ok:
                    self.stats['gardes'] += 1
                    log.info('%s message garde pour %s (absent)', cl.tag(), dest[:8])
                if o.get('ack'):
                    cl.send({'t': 'sent', 'pid': dest, 'ok': 0, 'stored': 1} if ok
                            else {'t': 'sent', 'pid': dest, 'ok': 0})
            elif o.get('ack'):
                cl.send({'t': 'sent', 'pid': dest, 'ok': 0})
            return None

        # --- identification : le client SIGNE le defi ---
        if t == 'auth':
            if cl.pid is not None:
                return None
            return self.auth(cl, o)

        if cl.pid is None:
            return None                     # rien avant l'identification

        if 'n' in o and t in ('quick', 'salon', 'join'):
            cl.set_nom(_nom(o.get('n'), cl.name))

        if t == 'ping':
            cl.send({'t': 'pong', 'ts': o.get('ts')})
            return None

        if t == 'who':
            ids = o.get('ids')
            if not isinstance(ids, list):
                return None
            en_ligne = [i for i in ids[:WHO_MAX] if isinstance(i, str) and self.vivant(i)]
            cl.send({'t': 'who_ok', 'on': en_ligne,
                     'names': {i: self.clients[i].name for i in en_ligne}})
            return None

        if t == 'quick':
            pv, pm = _entier(o.get('pv'), 1), _entier(o.get('pm'), 1)
            self.retirer(cl.pid)
            self.oublier_paire(cl.pid)
            self.file[:] = [e for e in self.file if self.vivant(e[0])]
            for i, e in enumerate(self.file):
                if e[0] != cl.pid and compatibles(e[1], e[2], pv, pm):
                    del self.file[i]
                    self.apparier(self.clients[e[0]], cl, 'partie rapide')
                    return None
            self.file.append((cl.pid, pv, pm, time.time()))
            cl.send({'t': 'queued', 'n': len(self.file), 'online': len(self.clients)})
            log.info('%s en attente de partie rapide (%d dans la file)', cl.tag(), len(self.file))
            return None

        if t == 'salon':
            code = str(o.get('code', ''))[:8]
            if not code.isdigit() or len(code) < 4:
                cl.send({'t': 'salon_ko', 'why': 'code'})
                return None
            pv, pm = _entier(o.get('pv'), 1), _entier(o.get('pm'), 1)
            self.retirer(cl.pid)
            self.oublier_paire(cl.pid)
            ex = self.salons.get(code)
            if (ex is not None and ex[0] != cl.pid and self.vivant(ex[0])
                    and time.time() - ex[3] < SALON_TTL):
                cl.send({'t': 'salon_ko', 'why': 'pris'})
                return None
            self.salons[code] = (cl.pid, pv, pm, time.time())
            cl.send({'t': 'salon_ok', 'code': code})
            log.info('%s ouvre le salon %s', cl.tag(), code)
            return None

        if t == 'join':
            code = str(o.get('code', ''))[:8]
            pv, pm = _entier(o.get('pv'), 1), _entier(o.get('pm'), 1)
            ex = self.salons.get(code)
            hote = self.vivant(ex[0]) if ex else None
            if ex is None or hote is None or time.time() - ex[3] > SALON_TTL:
                self.salons.pop(code, None)
                cl.send({'t': 'join_ko', 'why': 'inconnu'})
                return None
            if hote.pid == cl.pid:
                cl.send({'t': 'join_ko', 'why': 'soi'})
                return None
            if not compatibles(ex[1], ex[2], pv, pm):
                cl.send({'t': 'join_ko', 'why': 'version'})
                return None
            del self.salons[code]
            self.retirer(cl.pid)
            self.apparier(hote, cl, 'salon %s' % code)
            return None

        if t == 'cancel':
            self.retirer(cl.pid)
            self.oublier_paire(cl.pid)
            cl.send({'t': 'cancel_ok'})
            return None

        if t == 'pair':
            # v15.1 : apres une reconnexion (ou un redemarrage du relais), le jeu
            # rappelle avec qui il se bat, pour que l'autre soit prevenu s'il part
            p2 = o.get('pid')
            if pid_valide(p2) and p2 != cl.pid:
                self.paires[cl.pid] = (p2, time.time())
            return None

        if t == 'stats':
            cl.send({'t': 'stats_ok', 'online': len(self.clients),
                     'up': int(time.time() - self.depuis),
                     'msg': self.stats['messages'], 'relayed': self.stats['relayes'],
                     'queue': len(self.file), 'max': self.a.max})
            return None
        return None

    def auth(self, cl, o):
        try:
            pk = _b64d(o['pk'])
            pid = hashlib.sha256(pk).hexdigest()[:ID_LEN]
            if pid != o.get('pid'):
                self.stats['refus_auth'] += 1
                log.info('%s identification refusee (identifiant faux)', cl.tag())
                cl.send({'t': 'auth_ko', 'why': 'id'})
                return 'close'
            if not ed25519_verify(cl.defi.encode(), _b64d(o['sig']), pk):
                self.stats['refus_auth'] += 1
                log.info('%s identification refusee (signature fausse)', cl.tag())
                cl.send({'t': 'auth_ko', 'why': 'sig'})
                return 'close'
        except (KeyError, TypeError, ValueError, binascii.Error):
            self.stats['refus_auth'] += 1
            cl.send({'t': 'auth_ko', 'why': 'bad'})
            return 'close'
        if pid not in self.clients and len(self.clients) >= self.a.max:
            # serveur plein : le jeu essaiera le relais suivant de sa liste
            self.stats['pleins'] += 1
            log.warning('%s relais plein (%d/%d) : refuse', cl.tag(), len(self.clients), self.a.max)
            cl.send({'t': 'auth_ko', 'why': 'full'})
            return 'close'
        cl.pid = pid
        cl.pk = str(o.get('pk', ''))
        cl.set_nom(_nom(o.get('n')))
        vieux = self.clients.get(pid)
        if vieux is not None and vieux is not cl:
            log.info('%s se reconnecte : l\'ancienne connexion est fermee', cl.tag())
            self.retirer(pid)
            vieux.close()
        self.clients[pid] = cl
        self.stats['identifies'] += 1
        cl.send({'t': 'auth_ok', 'pid': pid, 'pv': PROTO, 'features': ['match', 'gone'],
                 'online': len(self.clients)})
        attente = self.courrier.retirer_tout(pid)
        for m in attente:                      # courrier en attente
            cl.send({'t': 'from', 'pid': m.get('from'), 'n': m.get('n', '?'),
                     'd': m.get('d'), 'late': 1, 'ts': m.get('t')})
        self.stats['remis'] += len(attente)
        # partie en cours : l'adversaire apprend que ce joueur est revenu
        pr = self.paires.get(pid)
        if pr and vieux is None:
            c2 = self.vivant(pr[0])
            if c2 is not None:
                c2.send({'t': 'back', 'pid': pid})
        log.info('%s identifie (%s)%s - %d en ligne', cl.tag(), cl.name,
                 (' - %d message(s) en attente remis' % len(attente)) if attente else '',
                 len(self.clients))
        return None

    # ---------- taches de fond ----------
    async def battement(self):
        """Ligne vide reguliere : garde les connexions ouvertes (box, 4G)."""
        while True:
            await asyncio.sleep(self.a.heartbeat)
            for cl in list(self.conns):
                if cl.pid is not None:
                    cl.send_line(b'\n')

    async def delais(self):
        """Une fois par seconde : identification trop lente, silence trop long."""
        while True:
            await asyncio.sleep(1.0 if self.a.hello_timeout >= 2 else 0.25)
            now = time.monotonic()
            for cl in list(self.conns):
                if not cl.alive:
                    continue
                if cl.pid is None:
                    if now - cl.t0 > self.a.hello_timeout:
                        log.info('%s pas identifie a temps : deconnexion', cl.tag())
                        cl.close()
                elif now - cl.last > self.a.idle:
                    log.info('%s silence trop long : deconnexion', cl.tag())
                    cl.close()
            for p, t0 in list(self.ws_attente.items()):
                if now - t0 > self.a.hello_timeout:
                    self.ws_attente.pop(p, None)
                    try:
                        p.tr.close()
                    except Exception:
                        pass

    async def menage(self):
        n = 0
        while True:
            await asyncio.sleep(10)
            n += 1
            self.courrier.purger()
            self.courrier.sauver()
            now = time.time()
            for c in [c for c, e in self.salons.items() if now - e[3] > SALON_TTL]:
                del self.salons[c]
            self.file[:] = [e for e in self.file if self.vivant(e[0])]
            for pid in [p for p, e in self.paires.items()
                        if not self.vivant(p) and not self.vivant(e[0]) and now - e[1] > 60]:
                self.paires.pop(pid, None)
            mono = time.monotonic()
            for ip in list(self.ip_rythme):
                self.ip_rythme[ip] = [x for x in self.ip_rythme[ip] if mono - x < 60]
                if not self.ip_rythme[ip]:
                    del self.ip_rythme[ip]
            if n % (self.a.stats_every // 10 or 1) == 0:
                self.journal_stats()

    def journal_stats(self):
        s = self.stats
        log.info('etat : %d en ligne, %d connexions, file=%d, salons=%d, courrier=%d | '
                 'depuis le debut : %d connexions (%d websocket), %d identifies, %d relayes, %d gardes, '
                 '%d remis, %d face-a-face, %d refus auth, %d pleins, %d rejetes',
                 len(self.clients), len(self.conns), len(self.file), len(self.salons),
                 self.courrier.total(), s['connexions'], s['ws'], s['identifies'], s['relayes'],
                 s['gardes'], s['remis'], s['appariements'], s['refus_auth'], s['pleins'],
                 s['rejetes'])


def _verif_rapide():
    """Si le module 'cryptography' est installe, la verification de signature
    est 30 fois plus rapide (sinon : le calcul en Python pur, identique)."""
    global ed25519_verify
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return False
    lent = ed25519_verify

    def rapide(msg, sig, pk):
        try:
            if len(sig) != 64 or len(pk) != 32:
                return False
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return lent(msg, sig, pk)
    ed25519_verify = rapide
    return True


async def principal(args):
    r = Relais(args)
    loop = asyncio.get_running_loop()
    srv = await loop.create_server(lambda: ProtoTCP(r), args.host, args.port,
                                   reuse_address=True, backlog=1024)
    srv_ws = None
    if args.ws_port:
        ctx = None
        if args.ws_cert:
            import ssl
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(args.ws_cert, args.ws_key or None)
        try:
            srv_ws = await loop.create_server(lambda: ProtoWS(r), args.host, args.ws_port,
                                              reuse_address=True, backlog=1024, ssl=ctx)
        except OSError as e:
            log.warning('WebSocket : port %d indisponible (%s) - TCP seulement', args.ws_port, e)
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass                              # Windows : Ctrl+C arrete quand meme
    taches = [asyncio.ensure_future(r.battement()), asyncio.ensure_future(r.menage()),
              asyncio.ensure_future(r.delais())]
    log.info('Relais Arene des Origines (protocole %d) sur %s:%d%s - max %d joueurs%s',
             PROTO, args.host, args.port,
             (' + WebSocket %s:%d' % ('wss' if args.ws_cert else 'ws', args.ws_port)) if srv_ws else '',
             args.max,
             (', courrier dans %s' % args.mail_file) if args.mail_file else ', courrier en memoire')
    log.info('Le relais ne peut pas lire ce qu il transporte (chiffre de bout en bout).%s%s',
             ' Signatures : verification rapide.' if args.rapide else '',
             ' Boucle : uvloop.' if args.uvloop else '')
    try:
        await stop.wait()
    finally:
        log.info('arret demande : on ferme proprement')
        srv.close()
        if srv_ws is not None:
            srv_ws.close()
        for t in taches:
            t.cancel()
        for cl in list(r.conns):
            cl.close()
        r.courrier.purger()
        r.courrier.sauver(force=bool(args.mail_file))
        r.journal_stats()
        await asyncio.sleep(0.05)


def main(argv=None):
    global IDLE_MAX
    ap = argparse.ArgumentParser(description='Relais en ligne - Arene des Origines')
    ap.add_argument('--port', type=int, default=50055, help='port TCP (50055 par defaut)')
    ap.add_argument('--ws-port', type=int, default=50056,
                    help='port WebSocket pour la version navigateur / iPhone (50056 par defaut, '
                         '0 = desactive)')
    ap.add_argument('--ws-cert', default='',
                    help='certificat (fullchain.pem) : le WebSocket passe en wss:// (obligatoire '
                         'pour une page en https, comme la version iPhone)')
    ap.add_argument('--ws-key', default='', help='cle privee du certificat (privkey.pem)')
    ap.add_argument('--host', default='0.0.0.0', help='adresse d ecoute (0.0.0.0 = toutes)')
    ap.add_argument('--max', type=int, default=1000,
                    help='joueurs identifies en meme temps (1000 par defaut) ; au-dela le jeu '
                         'passe au relais suivant de sa liste')
    ap.add_argument('--max-conn', type=int, default=0,
                    help='connexions ouvertes en tout (defaut : max + 20%% + 50)')
    ap.add_argument('--per-ip', type=int, default=64,
                    help='connexions ouvertes par adresse IP (defaut 64 : les reseaux 4G '
                         'et les box partagent souvent une IP)')
    ap.add_argument('--ip-rate', type=int, default=120,
                    help='nouvelles connexions par minute et par IP (defaut 120)')
    ap.add_argument('--idle', type=float, default=IDLE_MAX,
                    help='secondes de silence avant deconnexion (defaut 900)')
    ap.add_argument('--heartbeat', type=float, default=HEARTBEAT,
                    help='secondes entre deux lignes vides de maintien (defaut 25)')
    ap.add_argument('--hello-timeout', type=float, default=HELLO_TIMEOUT,
                    help='secondes pour s identifier apres la connexion (defaut 20)')
    ap.add_argument('--mail-file', default='',
                    help='fichier JSON ou garder les messages des absents (sinon : memoire)')
    ap.add_argument('--stats-every', type=int, default=300,
                    help='secondes entre deux lignes d etat dans le journal (defaut 300)')
    ap.add_argument('--no-uvloop', action='store_true',
                    help='ne pas utiliser uvloop meme s il est installe')
    ap.add_argument('-v', '--verbose', action='store_true', help='journal detaille')
    a = ap.parse_args(argv)
    a.max = max(2, a.max)
    a.max_conn = a.max_conn or (a.max + a.max // 5 + 50)
    a.per_ip = max(1, a.per_ip)
    a.idle = max(30.0, a.idle)
    a.heartbeat = max(0.5, a.heartbeat)
    a.hello_timeout = max(1.0, a.hello_timeout)
    a.mail_file = a.mail_file or None
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG if a.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    a.rapide = _verif_rapide()
    a.uvloop = False
    if not a.no_uvloop:
        try:
            import uvloop
            uvloop.install()
            a.uvloop = True
        except Exception:
            pass
    try:
        asyncio.run(principal(a))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
