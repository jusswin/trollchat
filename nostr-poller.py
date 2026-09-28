#!/usr/bin/env python3
"""
TrollChat operator-side Nostr poller.

- Connects over wss to public Nostr relays.
- Subscribes to kind 4 (NIP-04) DMs addressed to the operator pubkey.
- Decrypts with the operator private key (from the TROLLCHAT_OPERATOR_PRIV
  environment variable -- never commit it).
- Prints each DM on stdout and appends it to inbox.log.
- Send mode: ./nostr-poller.py send <dest_pubkey_hex> "<message>"

Run continuously, e.g.:  nohup ./nostr-poller.py >> inbox.log 2>&1 &
"""
import base64, hashlib, json, os, sys, threading, time, secrets
import websocket
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from Crypto.Cipher import AES
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))

OP_PRIV = os.environ.get("TROLLCHAT_OPERATOR_PRIV", "").strip()
if not OP_PRIV or len(OP_PRIV) != 64:
    sys.exit("error: set TROLLCHAT_OPERATOR_PRIV to your 64-hex operator private key")
# Operator pubkey is derived from the private key (x-only, BIP-340 style).
OP_PUB = SigningKey.from_string(bytes.fromhex(OP_PRIV), curve=SECP256k1) \
    .get_verifying_key().to_string()[:32].hex()

RELAYS = ["wss://relay.damus.io", "wss://relay.primal.net", "wss://relay.snort.social"]
INBOX = os.path.join(BASE, "inbox.log")

def _proxy_kwargs():
    """Build websocket-client proxy kwargs from HTTPS_PROXY/HTTP_PROXY env."""
    kw = {}
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if proxy:
        p = urlparse(proxy)
        kw["http_proxy_host"] = p.hostname
        kw["http_proxy_port"] = p.port or 8080
        if p.username:
            kw["http_proxy_auth"] = (p.username, p.password or "")
    ca = os.environ.get("SSL_CERT_FILE")
    if ca:
        kw["sslopt"] = {"ca_certs": ca}
    return kw

WS_KW = _proxy_kwargs()

# ---------- secp256k1 / BIP-340 ----------
_P = SECP256k1.curve.p()
_N = SECP256k1.order
_G = SECP256k1.generator

def _tagged(tag: bytes, msg: bytes) -> bytes:
    h = hashlib.sha256(tag).digest()
    return hashlib.sha256(h + h + msg).digest()

def _has_even_y(P) -> bool:
    return P.y() % 2 == 0

def schnorr_sign(priv_hex: str, msg: bytes) -> bytes:
    d = int(priv_hex, 16)
    P = d * _G
    dd = d if _has_even_y(P) else _N - d
    aux = secrets.token_bytes(32)
    t = bytes(a ^ b for a, b in zip(dd.to_bytes(32, "big"), _tagged(b"BIP0340/aux", aux)))
    rand = _tagged(b"BIP0340/nonce", t + P.x().to_bytes(32, "big") + msg)
    k = int.from_bytes(rand, "big") % _N
    assert k != 0
    R = k * _G
    kk = k if _has_even_y(R) else _N - k
    e = int.from_bytes(_tagged(b"BIP0340/challenge",
        R.x().to_bytes(32, "big") + P.x().to_bytes(32, "big") + msg), "big") % _N
    s = (kk + e * dd) % _N
    return R.x().to_bytes(32, "big") + s.to_bytes(32, "big")

def _lift_x(x_bytes: bytes):
    from ecdsa.ellipticcurve import Point
    p = SECP256k1.curve.p()
    x = int.from_bytes(x_bytes, "big")
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if (y * y) % p != y_sq:
        raise ValueError("invalid secp256k1 x")
    if y % 2 != 0:
        y = p - y
    return Point(SECP256k1.curve, x, y, _N)

def ecdh_key(priv_hex: str, pub_hex: str) -> bytes:
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    point = _lift_x(bytes.fromhex(pub_hex))
    shared = point * sk.privkey.secret_multiplier
    return hashlib.sha256(shared.x().to_bytes(32, "big")).digest()

# ---------- NIP-04 ----------
def nip04_encrypt(priv_hex: str, pub_hex: str, plaintext: str) -> str:
    key = ecdh_key(priv_hex, pub_hex)
    iv = secrets.token_bytes(16)
    data = plaintext.encode("utf-8")
    pad = 16 - len(data) % 16
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(data + bytes([pad]) * pad)
    return base64.b64encode(ct).decode() + "?iv=" + base64.b64encode(iv).decode()

def nip04_decrypt(priv_hex: str, pub_hex: str, payload: str) -> str:
    key = ecdh_key(priv_hex, pub_hex)
    b64ct, _, b64iv = payload.partition("?iv=")
    pt = AES.new(key, AES.MODE_CBC, base64.b64decode(b64iv)).decrypt(base64.b64decode(b64ct))
    return pt[:-pt[-1]].decode("utf-8")

# ---------- events ----------
def make_event(priv_hex: str, kind: int, tags, content: str) -> dict:
    pub = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)\
        .get_verifying_key().to_string()[:32].hex()
    created = int(time.time())
    eid = hashlib.sha256(json.dumps(
        [0, pub, created, kind, tags, content], separators=(",", ":")).encode()).hexdigest()
    sig = schnorr_sign(priv_hex, bytes.fromhex(eid)).hex()
    return {"id": eid, "pubkey": pub, "created_at": created, "kind": kind,
            "tags": tags, "content": content, "sig": sig}

def _send_raw(url: str, msgs) -> list:
    out = []
    ws = websocket.create_connection(url, timeout=15, **WS_KW)
    try:
        for m in msgs:
            ws.send(m)
        ws.settimeout(6)
        while True:
            try:
                out.append(ws.recv())
            except websocket.WebSocketTimeoutException:
                break
    finally:
        ws.close()
    return out

def publish_dm(to_pubkey: str, text: str):
    ev = make_event(OP_PRIV, 4, [["p", to_pubkey]], nip04_encrypt(OP_PRIV, to_pubkey, text))
    msg = json.dumps(["EVENT", ev], separators=(",", ":"))
    for url in RELAYS:
        try:
            resps = _send_raw(url, [msg])
            ok = any('"OK"' in r and ev["id"][:16] in r for r in resps)
            print(f"  {url}: {'ACCEPTED' if ok else 'resp: ' + str(resps)[:100]}", flush=True)
        except Exception as e:
            print(f"  {url}: ERROR {type(e).__name__} {str(e)[:80]}", flush=True)

def _handle_event(url: str, ev: dict):
    try:
        if ev.get("kind") != 4:
            return
        sender = ev.get("pubkey", "")
        if not any(t[0] == "p" and t[1] == OP_PUB for t in ev.get("tags", [])):
            return
        text = nip04_decrypt(OP_PRIV, sender, ev.get("content", ""))
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DM from {sender[:16]}… via {url}: {text}"
        print(line, flush=True)
        with open(INBOX, "a") as f:
            f.write(line + "\n")
            f.write(f"  sender_full={sender} event_id={ev.get('id')} created_at={ev.get('created_at')}\n")
    except Exception as e:
        print(f"[{url}] undecryptable event: {type(e).__name__} {str(e)[:60]}", flush=True)

def _relay_loop(url: str):
    backoff = 10
    while True:
        # 5-minute overlap: avoid re-fetching old history on each reconnect
        since = int(time.time()) - 300
        sub = json.dumps(["REQ", "trollchat-op", {"kinds": [4], "#p": [OP_PUB], "since": since}], separators=(",", ":"))
        try:
            # timeout 90s >> ping_interval 25s: pings keep the connection
            # alive through proxies; recv only expires if truly dead
            ws = websocket.create_connection(url, timeout=90, ping_interval=25, ping_timeout=10, **WS_KW)
            print(f"[{url}] connected, subscribed to DMs", flush=True)
            ws.send(sub)
            backoff = 5
            while True:
                raw = ws.recv()
                try:
                    m = json.loads(raw)
                except Exception:
                    continue
                if isinstance(m, list) and len(m) >= 3 and m[0] == "EVENT":
                    _handle_event(url, m[2])
        except Exception as e:
            print(f"[{url}] disconnected ({type(e).__name__}); retry in {backoff}s", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)

def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "send":
        print(f"Sending DM to {sys.argv[2][:16]}…")
        publish_dm(sys.argv[2], sys.argv[3])
        return
    print(f"TrollChat operator poller {OP_PUB[:16]}… | relays: {', '.join(RELAYS)}", flush=True)
    for url in RELAYS:
        threading.Thread(target=_relay_loop, args=(url,), daemon=True).start()
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
