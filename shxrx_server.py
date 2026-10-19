#!/usr/bin/env python3
"""
shxrx_server.py - the ONLINE license server for shxrx.

LOCAL USE (unchanged):
  First run:      python shxrx_server.py
  Make reachable: python shxrx_server.py --install http://YOUR-IP-OR-DOMAIN:8765
  Client folder:  python shxrx_server.py --sync CLIENT_FOLDER [--url http://YOUR-ADDRESS:8765]

HOSTED USE (Render, etc.):
  The process reads two environment variables instead of hardcoded local values:
    PORT              - the port to bind (Render sets this itself; defaults to 8765 locally)
    SHXRX_DATA_DIR    - where keys.json / server_secret.key / keys.lock live (defaults to this
                         script's folder). Point this at a MOUNTED PERSISTENT DISK on Render, or
                         every restart/redeploy wipes your signing key and every sold key.
    ADMIN_TOKEN       - a long random secret. If set, enables the /admin/* API below so keygen2.py
                         can manage keys over HTTPS from any machine, instead of needing local
                         filesystem access to keys.json. If unset, /admin/* is disabled (501).

  Customer-facing endpoints (unchanged, used by the shipped .exe): POST /api/activate, POST /api/ping,
  GET /status. These need no auth - they are the public license check.

  Admin endpoints (new, used by keygen2.py in remote mode): POST /admin/<action> with header
  "Authorization: Bearer <ADMIN_TOKEN>" and a JSON body. Actions: new_key, list, revoke, unrevoke,
  unbind, extend, note, delete, online. NEVER put ADMIN_TOKEN in a customer build.

The keygen imports this file for its local/legacy mode, so keep all files in one folder either way.
"""
import os
import re
import sys
import json
import time
import hmac
import secrets
import hashlib
import socket
import shutil
import threading
import math
from shxrx_safety import atomic_json
from shxrx_storage import FileMutex
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__))
sys.path.insert(0, HERE)
import shxrx_license as L

# DATA_DIR holds everything that must survive restarts: point it at a persistent disk when hosted.
DATA_DIR = os.environ.get("SHXRX_DATA_DIR", HERE)
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")
SECRET_FILE = os.path.join(DATA_DIR, "server_secret.key")
LIC_FILE = os.path.join(HERE, "shxrx_license.py")          # local dev convenience only
PORT = int(os.environ.get("PORT", 8765))                    # Render injects PORT itself
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")              # unset = admin API disabled
SERVER_VERSION = 3
GRACE = 3 * 86400            # app may run this long without reaching the server
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_lock = FileMutex(os.path.join(DATA_DIR, 'keys.lock'))
_last_ping = {}          # key -> last time its app checked in (memory only)
_admin_fail = {}          # ip -> (count, window_start) for admin auth throttling (memory only)
_admin_fail_lock = threading.Lock()


# ───────── keys ─────────
def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, encoding='utf-8') as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError('keys.json is damaged; restore keys.json.bak. No keys were overwritten.')
    return data


def save_keys(keys):
    # Call within _lock for every read-modify-write transaction.
    if os.path.exists(KEYS_FILE):
        load_keys()  # Never overwrite the last good backup with corrupt JSON.
        shutil.copy2(KEYS_FILE, KEYS_FILE + '.bak')
    atomic_json(KEYS_FILE, keys)


def new_key(tier, days, note=""):
    """Makes and stores a key. Returns it formatted (SHXRX-XXXXX-...)."""
    if int(tier) not in L.TIERS or not 0 <= int(days) <= 36500:
        raise ValueError('Invalid tier or days (0 = lifetime; maximum 36500).')
    with _lock:
        keys = load_keys()
        while True:
            raw = "".join(secrets.choice(ALPHABET) for _ in range(20))
            if raw not in keys:
                break
        keys[raw] = {"tier": int(tier), "days": int(days), "created": time.time(), "activated": 0,
                     "hwid": "", "pc": "", "note": str(note)[:120], "revoked": False}
        save_keys(keys)
    return L.format_key(raw)


def hook_revoke(body):
    """Disable a key (used by keygen / admin panel)."""
    raw = L.clean_key(body.get("key", ""))
    with _lock:
        keys = load_keys()
        if raw not in keys:
            raise KeyError("Unknown key")
        keys[raw]["revoked"] = True
        save_keys(keys)
    return {"ok": True}


def _edit(body, fn):
    raw = L.clean_key(body.get("key", ""))
    with _lock:
        keys = load_keys()
        if raw not in keys:
            raise KeyError("Unknown key")
        fn(keys, raw)
        save_keys(keys)
    return {"ok": True}


def hook_unrevoke(body):
    """Enable a disabled key again."""
    return _edit(body, lambda ks, r: ks[r].__setitem__("revoked", False))


def hook_unbind(body):
    """Free a key from its PC so the buyer can move it to a new one (expiry clock is kept)."""
    def f(ks, r):
        ks[r]["hwid"], ks[r]["pc"] = "", ""
    return _edit(body, f)


def hook_extend(body):
    """Add days to a key (lifetime keys stay lifetime)."""
    add = int(body.get("days", 0))
    def f(ks, r):
        if ks[r]["days"]:
            ks[r]["days"] = max(1, ks[r]["days"] + add)
    return _edit(body, f)


def hook_note(body):
    return _edit(body, lambda ks, r: ks[r].__setitem__("note", str(body.get("note", ""))[:120]))


def hook_delete(body):
    return _edit(body, lambda ks, r: ks.pop(r))


def online_keys(window=300):
    n = time.time()
    return [k for k, t in list(_last_ping.items()) if n - t < window]


# ───────── signing ─────────
def secret():
    with _lock:
        if os.path.exists(SECRET_FILE):
            with open(SECRET_FILE, encoding='utf-8') as fh:
                s = bytes.fromhex(fh.read().strip())
            if len(s) != 32:
                raise ValueError('Invalid signing key. Restore the original private key; do not regenerate it.')
            return s
        # Losing a signing key must never silently rotate all customer trust.
        if load_keys():
            raise RuntimeError('Signing key missing while licenses exist. Restore server_secret.key from backup.')
        os.makedirs(DATA_DIR, exist_ok=True)
        s = secrets.token_bytes(32)
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(s.hex())
            fh.flush()
            os.fsync(fh.fileno())
        print('Created private signing key at %s; keep it out of client builds and BACK IT UP.' % SECRET_FILE)
        return s


def patch_license(pub_hex=None, url=None):
    with open(LIC_FILE, encoding="utf-8", newline="") as fh:
        src = fh.read()
    if pub_hex:
        src = re.sub(r'SERVER_PUBKEY_HEX = "[0-9a-fA-F]*"', 'SERVER_PUBKEY_HEX = "%s"' % pub_hex, src)
    if url:
        src = re.sub(r'SERVER_URL = "[^"]*"', 'SERVER_URL = "%s"' % url.rstrip("/"), src)
    with open(LIC_FILE, "w", encoding="utf-8", newline="") as fh:
        fh.write(src)
    _drop_pyc(LIC_FILE)


def _drop_pyc(path):
    """A just-patched file can keep an old compiled copy (same size, same second) - delete it."""
    import glob
    d, base = os.path.dirname(path), os.path.splitext(os.path.basename(path))[0]
    for f in glob.glob(os.path.join(d, "__pycache__", base + ".*.pyc")):
        try:
            os.remove(f)
        except OSError:
            pass


def sync_client(target, pub_hex, url=None):
    """Write this server's public key (and URL) into ANOTHER shxrx_license.py, e.g. the client build folder."""
    target = os.path.abspath(target)
    if os.path.isdir(target):
        target = os.path.join(target, "shxrx_license.py")
    with open(target, encoding="utf-8", newline="") as fh:
        src = fh.read()
    if 'SERVER_PUBKEY_HEX = "' not in src:
        raise SystemExit("%s does not look like shxrx_license.py" % target)
    src = re.sub(r'SERVER_PUBKEY_HEX = "[0-9a-fA-F]*"', 'SERVER_PUBKEY_HEX = "%s"' % pub_hex, src)
    if url:
        src = re.sub(r'SERVER_URL = "[^"]*"', 'SERVER_URL = "%s"' % url.rstrip("/"), src)
    with open(target, "w", encoding="utf-8", newline="") as fh:
        fh.write(src)
    _drop_pyc(target)
    return target


def sign(payload):
    p = json.dumps(payload, separators=(",", ":"))
    return {"p": p, "s": L.ed_sign(secret(), b"shxrx-resp|" + p.encode()).hex()}


# ───────── license logic (customer-facing, unauthenticated by design) ─────────
def handle(path, body):
    nonce, hwid = str(body.get("nonce", "")), str(body.get("hwid", ""))
    now = time.time()
    base = {"nonce": nonce, "hwid": hwid, "now": now, "issued": now, "grace": GRACE}
    raw = L.clean_key(str(body.get("key", "")))
    with _lock:
        keys = load_keys()
        k = keys.get(raw)
        if len(hwid) != 32 or k is None:
            return dict(base, ok=False, err="This key is not valid.")
        if k["revoked"]:
            return dict(base, ok=False, err="This key has been disabled. Contact the seller.")
        if not k["hwid"]:
            if path != "/api/activate":
                return dict(base, ok=False, err="This key is not activated. Restart and activate it.")
            k["hwid"], k["pc"] = hwid, str(body.get("pc", ""))[:40]
            k["activated"] = k["activated"] or now      # keep the original start (unbind must not give free time)
            save_keys(keys)
        elif k["hwid"] != hwid:
            return dict(base, ok=False, err="This key is already used on another PC.")
        exp = k["activated"] + k["days"] * 86400 if k["days"] else None
        if exp and now > exp:
            return dict(base, ok=False, err="This key has expired.")
    _last_ping[raw] = now
    return dict(base, ok=True, tier=k["tier"], expires=exp,
                serial=int.from_bytes(hashlib.sha256(raw.encode()).digest()[:4], "big"))


def _stamp():
    try:
        st = os.stat(KEYS_FILE)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def hold(path, body, wait):
    """Long-poll: keep the app's request open and answer the moment keys.json changes and this key is no
    longer valid (disabled, expired...). If nothing changes, answer normally after `wait` seconds."""
    end, seen = time.time() + wait, _stamp()
    while time.time() < end:
        time.sleep(0.3)
        cur = _stamp()
        if cur != seen:
            seen = cur
            ans = handle(path, body)
            if not ans.get("ok"):
                return ans
    return handle(path, body)


# ───────── admin API (authenticated, used by keygen2.py in remote mode) ─────────
ADMIN_ACTIONS = {
    "new_key":  lambda b: {"ok": True, "key": new_key(b.get("tier"), b.get("days"), b.get("note", ""))},
    "list":     lambda b: {"ok": True, "keys": load_keys()},
    "online":   lambda b: {"ok": True, "online": online_keys()},
    "revoke":   hook_revoke,
    "unrevoke": hook_unrevoke,
    "unbind":   hook_unbind,
    "extend":   hook_extend,
    "note":     hook_note,
    "delete":   hook_delete,
}


def _admin_throttled(ip):
    """Simple in-memory lockout: 8 failed attempts/5min per IP blocks that IP for the rest of the window."""
    with _admin_fail_lock:
        n, window = _admin_fail.get(ip, (0, time.time()))
        if time.time() - window > 300:
            n, window = 0, time.time()
        if n >= 8:
            return True
        _admin_fail[ip] = (n, window)
        return False


def _admin_fail_inc(ip):
    with _admin_fail_lock:
        n, window = _admin_fail.get(ip, (0, time.time()))
        if time.time() - window > 300:
            n, window = 0, time.time()
        _admin_fail[ip] = (n + 1, window)


def admin_authorized(handler):
    if not ADMIN_TOKEN:
        return False
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return hmac.compare_digest(auth[7:].strip(), ADMIN_TOKEN)


class Handler(BaseHTTPRequestHandler):
    server_version = "shxrx"

    def setup(self):
        self.request.settimeout(35)
        super().setup()

    def log_message(self, *a):
        pass

    def _send(self, code, data, ctype="application/json"):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self, limit=8192):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('chunked bodies are not accepted')
        n = self.headers.get('Content-Length')
        if n is None:
            raise ValueError('missing Content-Length')
        n = int(n)
        if n <= 0 or n > limit:
            raise ValueError('bad body size')
        body = json.loads(self.rfile.read(n).decode())
        if not isinstance(body, dict):
            raise ValueError('expected a JSON object')
        return body

    def do_POST(self):
        if self.path.startswith('/admin/'):
            return self._do_admin()
        if self.path not in ('/api/activate', '/api/ping'):
            return self._send(404, b'{}')
        try:
            body = self._read_json()
            for field in ('hwid', 'nonce'):
                if not isinstance(body.get(field), str) or not re.fullmatch(r'[0-9a-fA-F]{32}', body[field]):
                    raise ValueError('Invalid client identifier')
            if not isinstance(body.get('key'), str) or len(body['key']) > 100:
                raise ValueError('Invalid key field')
            wait = float(body.get('wait') or 0)
            if not math.isfinite(wait) or wait < 0:
                raise ValueError('Invalid wait')
            wait = min(wait, 25.0)
        except Exception:
            return self._send(400, b'{}')
        try:
            ans = handle(self.path, body)
            if self.path == '/api/ping' and ans.get('ok') and wait > 0:
                ans = hold(self.path, body, wait)
            self._send(200, json.dumps(sign(ans)).encode())
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            import traceback
            traceback.print_exc()
            self._send(500, b'{}')

    def _do_admin(self):
        if not ADMIN_TOKEN:
            return self._send(501, json.dumps({"ok": False, "err": "Admin API disabled (no ADMIN_TOKEN set)."}).encode())
        ip = self.client_address[0]
        if _admin_throttled(ip):
            return self._send(429, json.dumps({"ok": False, "err": "Too many failed attempts. Wait a few minutes."}).encode())
        if not admin_authorized(self):
            _admin_fail_inc(ip)
            time.sleep(0.4)   # slow down brute force without blocking the whole process
            return self._send(401, json.dumps({"ok": False, "err": "Unauthorized."}).encode())
        action = self.path[len('/admin/'):].strip('/')
        fn = ADMIN_ACTIONS.get(action)
        if fn is None:
            return self._send(404, json.dumps({"ok": False, "err": "Unknown admin action."}).encode())
        try:
            body = self._read_json(limit=16384)
        except Exception:
            return self._send(400, json.dumps({"ok": False, "err": "Bad request body."}).encode())
        try:
            self._send(200, json.dumps(fn(body)).encode())
        except KeyError:
            self._send(404, json.dumps({"ok": False, "err": "Unknown key."}).encode())
        except ValueError as e:
            self._send(400, json.dumps({"ok": False, "err": str(e)}).encode())
        except Exception:
            import traceback
            traceback.print_exc()
            self._send(500, json.dumps({"ok": False, "err": "Server error."}).encode())

    def do_GET(self):
        if self.path == "/status":
            n = time.time()
            return self._send(200, json.dumps({"shxrx_server": SERVER_VERSION, "keys": len(load_keys()),
                                               "online_5min": sum(1 for t in list(_last_ping.values()) if n - t < 300)}).encode())
        if self.path == "/online" and self.client_address[0] in ("127.0.0.1", "::1"):   # only the keygen on this PC
            return self._send(200, json.dumps({"online": online_keys()}).encode())
        self._send(404, b"not found", "text/plain")


class Server(ThreadingHTTPServer):
    """Refuses to start if the port is already taken. (Python's default lets a second server share the
    port on Windows, so an OLD server window can keep answering while the new one looks fine.)"""
    allow_reuse_address = (os.name != "nt")   # Windows: never share a port (see above)
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        ThreadingHTTPServer.server_bind(self)


def main():
    pub = L.ed_public(secret()).hex()
    args = sys.argv[1:]
    if "--sync" in args:
        idx = args.index("--sync")
        if idx + 1 >= len(args):
            raise SystemExit("Usage: python shxrx_server.py --sync PATH_TO_CLIENT_FOLDER [--url https://YOUR-DOMAIN]")
        url = args[args.index("--url") + 1] if "--url" in args and args.index("--url") + 1 < len(args) else None
        t = sync_client(args[idx + 1], pub, url)
        print("Client license file updated: %s\n  public key = %s%s\nRebuild the app with it."
              % (t, pub, ("\n  SERVER_URL = " + url) if url else ""))
        return
    if "--install" in args:
        idx = args.index('--install')
        if idx + 1 >= len(args):
            raise SystemExit('Usage: python shxrx_server.py --install https://YOUR-DOMAIN')
        url = args[idx + 1]
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or any(c in url for c in ('"', "'", '\\', '\n', '\r'))):
            raise SystemExit('Invalid server URL. Use a plain http(s) address without credentials or a query.')
        if parsed.scheme != 'https' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
            print('WARNING: use an HTTPS reverse proxy for public deployments. Signed responses do not encrypt keys or PC names.')
        patch_license(pub, url)
        print("shxrx_license.py updated:\n  SERVER_URL = %s\n  public key = %s\nRebuild the app with it." % (url, pub))
        return
    if not os.environ.get("SHXRX_DATA_DIR") and L.SERVER_PUBKEY_HEX != pub:
        # Only auto-patch the LOCAL dev license file; never touch it when running as a hosted service.
        patch_license(pub)
        print("Public key written into shxrx_license.py (it did not match this server).")
    try:
        srv = Server(("0.0.0.0", PORT), Handler)
    except OSError as e:
        print("\nCAN'T START: port %d is already in use (%s)." % (PORT, e))
        print("An OLD server is still running. Close its window, or find and stop it:")
        print("    netstat -ano | findstr :%d        (the last number is the PID)" % PORT)
        print("    taskkill /PID <that number> /F")
        print("Then run this again.")
        sys.exit(1)
    print("shxrx license server running on port %d  (Ctrl+C to stop)" % PORT)
    print("Data directory: %s" % DATA_DIR)
    print("Signing public key: %s" % pub)
    print("Admin API: %s" % ("ENABLED" if ADMIN_TOKEN else "disabled (set ADMIN_TOKEN to enable)"))
    print("The app's shxrx_license.py must contain EXACTLY this key. If activation says the signature does not\n"
          "match, run:  python shxrx_server.py --sync PATH_TO_CLIENT_FOLDER   and rebuild.")
    srv.serve_forever()


if __name__ == "__main__":
    main()
