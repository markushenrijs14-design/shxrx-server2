"""
shxrx_license.py - online license for shxrx
--------------------------------------------
* A key is bound to the FIRST PC that activates it (the server remembers it). No PC ID needed.
  Another PC that tries the same key is refused.
* The license server (shxrx_server.py) signs every answer with Ed25519 and the app only holds the PUBLIC key,
  so a fake server cannot say "yes". Each answer is tied to a one-time nonce and to this PC.
* The app works offline for a few days using the last signed answer, then must reach the server again.
* The same server pushes announcements, live events (Halloween ...) and direct messages to the app.

No third-party packages needed: Ed25519 is implemented below (RFC 8032).
"""

import os
import sys
import json
import time
import uuid
import queue
import base64
import hashlib
import secrets
import datetime
import threading
import urllib.request
import urllib.parse
import urllib.error
from shxrx_safety import atomic_json

# `python shxrx_server.py --install http://YOUR-ADDRESS:8765` rewrites these two lines. Don't edit by hand.
SERVER_URL = "http://127.0.0.1:8765"
SERVER_PUBKEY_HEX = "260f05bed8ced22eace1512a989a2ccda0805ebdf9d0e20fe0536d2c083762e8"

APP_VERSION = ""
TIERS = {1: "Standard", 2: "Pro", 3: "Ultimate"}
TIER_COLORS = {1: "#5ec8ff", 2: "#b266ff", 3: "#ffb02e"}
FROZEN = bool(getattr(sys, "frozen", False))


# ───────────────────────────── Ed25519 (RFC 8032 reference) ─────────────────────────────
_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s):
    return hashlib.sha512(s).digest()


def _inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return ((P[0] * Q[2] - Q[0] * P[2]) % _p == 0) and ((P[1] * Q[2] - Q[1] * P[2]) % _p == 0)


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _hmod(s):
    return int.from_bytes(_sha512(s), "little") % _q


def _expand(secret):
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_public(secret):
    return _compress(_mul(_expand(secret)[0], _G))


def ed_sign(secret, msg):
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _hmod(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _hmod(Rs + A + msg)
    return Rs + int.to_bytes((r + h * a) % _q, 32, "little")


def ed_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _q:
        return False
    h = _hmod(sig[:32] + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))



# ───────────────────────────── identity ─────────────────────────────
def hwid():
    """Full 128-bit ID of this PC (sent to the server, never shown)."""
    raw = ""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                raw = winreg.QueryValueEx(k, "MachineGuid")[0]
        except Exception:
            raw = ""
    if not raw:  # no readable machine GUID: keep one random ID on disk so it never changes between launches
        p = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "shxrx", "machine.id")
        try:
            with open(p, encoding="utf-8") as fh:
                raw = fh.read().strip()
        except OSError:
            raw = ""
        if len(raw) < 16:
            raw = uuid.uuid4().hex
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(raw)
            except OSError:
                pass
    return hashlib.sha256(("shxrx2|" + raw).encode()).hexdigest()[:32]


def machine_id():
    """Short ID for display only (License page). Nobody has to send it to anyone any more."""
    h = hwid()[:8].upper()
    return h[:4] + "-" + h[4:]


def pc_name():
    try:
        return os.environ.get("COMPUTERNAME") or os.uname().nodename
    except Exception:
        return ""


def clean_key(text):
    s = "".join(c for c in (text or "").upper() if c.isalnum())
    if len(s) == 25 and s.startswith("SHXRX"):
        s = s[5:]
    return s


def format_key(k):
    k = clean_key(k)
    return "SHXRX-" + "-".join(k[i:i + 5] for i in range(0, len(k), 5))


format_stored_key = format_key


# ───────────────────────────── tamper tests ─────────────────────────────
_ST_PUB = bytes.fromhex("757013513502f0c70c2b19c477dbfc63633594c056d8446ad3f1c6b91c955bc8")
_ST_SIG = bytes.fromhex("cd8c988309ed7dcab22957141e51bfde6cf451e94fc5662dfa965bec793ad5a1"
                        "127883223ea2e3f1b3e1cf41e2a3a74d9e84807817865cb4579d8d85740a5605")


def selftest():
    """Stops the app if the signature check was patched to 'always true' (a typical crack)."""
    bad = bytes([_ST_SIG[0] ^ 1]) + _ST_SIG[1:]
    ok = (ed_verify(_ST_PUB, b"shxrx-selftest", _ST_SIG) is True
          and ed_verify(_ST_PUB, b"shxrx-selftesT", _ST_SIG) is False
          and ed_verify(_ST_PUB, b"shxrx-selftest", bad) is False)
    if FROZEN and os.name == "nt":
        try:
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                ok = False
        except Exception:
            pass
    if not ok:
        os._exit(3)


# ───────────────────────────── server talk ─────────────────────────────
class NetError(Exception):
    """Server not reachable / answer not genuine."""


def _server_pub():
    try:
        b = bytes.fromhex(SERVER_PUBKEY_HEX)
        return b if len(b) == 32 else None
    except ValueError:
        return None


def verify_envelope(env, nonce=None):
    """Check a signed server answer. Returns the payload dict or raises NetError."""
    pub = _server_pub()
    if pub is None or not SERVER_URL:
        raise NetError("This build has no license server set. Run shxrx_server.py --install with your server address and rebuild.")
    try:
        p = env["p"]
        sig = bytes.fromhex(env["s"])
        if not ed_verify(pub, b"shxrx-resp|" + p.encode(), sig):
            raise NetError("The license server's signature does not match the public key built into this app "
                           "(SERVER_PUBKEY_HEX). The app and the server were set up with different keys - "
                           "copy the shxrx_license.py that shxrx_server.py patched into the app folder and rebuild.")
        d = json.loads(p)
        if not isinstance(d, dict) or not isinstance(d.get('ok'), bool):
            raise ValueError('Invalid license payload')
    except NetError:
        raise
    except Exception:
        raise NetError("The license server sent something unreadable.")
    if d.get("hwid") != hwid() or (nonce is not None and d.get("nonce") != nonce):
        raise NetError("The license server's answer did not match this request (wrong PC ID or replayed answer).")
    return d


def _call(path, body, timeout=10):
    if not SERVER_URL:
        raise NetError("This build has no license server set. Run shxrx_server.py --install with your server address and rebuild.")
    nonce = secrets.token_hex(16)
    body = dict(body, nonce=nonce, hwid=hwid(), ver=APP_VERSION, pc=pc_name())
    req = urllib.request.Request(SERVER_URL.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "shxrx/" + (APP_VERSION or "0")})
    try:
        host = urllib.parse.urlparse(SERVER_URL).hostname or ""
        # a server on this same PC must never go through a Windows/system proxy
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if host in ("127.0.0.1", "localhost", "::1") \
            else urllib.request.build_opener()
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65537)
            if len(raw) > 65536:
                raise ValueError('License response exceeds size limit')
            env = json.loads(raw.decode())
    except urllib.error.HTTPError as e:
        raise NetError("License server error (%s)." % e.code)
    except Exception as e:
        why = str(getattr(e, "reason", None) or e)[:120]
        raise NetError("Can't reach the license server at %s (%s)." % (SERVER_URL, why))
    return verify_envelope(env, nonce), env


def info_from(d):
    exp = d.get("expires")
    now = d.get("now") or time.time()
    return {"tier": d["tier"], "tier_name": TIERS.get(d["tier"], "Tier %d" % d["tier"]),
            "expires": None if exp is None else datetime.date.fromtimestamp(exp),
            "expires_ts": exp, "serial": d.get("serial", 0), "machine": bytes.fromhex(hwid())[:4],
            "days_left": None if exp is None else max(0, int(-(-(exp - now) // 86400)))}


def _activate_server(key):
    """Bind this key to this PC (first PC wins). Returns (info, payload, err)."""
    try:
        d, env = _call("/api/activate", {"key": clean_key(key)})
    except NetError as e:
        return None, None, str(e)
    if not d.get("ok"):
        return None, d, d.get("err") or "Key refused."
    return info_from(d), (d, env), None


def activate(key):
    return _activate_server(key)


# ───────────────────────────── storage ─────────────────────────────
def _file(data_dir):
    return os.path.join(data_dir, "license.json")


def _load(data_dir):
    try:
        with open(_file(data_dir), encoding="utf-8") as fh:
            d = json.load(fh)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data_dir, key, env=None):
    old = _load(data_dir)
    try:
        atomic_json(_file(data_dir), {'key': format_key(key), 'env': env or old.get('env'), 'last_seen': time.time()})
    except OSError:
        pass


def stored_key(data_dir):
    return _load(data_dir).get("key", "")


def forget(data_dir):
    """Remove the saved key from this PC (used by 'Use a different key'). The key stays bound on the server."""
    try:
        os.remove(_file(data_dir))
    except OSError:
        pass


def describe(info):
    if not info:
        return "Not activated"
    if info.get("expires") is None:
        return "%s  -  lifetime" % info["tier_name"]
    d = info.get("days_left")
    return "%s  -  expires %s (%s)" % (info["tier_name"], info["expires"].isoformat(),
                                       "today" if d == 0 else "%d day%s left" % (d, "" if d == 1 else "s"))


def _offline_info(st):
    """Use the last signed answer if it is still inside the offline grace period."""
    env = st.get("env")
    if not env:
        return None, "Can't reach the license server and this PC has no saved activation."
    try:
        d = verify_envelope(env)
    except NetError as e:
        return None, str(e)
    if not d.get("ok"):
        return None, "Saved activation is not valid."
    now, last = time.time(), st.get("last_seen", 0)
    if last and now < last - 86400:
        return None, "Your system clock was set back. Fix the date and try again."
    if now > d["issued"] + d.get("grace", 0):
        return None, ("Can't reach the license server, and the offline period has ended. "
                      "Connect to the internet once to continue.")
    if d.get("expires") and now > d["expires"]:
        return None, "This key has expired."
    return info_from(dict(d, now=now)), None


def revalidate(data_dir):
    """Called at startup with the saved key. Returns (info or None, message, payload)."""
    st = _load(data_dir)
    key = st.get("key")
    if not key:
        return None, None, None
    try:
        d, env = _call("/api/ping", {"key": key})
    except NetError as e:
        info, err = _offline_info(st)
        return info, (err or str(e)), None
    if not d.get("ok"):
        return None, d.get("err"), d
    _save(data_dir, key, env)
    return info_from(d), None, d


class Heartbeat(threading.Thread):
    """Asks the server every minute or so: still valid? any announcement / event / message?
    on_data(payload_or_None, error_text, info) is called from this thread."""

    def __init__(self, data_dir, on_data, interval=60):
        threading.Thread.__init__(self, daemon=True)
        self.data_dir, self.on_data, self.interval = data_dir, on_data, interval
        self.stop = threading.Event()

    def run(self):
        pause = 4
        while not self.stop.wait(pause):
            st = _load(self.data_dir)
            key = st.get("key")
            if not key:
                pause = 5
                continue
            t0 = time.time()
            try:
                # long-poll: the server keeps this request open and answers the moment the key is disabled
                d, env = _call("/api/ping", {"key": key, "wait": 25}, timeout=45)
            except NetError:
                info, err = _offline_info(st)
                if info is None:
                    self.on_data(None, err, None)
                pause = 10
                continue
            if d.get("ok"):
                _save(self.data_dir, key, env)
                self.on_data(d, None, info_from(d))
                # answered at once = an older server without long-poll: fall back to a normal pause
                pause = 1 if time.time() - t0 > 5 else self.interval
            else:
                self.on_data(d, d.get("err"), None)
                return


# ───────────────────────────── activation window ─────────────────────────────
def _mix(a, b, t):
    """Blend two #rrggbb colours (t = 0..1)."""
    t = max(0.0, min(1.0, t))
    ra = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    rb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(ra[i] + (rb[i] - ra[i]) * t) for i in range(3))


def _rrect(c, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle on a Canvas."""
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
           x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def _scene(root, tk, W, H, BG, ACC, title, subtitle):
    """Animated hero banner: moon, drifting clouds, haunted house, bare tree, bats, rising embers,
    flickering pumpkin and the app title. The pumpkin and embers react to st['mood'] (idle/ok/bad)
    and st['celebrate']() sends a shockwave ring out of the pumpkin."""
    import math
    import random
    rnd = random.Random()
    c = tk.Canvas(root, width=W, height=H, bg=BG, highlightthickness=0, bd=0)
    c.pack()
    st = {"f": 0, "live": True, "mood": "idle", "ring": -1, "rid": None}

    # sky gradient
    for y in range(0, H, 2):
        t = y / float(H)
        col = _mix("#06020c", "#2c1050", t / 0.62) if t < 0.62 else _mix("#2c1050", "#8a3340", (t - 0.62) / 0.38)
        c.create_rectangle(0, y, W, y + 2, outline="", fill=col)

    stars = []
    for _ in range(64):
        x, y, r = rnd.uniform(0, W), rnd.uniform(2, H * 0.62), rnd.choice((0.7, 1.0, 1.4))
        stars.append((c.create_oval(x - r, y - r, x + r, y + r, outline="", fill="#554070"), rnd.uniform(0, 6.28)))

    # moon
    mx, my = W - 118, 52
    halo = [(c.create_oval(mx - rad, my - rad, mx + rad, my + rad, outline="", fill=_mix("#1b0a30", "#ffcf8a", k)), k)
            for rad, k in ((70, 0.04), (56, 0.07), (44, 0.12))]
    c.create_oval(mx - 24, my - 24, mx + 24, my + 24, fill="#ffe6b3", outline="#ffb066", width=2)
    for dx, dy, r in ((-8, -8, 5), (9, 4, 6), (-4, 11, 3), (10, -11, 3)):
        c.create_oval(mx + dx - r, my + dy - r, mx + dx + r, my + dy + r, fill="#f0c27e", outline="")

    # clouds
    clouds = []
    for i in range(3):
        parts = [(c.create_oval(0, 0, 1, 1, outline="", fill=_mix("#1b0a30", "#3a1b5c", 0.35 + 0.12 * i)), ox, oy, w, h)
                 for ox, oy, w, h in ((0, 0, 70, 11), (-42, 5, 48, 8), (46, 6, 54, 8))]
        clouds.append((rnd.uniform(0, W), 34 + i * 26, 0.25 + 0.15 * i, parts))

    # far hill, haunted house, tree
    c.create_polygon(0, H, 0, H - 52, 70, H - 62, 160, H - 48, 270, H - 64, 380, H - 50, 500, H - 66, W, H - 54, W, H,
                     fill="#150a22", outline="")
    hx, hb = 44, H - 38
    HC, HO = "#0d0716", "#2a1640"
    c.create_rectangle(hx, hb - 50, hx + 92, hb + 8, fill=HC, outline=HO)
    c.create_polygon(hx - 8, hb - 50, hx + 46, hb - 84, hx + 100, hb - 50, fill=HC, outline=HO)
    c.create_rectangle(hx + 62, hb - 86, hx + 84, hb - 50, fill=HC, outline=HO)
    c.create_polygon(hx + 58, hb - 86, hx + 73, hb - 104, hx + 88, hb - 86, fill=HC, outline=HO)
    c.create_rectangle(hx + 14, hb - 96, hx + 22, hb - 68, fill=HC, outline=HO)
    wins = [c.create_rectangle(x1, y1, x2, y2, fill="#ffb347", outline="#3a1f52")
            for x1, y1, x2, y2 in ((hx + 10, hb - 38, hx + 22, hb - 22), (hx + 36, hb - 38, hx + 48, hb - 22),
                                   (hx + 68, hb - 76, hx + 78, hb - 62), (hx + 66, hb - 38, hx + 78, hb - 22))]

    def branch(x, y, ang, ln, wd, d):
        if d == 0:
            return
        x2, y2 = x + math.cos(ang) * ln, y - math.sin(ang) * ln
        c.create_line(x, y, x2, y2, fill=HC, width=wd, capstyle="round")
        branch(x2, y2, ang + rnd.uniform(0.3, 0.7), ln * 0.74, max(1, wd - 1), d - 1)
        branch(x2, y2, ang - rnd.uniform(0.3, 0.7), ln * 0.74, max(1, wd - 1), d - 1)
    branch(W - 44, H - 30, math.pi / 2 + 0.08, 28, 5, 6)

    # near hill + gravestones
    c.create_polygon(0, H, 0, H - 30, 110, H - 40, 230, H - 28, 340, H - 38, 470, H - 26, W, H - 36, W, H,
                     fill="#0b0612", outline="")
    for gx, gy in ((176, H - 32), (204, H - 30), (238, H - 28)):
        c.create_rectangle(gx, gy, gx + 12, gy + 14, fill="#1a0f26", outline="#3a1f52")
        c.create_oval(gx, gy - 6, gx + 12, gy + 6, fill="#1a0f26", outline="#3a1f52")

    # pumpkin
    jx, jy = W // 2, H - 20
    glows = [(c.create_oval(jx - rx, jy - ry, jx + rx, jy + ry, outline="", fill="#12081d"), rx, ry, base)
             for rx, ry, base in ((84, 48, 0.06), (64, 38, 0.10), (46, 28, 0.16))]
    c.create_oval(jx - 24, jy - 18, jx + 24, jy + 18, fill="#e8620c", outline="#7a2a00")
    c.create_oval(jx - 12, jy - 19, jx + 12, jy + 19, fill="#ff7a1a", outline="#7a2a00")
    c.create_polygon(jx - 2, jy - 17, jx + 3, jy - 17, jx + 6, jy - 27, jx + 1, jy - 27, fill="#4f8a22", outline="")
    face = [c.create_polygon(jx - 12, jy - 2, jx - 4, jy - 2, jx - 8, jy - 11, fill="#ffe27a", outline=""),
            c.create_polygon(jx + 4, jy - 2, jx + 12, jy - 2, jx + 8, jy - 11, fill="#ffe27a", outline=""),
            c.create_polygon(jx - 13, jy + 4, jx + 13, jy + 4, jx + 9, jy + 13, jx + 4, jy + 8, jx, jy + 14,
                             jx - 4, jy + 8, jx - 9, jy + 13, fill="#ffe27a", outline="")]

    # title with a dark-orange halo
    ty = 52
    big = ("Segoe UI Black", 34)
    for dx, dy in ((-2, 0), (2, 0), (0, -2), (0, 2), (-2, -2), (2, 2), (-2, 2), (2, -2)):
        c.create_text(W // 2 + dx, ty + dy, text=title, font=big, fill="#4a1c00")
    title_id = c.create_text(W // 2, ty, text=title, font=big, fill=ACC)
    c.create_text(W // 2, ty + 36, text=subtitle, font=("Segoe UI", 9, "bold"), fill="#c9a6e8")

    embers = [{"id": c.create_oval(0, 0, 2, 2, outline="", fill="#ffb347"), "x": jx, "y": jy, "vy": 1.0,
               "ph": rnd.uniform(0, 6.28), "life": rnd.random()} for _ in range(18)]
    bats = [{"x": rnd.uniform(0, W), "y": rnd.uniform(8, H * 0.55), "vx": rnd.uniform(1.3, 2.8) * rnd.choice((-1, 1)),
             "ph": rnd.uniform(0, 6.28), "s": rnd.uniform(0.8, 1.3),
             "id": c.create_polygon(0, 0, 1, 1, 2, 0, fill="#0a0412", outline="#9b6bdc")} for _ in range(5)]

    MOODS = {"idle": ("#ffb247", "#ffe27a", "#ff7518"), "ok": ("#6fc22a", "#d6ff9a", "#8bdc3c"),
             "bad": ("#ff4a4a", "#ffb0b0", "#ff5a5a")}
    BAT = ((0, -2), (-3, -5), (-5, -4), (-12, -3), (-9, 1), (-6, -1), (-3, 3), (0, 4),
           (3, 3), (6, -1), (9, 1), (12, -3), (5, -4), (3, -5))

    def celebrate():
        try:
            if st["rid"]:
                c.delete(st["rid"])
            st["rid"] = c.create_oval(0, 0, 1, 1, outline=MOODS.get(st["mood"], MOODS["idle"])[2], width=3)
            st["ring"] = st["f"]
        except tk.TclError:
            pass

    def tick():
        if not st["live"]:
            return
        try:
            st["f"] += 1
            f = st["f"]
            lo, hi, gcol = MOODS.get(st["mood"], MOODS["idle"])
            k = max(0.0, min(1.0, 0.5 + 0.5 * math.sin(f * 0.2) * math.sin(f * 0.07 + 1) + rnd.uniform(-0.1, 0.1)))
            for it in face:
                c.itemconfigure(it, fill=_mix(lo, hi, k))
            for it, _rx, _ry, base in glows:
                c.itemconfigure(it, fill=_mix("#12081d", gcol, base * (0.5 + 0.8 * k)))
            c.itemconfigure(title_id, fill=_mix(ACC, "#ffb877", 0.35 * k))
            for it, kk in halo:
                c.itemconfigure(it, fill=_mix("#1b0a30", "#ffcf8a", kk * (0.85 + 0.3 * math.sin(f * 0.03))))
            if f % 2 == 0:
                for it, ph in stars:
                    c.itemconfigure(it, fill=_mix("#3a2a55", "#ffffff", 0.5 + 0.5 * math.sin(f * 0.07 + ph)))
            for cx0, cy, sp, parts in clouds:
                x = (cx0 + f * sp) % (W + 240) - 120
                for it, ox, oy, w, h in parts:
                    c.coords(it, x + ox - w, cy + oy - h, x + ox + w, cy + oy + h)
            for w in wins:
                if rnd.random() < 0.04:
                    c.itemconfigure(w, fill=_mix("#7a4a14", "#ffd27a", rnd.random()))
            for e in embers:
                e["life"] -= 0.012
                if e["life"] <= 0:
                    e["x"], e["y"], e["vy"], e["life"] = jx + rnd.uniform(-26, 26), jy - 8, rnd.uniform(0.8, 1.8), 1.0
                e["y"] -= e["vy"]
                e["x"] += math.sin(f * 0.1 + e["ph"]) * 0.6
                r = 0.8 + e["life"] * 1.6
                c.coords(e["id"], e["x"] - r, e["y"] - r, e["x"] + r, e["y"] + r)
                c.itemconfigure(e["id"], fill=_mix(gcol, "#12081d", 1 - e["life"]))
            for b in bats:
                b["x"] += b["vx"]
                if b["x"] < -30:
                    b["x"] = W + 30
                elif b["x"] > W + 30:
                    b["x"] = -30
                y = b["y"] + math.sin(f * 0.1 + b["ph"]) * 7
                wing = 6 * math.sin(f * 0.5 + b["ph"])
                flat = []
                for i, (px, py) in enumerate(BAT):
                    if i in (3, 11):
                        py -= wing
                    elif i in (2, 12):
                        py -= wing * 0.4
                    flat += [b["x"] + px * b["s"], y + py * b["s"]]
                c.coords(b["id"], *flat)
            if st["ring"] >= 0:
                age = f - st["ring"]
                if age > 28:
                    c.delete(st["rid"])
                    st["rid"], st["ring"] = None, -1
                else:
                    r = 14 + age * 9
                    c.coords(st["rid"], jx - r, jy - r * 0.6, jx + r, jy + r * 0.6)
                    c.itemconfigure(st["rid"], outline=_mix(gcol, "#12081d", age / 28.0), width=max(1, 4 - age // 8))
            c.after(40, tick)
        except tk.TclError:
            st["live"] = False
    tick()
    st["celebrate"] = celebrate
    return c, st

def _activation_window(app, version, data_dir, url, current=None, message=None):
    import math
    import tkinter as tk
    import tkinter.font as tkfont

    BG, CARD, CARD2, ACC, TXT, MUT, BAD, GOOD = ("#08040d", "#160b21", "#1d1030", "#ff7518", "#f3e8d8",
                                                  "#9a82ad", "#ff5a5a", "#8bdc3c")
    BORDER, DIM = "#3a1f52", "#6a5580"
    W, SH = 620, 150
    PAD = 30
    IW = W - 2 * PAD
    result = {"info": None, "payload": None}
    alive = {"v": True}
    done_q = queue.Queue()

    root = tk.Tk()
    root.title("%s  |  Activate" % app)
    root.configure(bg=BG)
    root.resizable(False, False)
    try:
        root.attributes("-alpha", 0.0)
    except tk.TclError:
        pass

    scene, scene_state = _scene(root, tk, W, SH, BG, ACC, "\u2620  %s  \u2620" % app.upper(),
                                " ".join("LICENSE ACTIVATION"))
    scene.create_text(W - 12, 10, text="v%s" % version, anchor="ne", fill="#7a668f", font=("Segoe UI", 8, "bold"))

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=PAD)

    class RButton(tk.Canvas):
        def __init__(self, parent, text, cmd, w, h, primary=False, size=10, bg=BG):
            tk.Canvas.__init__(self, parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
            self.cmd, self.primary = cmd, primary
            self.enabled, self.hover, self.target, self.pulse, self.running = True, 0.0, 0.0, 0.0, False
            self.shape = _rrect(self, 1, 1, w - 1, h - 1, min(14, h // 2), fill=CARD, outline=BORDER, width=1)
            self.label = self.create_text(w // 2, h // 2, text=text, font=("Segoe UI", size, "bold"), fill=TXT)
            self.bind("<Enter>", lambda e: self._to(1.0))
            self.bind("<Leave>", lambda e: self._to(0.0))
            self.bind("<Button-1>", self._click)
            self._paint()

        def _click(self, _e=None):
            if self.enabled:
                self.cmd()

        def _to(self, t):
            self.target = t if self.enabled else 0.0
            if not self.running:
                self.running = True
                self._step()

        def _step(self):
            try:
                d = self.target - self.hover
                if abs(d) < 0.02:
                    self.hover, self.running = self.target, False
                    self._paint()
                    return
                self.hover += d * 0.35
                self._paint()
                self.after(16, self._step)
            except tk.TclError:
                self.running = False

        def _paint(self):
            if self.primary:
                if self.enabled:
                    col = _mix(ACC, "#ffb877", self.hover * 0.55 + self.pulse * 0.22)
                    fill, outl, tc = col, col, BG
                else:
                    fill, outl, tc = "#211230", "#34204a", DIM
            else:
                fill, outl = _mix(CARD, "#2b1640", self.hover), _mix(BORDER, ACC, self.hover)
                tc = TXT if self.enabled else DIM
            self.itemconfigure(self.shape, fill=fill, outline=outl)
            self.itemconfigure(self.label, fill=tc)

        def set_text(self, text):
            self.itemconfigure(self.label, text=text)

        def set_enabled(self, on):
            self.enabled = on
            self.target = 0.0 if not on else self.target
            self.configure(cursor="hand2" if on else "arrow")
            self._paint()

    # ───────── key input ─────────
    krow = tk.Frame(body, bg=BG)
    krow.pack(fill="x", pady=(16, 4))
    tk.Label(krow, text="LICENSE KEY", bg=BG, fg=TXT, font=("Segoe UI", 9, "bold")).pack(side="left")
    count_lbl = tk.Label(krow, text="0 / 20", bg=BG, fg=MUT, font=("Consolas", 9, "bold"))
    count_lbl.pack(side="right")

    box = tk.Text(body, height=1, bg=CARD, fg=TXT, insertbackground=ACC, relief="flat", bd=0, padx=12, pady=11,
                  font=("Consolas", 13), wrap="none", highlightthickness=2, highlightbackground=BORDER,
                  highlightcolor=ACC, selectbackground=ACC, selectforeground=BG)
    box.pack(fill="x")
    box.focus_set()
    hint = tk.Label(box, text="SHXRX-XXXXX-XXXXX-XXXXX-XXXXX   (Ctrl+V to paste)", bg=CARD, fg="#4a3566",
                    font=("Segoe UI", 10), cursor="xterm")
    hint.place(x=12, y=11)
    hint.bind("<Button-1>", lambda e: box.focus_set())

    CW, CHH, GAP = (IW - 3 * 8 - 2) // 4, 30, 8
    gc = tk.Canvas(body, width=IW, height=CHH + 2, bg=BG, highlightthickness=0, bd=0)
    gc.pack(pady=(10, 0))
    cells = []
    for i in range(4):
        x1 = 1 + i * (CW + GAP)
        r = _rrect(gc, x1, 1, x1 + CW, 1 + CHH, 9, fill="#0f0819", outline="#24123a")
        t = gc.create_text(x1 + CW // 2, 1 + CHH // 2, text="\u00b7" * 5, fill="#3a2a50", font=("Consolas", 12, "bold"))
        cells.append((r, t))

    # ───────── result card ─────────
    CH = 90
    rc = tk.Canvas(body, width=IW, height=CH, bg=BG, highlightthickness=0, bd=0)
    rc.pack(pady=(14, 0))
    small = tkfont.Font(family="Segoe UI", size=9)
    pillf = tkfont.Font(family="Segoe UI", size=9, weight="bold")

    def set_card(kind, title, sub, tier="", tier_col=None, chips=()):
        col = {"idle": MUT, "info": ACC, "ok": GOOD, "bad": BAD}[kind]
        glyph = {"idle": "\u2026", "info": "\u2026", "ok": "\u2713", "bad": "\u2715"}[kind]
        rc.delete("all")
        _rrect(rc, 1, 1, IW - 1, CH - 1, 14, fill=CARD, outline=BORDER if kind == "idle" else col)
        rc.create_oval(18, 14, 52, 48, fill=_mix(CARD, col, 0.22), outline=col)
        rc.create_text(35, 31, text=glyph, fill=col, font=("Segoe UI Symbol", 14, "bold"))
        rc.create_text(66, 24, text=title, anchor="w", fill=TXT if kind == "idle" else col, font=("Segoe UI", 12, "bold"))
        rc.create_text(66, 44, text=sub, anchor="nw", fill=MUT, font=("Segoe UI", 9), width=IW - 86)
        if tier:
            pw = pillf.measure(tier.upper()) + 22
            _rrect(rc, IW - 16 - pw, 13, IW - 16, 35, 9, fill=tier_col or ACC, outline="")
            rc.create_text(IW - 16 - pw // 2, 24, text=tier.upper(), fill=BG, font=("Segoe UI", 9, "bold"))
        x = 66
        for text in chips:
            cw = small.measure(text) + 30
            _rrect(rc, x, 60, x + cw, 82, 9, fill=CARD2, outline=BORDER)
            rc.create_oval(x + 9, 68, x + 15, 74, fill=col, outline="")
            rc.create_text(x + 21, 71, text=text, anchor="w", fill=TXT, font=("Segoe UI", 9))
            x += cw + 8

    IDLE_SUB = "Paste the key you got from the seller. It locks to the first PC that activates it."
    if message:
        set_card("bad", "Activation needed", message)
    else:
        set_card("idle", "Waiting for your key", IDLE_SUB)

    # ───────── buttons ─────────
    brow = tk.Frame(body, bg=BG)
    brow.pack(pady=(14, 0))
    SW = 126
    act_w = IW - SW - 12 - ((SW + 12) if url else 0)
    paste_b = RButton(brow, "Paste", lambda: paste(), SW, 44)
    paste_b.pack(side="left")
    act_b = RButton(brow, "Activate", lambda: do_activate(), act_w, 44, primary=True, size=12)
    act_b.pack(side="left", padx=12)
    act_b.set_enabled(False)
    if url:
        import webbrowser
        RButton(brow, "Get a key", lambda: webbrowser.open(url), SW, 44).pack(side="left")

    status = tk.Label(body, text="", bg=BG, fg=MUT, font=("Segoe UI", 9), wraplength=IW, height=1)
    status.pack(pady=(8, 0))
    tk.Label(body, text="Enter to activate   \u00b7   Esc to close   \u00b7   Internet needed to activate",
             bg=BG, fg="#4a3566", font=("Segoe UI", 8)).pack(pady=(4, 10))

    state = {"locked": False, "busy": False}

    def set_status(text, col=MUT):
        status.config(text=text, fg=col)

    def paint_grid(s, mode=None):
        for i in range(4):
            part = s[i * 5:(i + 1) * 5]
            if mode == "ok":
                fill, outl, tc = _mix(CARD, GOOD, 0.12), GOOD, GOOD
            elif mode == "bad" and part:
                fill, outl, tc = _mix(CARD, BAD, 0.12), BAD, BAD
            elif len(part) == 5:
                fill, outl, tc = CARD2, _mix(BORDER, ACC, 0.6), TXT
            elif part:
                fill, outl, tc = CARD2, ACC, ACC
            else:
                fill, outl, tc = "#0f0819", "#24123a", "#3a2a50"
            gc.itemconfigure(cells[i][0], fill=fill, outline=outl)
            gc.itemconfigure(cells[i][1], text=part + "\u00b7" * (5 - len(part)), fill=tc)

    def on_change(_e=None):
        if state["locked"] or state["busy"]:
            return
        raw = box.get("1.0", "end")
        s = clean_key(raw)
        n = len(s)
        count_lbl.config(text="%d / 20" % n, fg=GOOD if n == 20 else (BAD if n > 20 else MUT))
        if raw.strip():
            hint.place_forget()
        else:
            hint.place(x=12, y=11)
        if n == 20 and raw.strip() != format_key(s):
            box.delete("1.0", "end")
            box.insert("1.0", format_key(s))
        scene_state["mood"] = "idle"
        paint_grid(s)
        act_b.set_enabled(n == 20)
        if n == 0:
            set_card("idle", "Waiting for your key", IDLE_SUB)
        elif n < 20:
            set_card("info", "Reading your key...", "%d more character%s to go." % (20 - n, "" if 20 - n == 1 else "s"))
        else:
            set_card("info", "Key looks complete", "Press Activate to check it with the license server.")

    def paste():
        if state["locked"] or state["busy"]:
            return
        try:
            txt = root.clipboard_get()
        except tk.TclError:
            set_status("The clipboard is empty.", BAD)
            return
        box.delete("1.0", "end")
        box.insert("1.0", txt.strip().replace("\n", ""))
        set_status("", MUT)
        on_change()
        box.focus_set()

    x0 = y0 = 0

    def shake():
        for dx in (-10, 10, -8, 8, -5, 5, -2, 2, 0):
            root.geometry("+%d+%d" % (x0 + dx, y0))
            root.update()
            root.after(14)

    def finish():
        alive["v"] = False
        scene_state["live"] = False
        try:
            for i in range(10):
                root.attributes("-alpha", 1.0 - (i + 1) / 10.0)
                root.update()
                root.after(18)
        except tk.TclError:
            pass
        root.destroy()

    def do_activate(_e=None):
        if state["locked"] or state["busy"]:
            return "break"
        s = clean_key(box.get("1.0", "end"))
        if len(s) != 20:
            set_status("Paste a complete key first.", BAD)
            return "break"
        state["busy"] = True
        act_b.set_text("Checking...")
        act_b.set_enabled(False)
        set_card("info", "Contacting the license server...", "Binding this key to this PC.")

        def work():
            done_q.put(activate_online(s))
        threading.Thread(target=work, daemon=True).start()
        return "break"

    def activate_online(s):
        return _activate_server(s)

    def on_done(res):
        info, pl, err = res
        state["busy"] = False
        act_b.set_text("Activate")
        s = clean_key(box.get("1.0", "end"))
        if err:
            paint_grid(s, "bad")
            scene_state["mood"] = "bad"
            set_card("bad", "This key can't be used", err)
            act_b.set_enabled(True)
            shake()
            return
        d, env = pl
        state["locked"] = True
        _save(data_dir, s, env)
        result["info"], result["payload"] = info, d
        box.config(state="disabled")
        paint_grid(s, "ok")
        scene_state["mood"] = "ok"
        scene_state["celebrate"]()
        act_b.set_text("\u2713  Activated")
        act_b.set_enabled(False)
        d_left = info.get("days_left")
        first = "Never expires" if info["expires"] is None else "Expires %s  \u00b7  %d day%s left" % (
            info["expires"].isoformat(), d_left, "" if d_left == 1 else "s")
        set_card("ok", "Activated  -  welcome!", "Opening %s..." % app, info["tier_name"],
                 TIER_COLORS.get(info["tier"], ACC), (first, "Locked to this PC", "ID %08X" % info["serial"]))
        root.after(1300, finish)

    def poll_done():
        if not alive["v"]:
            return
        try:
            while True:
                on_done(done_q.get_nowait())
        except queue.Empty:
            pass
        except tk.TclError:
            return
        try:
            root.after(80, poll_done)
        except tk.TclError:
            pass

    def on_close():
        alive["v"] = False
        scene_state["live"] = False
        root.destroy()

    def pulse_loop():
        if not alive["v"]:
            return
        try:
            if act_b.enabled and not state["locked"]:
                act_b.pulse = 0.5 + 0.5 * math.sin(time.time() * 3.2)
                act_b._paint()
            root.after(50, pulse_loop)
        except tk.TclError:
            pass

    def dark_titlebar():
        if os.name != "nt":
            return
        try:
            import ctypes
            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            for attr, val in ((20, 1), (19, 1), (35, 0x000D0408), (36, 0x00D8E8F3)):
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(ctypes.c_int(val)), 4)
        except Exception:
            pass

    box.bind("<KeyRelease>", on_change)
    box.bind("<<Paste>>", lambda e: root.after(30, on_change))
    box.bind("<Return>", do_activate)
    root.bind("<Escape>", lambda e: on_close())
    root.protocol("WM_DELETE_WINDOW", on_close)

    if current:
        set_status("Current license: %s" % describe(current), MUT)
    try:  # a key sitting on the clipboard? say so
        clip = clean_key(root.clipboard_get())
        if len(clip) == 20:
            set_status("A key was found on your clipboard - press Paste to use it.", ACC)
    except Exception:
        pass

    root.update_idletasks()
    H = root.winfo_reqheight()
    x0 = (root.winfo_screenwidth() - W) // 2
    y0 = max(8, (root.winfo_screenheight() - H) // 4)
    root.geometry("%dx%d+%d+%d" % (W, H, x0, y0))
    root.after(60, dark_titlebar)
    pulse_loop()
    poll_done()

    def fade_in(i=0):
        try:
            root.attributes("-alpha", min(1.0, (i + 1) / 10.0))
        except tk.TclError:
            return
        if i < 9:
            root.after(20, lambda: fade_in(i + 1))
    fade_in()
    try:
        root.lift()
        root.focus_force()
    except tk.TclError:
        pass
    root.mainloop()
    return (result["info"], result["payload"]) if result["info"] else (None, None)


def ensure_licensed(app="shxrx", version="", data_dir=".", url=None, force=False, current=None):
    """Returns (license info, first server payload) if the app may run, or (None, None) if the user closed the window.
    force=True always shows the window (used by 'Use a different key')."""
    global APP_VERSION
    APP_VERSION = version
    selftest()
    message = None
    if not force:
        info, message, payload = revalidate(data_dir)
        if info:
            return info, payload
    return _activation_window(app, version, data_dir, url, current, message)
