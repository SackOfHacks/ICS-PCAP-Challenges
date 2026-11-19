#!/usr/bin/env python3
"""Download a PUBLIC MEGA folder link (https://mega.nz/folder/<id>#<key>) without an account.

Implements MEGA's public-folder protocol: list the folder's nodes, decrypt node keys and names with the
folder key (AES-128-ECB / AES-CBC), request each file's download URL, and decrypt the content with
AES-128-CTR. Needs the `cryptography` package and curl. Usage:
  mega_fetch.py <folder-link> --list
  mega_fetch.py <folder-link> --out DIR [--include REGEX]

Safety: every node name must be a single plain path component and every output path must stay inside --out;
transfers are HTTPS-only; each file's MEGA MAC (the CBC-MAC carried in its key) is verified while it is
decrypted, and a file that fails it is discarded. Exit status 1 if any file was refused or failed.
"""
import argparse, base64, json, os, re, struct, subprocess, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

API = "https://g.api.mega.co.nz/cs"
UA = "dataset-fetch/1.0 (research download)"
SEQ = [int(time.time()) % 100000]
CURL = ["curl", "--proto", "=https", "--proto-redir", "=https"]
BAD = re.compile(r"[/\\\x00-\x1f\x7f]")

class Refused(Exception):
    pass

def b64d(s):
    s = s.replace("-", "+").replace("_", "/").replace(",", "")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def a32(b): return struct.unpack(">%dI" % (len(b) // 4), b)
def b32(a): return struct.pack(">%dI" % len(a), *a)

def api(req, folder):
    SEQ[0] += 1
    r = subprocess.run(CURL + ["-sS", "--retry", "5", "--retry-delay", "5", "-A", UA, "-H", "Content-Type: application/json",
                               "-d", json.dumps([req]), "--", f"{API}?id={SEQ[0]}&n={folder}"], capture_output=True, text=True, timeout=120)
    out = json.loads(r.stdout)
    if isinstance(out, int) or (isinstance(out, list) and isinstance(out[0], int)):
        raise SystemExit(f"MEGA API error {out}")
    return out[0]

def ecb_dec(key, data):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor(); return d.update(data) + d.finalize()

def cbc_dec(key, data):
    d = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).decryptor(); return d.update(data) + d.finalize()

def safe_component(nm):
    if not isinstance(nm, str) or not nm or nm in (".", "..") or BAD.search(nm):
        raise Refused(f"unsafe name in the MEGA folder: {nm!r}")
    return nm

def nodes(folder, fkey):
    res = api({"a": "f", "c": 1, "r": 1, "ca": 1}, folder)
    out, names = [], {}
    for n in res["f"]:
        k = n.get("k", "")
        if ":" not in k: continue
        raw = ecb_dec(fkey, b64d(k.split(":", 1)[1]))
        if n["t"] == 0:                                    # file: 256-bit composite key = AES key, CTR nonce, meta-MAC
            w = a32(raw)
            key = b32((w[0] ^ w[4], w[1] ^ w[5], w[2] ^ w[6], w[3] ^ w[7]))
            iv, mac_iv, meta_mac = b32((w[4], w[5], 0, 0)), b32((w[4], w[5], w[4], w[5])), (w[6], w[7])
        else:
            key, iv, mac_iv, meta_mac = raw[:16], None, None, None
        attr = cbc_dec(key, b64d(n["a"])).rstrip(b"\0")
        name = json.loads(attr[4:].decode("utf-8", "replace")).get("n", n["h"]) if attr.startswith(b"MEGA") else n["h"]
        names[n["h"]] = (name, n.get("p"))
        out.append({"h": n["h"], "t": n["t"], "p": n.get("p"), "name": name, "size": n.get("s", 0), "key": key, "iv": iv,
                    "mac_iv": mac_iv, "meta_mac": meta_mac})
    def path(h):
        parts, seen = [], set()
        while h in names and h not in seen:
            seen.add(h); nm, p = names[h]; parts.append(nm); h = p
        return list(reversed(parts))
    for n in out:
        try:
            n["path"] = "/".join(safe_component(c) for c in path(n["h"])); n["refused"] = None
        except Refused as e:
            n["path"] = "/".join(path(n["h"])); n["refused"] = str(e)
    return out

def chunk_sizes(size):
    """MEGA's MAC chunking: 128 KiB, 256 KiB, ... up to 1 MiB, then 1 MiB chunks."""
    p, s = 0, 0x20000
    while p + s < size:
        yield s; p += s
        if s < 0x100000: s += 0x20000
    yield size - p

class Mac:
    """MEGA's file MAC: a CBC-MAC per chunk (IV = nonce|nonce) chained by a CBC-MAC over the chunk MACs."""
    def __init__(self, key, mac_iv):
        self.key, self.mac_iv = key, mac_iv
        self.chain = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor(); self.last = b"\0" * 16
    def chunk(self, pt):
        if not pt: return
        e = Cipher(algorithms.AES(self.key), modes.CBC(self.mac_iv)).encryptor()
        self.last = self.chain.update(e.update(pt + b"\0" * (-len(pt) % 16))[-16:])
    def ok(self, meta_mac):
        m = struct.unpack(">4I", self.last)
        return (m[0] ^ m[1], m[2] ^ m[3]) == tuple(meta_mac)

def mac_ok_file(path, n):
    """Re-check an already decrypted file on disk (resume) against its MEGA MAC."""
    if n["size"] == 0: return True
    mac = Mac(n["key"], n["mac_iv"])
    with open(path, "rb") as f:
        for s in chunk_sizes(n["size"]): mac.chunk(f.read(s))
    return mac.ok(n["meta_mac"])

def fetch_blob(url, tmp):
    """The encrypted bytes, over HTTPS only. Separate so tests can substitute it."""
    subprocess.run(CURL + ["-sS", "-L", "--retry", "8", "--retry-delay", "10", "-C", "-", "-A", UA, "-o", tmp, "--", url], check=True)

def download(folder, n, dest):
    if os.path.exists(dest) and os.path.getsize(dest) == n["size"]:
        if mac_ok_file(dest, n): return "exists"
        os.remove(dest)                                    # a stale or altered copy: fetch it again
    g = api({"a": "g", "g": 1, "ssl": 2, "n": n["h"]}, folder)
    url = g.get("g", "") if isinstance(g, dict) else ""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise Refused(f"MEGA returned a non-https download URL for {n['path']}")
    tmp = dest + ".enc"
    fetch_blob(url, tmp)
    if os.path.getsize(tmp) != n["size"]: return f"size mismatch {os.path.getsize(tmp)} != {n['size']}"
    dec = Cipher(algorithms.AES(n["key"]), modes.CTR(n["iv"])).decryptor(); mac = Mac(n["key"], n["mac_iv"])
    part = dest + ".partial"
    with open(tmp, "rb") as fi, open(part, "wb") as fo:
        for s in chunk_sizes(n["size"]):
            pt = dec.update(fi.read(s)); mac.chunk(pt); fo.write(pt)
        fo.write(dec.finalize())
    os.remove(tmp)
    if n["size"] and not mac.ok(n["meta_mac"]):
        os.remove(part)
        raise Refused(f"MAC mismatch - {n['path']} was altered in transit or at the source; discarded")
    os.replace(part, dest)
    return "ok"

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("link"); ap.add_argument("--list", action="store_true")
    ap.add_argument("--out"); ap.add_argument("--include", default=".")
    a = ap.parse_args()
    m = re.match(r"https://mega\.(?:nz|co\.nz)/folder/([A-Za-z0-9_-]+)#([A-Za-z0-9_-]+)$", a.link)
    if not m: raise SystemExit("expected a https://mega.nz/folder/<id>#<key> link")
    folder, fkey = m.group(1), b64d(m.group(2))
    ns = [n for n in nodes(folder, fkey) if n["t"] == 0]
    tot = sum(n["size"] for n in ns)
    if a.list or not a.out:
        for n in sorted(ns, key=lambda x: x["path"]):
            print(f"{n['size']/1e6:10.1f} MB  {n['path']}" + (f"   [REFUSED: {n['refused']}]" if n["refused"] else ""))
        print(f"{len(ns)} files, {tot/1e9:.2f} GB"); return
    inc = re.compile(a.include, re.I)
    out = os.path.realpath(a.out); os.makedirs(out, exist_ok=True)
    bad = 0
    for n in sorted(ns, key=lambda x: x["path"]):
        if not inc.search(n["path"]): continue
        try:
            if n["refused"]: raise Refused(n["refused"])
            dest = os.path.realpath(os.path.join(out, n["path"]))
            if os.path.commonpath([out, dest]) != out: raise Refused(f"path leaves --out: {n['path']!r}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            status = download(folder, n, dest)
            if status not in ("ok", "exists"): bad += 1
            print(f"{status:10} {n['size']/1e6:9.1f} MB  {n['path']}", flush=True)
        except Refused as e:
            bad += 1; print(f"REFUSED    {e}", flush=True)
    if bad:
        print(f"{bad} file(s) refused or failed", flush=True); sys.exit(1)

if __name__ == "__main__":
    main()
