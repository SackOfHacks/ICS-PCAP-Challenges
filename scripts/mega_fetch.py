#!/usr/bin/env python3
"""Download a PUBLIC MEGA folder link (https://mega.nz/folder/<id>#<key>) without an account.

Implements MEGA's public-folder protocol: list the folder's nodes, decrypt node keys and names with the
folder key (AES-128-ECB / AES-CBC), request each file's download URL, and decrypt the content with
AES-128-CTR. Needs the `cryptography` package and curl. Usage:
  mega_fetch.py <folder-link> --list
  mega_fetch.py <folder-link> --out DIR [--include REGEX]
"""
import argparse, base64, json, os, re, struct, subprocess, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

API = "https://g.api.mega.co.nz/cs"
UA = "dataset-fetch/1.0 (research download)"
SEQ = [int(time.time()) % 100000]

def b64d(s):
    s = s.replace("-", "+").replace("_", "/").replace(",", "")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def a32(b): return struct.unpack(">%dI" % (len(b) // 4), b)
def b32(a): return struct.pack(">%dI" % len(a), *a)

def api(req, folder):
    SEQ[0] += 1
    r = subprocess.run(["curl", "-sS", "--retry", "5", "--retry-delay", "5", "-A", UA, "-H", "Content-Type: application/json",
                        "-d", json.dumps([req]), f"{API}?id={SEQ[0]}&n={folder}"], capture_output=True, text=True, timeout=120)
    out = json.loads(r.stdout)
    if isinstance(out, int) or (isinstance(out, list) and isinstance(out[0], int)):
        raise SystemExit(f"MEGA API error {out}")
    return out[0]

def ecb_dec(key, data):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor(); return d.update(data) + d.finalize()

def cbc_dec(key, data):
    d = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).decryptor(); return d.update(data) + d.finalize()

def nodes(folder, fkey):
    res = api({"a": "f", "c": 1, "r": 1, "ca": 1}, folder)
    out, names = [], {}
    for n in res["f"]:
        k = n.get("k", "")
        if ":" not in k: continue
        raw = ecb_dec(fkey, b64d(k.split(":", 1)[1]))
        if n["t"] == 0:                                    # file: 256-bit composite key
            w = a32(raw); key = b32((w[0] ^ w[4], w[1] ^ w[5], w[2] ^ w[6], w[3] ^ w[7])); iv = b32((w[4], w[5], 0, 0))
        else:
            key, iv = raw[:16], None
        attr = cbc_dec(key, b64d(n["a"])).rstrip(b"\0")
        name = json.loads(attr[4:].decode("utf-8", "replace")).get("n", n["h"]) if attr.startswith(b"MEGA") else n["h"]
        names[n["h"]] = (name, n.get("p"))
        out.append({"h": n["h"], "t": n["t"], "p": n.get("p"), "name": name, "size": n.get("s", 0), "key": key, "iv": iv})
    def path(h):
        parts = []
        while h in names:
            nm, p = names[h]; parts.append(nm); h = p
        return "/".join(reversed(parts))
    for n in out: n["path"] = path(n["h"])
    return out

def download(folder, n, dest):
    if os.path.exists(dest) and os.path.getsize(dest) == n["size"]: return "exists"
    g = api({"a": "g", "g": 1, "n": n["h"]}, folder)
    tmp = dest + ".enc"
    subprocess.run(["curl", "-sS", "-L", "--retry", "8", "--retry-delay", "10", "-C", "-", "-A", UA, "-o", tmp, g["g"]], check=True)
    if os.path.getsize(tmp) != n["size"]: return f"size mismatch {os.path.getsize(tmp)} != {n['size']}"
    dec = Cipher(algorithms.AES(n["key"]), modes.CTR(n["iv"])).decryptor()
    with open(tmp, "rb") as fi, open(dest, "wb") as fo:
        for chunk in iter(lambda: fi.read(1 << 22), b""): fo.write(dec.update(chunk))
        fo.write(dec.finalize())
    os.remove(tmp)
    return "ok"

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("link"); ap.add_argument("--list", action="store_true")
    ap.add_argument("--out"); ap.add_argument("--include", default=".")
    a = ap.parse_args()
    m = re.match(r"https://mega\.(?:nz|co\.nz)/folder/([^#]+)#(.+)$", a.link)
    if not m: raise SystemExit("expected a https://mega.nz/folder/<id>#<key> link")
    folder, fkey = m.group(1), b64d(m.group(2))
    ns = [n for n in nodes(folder, fkey) if n["t"] == 0]
    tot = sum(n["size"] for n in ns)
    if a.list or not a.out:
        for n in sorted(ns, key=lambda x: x["path"]): print(f"{n['size']/1e6:10.1f} MB  {n['path']}")
        print(f"{len(ns)} files, {tot/1e9:.2f} GB"); return
    inc = re.compile(a.include, re.I)
    for n in sorted(ns, key=lambda x: x["path"]):
        if not inc.search(n["path"]): continue
        dest = os.path.join(a.out, n["path"]); os.makedirs(os.path.dirname(dest), exist_ok=True)
        print(f"{download(folder, n, dest):10} {n['size']/1e6:9.1f} MB  {n['path']}", flush=True)

if __name__ == "__main__":
    main()
