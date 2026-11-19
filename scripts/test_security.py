#!/usr/bin/env python3
"""Regression tests for the safety properties of scripts/fetch.py, scripts/mega_fetch.py, scripts/build.py and the
web app. Every hostile input is built here, in a temporary folder; nothing else is touched and no network is used.
Uses 7z, tcpdump, the `cryptography` package and node when present, and reports which groups it skipped.
Run from anywhere:  python3 scripts/test_security.py      (exit 1 on any failure)
"""
import base64, io, json, os, re, shutil, stat, struct, subprocess, sys, tarfile, tempfile, zipfile
import importlib.util as ilu

HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(HERE)
def load(name):
    s = ilu.spec_from_file_location(name, os.path.join(HERE, name + ".py")); m = ilu.module_from_spec(s); s.loader.exec_module(m); return m
fetch, build = load("fetch"), load("build")
RESULTS, SKIPPED = [], []

def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail)); print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not cond else ""))

def tar_bytes(members, mode="w"):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode=mode) as tf:
        for kind, name, val in members:
            ti = tarfile.TarInfo(name)
            if kind == "sym": ti.type, ti.linkname = tarfile.SYMTYPE, val; tf.addfile(ti)
            elif kind == "hard": ti.type, ti.linkname = tarfile.LNKTYPE, val; tf.addfile(ti)
            else:
                ti.size = len(val); ti.mode = 0o4755 if kind == "suid" else 0o644; tf.addfile(ti, io.BytesIO(val))
    return bio.getvalue()

def links_under(root):
    return [os.path.join(dp, n) for dp, dns, fns in os.walk(root) for n in dns + fns if os.path.islink(os.path.join(dp, n))]

def test_extraction(t):
    fetch.DATA = os.path.join(t, "data"); victim = os.path.join(t, "victim"); os.makedirs(victim)
    open(os.path.join(victim, "precious.txt"), "w").write("original")
    # 1. the two-stage attack: a symlink to a folder outside, then a nested archive unpacked "into" that symlink
    inner = tar_bytes([("file", "PWNED.txt", b"written outside data/")])
    outer = os.path.join(t, "a.tar.gz"); open(outer, "wb").write(tar_bytes([("sym", "x", victim), ("file", "x.tar", inner)], "w:gz"))
    xd = os.path.join(t, "x1"); fetch.safe_extract(outer, xd); fetch.extract_nested(xd)
    check("tar: symlink + nested archive cannot write outside", not os.path.exists(os.path.join(victim, "PWNED.txt")) and not links_under(xd))
    check("tar: the nested archive still unpacks inside", os.path.exists(os.path.join(xd, "x", "PWNED.txt")))
    # 2-4. '..', absolute paths and a hard link to an outside file
    for label, members in (("'..' member", [("file", "../escape.txt", b"x")]),
                           ("absolute member", [("file", os.path.join(t, "abs.txt"), b"x")])):
        p = os.path.join(t, "b.tar"); open(p, "wb").write(tar_bytes(members))
        ok = fetch.safe_extract(p, os.path.join(t, "x2"))
        check(f"tar: {label} refused", not ok and not os.path.exists(os.path.join(t, "escape.txt")) and not os.path.exists(os.path.join(t, "abs.txt")))
    p = os.path.join(t, "c.tar"); open(p, "wb").write(tar_bytes([("hard", "h", os.path.join(victim, "precious.txt")), ("file", "ok.txt", b"fine")]))
    fetch.safe_extract(p, os.path.join(t, "x3"))
    check("tar: hard link to an outside file is not created", not os.path.exists(os.path.join(t, "x3", "h"))
          and open(os.path.join(victim, "precious.txt")).read() == "original")
    p = os.path.join(t, "d.tar"); open(p, "wb").write(tar_bytes([("suid", "tool", b"#!/bin/sh\n")]))
    fetch.safe_extract(p, os.path.join(t, "x4"))
    check("tar: setuid/exec bits stripped", stat.S_IMODE(os.stat(os.path.join(t, "x4", "tool")).st_mode) == 0o644)
    p = os.path.join(t, "e.tar.gz"); open(p, "wb").write(tar_bytes([("file", "dir/cap.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 20)], "w:gz"))
    check("tar: a normal archive unpacks (positive control)", fetch.safe_extract(p, os.path.join(t, "x5"))
          and open(os.path.join(t, "x5", "dir", "cap.pcap"), "rb").read(4) == b"\xd4\xc3\xb2\xa1")
    # the whole source route, end to end, with the download replaced by a local copy
    real_dl = fetch.download
    fetch.download = lambda url, dest, referer=None: (os.makedirs(os.path.dirname(dest), exist_ok=True), shutil.copyfile(outer, dest), (True, ""))[-1]
    try:
        ds = {"slug": "poc", "title": "poc", "keep": [], "files": [{"url": "https://example.invalid/capture.tar.gz", "name": "capture.tar.gz"}]}
        fetch.fetch(ds)
    finally:
        fetch.download = real_dl
    check("fetch(): source route end to end writes nothing outside data/", not os.path.exists(os.path.join(victim, "PWNED.txt")) and not links_under(fetch.DATA))
    if not shutil.which("7z"): SKIPPED.append("7z archives (7z missing)"); return
    z = os.path.join(t, "l.zip")
    with zipfile.ZipFile(z, "w") as zf:
        zi = zipfile.ZipInfo("d/link"); zi.create_system = 3; zi.external_attr = (stat.S_IFLNK | 0o777) << 16; zf.writestr(zi, victim)
        zf.writestr("d/x", "hi")
    check("zip: archive containing a symlink refused", not fetch.safe_extract(z, os.path.join(t, "x6")) and not links_under(os.path.join(t, "x6")))
    z = os.path.join(t, "dd.zip")
    with zipfile.ZipFile(z, "w") as zf: zf.writestr(zipfile.ZipInfo("../zip_escape.txt"), "x")
    check("zip: '..' member refused", not fetch.safe_extract(z, os.path.join(t, "x7")) and not os.path.exists(os.path.join(t, "zip_escape.txt")))
    src = os.path.join(t, "src7"); os.makedirs(os.path.join(src, "d")); open(os.path.join(src, "d", "x"), "w").write("hi")
    os.symlink(victim, os.path.join(src, "d", "link"))
    subprocess.run(["7z", "a", "-snl", "-bd", os.path.join(t, "l.7z"), "d"], cwd=src, capture_output=True)
    check("7z: archive containing a symlink refused", not fetch.safe_extract(os.path.join(t, "l.7z"), os.path.join(t, "x8")))
    z = os.path.join(t, "ok.zip")
    with zipfile.ZipFile(z, "w") as zf: zf.writestr("dir/notes.txt", "fine")
    check("zip: a normal archive unpacks (positive control)", fetch.safe_extract(z, os.path.join(t, "x9"))
          and open(os.path.join(t, "x9", "dir", "notes.txt")).read() == "fine")

def test_validation(t):
    good = {"slug": "ok", "files": [{"url": "https://example.invalid/a.zip", "name": "a.zip"}]}
    bad = {"slug '../x'": dict(good, slug="../x"), "name with '/'": dict(good, files=[{"url": "https://e.invalid/a", "name": "../../a"}]),
           "subdir '..'": dict(good, files=[{"url": "https://e.invalid/a", "subdir": "../../a"}]),
           "http URL": dict(good, files=[{"url": "http://e.invalid/a"}]), "file URL": dict(good, files=[{"url": "file:///etc/passwd"}]),
           "option-like URL": dict(good, files=[{"url": "-K/tmp/x"}]), "keep entry '..'": dict(good, keep=["../x"]),
           "bad MEGA link": dict(good, files=[{"mega_folder": "https://evil.invalid/folder/a#b"}]),
           "bad mirror asset name": dict(good, mirror={"tag": "data-v1", "archive_sha256": "0" * 64, "parts": [{"name": "../x", "sha256": "0" * 64, "size": 1}]})}
    for label, ds in bad.items():
        try: fetch.validate(ds); ok = False
        except fetch.Unsafe: ok = True
        check(f"catalog: {label} refused", ok)
    try: fetch.file_name({"url": "https://zenodo.org/api/records/1/files/..%2F..%2Fx/content"}, set()); ok = False
    except fetch.Unsafe: ok = True
    check("catalog: Zenodo name decoding to a path refused", ok)
    cat = json.load(open(os.path.join(REPO, "catalog", "datasets.json"))); errs = []
    for ds in cat:
        try: fetch.validate(ds)
        except fetch.Unsafe as e: errs.append(f"{ds['slug']}: {e}")
    check(f"catalog: all {len(cat)} real datasets validate (positive control)", not errs, "; ".join(errs[:3]))

def test_download_argv(t):
    captured = []; real = subprocess.run
    class R: returncode, stderr, stdout = 0, "", ""
    def fake(cmd, **kw): captured.append(cmd); return R()
    dest = os.path.join(t, "dl.bin"); open(dest, "wb").write(b"data")
    subprocess.run = fake
    try: fetch.download("https://example.invalid/a.pcap", dest)
    finally: subprocess.run = real
    cmd = captured[-1] if captured else []
    check("curl: '--' right before the URL", "--" in cmd and cmd[cmd.index("--") + 1] == "https://example.invalid/a.pcap")
    check("curl: https only, including redirects", cmd[1:5] == ["--proto", "=https", "--proto-redir", "=https"])
    for u in ("http://e.invalid/a", "-K/tmp/cfg", "file:///etc/passwd"):
        try: fetch.download(u, dest); ok = False
        except fetch.Unsafe: ok = True
        check(f"curl: {u!r} refused before curl runs", ok)

def test_mirror_policy(t):
    fetch.DATA = os.path.join(t, "data_m")
    ds = {"slug": "m1", "title": "m1", "files": [{"url": "https://e.invalid/x.zip", "name": "x.zip"}],
          "mirror": {"tag": "data-v1", "archive_sha256": "0" * 64, "parts": [{"name": "m1.tar.part000", "size": 5, "sha256": "1" * 64}]}}
    calls, real_dl, real_src = [], fetch.download, fetch.fetch_source
    fetch.download = lambda url, dest, referer=None: (os.makedirs(os.path.dirname(dest), exist_ok=True), open(dest, "wb").write(b"junk!"), (True, ""))[-1]
    fetch.fetch_source = lambda d: calls.append(d["slug"]) or True
    try: ok = fetch.fetch(ds)
    finally: fetch.download, fetch.fetch_source = real_dl, real_src
    check("mirror: a checksum mismatch fails and does NOT fall back to the source route", ok is False and calls == [])
    real_tar = fetch.tarfile
    class NoFilter: pass
    fetch.tarfile = NoFilter()
    try: fetch.need_tar_filter(); refused = False
    except SystemExit: refused = True
    finally: fetch.tarfile = real_tar
    check("unpacking refuses to run without tarfile's extraction filter", refused)

def pcap(path, n, size, nano=False, truncate=False):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(n):
            f.write(struct.pack("<IIII", 1_700_000_000 + i, 123456789 if nano else 0, size, size) + bytes(size))
        if truncate: f.write(struct.pack("<IIII", 1_800_000_000, 0, 5000, 5000) + b"\0" * 10)

def first_ts(p):
    with open(p, "rb") as f: hdr = f.read(24); rec = f.read(16)
    return struct.unpack("<II", rec[:8]), hdr[:4]

def test_split(t):
    if not shutil.which("tcpdump"): SKIPPED.append("splitting (tcpdump missing)"); return
    d = os.path.join(t, "split"); os.makedirs(d); pcap(os.path.join(d, "big.pcap"), 13000, 1000)
    fetch.split_large(d, split_at=1, chunk_mb=1)
    parts = sorted(f for f in os.listdir(d) if f.startswith("big.pcap.part"))
    ts = [first_ts(os.path.join(d, p))[0][0] for p in parts]
    check(f"split: {len(parts)} parts numbered in time order", len(parts) > 10 and ts == sorted(ts) and len(set(ts)) == len(ts))
    d2 = os.path.join(t, "split_ns"); os.makedirs(d2); pcap(os.path.join(d2, "ns.pcap"), 3000, 1000, nano=True)
    fetch.split_large(d2, split_at=1, chunk_mb=1)
    p0 = os.path.join(d2, "ns.pcap.part000.pcap")
    check("split: nanosecond timestamps kept", os.path.exists(p0) and first_ts(p0)[1] == struct.pack("<I", 0xa1b23c4d))
    d3 = os.path.join(t, "split_bad"); os.makedirs(d3); pcap(os.path.join(d3, "bad.pcap"), 1500, 1000, truncate=True)
    fetch.split_large(d3, split_at=1, chunk_mb=1)
    check("split: a tcpdump error keeps the capture whole", os.listdir(d3) == ["bad.pcap"])

def test_mega(t):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        SKIPPED.append("MEGA (cryptography missing)"); return
    mf = load("mega_fetch")
    b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    ecb = lambda k, d: (lambda e: e.update(d) + e.finalize())(Cipher(algorithms.AES(k), modes.ECB()).encryptor())
    def attr(k, name):
        a = b"MEGA" + json.dumps({"n": name}).encode(); a += b"\0" * (-len(a) % 16)
        e = Cipher(algorithms.AES(k), modes.CBC(b"\0" * 16)).encryptor(); return b64e(e.update(a) + e.finalize())
    fkey = os.urandom(16); nodes, blobs = [], {}; os.makedirs(os.path.join(t, "blobs"))
    def folder(h, parent, name):
        k = os.urandom(16); nodes.append({"h": h, "p": parent, "t": 1, "k": f"{h}:{b64e(ecb(fkey, k))}", "a": attr(k, name)})
    def file(h, parent, name, data, served=None):
        k = os.urandom(16); n0, n1 = struct.unpack(">2I", os.urandom(8))
        mac = mf.Mac(k, struct.pack(">4I", n0, n1, n0, n1)); pos = 0
        for s in mf.chunk_sizes(len(data)): mac.chunk(data[pos:pos + s]); pos += s
        m = struct.unpack(">4I", mac.last); mm = (m[0] ^ m[1], m[2] ^ m[3]); kw = struct.unpack(">4I", k)
        w = (kw[0] ^ n0, kw[1] ^ n1, kw[2] ^ mm[0], kw[3] ^ mm[1], n0, n1, mm[0], mm[1])
        enc = Cipher(algorithms.AES(k), modes.CTR(struct.pack(">4I", n0, n1, 0, 0))).encryptor()
        ct = enc.update(served if served is not None else data) + enc.finalize()
        blobs[h] = os.path.join(t, "blobs", h); open(blobs[h], "wb").write(ct)
        nodes.append({"h": h, "p": parent, "t": 0, "s": len(data), "k": f"{h}:{b64e(ecb(fkey, struct.pack('>8I', *w)))}", "a": attr(k, name)})
        return ct
    good = os.urandom(300_000)
    folder("ROOT0001", "XXXXXXXX", "IEEE_DataPort")
    file("GOOD0001", "ROOT0001", "good.bin", good)
    file("TRAV0001", "ROOT0001", "../../ESCAPED.txt", b"escape")
    folder("ABSF0001", "XXXXXXXX", os.path.join(t, "abs_target"))
    file("ABSX0001", "ABSF0001", "abs.txt", b"absolute")
    ct = file("TAMP0001", "ROOT0001", "tampered.bin", os.urandom(200_000))
    b = bytearray(ct); b[150_000] ^= 1; open(blobs["TAMP0001"], "wb").write(bytes(b))
    file("SUBS0001", "ROOT0001", "substituted.bin", b"A" * 4096, served=b"B" * 4096)   # re-encrypted with the same (public-derived) key
    real_api, real_blob, out = mf.api, mf.fetch_blob, os.path.join(t, "mega_out")
    mf.api = lambda req, folder: {"f": nodes} if req["a"] == "f" else {"g": f"https://example.invalid/{req['n']}"}
    mf.fetch_blob = lambda url, tmp: shutil.copyfile(blobs[url.rsplit("/", 1)[1]], tmp)
    argv = sys.argv; sys.argv = ["mega_fetch.py", f"https://mega.nz/folder/FAKEFOLD#{b64e(fkey)}", "--out", out]
    try:
        try: mf.main(); code = 0
        except SystemExit as e: code = e.code
        check("MEGA: a genuine file passes its MAC (positive control)", open(os.path.join(out, "IEEE_DataPort", "good.bin"), "rb").read() == good)
        check("MEGA: '..' in a node name cannot leave --out", not os.path.exists(os.path.join(t, "ESCAPED.txt")))
        check("MEGA: an absolute folder name cannot leave --out", not os.path.exists(os.path.join(t, "abs_target", "abs.txt")))
        check("MEGA: a flipped ciphertext byte is detected and discarded", not os.path.exists(os.path.join(out, "IEEE_DataPort", "tampered.bin")))
        check("MEGA: content re-encrypted with the folder's key is detected", not os.path.exists(os.path.join(out, "IEEE_DataPort", "substituted.bin")))
        check("MEGA: refusals make the exit status 1", code == 1)
        mf.api = lambda req, folder: {"f": nodes} if req["a"] == "f" else {"g": f"http://example.invalid/{req['n']}"}
        shutil.rmtree(out)
        try: mf.main()
        except SystemExit: pass
        check("MEGA: a non-https download URL is refused", not os.path.exists(os.path.join(out, "IEEE_DataPort", "good.bin")))
    finally:
        mf.api, mf.fetch_blob, sys.argv = real_api, real_blob, argv

def test_rendering(t):
    check("pages: raw HTML in catalog prose is escaped", build.md_text("<a href='x'>click</a> & <img src=y>") == "&lt;a href='x'&gt;click&lt;/a&gt; &amp; &lt;img src=y&gt;")
    check("pages: code spans are left as written", build.md_text("run `a<b` now") == "run `a<b` now")
    check("pages: javascript: is never a link", build.link("label", "javascript:alert(1)") == "label" and not build.url_ok("data:text/html,x"))
    check("pages: https stays a link", build.link("x", "https://example.org/a") == "[x](https://example.org/a)")
    check("pages: a command containing ``` cannot close its code block", build.fence("echo ```")[0] == "````bash")
    check("pages: a file name with a backtick stays one code span", build.code_span("a`b") == "``a`b``")
    check("names: mixed-script look-alikes folded, real Greek kept", fetch.fold_confusables("20200516_DNP3_Ιnfo") == "20200516_DNP3_Info"
          and fetch.fold_confusables("Δεδομένα_data") == "Δεδομένα_data")
    if not shutil.which("node"): SKIPPED.append("web app link filter (node missing)"); return
    html = open(os.path.join(REPO, "index.html"), encoding="utf-8").read()
    line = next((l for l in html.splitlines() if "const safeHref=" in l), "")
    js = line + "\nconsole.log(JSON.stringify(['javascript:alert(1)',' JaVaScRiPt:x','data:text/html,x','https://ok.example/a','mailto:a@b.c'].map(safeHref)));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True)
    check("web app: only http(s)/mailto URLs become links", r.stdout.strip() == json.dumps(["", "", "", "https://ok.example/a", "mailto:a@b.c"]).replace(" ", ""), r.stdout + r.stderr)

def main():
    with tempfile.TemporaryDirectory(prefix="ics-sec-") as t:
        for fn in (test_extraction, test_validation, test_download_argv, test_mirror_policy, test_split, test_mega, test_rendering):
            d = os.path.join(t, fn.__name__); os.makedirs(d); fn(d)
    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\nbasis: {len(RESULTS)} checks run, {len(bad)} failed; skipped: {', '.join(SKIPPED) or 'none'}")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
