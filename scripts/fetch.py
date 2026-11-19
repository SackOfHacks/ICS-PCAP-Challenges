#!/usr/bin/env python3
"""Fetch the ICS/OT/SCADA datasets into ./data/.

Datasets whose licence allows redistribution are mirrored as assets of this repository's GitHub
release (`data-v1`): the fetcher downloads the parts, verifies every SHA-256, unpacks them safely and
restores the gzip-compressed captures. Every other dataset is downloaded from its ORIGINAL source
(Zenodo, TU Wien, Netresec, GitHub, MEGA, ...): archives are extracted, only packet captures plus
label / documentation files are kept, captures >= 2 GB are split into < 2 GiB parts, captures published
without a file extension get .pcap/.pcapng from their magic bytes and names that mix Latin with look-alike
Greek/Cyrillic letters get the Latin ones (so the file names match the challenge catalog), and a PROVENANCE.md
credit file is written. Downloads resume.

Security model: original sources are third-party and NOT checksum-verified, so everything they serve is
treated as untrusted. Downloads are HTTPS-only (redirects too). Archives are unpacked into a fresh empty
folder; tar archives through Python's tarfile extraction filter, the others with 7z only after their listing
shows no links and no absolute or '..' paths; then anything that is not a regular file or folder is removed and
files are moved into place with a containment check. Catalog fields (slug, file names, sub-folders, URLs) are
validated before use. A mirrored dataset whose download or checksum fails is NOT silently fetched from its
source: re-run, or ask for the source route explicitly with --from-source.

Usage (run from the repo root):
  python3 scripts/fetch.py --list              # what's available + sizes
  python3 scripts/fetch.py --starter           # a small (< 1 GB) taste of the range
  python3 scripts/fetch.py lemay-scada-modbus-cset2016 cyber4ot   # by slug
  python3 scripts/fetch.py --all               # everything (large!)
  python3 scripts/fetch.py cyber4ot --from-source   # skip the mirror, use the original source
  python3 scripts/fetch.py --data-dir /big/disk ...  # put the captures somewhere else

Requires: Python with tarfile extraction filters (3.12+, or 3.9.17+/3.10.12+/3.11.4+), curl, gunzip; for source
downloads also 7z (7-Zip or p7zip) and tcpdump (splitting); for the MEGA-hosted dataset the `cryptography` package.
"""
import argparse, datetime, gzip, hashlib, io, json, os, re, shutil, stat, subprocess, sys, tarfile, tempfile, urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(REPO, "data")
CATALOG = os.path.join(REPO, "catalog", "datasets.json")
UA = "dataset-fetch/1.0 (research download)"
MAGIC = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
         b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1")
NANO = (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
ARCHIVE = re.compile(r"\.(zip|7z|rar|tar|tgz|tar\.gz|tar\.xz|tar\.bz2|xz)$", re.I)
SPLIT_AT = 2_000_000_000          # split captures at/above this size ...
CHUNK_MB = 1800                   # ... into ~1.8 GB parts (< 2 GiB)
STARTER = ["lemay-scada-modbus-cset2016", "modbus-labs-solymx", "digitalbond-s4x15-ctf",
           "nozomi-triton-tristation", "cyber4ot", "powerduck-goose-attacks"]
DEFAULT_KEEP = r"(readme|license|\.md$|\.txt$|\.csv$|\.pdf$|labels?|\.log\.labeled$)"
MIRROR_BASE = "https://github.com/SackOfHacks/ICS-PCAP-Challenges/releases/download"
FROM_SOURCE = False
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BAD_CHARS = re.compile(r"[/\\\x00-\x1f\x7f]")
MEGA_LINK = re.compile(r"^https://mega\.(?:nz|co\.nz)/folder/[A-Za-z0-9_-]+#[A-Za-z0-9_-]+$")
LINK_MODE = re.compile(r"(?:^|\s)[-0]?l[rwxsStT-]{9}(?:\s|$)")     # how 7z shows a symlink's unix mode
CURL = ["curl", "--proto", "=https", "--proto-redir", "=https"]        # https only, including every redirect
CONFUSABLE = {  # Greek and Cyrillic letters drawn exactly like Latin ones
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "ο": "o", "ρ": "p", "ν": "v", "υ": "u", "χ": "x", "ι": "i", "κ": "k", "α": "a",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l"}

class Unsafe(Exception):
    """Input that would write outside its folder, or that the catalog rules do not allow."""

def log(*a): print(*a, flush=True)

def need(tool):
    if shutil.which(tool) is None:
        sys.exit(f"missing required tool: {tool}")

def need_tar_filter():
    if not hasattr(tarfile, "data_filter"):
        sys.exit("this Python has no tarfile extraction filters (PEP 706); use Python 3.12+ "
                 "(or 3.9.17+, 3.10.12+, 3.11.4+) - unpacking without them is not safe")

def is_capture(p):
    try:
        with open(p, "rb") as f: return f.read(4) in MAGIC
    except OSError: return False

# ---------------------------------------------------------------- validation of catalog-derived values

def safe_name(n):
    """One path component the fetcher is willing to create."""
    if not isinstance(n, str) or not n or n in (".", "..") or BAD_CHARS.search(n) or n.startswith("-") or len(n.encode()) > 255:
        raise Unsafe(f"unsafe file name: {n!r}")
    return n

def safe_relpath(p):
    if not isinstance(p, str) or not p or p.startswith("/"):
        raise Unsafe(f"unsafe relative path: {p!r}")
    for c in p.split("/"): safe_name(c)
    return p

def check_url(u):
    if not isinstance(u, str) or not u.startswith("https://") or any(c.isspace() for c in u):
        raise Unsafe(f"refusing a non-https URL: {u!r}")
    return u

def inside(root, path):
    r, t = os.path.realpath(root), os.path.realpath(path)
    return os.path.commonpath([r, t]) == r

def validate(ds):
    if not SLUG.match(str(ds.get("slug", ""))): raise Unsafe(f"unsafe dataset slug: {ds.get('slug')!r}")
    for f in ds.get("files") or []:
        if f.get("mega_folder"):
            if not MEGA_LINK.match(f["mega_folder"]): raise Unsafe(f"not a public MEGA folder link: {f['mega_folder']!r}")
            safe_name(f.get("name", "mega"))
        else:
            check_url(f.get("url"))
            if f.get("name"): safe_name(f["name"])
        if f.get("subdir"): safe_relpath(f["subdir"])
    for k in ds.get("keep") or []: safe_relpath(k)
    if ds.get("referer"): check_url(ds["referer"])
    m = ds.get("mirror")
    if m:
        if not ASSET.match(str(m.get("tag", ""))) or not HEX64.match(str(m.get("archive_sha256", ""))):
            raise Unsafe(f"malformed mirror entry for {ds['slug']}")
        for p in m.get("parts") or []:
            if not ASSET.match(str(p.get("name", ""))) or not HEX64.match(str(p.get("sha256", ""))) or not isinstance(p.get("size"), int):
                raise Unsafe(f"malformed mirror part for {ds['slug']}: {p.get('name')!r}")

# ---------------------------------------------------------------- downloads (https only)

def resolve_kaggle(url):
    """Kaggle's anonymous dataset-download API redirects to a signed Google Cloud
    Storage URL; resolve it with a plain GET (no browser UA), then fetch from GCS."""
    if "kaggle.com/api/v1/datasets/download" not in url: return url
    r = subprocess.run(CURL + ["-sS", "-o", "/dev/null", "-w", "%{url_effective}", "-L", "-A", UA, "--", url],
                       capture_output=True, text=True)
    return r.stdout if r.stdout.startswith("https://storage.googleapis.com/") else url

# An honest client name: Zenodo's bot protection answers a bare/fake browser UA with HTTP 403.
def download(url, dest, referer=None):
    url = resolve_kaggle(check_url(url))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    cmd = CURL + ["-sSfL", "--http1.1", "--retry", "8", "--retry-all-errors", "--retry-delay", "10",
                  "--connect-timeout", "30", "-A", UA, "-C", "-", "-o", dest]
    if referer: cmd += ["-e", check_url(referer)]
    cmd += ["--", url]                                  # a URL can never be read as an option
    r = subprocess.run(cmd, capture_output=True, text=True)
    done_416 = r.returncode == 22 and "416" in r.stderr and os.path.exists(dest)
    if r.returncode not in (0, 33) and not done_416:
        return False, r.stderr.strip()[-300:]
    with open(dest, "rb") as fh:
        head = fh.read(48)
    if head.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        os.remove(dest)   # a CAPTCHA / login wall / error page saved in place of the data
        return False, "server returned an HTML page instead of data (CAPTCHA, login wall or error page)"
    if head.startswith(b"version https://git-lfs") and url.startswith("https://raw.githubusercontent.com/"):
        os.remove(dest)   # Git LFS pointer -> fetch the real object
        return download(url.replace("https://raw.githubusercontent.com/", "https://media.githubusercontent.com/media/"), dest, referer)
    return os.path.getsize(dest) > 0, ""

def sniff_archive(path, name):
    """Return a name with the right archive extension when the source served an
    opaque filename (Kaggle /download/<slug>, Figshare ndownloader, ...)."""
    if ARCHIVE.search(name): return name
    try:
        with open(path, "rb") as fh: m = fh.read(6)
    except OSError:
        return name
    if m[:4] == b"PK\x03\x04": return name + ".zip"
    if m[:6] == b"7z\xbc\xaf\x27\x1c": return name + ".7z"
    if m[:2] == b"\x1f\x8b": return name + ".tar.gz"
    return name

# ---------------------------------------------------------------- unpacking untrusted archives

def member_ok(name):
    """A relative archive path with no absolute, drive-letter or '..' component."""
    if not name or "\x00" in name or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name): return False
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    return bool(parts) and ".." not in parts

def _untar(path, tmp):
    need_tar_filter()
    with tarfile.open(path, "r:*") as tf:
        for m in tf:
            if not member_ok(m.name): raise Unsafe(f"unsafe path in archive: {m.name!r}")
            if m.isfile() or m.isdir(): tf.extract(m, tmp, filter="data")    # links, devices and fifos are skipped

def _7z_entries(path):
    r = subprocess.run(["7z", "l", "-slt", "--", path], capture_output=True, text=True, errors="surrogateescape")
    if r.returncode != 0: raise Unsafe(f"7z cannot list {os.path.basename(path)}")
    entries, cur, started = [], {}, False
    for line in r.stdout.splitlines():
        if line.startswith("----------"): started = True; continue
        if not started: continue
        if not line.strip():
            if cur: entries.append(cur); cur = {}
            continue
        k, sep, v = line.partition(" = ")
        if sep: cur[k.strip()] = v.strip()
    if cur: entries.append(cur)
    return entries

def _un7z(path, tmp):
    for e in _7z_entries(path):
        p = e.get("Path", "")
        if not member_ok(p): raise Unsafe(f"unsafe path in archive: {p!r}")
        if e.get("Symbolic Link") or e.get("Hard Link") or e.get("Link") or LINK_MODE.search(e.get("Attributes", "")):
            raise Unsafe(f"archive contains a link: {p!r}")
    r = subprocess.run(["7z", "x", "-y", "-bd", "-o" + tmp, "--", path], capture_output=True)
    if r.returncode != 0: raise Unsafe(f"7z failed on {os.path.basename(path)} (exit {r.returncode})")

def scrub(root):
    """Remove everything under root that is not a regular file or directory (symlinks, devices, fifos, sockets),
    give hard-linked files their own copy and drop setuid/exec bits. Returns the number of entries removed."""
    removed = 0
    for dp, dns, fns in os.walk(root):
        for n in list(dns):
            p = os.path.join(dp, n)
            if not stat.S_ISDIR(os.lstat(p).st_mode):          # a symlink to a directory is listed with the dirs
                os.unlink(p); dns.remove(n); removed += 1
            else:
                os.chmod(p, 0o755)
        for n in fns:
            p = os.path.join(dp, n); st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                os.unlink(p); removed += 1; continue
            if st.st_nlink > 1:                                 # never keep a name that writes through to another file
                c = p + ".copy-tmp"; shutil.copyfile(p, c); os.replace(c, p)
            os.chmod(p, 0o644)
    return removed

def move_into(src, dst, overwrite=True):
    """Move the (scrubbed) tree src into dst; every target must stay inside dst and never be a symlink."""
    os.makedirs(dst, exist_ok=True)
    for dp, dns, fns in os.walk(src):
        rel = os.path.relpath(dp, src)
        t = dst if rel == "." else os.path.join(dst, rel)
        if os.path.islink(t) or not inside(dst, t): raise Unsafe(f"refusing to write through {t}")
        os.makedirs(t, exist_ok=True)
        for f in fns:
            s, d = os.path.join(dp, f), os.path.join(t, f)
            if os.path.islink(d) or not inside(dst, d): raise Unsafe(f"refusing to write through {d}")
            if os.path.lexists(d):
                if overwrite and os.path.isfile(d): os.replace(s, d)
                continue
            shutil.move(s, d)

def safe_extract(path, outdir):
    """Unpack an UNTRUSTED archive into outdir: into a fresh empty folder first, then scrub, then move into place."""
    root = os.path.join(DATA, ".staging", ".unpack"); os.makedirs(root, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="x-", dir=root)
    try:
        low = path.lower()
        if low.endswith((".tar", ".tgz", ".tar.gz", ".tar.xz", ".tar.bz2")):
            _untar(path, tmp)
        elif low.endswith((".zip", ".7z", ".rar")) or low.endswith(".xz"):
            _un7z(path, tmp)
        else:
            return False
        dropped = scrub(tmp)
        if dropped: log(f"  removed {dropped} link/special entr{'y' if dropped == 1 else 'ies'} from {os.path.basename(path)}")
        move_into(tmp, outdir)
        return True
    except (Unsafe, tarfile.TarError, OSError) as e:
        log(f"  ! refused to unpack {os.path.basename(path)}: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

extract = safe_extract                                  # the only unpacking path

def extract_nested(d, rounds=3):
    for _ in range(rounds):
        found = False
        for dp, _, fns in os.walk(d):
            for f in fns:
                if ARCHIVE.search(f):
                    fp = os.path.join(dp, f)
                    if safe_extract(fp, os.path.join(dp, ARCHIVE.sub("", f))):
                        os.remove(fp); found = True
        if not found: break

def gunzip_captures(d):
    for dp, _, fns in os.walk(d):
        for f in fns:
            if f.lower().endswith((".pcap.gz", ".pcapng.gz", ".cap.gz")):
                subprocess.run(["gunzip", "-f", "--", os.path.join(dp, f)], capture_output=True)

def prune(d, include_re, keep_re):
    inc = re.compile(include_re, re.I) if include_re else None
    keep = re.compile(keep_re or DEFAULT_KEEP, re.I)
    for dp, _, fns in os.walk(d):
        for f in fns:
            fp = os.path.join(dp, f); rel = os.path.relpath(fp, d)
            if is_capture(fp) and (inc is None or inc.search(rel)): continue
            if keep.search(rel): continue
            os.remove(fp)
    for dp, _, _ in sorted(os.walk(d), key=lambda x: -len(x[0])):
        if dp != d and not os.listdir(dp): os.rmdir(dp)

def keep_only(d, keep):
    """Keep exactly the files the catalog lists for this dataset - the captures the challenges use,
    their ground truth and the dataset's own documentation (ICS/OT/SCADA scope). Everything else in
    the upstream archive is removed."""
    if not keep: return 0
    want = set(keep); removed = 0
    for dp, _, fns in os.walk(d):
        for f in fns:
            fp = os.path.join(dp, f)
            if os.path.relpath(fp, d).replace(os.sep, "/") not in want:
                os.remove(fp); removed += 1
    for dp, _, _ in sorted(os.walk(d), key=lambda x: -len(x[0])):
        if dp != d and not os.listdir(dp): os.rmdir(dp)
    return removed

def fold_confusables(name):
    """Words that mix Latin letters with look-alike Greek/Cyrillic ones (UOWM's '20200516_DNP3_Ιnfo' has a Greek
    capital iota) get the Latin letters; words written wholly in another script are left alone."""
    def word(m):
        w = m.group(0)
        if re.search(r"[A-Za-z]", w) and any(c in CONFUSABLE for c in w):
            return "".join(CONFUSABLE.get(c, c) for c in w)
        return w
    return re.sub(r"[^\W\d_]+", word, name)

def normalize_names(d):
    """Fold mixed-script look-alike names (files and folders, deepest first). Returns the number renamed."""
    renamed = 0
    for dp, dns, fns in os.walk(d, topdown=False):
        for n in fns + dns:
            new = fold_confusables(n)
            if new != n and not os.path.lexists(os.path.join(dp, new)):
                os.rename(os.path.join(dp, n), os.path.join(dp, new)); renamed += 1
    return renamed

def normalize_capture_names(d):
    """Captures identified by their magic bytes but lacking an extension get one (.pcapng for pcapng, else .pcap):
    some tools (Pcapper among them) pick files by extension. ELEGANT's cap_<n>_<timestamp> files need this.
    Returns the number of files renamed."""
    renamed = 0
    for dp, _, fns in os.walk(d):
        for f in fns:
            if f.lower().endswith((".pcap", ".pcapng", ".cap")): continue
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as h: m = h.read(4)
            except OSError:
                continue
            if m in MAGIC:
                ext = ".pcapng" if m == b"\x0a\x0d\x0d\x0a" else ".pcap"
                if not os.path.exists(p + ext): os.rename(p, p + ext); renamed += 1
    return renamed

def split_large(d, split_at=None, chunk_mb=None):
    """Split pcap captures >= split_at into chunk_mb parts named .part000.pcap, .part001.pcap ... in time order.
    tcpdump -C names its chunks X, X1, X2 ... X10, so they are ordered by that number, not as text; nanosecond
    captures keep nanosecond timestamps; a tcpdump error keeps the capture whole. pcapng is never split (tcpdump
    would rewrite it as pcap). Returns the number of captures split."""
    split_at, chunk_mb, n = split_at or SPLIT_AT, chunk_mb or CHUNK_MB, 0
    for dp, _, fns in os.walk(d):
        for f in sorted(fns):
            fp = os.path.join(dp, f)
            if os.path.getsize(fp) < split_at or not is_capture(fp): continue
            with open(fp, "rb") as h: magic = h.read(4)
            if magic == b"\x0a\x0d\x0d\x0a":
                log(f"  ! {f}: a pcapng >= 2 GB is kept whole (splitting would rewrite it as pcap)"); continue
            need("tcpdump")
            base = fp + ".splitpart"
            cmd = ["tcpdump", "-r", fp, "-w", base, "-C", str(chunk_mb), "-s", "0"]
            if magic in NANO: cmd[1:1] = ["--time-stamp-precision=nano"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            stem = os.path.basename(base)
            parts = [os.path.join(dp, x) for x in os.listdir(dp) if x.startswith(stem) and x[len(stem):].isdigit() or x == stem]
            parts.sort(key=lambda p: int(os.path.basename(p)[len(stem):] or 0))
            if r.returncode != 0 or not parts:
                for p in parts: os.remove(p)
                log(f"  ! could not split {f} (tcpdump exit {r.returncode}); kept whole. {r.stderr.strip()[-200:]}"); continue
            for i, p in enumerate(parts):
                os.replace(p, f"{fp}.part{i:03d}.pcap")
            os.remove(fp); n += 1
    return n

def merge(src, dst):
    move_into(src, dst, overwrite=False)               # first copy wins; never writes through a link

def provenance(ds, d):
    n = b = 0; rows = []
    for dp, _, fns in os.walk(d):
        for f in fns:
            fp = os.path.join(dp, f)
            if is_capture(fp):
                n += 1; sz = os.path.getsize(fp); b += sz; rows.append((os.path.relpath(fp, d), sz))
    L = [f"# {ds['title']}", "", f"- **Source:** {ds.get('source_url', '—')}"]
    if ds.get("doi"): L.append(f"- **DOI:** https://doi.org/{ds['doi']}")
    L += [f"- **Authors / owner:** {ds.get('authors', '—')}", f"- **Year:** {ds.get('year') or '—'}",
          f"- **License / terms:** {ds.get('license', 'see source')}",
          f"- **Retrieved:** {datetime.date.today().isoformat()} with scripts/fetch.py (original source, not checksum-verified)",
          f"- **Captures here:** {n} files, {b/1e9:.2f} GB",
          "- **Changes by the fetcher:** none to the packets. Captures >= 2 GB are split into < 2 GiB `.partNNN.pcap` parts",
          "  (tcpdump, in time order); captures published without a file extension get `.pcap`/`.pcapng` from their magic",
          "  bytes; names mixing Latin with look-alike Greek/Cyrillic letters get the Latin ones; only the files the",
          "  challenge catalog uses are kept."]
    if ds.get("citation"): L += ["", "## Cite as", "", ds["citation"]]
    L += ["", "## Files", ""] + [f"- `{r}` — {s/1e6:.1f} MB" for r, s in sorted(rows)[:400]]
    open(os.path.join(d, "PROVENANCE.md"), "w").write("\n".join(L) + "\n")
    return n, b

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

class Chain(io.RawIOBase):
    """The archive parts read back-to-back as one stream, hashed on the way through."""
    def __init__(self, paths): self.paths, self.f, self.h = list(paths), None, hashlib.sha256()
    def readable(self): return True
    def readinto(self, b):
        while True:
            if self.f is None:
                if not self.paths: return 0
                self.f = open(self.paths.pop(0), "rb")
            n = self.f.readinto(b)
            if n:
                self.h.update(memoryview(b)[:n]); return n
            self.f.close(); self.f = None

def safe_members(tf, slug):
    """Only regular files and directories inside data/<slug>/ - no absolute paths, '..', links or devices."""
    for m in tf:
        parts = m.name.split("/")
        if m.name.startswith("/") or ".." in parts or parts[0] != slug:
            sys.exit(f"refusing unsafe path in archive: {m.name}")
        if m.isfile() or m.isdir(): yield m

def fetch_mirror(ds):
    need_tar_filter()                                  # never unpack without the extraction filter
    mir = ds["mirror"]; slug = ds["slug"]
    stage = os.path.join(DATA, ".staging", slug, "mirror"); os.makedirs(stage, exist_ok=True)
    paths = []
    for p in mir["parts"]:                            # every part is verified BEFORE anything is unpacked
        dest = os.path.join(stage, p["name"])
        if not (os.path.exists(dest) and os.path.getsize(dest) == p["size"] and sha256_file(dest) == p["sha256"]):
            ok, err = download(f"{MIRROR_BASE}/{mir['tag']}/{p['name']}", dest)
            if not ok: return False, f"{p['name']}: {err}"
            if sha256_file(dest) != p["sha256"]:
                os.remove(dest); return False, f"{p['name']}: SHA-256 mismatch"
        paths.append(dest)
    chain = Chain(paths); buf = io.BufferedReader(chain, 1 << 20)
    with tarfile.open(fileobj=buf, mode="r|") as tf:
        for m in safe_members(tf, slug):
            tf.extract(m, DATA, filter="data")
    while buf.read(1 << 20): pass                      # drain tar padding so the whole archive is hashed
    if chain.h.hexdigest() != mir["archive_sha256"]: return False, "archive SHA-256 mismatch"
    d = os.path.join(DATA, slug); listing = os.path.join(d, "MIRROR-GZIPPED.txt")
    if os.path.exists(listing):                        # restore exactly the files the mirror compressed
        root = os.path.realpath(d)
        for rel in open(listing, encoding="utf-8").read().splitlines():
            if not rel.strip(): continue
            dst = os.path.realpath(os.path.join(d, rel))
            if os.path.commonpath([dst, root]) != root: sys.exit(f"refusing unsafe path in MIRROR-GZIPPED.txt: {rel}")
            with gzip.open(dst + ".gz", "rb") as fi, open(dst, "wb") as fo: shutil.copyfileobj(fi, fo, 1 << 20)
            os.remove(dst + ".gz")
        os.remove(listing)
    else:
        gunzip_captures(d)                             # archives packed before the listing existed
    shutil.rmtree(os.path.join(DATA, ".staging", slug), ignore_errors=True)
    return True, ""

def fetch_mega(f, dl):
    mdir = os.path.join(dl, safe_name(f.get("name", "mega")))
    r = subprocess.run([sys.executable, "-I", os.path.join(REPO, "scripts", "mega_fetch.py"), f["mega_folder"], "--out", mdir])
    return mdir if r.returncode == 0 else None

def file_name(f, taken):
    """A real, unique local name: Zenodo API URLs end in /files/<name>/content and Mendeley serves
    'file_downloaded', so the URL basename is not a usable name; duplicates get the parent folder as prefix.
    The result is validated: a name that would leave the download folder is refused."""
    n = f.get("name")
    path = urllib.parse.urlparse(f.get("url", "")).path
    if not n or n in ("content", "file_downloaded", "download", "download.bin"):
        m = re.search(r"/files/([^/]+)/content$", path)
        n = urllib.parse.unquote(m.group(1)) if m else (os.path.basename(path) or "download.bin")
    safe_name(n)
    key = (f.get("subdir", ""), n)
    if key in taken:
        parent = os.path.basename(os.path.dirname(path)) or "dup"
        n = f"{parent}_{n}"; key = (f.get("subdir", ""), n)
        i = 2
        while key in taken: n = f"{i}_{n}"; key = (f.get("subdir", ""), n); i += 1
        safe_name(n)
    taken.add(key)
    return n

def fetch(ds):
    """Fetch one dataset. Returns True on success."""
    try:
        validate(ds)
    except Unsafe as e:
        log(f"  ! refusing {ds.get('slug')!r}: {e}"); return False
    if ds.get("mirror") and not FROM_SOURCE:
        ok, err = fetch_mirror(ds)
        if ok:
            log(f"== {ds['slug']}: from the release mirror (all SHA-256 verified)"); return True
        log(f"  ! mirror failed ({err}). Nothing was taken from the original source instead: the mirror is the")
        log(f"    checksum-verified copy. Re-run to retry, or add --from-source to download {ds['slug']} from its")
        log("    original source, which is not checksum-verified.")
        return False
    try:
        return fetch_source(ds)
    except Unsafe as e:
        log(f"  ! refusing {ds['slug']}: {e}"); return False

def fetch_source(ds):
    for t in ("7z",): need(t)                          # only the source route unpacks third-party archives
    need_tar_filter()
    d = os.path.join(DATA, ds["slug"]); stage = os.path.join(DATA, ".staging", ds["slug"])
    dl, xd = os.path.join(stage, "dl"), os.path.join(stage, "x")
    os.makedirs(dl, exist_ok=True); os.makedirs(xd, exist_ok=True)
    errors = []; taken = set()
    for f in ds["files"]:
        if f.get("mega_folder"):
            mdir = fetch_mega(f, dl)
            if not mdir: errors.append("MEGA download failed"); continue
            for dp, _, fns in os.walk(mdir):
                for fn in fns:
                    fp = os.path.join(dp, fn); target = os.path.join(xd, os.path.relpath(dp, mdir))
                    if not inside(xd, target): raise Unsafe(f"MEGA path escapes the dataset folder: {fp}")
                    if ARCHIVE.search(fn):
                        target = os.path.join(target, ARCHIVE.sub("", fn))   # one folder per archive: its name is the label
                        if safe_extract(fp, target): os.remove(fp)
                        else: errors.append(f"{fn}: extract failed")
                    elif os.path.isfile(fp) and not os.path.islink(fp):
                        os.makedirs(target, exist_ok=True); shutil.move(fp, os.path.join(target, fn))
            continue
        name = file_name(f, taken)
        dest = os.path.join(dl, name)
        ok, err = download(f["url"], dest, ds.get("referer"))
        if not ok:
            errors.append(f"{name}: {err}"); log(f"  ! download failed: {name} {err[:120]}"); continue
        real = sniff_archive(dest, name)
        if real != name:
            os.replace(dest, os.path.join(dl, real)); dest = os.path.join(dl, real); name = real
        target = os.path.join(xd, f["subdir"]) if f.get("subdir") else xd
        if ARCHIVE.search(name):
            if safe_extract(dest, target): os.remove(dest)
            else: errors.append(f"{name}: extract failed"); log(f"  ! extract failed: {name}")
        else:
            os.makedirs(target, exist_ok=True); shutil.move(dest, os.path.join(target, name))
    extract_nested(xd); scrub(xd); gunzip_captures(xd)
    prune(xd, ds.get("include_re"), ds.get("keep_extra_re"))
    folded = normalize_names(xd)
    if folded: log(f"  gave {folded} name(s) mixing Latin with look-alike Greek/Cyrillic letters the Latin ones")
    renamed = normalize_capture_names(xd)
    if renamed: log(f"  named {renamed} capture(s) published without a file extension .pcap/.pcapng (by their magic bytes)")
    dropped = keep_only(xd, ds.get("keep"))
    if dropped: log(f"  scope: removed {dropped} file(s) the challenges do not use")
    split_large(xd)
    os.makedirs(d, exist_ok=True); merge(xd, d)
    shutil.rmtree(xd, ignore_errors=True)
    if not errors: shutil.rmtree(stage, ignore_errors=True)
    n, b = provenance(ds, d)
    log(f"== {ds['slug']}: {n} captures, {b/1e9:.2f} GB" + (f", {len(errors)} error(s) — re-run to resume" if errors else ""))
    return not errors

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("slugs", nargs="*"); ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true"); ap.add_argument("--starter", action="store_true")
    ap.add_argument("--from-source", action="store_true", help="ignore the release mirror (original sources are not checksum-verified)")
    ap.add_argument("--data-dir", help="where to put the captures (default: ./data)")
    a = ap.parse_args()
    global DATA, FROM_SOURCE
    if a.data_dir: DATA = os.path.abspath(a.data_dir)
    FROM_SOURCE = a.from_source
    cat = json.load(open(CATALOG))
    if a.list or not (a.slugs or a.all or a.starter):
        tot = 0
        for ds in cat:
            gb = (ds.get("approx_bytes") or 0) / 1e9; tot += gb
            log(f"  {ds['slug']:42} ~{gb:7.2f} GB  {'mirror' if ds.get('mirror') else 'source':6}  {ds.get('license','')[:30]}")
        log(f"\n  total ~{tot:.1f} GB.  Fetch with: python3 scripts/fetch.py <slug> ... | --starter | --all")
        return
    for t in ("curl", "gunzip"): need(t)
    want = set(a.slugs) | (set(STARTER) if a.starter else set())
    failed = []
    for ds in cat:
        if a.all or ds["slug"] in want:
            log(f"### {ds['slug']} — {ds['title']}")
            if not fetch(ds): failed.append(ds["slug"])
    log("\nDone. Rebuild the catalog with:  python3 scripts/build.py")
    if failed:
        log(f"Not complete: {', '.join(failed)} (see the messages above).")
        sys.exit(1)

if __name__ == "__main__":
    main()
