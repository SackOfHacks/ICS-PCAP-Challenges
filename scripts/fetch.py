#!/usr/bin/env python3
"""Fetch the ICS/OT/SCADA datasets from their ORIGINAL sources into ./data/.

The captures are not stored in this repository (see ATTRIBUTION.md). This
script downloads each dataset from its source (Zenodo, TU Wien, Netresec,
GitHub, ...), extracts archives, keeps only packet captures plus label /
documentation files, splits any capture >= 2 GB into < 2 GiB parts (so the
file names match the challenge catalog), and writes a PROVENANCE.md credit
file into every dataset folder. Downloads are resumable.

Usage (run from the repo root):
  python3 scripts/fetch.py --list              # what's available + sizes
  python3 scripts/fetch.py --starter           # a small (< 1 GB) taste of the range
  python3 scripts/fetch.py lemay-scada-modbus-cset2016 cyber4ot   # by slug
  python3 scripts/fetch.py --all               # everything (large!)

Requires: python3, curl, 7z (p7zip), tar, gunzip, tcpdump (for splitting).
"""
import argparse, datetime, json, os, re, shutil, subprocess, sys, urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(REPO, "data")
CATALOG = os.path.join(REPO, "catalog", "datasets.json")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
MAGIC = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
         b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1")
ARCHIVE = re.compile(r"\.(zip|7z|rar|tar|tgz|tar\.gz|tar\.xz|tar\.bz2|xz)$", re.I)
SPLIT_AT = 2_000_000_000          # split captures at/above this size ...
CHUNK_MB = 1800                   # ... into ~1.8 GB parts (< 2 GiB)
STARTER = ["lemay-scada-modbus-cset2016", "modbus-labs-solymx", "digitalbond-s4x15-ctf",
           "nozomi-triton-tristation", "cyber4ot", "powerduck-goose-attacks"]
DEFAULT_KEEP = r"(readme|license|\.md$|\.txt$|\.csv$|\.pdf$|labels?|\.log\.labeled$)"

def log(*a): print(*a, flush=True)

def need(tool):
    if shutil.which(tool) is None:
        sys.exit(f"missing required tool: {tool}")

def is_capture(p):
    try:
        with open(p, "rb") as f: return f.read(4) in MAGIC
    except OSError: return False

def resolve_kaggle(url):
    """Kaggle's anonymous dataset-download API redirects to a signed Google Cloud
    Storage URL; resolve it with a plain GET (no browser UA), then fetch from GCS."""
    if "kaggle.com/api/v1/datasets/download" not in url: return url
    r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{url_effective}", "-L", "-A", "Mozilla/5.0", url],
                       capture_output=True, text=True)
    return r.stdout if "storage.googleapis.com" in r.stdout else url

def download(url, dest, referer=None):
    url = resolve_kaggle(url)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    cmd = ["curl", "-sSfL", "--http1.1", "--retry", "8", "--retry-all-errors", "--retry-delay", "10",
           "--connect-timeout", "30", "-A", UA, "-C", "-", "-o", dest, url]
    if referer: cmd[1:1] = ["-e", referer]
    r = subprocess.run(cmd, capture_output=True, text=True)
    done_416 = r.returncode == 22 and "416" in r.stderr and os.path.exists(dest)
    if r.returncode not in (0, 33) and not done_416:
        return False, r.stderr.strip()[-300:]
    with open(dest, "rb") as fh:
        head = fh.read(48)
    if head.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        os.remove(dest)   # a CAPTCHA / login wall / error page saved in place of the data
        return False, "server returned an HTML page instead of data (CAPTCHA, login wall or error page)"
    if head.startswith(b"version https://git-lfs") and "raw.githubusercontent.com/" in url:
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

def extract(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    low = path.lower()
    if low.endswith((".zip", ".7z", ".rar")) or (low.endswith(".xz") and not low.endswith(".tar.xz")):
        r = subprocess.run(["7z", "x", "-y", "-o" + outdir, path], capture_output=True)
    elif low.endswith((".tar.gz", ".tgz", ".tar", ".tar.xz", ".tar.bz2")):
        r = subprocess.run(["tar", "xf", path, "-C", outdir], capture_output=True)
    else:
        return False
    return r.returncode == 0

def extract_nested(d, rounds=3):
    for _ in range(rounds):
        found = False
        for dp, _, fns in os.walk(d):
            for f in fns:
                if ARCHIVE.search(f):
                    fp = os.path.join(dp, f)
                    if extract(fp, os.path.join(dp, ARCHIVE.sub("", f))):
                        os.remove(fp); found = True
        if not found: break

def gunzip_captures(d):
    for dp, _, fns in os.walk(d):
        for f in fns:
            if f.lower().endswith((".pcap.gz", ".pcapng.gz", ".cap.gz")):
                subprocess.run(["gunzip", "-f", os.path.join(dp, f)], capture_output=True)

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
    """Repo scope (ICS/OT/SCADA only): keep exactly the files the catalog lists for this dataset -
    the captures the challenges use or that carry an industrial protocol, their ground truth and
    the dataset's own documentation. Everything else in the upstream archive is removed."""
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

def split_large(d):
    for dp, _, fns in os.walk(d):
        for f in fns:
            fp = os.path.join(dp, f)
            if os.path.getsize(fp) < SPLIT_AT or not is_capture(fp): continue
            need("tcpdump")
            base = fp + ".splitpart"
            subprocess.run(["tcpdump", "-r", fp, "-w", base, "-C", str(CHUNK_MB), "-s", "0"], capture_output=True)
            parts = sorted(p for p in (os.path.join(dp, x) for x in os.listdir(dp)) if p.startswith(base))
            for i, p in enumerate(parts):
                os.replace(p, f"{fp}.part{i:03d}.pcap")
            if parts: os.remove(fp)

def merge(src, dst):
    for dp, _, fns in os.walk(src):
        rel = os.path.relpath(dp, src)
        t = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(t, exist_ok=True)
        for f in fns:
            target = os.path.join(t, f)
            if not os.path.exists(target):
                shutil.move(os.path.join(dp, f), target)

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
          f"- **Retrieved:** {datetime.date.today().isoformat()} with scripts/fetch.py",
          f"- **Captures here:** {n} files, {b/1e9:.2f} GB"]
    if ds.get("citation"): L += ["", "## Cite as", "", ds["citation"]]
    L += ["", "## Files", ""] + [f"- `{r}` — {s/1e6:.1f} MB" for r, s in sorted(rows)[:400]]
    open(os.path.join(d, "PROVENANCE.md"), "w").write("\n".join(L) + "\n")
    return n, b

def fetch(ds):
    d = os.path.join(DATA, ds["slug"]); stage = os.path.join(DATA, ".staging", ds["slug"])
    dl, xd = os.path.join(stage, "dl"), os.path.join(stage, "x")
    os.makedirs(dl, exist_ok=True); os.makedirs(xd, exist_ok=True)
    errors = []
    for f in ds["files"]:
        name = f.get("name") or os.path.basename(urllib.parse.urlparse(f["url"]).path)
        dest = os.path.join(dl, name)
        ok, err = download(f["url"], dest, ds.get("referer"))
        if not ok:
            errors.append(f"{name}: {err}"); log(f"  ! download failed: {name} {err[:120]}"); continue
        real = sniff_archive(dest, name)
        if real != name:
            os.replace(dest, os.path.join(dl, real)); dest = os.path.join(dl, real); name = real
        target = os.path.join(xd, f["subdir"]) if f.get("subdir") else xd
        if ARCHIVE.search(name):
            if extract(dest, target): os.remove(dest)
            else: errors.append(f"{name}: extract failed"); log(f"  ! extract failed: {name}")
        else:
            os.makedirs(target, exist_ok=True); shutil.move(dest, os.path.join(target, name))
    extract_nested(xd); gunzip_captures(xd)
    prune(xd, ds.get("include_re"), ds.get("keep_extra_re"))
    dropped = keep_only(xd, ds.get("keep"))
    if dropped: log(f"  scope: removed {dropped} file(s) outside the ICS/OT/SCADA catalog")
    split_large(xd)
    os.makedirs(d, exist_ok=True); merge(xd, d)
    shutil.rmtree(xd, ignore_errors=True)
    if not errors: shutil.rmtree(stage, ignore_errors=True)
    n, b = provenance(ds, d)
    log(f"== {ds['slug']}: {n} captures, {b/1e9:.2f} GB" + (f", {len(errors)} error(s) — re-run to resume" if errors else ""))

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("slugs", nargs="*"); ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true"); ap.add_argument("--starter", action="store_true")
    a = ap.parse_args()
    cat = json.load(open(CATALOG))
    if a.list or not (a.slugs or a.all or a.starter):
        tot = 0
        for ds in cat:
            gb = (ds.get("approx_bytes") or 0) / 1e9; tot += gb
            log(f"  {ds['slug']:42} ~{gb:7.2f} GB  {ds.get('license','')[:30]}")
        log(f"\n  total ~{tot:.1f} GB.  Fetch with: python3 scripts/fetch.py <slug> ... | --starter | --all")
        return
    for t in ("curl", "7z", "tar", "gunzip"): need(t)
    want = set(a.slugs) | (set(STARTER) if a.starter else set())
    for ds in cat:
        if a.all or ds["slug"] in want:
            log(f"### {ds['slug']} — {ds['title']}")
            fetch(ds)
    log("\nDone. Rebuild the catalog with:  python3 scripts/build.py")

if __name__ == "__main__":
    main()
