#!/usr/bin/env python3
"""Build the ICS/OT/SCADA challenge range from the catalog.

Reads catalog/challenges.json (challenge definitions) and catalog/datasets.json
(dataset credits), scans ./data for what is present, and writes:
  challenges.js           - catalog for the web app (index.html)
  datasets.js             - where each dataset's captures are (release parts / original source), for the app
  challenges/<id>.md      - one GitHub-readable page per challenge, starting with "Get the captures"
  challenges/README.md    - browsable index of every challenge
  DATASETS.md             - every dataset: fetch.py name, size, download links, the challenges that use it
  ATTRIBUTION.md          - credits/licenses for every dataset (generated)
Run from the repo root:  python3 scripts/build.py
"""
import datetime, json, os, re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(REPO, "data")
GH = "https://github.com/SackOfHacks/ICS-PCAP-Challenges"     # release links; same base as MIRROR_BASE in fetch.py
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")                       # GitHub's heading anchor for "### <slug>" is the slug itself
DS = {}                                                          # slug -> catalog/datasets.json entry (set in main)
MAGIC = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
         b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1")

def is_capture(p):
    try:
        with open(p, "rb") as f: return f.read(4) in MAGIC
    except OSError: return False

def scan(files):
    """Size, count and list of the challenge's files that exist on disk. Existence is what matters
    here: one CTF capture is deliberately corrupted (its magic bytes are the puzzle)."""
    total = n = 0; present = []
    for rel in files:
        ap = os.path.join(REPO, rel)
        if os.path.isfile(ap):
            total += os.path.getsize(ap); n += 1; present.append(rel)
    return total, n, present

def gb(b): return f"{b/1e9:.2f} GB" if b >= 1e8 else f"{b/1e6:.1f} MB"

def mdesc(t): return str(t).replace("|", "\\|").replace("[", "\\[").replace("]", "\\]")

def fetch_slugs(c):
    """The datasets a challenge needs, primary first: its declared datasets plus any dataset its file paths name."""
    out = [c.get("dataset")] + list(c.get("datasets") or [])
    out += [f.split("/")[1] for f in c.get("files", []) if f.startswith("data/") and f.count("/") >= 2]
    return [s for s in dict.fromkeys(out) if s]

def short_url(u):
    u = re.sub(r"^https?://(www\.)?", "", u or "").rstrip("/")
    return u if len(u) <= 60 else u[:57] + "…"

def where_md(d):
    """Bullets saying where one dataset's captures come from (mirror parts and/or original source)."""
    m, L = d.get("mirror"), []
    if m:
        links = " · ".join(f"[{p['name'].rsplit('.tar.', 1)[-1]}]({GH}/releases/download/{m['tag']}/{p['name']}) ({gb(p['size'])})"
                           for p in m["parts"])
        L.append(f"**Mirror:** this repo's [`{m['tag']}` release]({GH}/releases/tag/{m['tag']}), "
                 f"{len(m['parts'])} part{'s' if len(m['parts']) > 1 else ''} ({gb(m['bytes_packed'])} compressed): {links}")
    elif d.get("mirror_pending"):
        L.append("**Mirror:** being uploaded to this repo's release; until then `fetch.py` downloads it from the original source")
    else:
        L.append("**Not mirrored** (no licence that allows re-hosting): `fetch.py` downloads it from the original source")
    src = f"[{short_url(d['source_url'])}]({d['source_url']})" if d.get("source_url") else "—"
    if d.get("doi"): src += f" · [doi:{d['doi']}](https://doi.org/{d['doi']})"
    L.append(f"**Original source:** {src}")
    return L

def data_md(c):
    """The 'Get the captures' section of a challenge page."""
    slugs = c["fetch"]
    L = ["## 📥 Get the captures", "",
         "The commands on this page read the captures from `data/`. Fetch " +
         ("the dataset" if len(slugs) == 1 else f"its {len(slugs)} datasets") + " first, from the repo root:", "",
         "```bash", "python3 scripts/fetch.py " + " ".join(slugs), "```", ""]
    for s in slugs:
        d = DS.get(s, {"title": s})
        L.append(f"- **[{mdesc(d.get('title', s))}](../DATASETS.md#{s})** (`{s}`), ~{gb(d.get('approx_bytes') or 0)} once fetched")
        L += [f"  - {x}" for x in where_md(d)]
    if any(DS.get(s, {}).get("mirror") for s in slugs):
        L += ["", "Without `fetch.py`: download every part of the dataset, run `cat <dataset>.tar.part* | tar -x`, then "
                  "`gunzip` the files listed in its `MIRROR-GZIPPED.txt`."]
    return L + [""]

def datasets_page(datasets, by_slug):
    used = sorted((d for d in datasets if d["slug"] in by_slug), key=lambda d: d.get("title", d["slug"]).lower())
    nm = sum(1 for d in used if d.get("mirror")); total = sum(d.get("approx_bytes") or 0 for d in used)
    tag = next((d["mirror"]["tag"] for d in used if d.get("mirror")), "data-v1")
    L = ["# Where the captures are", "",
         f"Every challenge reads its captures from `data/<dataset>/`, which `scripts/fetch.py` fills: {len(used)} datasets, "
         f"~{total/1e9:.0f} GB once fetched.", "",
         f"- **{nm} are mirrored in this repository's [`{tag}` release]({GH}/releases/tag/{tag})**: their licence (or their authors) "
         "allow redistribution. `fetch.py` downloads the parts, checks every SHA-256 against `catalog/datasets.json` and unpacks them.",
         f"- **{len(used) - nm} are downloaded from their original sources**: they were published without a licence that allows re-hosting.", "",
         "Every challenge page starts with a **Get the captures** section with the exact command and these links. Without `fetch.py`: "
         "download every part of a dataset, `cat <dataset>.tar.part* | tar -x`, then `gunzip` the files listed in its `MIRROR-GZIPPED.txt`.", "",
         "_Generated by `scripts/build.py` from `catalog/datasets.json`. Credits and licences: [ATTRIBUTION.md](ATTRIBUTION.md)._", "",
         "| Dataset | `fetch.py` name | Size | Where | Challenges |", "|---|---|---|---|---|"]
    for d in used:
        s, m = d["slug"], d.get("mirror")
        where = f"[mirror]({GH}/releases/tag/{m['tag']}), {len(m['parts'])} part{'s' if len(m['parts']) > 1 else ''}" if m else "original source"
        L.append(f"| [{mdesc(d.get('title', s))}](#{s}) | `{s}` | {gb(d.get('approx_bytes') or 0)} | {where} | {len(by_slug[s])} |")
    for d in used:
        s, cs = d["slug"], by_slug[d["slug"]]
        L += ["", f"### {s}", "", f"**{mdesc(d.get('title', s))}**: {d.get('authors', '—')}" + (f" ({d['year']})" if d.get("year") else ""), "",
              "```bash", f"python3 scripts/fetch.py {s}", "```", "",
              f"- **Size:** ~{gb(d.get('approx_bytes') or 0)} once fetched · **Licence:** {d.get('license', '—')}"]
        L += [f"- {x}" for x in where_md(d)]
        why = (d.get("redistribution") or {}).get("reason")
        if why: L.append(f"- **Why {'mirrored' if (d.get('redistribution') or {}).get('mirrored') else 'not mirrored'}:** {why}")
        L.append(f"- **Challenges ({len(cs)}):** " + " · ".join(f"[{mdesc(c['title'])}](challenges/{c['id']}.md)" for c in cs))
    return "\n".join(L) + "\n"

def md_page(c):
    L = [f"# {c['title']}", "",
         f"**{c['category']}** · **{c['difficulty']}** · {gb(c['bytes'])} · {c['file_count']} capture file(s)", "",
         f"> {c['hook']}", ""]
    if c.get("warning"): L += [f"> ⚠️ **Safety:** {c['warning']}", ""]
    L += ["## Scenario", "", c["scenario"], "", "## Objectives", ""] + [f"- {o}" for o in c["objectives"]]
    L += [""] + data_md(c)
    tracks = c.get("tracks") or {"pcapper": c["steps"]}
    L += ["## Work it step by step", "",
          "Two complete walkthroughs — pick your tool. Run every command from the repo root.", ""]
    for name, label, blurb in (
            ("pcapper", "With Pcapper", "[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you."),
            ("tshark", "With tshark / Wireshark", "The by-hand route: display filters, field extraction and statistics.")):
        steps = tracks.get(name)
        if not steps: continue
        L += [f"### {label}", "", blurb, ""]
        for i, st in enumerate(steps, 1):
            L += [f"**{i}. {st['title']}**", ""]
            if st.get("note"): L += [st["note"], ""]
            L += ["```bash", st["cmd"], "```", ""]
    L += ["## Hints", ""]
    for i, h in enumerate(c["hints"], 1):
        L += [f"<details><summary>Hint {i}</summary>", "", h, "", "</details>", ""]
    L += ["## Solution", "", "<details><summary>Reveal walkthrough / answer</summary>", "", c["solution"], "", "</details>", ""]
    L += ["## Dataset & credit", ""]
    if c.get("credit"): L += [f"**{c['credit']}** — license: {c.get('license','see source')}", ""]
    for r in c.get("references", []):
        L.append(f"- [{r['label']}]({r['url']})")
    files = c.get("files") or []
    if files:
        L += ["", "<details><summary>Capture files</summary>", ""] + [f"- `{f}`" for f in files[:60]] + ["", "</details>"]
    return "\n".join(L) + "\n"

def attribution(datasets, used):
    L = ["# Dataset attribution & licenses", "",
         "The packet captures are not in this repository's git history. Datasets whose licence (or authors) allow "
         "redistribution are **mirrored, unmodified, as assets of the `data-v1` release** under their own licences; "
         "every other dataset is downloaded by `scripts/fetch.py` from its original source. **If you use these captures, "
         "cite the original authors below** — for the Creative Commons datasets this is a licence requirement, not just a courtesy.", "",
         "_This file is generated by `scripts/build.py` from `catalog/datasets.json`._", "",
         "| Dataset | Authors / owner | Year | Licence | Source | Copy |", "|---|---|---|---|---|---|"]
    for d in datasets:
        if d["slug"] not in used: continue
        src = f"[{('doi:' + d['doi']) if d.get('doi') else 'link'}]({('https://doi.org/' + d['doi']) if d.get('doi') else d.get('source_url')})"
        copy = f"[{'mirrored (`' + d['mirror']['tag'] + '`)' if d.get('mirror') else 'from source'}](DATASETS.md#{d['slug']})"
        L.append(f"| {d['title']} | {d.get('authors','—')} | {d.get('year') or '—'} | {d.get('license','—')} | {src} | {copy} |")
    L += ["", "## Full citations", ""]
    for d in datasets:
        if d["slug"] not in used or not d.get("citation"): continue
        L += [f"- {d['citation']}"]
    L += ["", "## Obligations", "",
          "- **Attribution:** credit the authors above and keep this file with any redistribution of challenge material.",
          "- **Non-commercial datasets** (CC BY-NC / BY-NC-SA, e.g. Cyber4OT and the electrical-substation ML-IDS set) may not be used commercially; the MIT license on this repo's code does not relicense any data.",
          "- **Share-alike datasets** (CC BY-SA, GPL) that are mirrored are redistributed under the same licence; keep it with any copy.",
          "- **Datasets published without a licence** (community collections, CTF challenge files, some academic sets) are credited to their authors and only *linked* — fetched from their source, never re-hosted here.",
          "- Each mirrored archive contains `LICENSE-NOTICE.md` (licence, why redistribution is allowed, citation) and, where required, the original licence text.", ""]
    return "\n".join(L)

def main():
    chals = json.load(open(os.path.join(REPO, "catalog", "challenges.json")))
    datasets = json.load(open(os.path.join(REPO, "catalog", "datasets.json")))
    DS.update({d["slug"]: d for d in datasets})
    out = []; seen = set(); total = 0                 # total counts every file once (challenges share files)
    for c in chals:
        b, n, present = scan(c.get("files", []))
        c = dict(c, bytes=b, file_count=n, present=n > 0, fetch=fetch_slugs(c))
        bad = [s for s in c["fetch"] if s not in DS or not SLUG.match(s)]
        if bad: raise SystemExit(f"{c['id']}: dataset(s) {bad} missing from catalog/datasets.json or not a plain slug")
        c["files_present"] = present[:60]
        for rel in present:
            if rel not in seen: seen.add(rel); total += os.path.getsize(os.path.join(REPO, rel))
        out.append(c)
    meta = {"total_bytes": total, "count": len(out), "present": sum(1 for c in out if c["present"]),
            "subtitle": f"{len(out)} ICS / OT / SCADA challenges",
            "generated": datetime.datetime.now().isoformat(timespec="seconds")}
    app = [{k: v for k, v in c.items() if k != "files"} | {"files": c["files_present"]} for c in out]
    with open(os.path.join(REPO, "challenges.js"), "w") as f:
        f.write("// generated by scripts/build.py — do not edit by hand\n")
        f.write("window.CORPUS_META=" + json.dumps(meta) + ";\n")
        f.write("window.CHALLENGES=" + json.dumps(app, indent=0, ensure_ascii=False) + ";\n")
    used = {s for c in out for s in c["fetch"]}
    ds_app = {}
    for d in datasets:
        if d["slug"] not in used: continue
        m = d.get("mirror")
        ds_app[d["slug"]] = {"title": d.get("title"), "license": d.get("license"), "source_url": d.get("source_url"), "doi": d.get("doi"),
                             "approx_bytes": d.get("approx_bytes") or 0, "pending": bool(d.get("mirror_pending")),
                             "mirror": {"tag": m["tag"], "bytes_packed": m["bytes_packed"],
                                        "parts": [{"name": p["name"], "size": p["size"]} for p in m["parts"]]} if m else None}
    with open(os.path.join(REPO, "datasets.js"), "w") as f:
        f.write("// generated by scripts/build.py — do not edit by hand\n")
        f.write("window.DATASETS=" + json.dumps(ds_app, ensure_ascii=False) + ";\n")
    cdir = os.path.join(REPO, "challenges"); os.makedirs(cdir, exist_ok=True)
    keep = set()
    for c in out:
        fn = f"{c['id']}.md"; keep.add(fn)
        open(os.path.join(cdir, fn), "w").write(md_page(dict(c, files=c["files_present"] or c.get("files", []))))
    for fn in os.listdir(cdir):           # drop pages for challenges that no longer exist
        if fn.endswith(".md") and fn not in keep and fn != "README.md":
            os.remove(os.path.join(cdir, fn))
    # index
    idx = ["# All challenges", "", f"{len(out)} challenges. Open `index.html` (or the GitHub Pages site) for the interactive version.", "",
           "Where each dataset's captures are (mirror or original source): [DATASETS.md](../DATASETS.md).", "",
           "| Challenge | Difficulty | Protocols / tags | Captures |", "|---|---|---|---|"]
    order = {"Easy": 0, "Medium": 1, "Hard": 2, "Expert": 3}
    for c in sorted(out, key=lambda c: (c.get("group", ""), order.get(c["difficulty"], 9), c["title"])):
        s = c["fetch"][0]; more = f" +{len(c['fetch']) - 1}" if len(c["fetch"]) > 1 else ""
        size = gb(c["bytes"]) + " · " if c["present"] else ""
        idx.append(f"| [{mdesc(c['title'])}]({c['id']}.md) | {c['difficulty']} | {', '.join(c.get('tags', [])[:4])} | {size}[`{s}`](../DATASETS.md#{s}){more} |")
    open(os.path.join(cdir, "README.md"), "w").write("\n".join(idx) + "\n")
    by_slug = {}
    for c in out:
        for s in c["fetch"]: by_slug.setdefault(s, []).append(c)
    open(os.path.join(REPO, "DATASETS.md"), "w").write(datasets_page(datasets, by_slug))
    open(os.path.join(REPO, "ATTRIBUTION.md"), "w").write(attribution(datasets, used))
    print(f"wrote challenges.js ({len(out)} challenges, {meta['present']} with data, {total/1e9:.1f} GB), datasets.js "
          f"({len(ds_app)} datasets, {sum(1 for v in ds_app.values() if v['mirror'])} mirrored), {len(out)} pages in challenges/, "
          f"DATASETS.md, ATTRIBUTION.md")

if __name__ == "__main__":
    main()
