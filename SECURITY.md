# Security policy

## Reporting a vulnerability

Please report security problems **privately** with GitHub's *Report a vulnerability* button (the repository's
**Security** tab → **Advisories**), not in a public issue. That covers the scripts (`fetch.py`, `mega_fetch.py`,
`build.py`), the web app, the challenge content and the release mirror. You will get an answer, and credit if you want it.

## What the tools defend against

- **The release mirror is verified.** Every part of every mirrored dataset is checked against the SHA-256 in
  `catalog/datasets.json` (in git) *before* anything is unpacked, and unpacking keeps only regular files and folders
  inside `data/<dataset>/` (Python's `tarfile` extraction filter is required). A mismatch stops the fetch; `fetch.py` never
  falls back to an unverified source on its own.
- **Original sources are untrusted.** Datasets that cannot be re-hosted come from their publishers (Zenodo, GitHub, Kaggle,
  MEGA, university sites …) and are not checksum-verified. `fetch.py` therefore downloads over HTTPS only (redirects
  included), validates every catalog field it turns into a path, unpacks each archive into a fresh empty folder (links,
  device files and absolute or `..` paths are refused or removed) and moves files into place with a containment check.
  `mega_fetch.py` refuses unsafe MEGA names and verifies each file's MEGA MAC.
- **Catalog text is data, never markup.** Challenge and dataset text is escaped in the Markdown pages and the web app;
  only `http(s)`/`mailto` URLs become links.
- **Walkthroughs are passive analysis.** The commands read capture files. The one step that loads third-party code (the
  TriStation Lua dissector) pins its source to a commit and loads it only if its SHA-256 matches.

## What you should still do

The captures are real attack and plant traffic. Analyse them offline, never replay them onto a network, never send the
commands you find to a real controller, and treat anything you carve as live malware. Some challenges say they carry
executables or were recorded at a real facility; take that literally.

## Check it yourself

```bash
python3 scripts/test_security.py      # builds hostile archives, catalogs and pages in a temp folder and checks every defence
```
