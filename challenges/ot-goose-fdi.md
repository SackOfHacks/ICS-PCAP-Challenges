# GOOSE false-data injection between IEDs

**Power grid & substations** · **Hard** · 4.4 MB · 2 capture file(s)

> False data injected into GOOSE messaging between IEDs, with a clean baseline.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

False data injected into GOOSE messaging between IEDs, with a clean baseline.

False-data-injection attack on GOOSE messaging between IEDs, with a clean baseline capture.

## Objectives

- Identify devices and protocol roles.
- Find and characterize the malicious activity.
- Use the dataset's labels/companion files to check yourself.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' --overview
```

**2. Deep-dive with Pcapper (--goose)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' --goose --ot-commands
```

**3. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng'
tshark -r 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' -q -z io,phs | head -40
```

**2. Map the IEC 61850 GOOSE conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' -Y goose -T fields -e eth.src -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.timeAllowedtoLive | head -40
```

**3. Hunt the dangerous operations**

Flag GOOSE has no confirmed 'write' — the attack surface is the event stream itself: stNum jumping without a real state change, sqNum resets, bursts far above the retransmission curve, the test/simulation flag, or an unexpected source MAC publishing a known gocbRef.

```bash
tshark -r 'data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng' -Y 'goose' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

## Hints

<details><summary>Hint 1</summary>

Look for label files (CSV/JSON/logs) next to the captures — they are the answer key.

</details>

<details><summary>Hint 2</summary>

Compare attack captures against the clean/normal ones.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

The dataset's bundled labels and companion files are the authoritative answer key; the computed evidence below summarizes what the packets show.

**Computed evidence (auto-extracted with tshark — verify it yourself):** IEC 61850 GOOSE packets matching `goose`: 7,773; GOOSE streams — DEVICE_1UD1/LLN0$GO$Control_DataSet from b4:b1:5a:14:71:49: 7773 frames, 68 distinct stNum, 74 sqNum resets; top conversations in FDI_Attack_traffic.pcapng: 192.168.125.14↔239.255.255.250 (732 pkts), 169.254.104.1↔239.255.255.250 (732 pkts), 0.0.0.0↔255.255.255.255 (159 pkts) (basis: 2 of 2 capture file(s), first 300,000 packets each)

_Dataset credit: Enache, Bogdan-Adrian; Stan, Viorel; Barbulescu, Cristinel (2024) — doi:10.5281/zenodo.13908638 · License: CC BY 4.0._

</details>

## Dataset & credit

**Enache, Bogdan-Adrian; Stan, Viorel; Barbulescu, Cristinel (2024) — doi:10.5281/zenodo.13908638** — license: CC BY 4.0

- [Dataset source — False-data injection in GOOSE communication](https://zenodo.org/records/13908638)
- [DOI 10.5281/zenodo.13908638](https://doi.org/10.5281/zenodo.13908638)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/goose-false-data-injection/FDI/Attack/FDI_Attack_traffic.pcapng`
- `data/goose-false-data-injection/FDI/Clean/clean.pcapng`

</details>
