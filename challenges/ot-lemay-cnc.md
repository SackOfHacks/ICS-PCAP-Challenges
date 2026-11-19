# Lemay SCADA — C&C channel uploading an executable

**ICS malware & intrusions** · **Hard** · 0.2 MB · 1 capture file(s)

> A command-and-control channel pushes an executable onto a SCADA host. Carve it.

> ⚠️ **Safety:** Contains live exploit/malware traffic. Carve and hash only — never execute, and never replay.

## Scenario

Lemay & Fernandez (CSET 2016) built simulated SCADA networks — a master polling Modbus RTUs — and recorded normal operation plus labelled malicious activity, to give ICS intrusion-detection research realistic data.

A command-and-control channel pushes an executable onto a SCADA host. Carve it.

## Objectives

- Separate normal polling from everything else.
- Identify the malicious activity, its source and its targets.
- Explain how a defender would detect it.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage with Pcapper**

```bash
pcapper 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' --overview
```

**2. Carve the executable**

Reassemble the C&C session and look for an MZ header; hash it, never run it.

```bash
pcapper 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' --files --carve --carve-out ./carved_lemay && sha256sum ./carved_lemay/* 2>/dev/null
```

**3. Normalize all control operations**

```bash
pcapper 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' --modbus --ot-commands
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage with Pcapper**

```bash
capinfos 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap'
tshark -r 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' -q -z io,phs | head -40
```

**2. Who talks to whom**

```bash
tshark -r 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' -q -z conv,tcp | head -25
```

**3. Carve the executable**

Reassemble the C&C session and look for an MZ header; hash it, never run it.

```bash
tshark -r 'data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap' -Y '!mbtcp && tcp.len>0' -q -z conv,tcp | head
```

## Hints

<details><summary>Hint 1</summary>

Do the baseline challenge first — the attacks only stand out against the normal cycle.

</details>

<details><summary>Hint 2</summary>

Anything that isn't Modbus on this network is suspicious by default.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

A compromised host on the SCADA network receives an executable over a command-and-control channel. Find the non-Modbus session, reassemble it, and carve/hash the PE (MZ) payload — treat it as live malware. The capture's filename is the dataset's ground-truth label.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Read Holding Registers ×96, Read Discrete Inputs ×96, Read Coils ×96, Write Single Coil ×2; dangerous-operation matches: 2 (top sources: 192.168.1.100 ×1, 192.168.1.103 ×1) (basis: 1 of 1 capture file(s), first 300,000 packets each)

_Dataset credit: Antoine Lemay & José M. Fernandez (Polytechnique Montréal) (2016) · License: No license stated in repo — credit the author._

</details>

## Dataset & credit

**Antoine Lemay & José M. Fernandez (Polytechnique Montréal) (2016)** — license: No license stated in repo — credit the author

- [Dataset source — Lemay & Fernandez SCADA Modbus dataset (CSET 2016)](https://github.com/antoine-lemay/Modbus_dataset)
- [Lemay & Fernandez, CSET '16 (USENIX)](https://www.usenix.org/conference/cset16/workshop-program/presentation/lemay)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/lemay-scada-modbus-cset2016/CnC_uploading_exe_modbus_6RTU_with_operate.pcap`

</details>
