# ELEGANT — flood against one PLC (rate 2)

**Process control & PLC testbeds** · **Medium** · 4.71 GB · 471 capture file(s)

> The same single-PLC flood at the higher rate, in two trial runs.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

The ELEGANT project (University of Coimbra) built a digital-twin testbed of Modbus/TCP programmable logic controllers and attacked it: denial-of-service (flooding and amplification, against one PLC or many) and man-in-the-middle (ARP poisoning, then the full attack chain). Each scenario was captured as rotating 10 MB files named cap_<n>_<timestamp>.

This challenge is **flood against one PLC (rate 2)**. Quantify it against the normal-traffic challenge.

## Objectives

- Identify the Modbus master, the PLCs and any attacker host (IP and MAC).
- Find the attack, its start and its source.
- Measure the impact on the Modbus exchange (latency, gaps, failed requests).
- Write a detection that would fire on this scenario but not on normal traffic.

## 📥 Get the captures

The commands on this page read the captures from `data/`. Fetch the dataset first, from the repo root:

```bash
python3 scripts/fetch.py elegant-plc-dos-mitm
```

- **[ELEGANT — DoS and man-in-the-middle attacks on PLCs](../DATASETS.md#elegant-plc-dos-mitm)** (`elegant-plc-dos-mitm`), ~19.06 GB once fetched
  - **Mirror:** this repo's [`data-v1` release](https://github.com/SackOfHacks/ICS-PCAP-Challenges/releases/tag/data-v1), 2 parts (3.12 GB compressed): [part000](https://github.com/SackOfHacks/ICS-PCAP-Challenges/releases/download/data-v1/elegant-plc-dos-mitm.tar.part000) (1.90 GB) · [part001](https://github.com/SackOfHacks/ICS-PCAP-Challenges/releases/download/data-v1/elegant-plc-dos-mitm.tar.part001) (1.22 GB)
  - **Original source:** [ieee-dataport.org/open-access/denial-service-and-man-midd…](https://ieee-dataport.org/open-access/denial-service-and-man-middle-attacks-programmable-logic-controllers) · [doi:10.21227/mewp-g646](https://doi.org/10.21227/mewp-g646)

Without `fetch.py`: download every part of the dataset, run `cat <dataset>.tar.part* | tar -x`, then `gunzip` the files listed in its `MIRROR-GZIPPED.txt`.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' --overview
```

**2. Deep-dive with Pcapper (--modbus)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' --modbus --ot-commands
```

**3. Threats and timeline with Pcapper**

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' --threats --scan
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng'
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -q -z io,phs | head -40
```

**2. Map the Modbus/TCP conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -Y mbtcp -T fields -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Measure the attack**

Packets per second, who sends them, and how far the Modbus exchange is crowded out.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -q -z io,stat,1 | head -40
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -q -z conv,ip | head -15
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

**5. Does the PLC still answer?**

Compare Modbus request/response pairs and response gaps with the normal-traffic challenge.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng' -Y mbtcp -T fields -e frame.time_relative -e ip.src -e ip.dst -e modbus.func_code | head -40
```

## Hints

<details><summary>Hint 1</summary>

The capture is a series of 10 MB files — mergecap them or work file by file.

</details>

<details><summary>Hint 2</summary>

Diff every number against the normal PLC traffic.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

Labelled by the dataset as flood against one PLC (rate 2) (folder single_flood_rate_2_t…). Expected answer: the attacker, the window, the mechanism and the measured effect on Modbus.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Read Holding Registers ×29; dangerous-operation matches: 0 for the Modbus/TCP filter (29 Modbus/TCP packets present, so the zero is real); top conversations in cap_00122_20210313200405.pcapng: 192.168.10.2↔192.168.12.2 (7 pkts), 192.168.10.2↔192.168.11.2 (4 pkts), 12.194.211.173↔192.168.10.2 (2 pkts) (basis: 3 of 471 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Dataset credit: Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646 · License: CC BY 4.0._

</details>

## Dataset & credit

**Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646** — license: CC BY 4.0

- [Dataset source — ELEGANT — DoS and man-in-the-middle attacks on PLCs](https://ieee-dataport.org/open-access/denial-service-and-man-middle-attacks-programmable-logic-controllers)
- [DOI 10.21227/mewp-g646](https://doi.org/10.21227/mewp-g646)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00016_20210313195826.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00017_20210313200245.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00018_20210313200245.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00019_20210313200246.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00020_20210313200247.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00021_20210313200248.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00022_20210313200248.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00023_20210313200249.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00024_20210313200250.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00025_20210313200251.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00026_20210313200251.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00027_20210313200252.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00028_20210313200253.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00029_20210313200254.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00030_20210313200254.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00031_20210313200255.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00032_20210313200256.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00033_20210313200257.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00034_20210313200257.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00035_20210313200258.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00036_20210313200259.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00037_20210313200300.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00038_20210313200301.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00039_20210313200301.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00040_20210313200302.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00041_20210313200303.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00042_20210313200304.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00043_20210313200304.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00044_20210313200305.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00045_20210313200306.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00046_20210313200307.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00047_20210313200307.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00048_20210313200308.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00049_20210313200309.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00050_20210313200310.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00051_20210313200310.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00052_20210313200311.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00053_20210313200312.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00054_20210313200313.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00055_20210313200313.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00056_20210313200314.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00057_20210313200315.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00058_20210313200316.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00059_20210313200317.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00060_20210313200317.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00061_20210313200318.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00062_20210313200319.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00063_20210313200320.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00064_20210313200320.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00065_20210313200321.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00066_20210313200322.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00067_20210313200323.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00068_20210313200323.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00069_20210313200324.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00070_20210313200325.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00071_20210313200326.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00072_20210313200326.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00073_20210313200327.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00074_20210313200328.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_flood_rate_2_t1/cap_00075_20210313200329.pcapng`

</details>
