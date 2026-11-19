# ELEGANT — amplification DoS against one PLC

**Process control & PLC testbeds** · **Hard** · 3.59 GB · 359 capture file(s)

> An amplification attack against a single PLC, in two trial runs.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

The ELEGANT project (University of Coimbra) built a digital-twin testbed of Modbus/TCP programmable logic controllers and attacked it: denial-of-service (flooding and amplification, against one PLC or many) and man-in-the-middle (ARP poisoning, then the full attack chain). Each scenario was captured as rotating 10 MB files named cap_<n>_<timestamp>.

This challenge is **amplification DoS against one PLC**. Quantify it against the normal-traffic challenge.

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
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' --overview
```

**2. Deep-dive with Pcapper (--modbus)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' --modbus --ot-commands
```

**3. Threats and timeline with Pcapper**

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' --threats --scan
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng'
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -q -z io,phs | head -40
```

**2. Map the Modbus/TCP conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -Y mbtcp -T fields -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Measure the attack**

Packets per second, who sends them, and how far the Modbus exchange is crowded out.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -q -z io,stat,1 | head -40
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -q -z conv,ip | head -15
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

**5. Does the PLC still answer?**

Compare Modbus request/response pairs and response gaps with the normal-traffic challenge.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng' -Y mbtcp -T fields -e frame.time_relative -e ip.src -e ip.dst -e modbus.func_code | head -40
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

Labelled by the dataset as amplification DoS against one PLC (folder single_amp_t…). Expected answer: the attacker, the window, the mechanism and the measured effect on Modbus.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Read Holding Registers ×68357; dangerous-operation matches: 0 for the Modbus/TCP filter (68,357 Modbus/TCP packets present, so the zero is real); top conversations in cap_00842_20210313204406.pcapng: 192.168.10.2↔192.168.12.2 (38,316 pkts), 192.168.10.2↔192.168.11.2 (38,314 pkts) (basis: 3 of 359 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Dataset credit: Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646 · License: CC BY 4.0._

</details>

## Dataset & credit

**Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646** — license: CC BY 4.0

- [Dataset source — ELEGANT — DoS and man-in-the-middle attacks on PLCs](https://ieee-dataport.org/open-access/denial-service-and-man-middle-attacks-programmable-logic-controllers)
- [DOI 10.21227/mewp-g646](https://doi.org/10.21227/mewp-g646)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00485_20210313201342.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00486_20210313202103.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00487_20210313202104.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00488_20210313202105.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00489_20210313202106.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00490_20210313202106.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00491_20210313202107.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00492_20210313202109.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00493_20210313202110.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00494_20210313202111.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00495_20210313202112.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00496_20210313202113.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00497_20210313202114.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00498_20210313202115.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00499_20210313202116.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00500_20210313202117.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00501_20210313202118.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00502_20210313202119.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00503_20210313202120.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00504_20210313202121.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00505_20210313202122.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00506_20210313202124.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00507_20210313202125.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00508_20210313202126.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00509_20210313202127.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00510_20210313202128.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00511_20210313202129.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00512_20210313202130.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00513_20210313202131.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00514_20210313202132.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00515_20210313202133.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00516_20210313202134.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00517_20210313202136.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00518_20210313202137.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00519_20210313202138.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00520_20210313202139.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00521_20210313202140.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00522_20210313202141.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00523_20210313202142.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00524_20210313202143.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00525_20210313202144.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00526_20210313202145.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00527_20210313202146.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00528_20210313202147.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00529_20210313202148.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00530_20210313202149.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00531_20210313202150.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00532_20210313202151.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00533_20210313202153.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00534_20210313202154.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00535_20210313202155.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00536_20210313202156.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00537_20210313202157.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00538_20210313202158.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00539_20210313202159.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00540_20210313202200.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00541_20210313202201.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00542_20210313202202.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00543_20210313202203.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/single_amp_t1/cap_00544_20210313202204.pcapng`

</details>
