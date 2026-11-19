# ELEGANT — flood against multiple PLCs

**Process control & PLC testbeds** · **Hard** · 5.24 GB · 263 capture file(s)

> A flood spread over several PLCs at once.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

The ELEGANT project (University of Coimbra) built a digital-twin testbed of Modbus/TCP programmable logic controllers and attacked it: denial-of-service (flooding and amplification, against one PLC or many) and man-in-the-middle (ARP poisoning, then the full attack chain). Each scenario was captured as rotating 10 MB files named cap_<n>_<timestamp>.

This challenge is **flood against multiple PLCs**. Quantify it against the normal-traffic challenge.

## Objectives

- Identify the Modbus master, the PLCs and any attacker host (IP and MAC).
- Find the attack, its start and its source.
- Measure the impact on the Modbus exchange (latency, gaps, failed requests).
- Write a detection that would fire on this scenario but not on normal traffic.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' --overview
```

**2. Deep-dive with Pcapper (--modbus)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' --modbus --ot-commands
```

**3. Threats and timeline with Pcapper**

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' --threats --scan
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng'
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -q -z io,phs | head -40
```

**2. Map the Modbus/TCP conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -Y mbtcp -T fields -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Measure the attack**

Packets per second, who sends them, and how far the Modbus exchange is crowded out.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -q -z io,stat,1 | head -40
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -q -z conv,ip | head -15
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

**5. Does the PLC still answer?**

Compare Modbus request/response pairs and response gaps with the normal-traffic challenge.

```bash
tshark -r 'data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng' -Y mbtcp -T fields -e frame.time_relative -e ip.src -e ip.dst -e modbus.func_code | head -40
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

Labelled by the dataset as flood against multiple PLCs (folder multiple_flood_…). Expected answer: the attacker, the window, the mechanism and the measured effect on Modbus.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Read Holding Registers ×36969; dangerous-operation matches: 0 for the Modbus/TCP filter (36,969 Modbus/TCP packets present, so the zero is real); top conversations in cap_00244_20210314012538.pcapng: 192.168.10.2↔192.168.20.2 (1,758 pkts), 192.168.10.2↔192.168.20.3 (1,758 pkts), 192.168.10.2↔192.168.20.4 (1,758 pkts) (basis: 3 of 263 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Dataset credit: Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646 · License: CC BY 4.0._

</details>

## Dataset & credit

**Sousa, B.; Arieiro, M.; Pereira, V.; Cruz, T. (University of Coimbra) (2021) — doi:10.21227/mewp-g646** — license: CC BY 4.0

- [Dataset source — ELEGANT — DoS and man-in-the-middle attacks on PLCs](https://ieee-dataport.org/open-access/denial-service-and-man-middle-attacks-programmable-logic-controllers)
- [DOI 10.21227/mewp-g646](https://doi.org/10.21227/mewp-g646)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314005755.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00001_20210314010944.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00002_20210314010231.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00002_20210314011221.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00003_20210314010240.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00003_20210314011223.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00004_20210314010250.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00004_20210314011224.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00005_20210314010259.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00005_20210314011226.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00006_20210314010309.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00006_20210314011227.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00007_20210314010319.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00007_20210314011229.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00008_20210314010329.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00008_20210314011230.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00009_20210314010338.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00009_20210314011232.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00010_20210314010348.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00010_20210314011234.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00011_20210314010358.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00011_20210314011235.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00012_20210314010407.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00012_20210314011237.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00013_20210314010417.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00013_20210314011238.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00014_20210314010427.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00014_20210314011240.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00015_20210314010437.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00015_20210314011241.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00016_20210314010446.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00016_20210314011243.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00017_20210314010456.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00017_20210314011245.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00018_20210314010506.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00018_20210314011246.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00019_20210314010515.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00019_20210314011248.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00020_20210314011250.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00021_20210314011251.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00022_20210314011253.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00023_20210314011254.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00024_20210314011256.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00025_20210314011258.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00026_20210314011259.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00027_20210314011301.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00028_20210314011303.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00029_20210314011304.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00030_20210314011306.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00031_20210314011307.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00032_20210314011309.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00033_20210314011310.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00034_20210314011312.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00035_20210314011313.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00036_20210314011315.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00037_20210314011316.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00038_20210314011318.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00039_20210314011319.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00040_20210314011321.pcapng`
- `data/elegant-plc-dos-mitm/IEEE_DataPort/DoS/multiple_flood_0100_0125/capture/cap_00041_20210314011322.pcapng`

</details>
