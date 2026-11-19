# TU Wien Smart Factory — OT Attack & Operations

**Manufacturing & smart factory** · **Hard** · 127.15 GB · 73 capture file(s)

> Real factory-cell traffic: MQTT, OPC UA and Modbus/TCP, with attack and operational days. The Tuesday DoS day is unlabeled.

> ⚠️ **Safety:** OT capture is passive and safe to read. Never replay these onto a live industrial network.

## Scenario

Captures from a real TU Wien smart-factory cell, mixing normal operational traffic with attack days. Industrial protocols — MQTT, OPC UA and Modbus/TCP — carry the process data. One day (Tuesday) is an unlabeled DoS: you have to characterize it yourself.

## Objectives

- Inventory the OT assets and protocols.
- Baseline normal MQTT/OPC-UA/Modbus behavior.
- Characterize the unlabeled Tuesday DoS.
- Distinguish attack traffic from normal process variation.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage with Pcapper**

Pcapper auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/tuwien-smart-factory/captures/a_day1.pcap.part000.pcap' --overview
```

**2. Normalize every OT command with Pcapper**

```bash
pcapper 'data/tuwien-smart-factory/captures/a_day1.pcap.part000.pcap' --ot-commands --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Inventory**

Read the retained readme.txt for what each file is.

```bash
ls -lh data/tuwien-smart-factory/captures/
tshark -r data/tuwien-smart-factory/captures/s_day1.pcap.part000.pcap -q -z io,phs | grep -iE 'mqtt|opcua|modbus|tcp'
```

**2. Profile the protocols**

MQTT topics and Modbus function codes define the process baseline.

```bash
tshark -r <file>.pcap -Y 'mqtt' -T fields -e mqtt.topic | sort | uniq -c | sort -rn | head
tshark -r <file>.pcap -Y 'modbus' -T fields -e modbus.func_code | sort | uniq -c
```

**3. Baseline rates**

Establish packets/sec per protocol during normal operation.

```bash
tshark -r <normal>.pcap -q -z io,stat,1 | head -30
```

**4. Characterize the DoS**

Look for a rate spike, a flood source, or a protocol abused to stall the cell.

```bash
tshark -r <tuesday>.pcap -q -z io,stat,1 | head
tshark -r <tuesday>.pcap -q -z conv,tcp | sort -k2 -rn | head
```

## Hints

<details><summary>Hint 1</summary>

These files are large (up to ~12 GB) — stay offline and use display filters, not the whole-file GUI.

</details>

<details><summary>Hint 2</summary>

Compare the unlabeled Tuesday capture's per-second rates against a known-normal day.

</details>

<details><summary>Hint 3</summary>

A Modbus or MQTT flood shows as a single source dominating the conversation table with tiny, rapid packets.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

No single answer — it's a characterization exercise. Baseline the normal days (MQTT topic cadence, OPC-UA sessions, Modbus function-code mix, per-second rates), then show how the Tuesday capture deviates (rate spike / flood source / abused function). The retained readme.txt labels the other days; Tuesday you argue from the evidence.

</details>

## Dataset & credit

**Brenner, B., Fabini, J., Offermanns, M., Semper, S. & Zseby, T. (2025), TU Wien — DOI 10.48436/ghdc6-45k78 — CC BY 4.0.** — license: CC BY 4.0

- [TU Wien Smart Factory dataset](https://researchdata.tuwien.ac.at/records/ghdc6-45k78)
- [DOI 10.48436/ghdc6-45k78](https://doi.org/10.48436/ghdc6-45k78)

<details><summary>Capture files</summary>

- `data/tuwien-smart-factory/captures/a_day1.pcap.part000.pcap`
- `data/tuwien-smart-factory/captures/a_day1.pcap.part001.pcap`
- `data/tuwien-smart-factory/captures/a_day1.pcap.part002.pcap`
- `data/tuwien-smart-factory/captures/a_day2.pcap.part000.pcap`
- `data/tuwien-smart-factory/captures/a_day2.pcap.part001.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part000.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part001.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part002.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part003.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part004.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part005.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part006.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part007.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part008.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part009.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part010.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part011.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part012.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part013.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part014.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part015.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part016.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part017.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part018.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part019.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part020.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part021.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part022.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part023.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part024.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part025.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part026.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part027.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part028.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part029.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part030.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part031.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part032.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part033.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part034.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part035.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part036.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part037.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part038.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part039.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part040.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part041.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part042.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part043.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part044.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part045.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part046.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part047.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part048.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part049.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part050.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part051.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part052.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part053.pcap`
- `data/tuwien-smart-factory/captures/a_day_tuesday_dos.pcap.part054.pcap`

</details>
