# Cyber4OT — the full attack (successful and failed) and its aftermath

**Process control & PLC testbeds** · **Expert** · 37.3 MB · 7 capture file(s)

> The end-to-end PLC hijack: successful attack, a failed attempt, the hostile connection afterwards, and normal activity + attack in one trace.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

Cyber4OT (Warsaw University of Technology testbed) records an OT network's normal activity and a full attack: reconnaissance, then disconnection of the legitimate Modbus/TCP session and PLC hijacking. This challenge covers one band of the dataset's 96 traces, as described in its README.

The end-to-end PLC hijack: successful attack, a failed attempt, the hostile connection afterwards, and normal activity + attack in one trace.

## Objectives

- Characterize the traffic in this band.
- Identify attacker, technique and targets.
- Explain how you would detect it on a real OT network.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Open a representative trace**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' --overview
```

**2. Deep-dive with Pcapper (--modbus)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' --modbus --ot-commands
```

**3. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Open a representative trace**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng'
tshark -r 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' -q -z io,phs | head -40
```

**2. Map the Modbus/TCP conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' -Y mbtcp -T fields -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code | sort | uniq -c | sort -rn | head -25
```

**3. MAC flood and RST injection**

macof = huge numbers of random source MACs; tcpkill = forged RSTs on the Modbus session.

```bash
tshark -r 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' -T fields -e eth.src | sort -u | wc -l
tshark -r 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' -Y 'tcp.flags.reset==1 && tcp.port==502' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.seq | head
```

**4. Hunt the dangerous operations**

Flag writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

```bash
tshark -r 'data/cyber4ot/data/traces/Cyber4OT_096.pcapng' -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

## Hints

<details><summary>Hint 1</summary>

The dataset README (data/README.txt) describes each trace band — use it to check yourself.

</details>

<details><summary>Hint 2</summary>

Compare against the normal-activity band.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

090–091: successful attack (attacker ends up holding the Modbus/TCP session to the slave PLC). 092–093: failed attack (legit devices reconnect first). 094: post-attack state — the master's session can't be re-established, a hostile Modbus session appears instead. 095–096: 15 minutes of normal activity followed by the full successful attack.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Read Input Registers ×7694, Write Multiple Registers ×692, Read Holding Registers ×4; dangerous-operation matches: 692 (top sources: 192.168.127.20 ×346, 192.168.127.21 ×346) (basis: 3 of 7 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Dataset credit: Cabaj, K.; Plamowski, S.; Chaber, P.; Ławryńczuk, M.; Marusak, P.; Nebeluk, R.; Wojtulewicz, A.; Zarzycki, K. (2025) — doi:10.5281/zenodo.15005190 · License: CC BY-NC 4.0._

</details>

## Dataset & credit

**Cabaj, K.; Plamowski, S.; Chaber, P.; Ławryńczuk, M.; Marusak, P.; Nebeluk, R.; Wojtulewicz, A.; Zarzycki, K. (2025) — doi:10.5281/zenodo.15005190** — license: CC BY-NC 4.0

- [Dataset source — Cyber4OT: ICS network traces containing normal activity and ](https://zenodo.org/records/15005190)
- [DOI 10.5281/zenodo.15005190](https://doi.org/10.5281/zenodo.15005190)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/cyber4ot/data/traces/Cyber4OT_090.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_091.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_092.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_093.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_094.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_095.pcapng`
- `data/cyber4ot/data/traces/Cyber4OT_096.pcapng`

</details>
