# Coimbra Modbus SCADA — TCP SYN-flood DDoS

**Process control & PLC testbeds** · **Medium** · 1.00 GB · 37 capture file(s)

> A TCP SYN flood against the Modbus server. Measure it and its effect on the process data.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

The University of Coimbra built a Modbus/TCP SCADA testbed and captured clean operation plus a set of attacks for ICS intrusion-detection research (CRITIS 2018). Each challenge isolates one condition across the three capture sets.

A TCP SYN flood against the Modbus server. Measure it and its effect on the process data.

## Objectives

- Characterize the traffic in this condition.
- Quantify the attack (rate, sources, targets) where present.
- Determine the effect on the Modbus process traffic.
- Write a detection for it.

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Inventory the captures**

Three capture sets with several runs each — pick one to start, compare the rest later.

```bash
ls -lh 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-1m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-30m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-5m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap' ...
```

**2. Triage with Pcapper**

```bash
pcapper 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' --overview
```

**3. Confirm with Pcapper**

```bash
pcapper 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' --modbus --protocols --scan
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap'
tshark -r 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' -q -z io,phs | head -40
```

**2. Inventory the captures**

Three capture sets with several runs each — pick one to start, compare the rest later.

```bash
ls -lh 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-1m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-30m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-5m-12h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap' 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap' ...
```

**3. Measure the flood**

Half-open connections against port 502 and their effect on polling.

```bash
tshark -r 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head
tshark -r 'data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap' -q -z io,stat,1,'tcp.flags.syn==1 && tcp.flags.ack==0',mbtcp | head -30
```

## Hints

<details><summary>Hint 1</summary>

Compare against the clean baseline challenge — the delta is the attack.

</details>

<details><summary>Hint 2</summary>

io,stat with per-protocol columns shows the attack and the process traffic side by side.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

A TCP SYN flood (many half-open connections, typically spoofed sources) against the Modbus service on TCP 502; quantify it and check the polling cycle for gaps and retransmissions. The dataset's folder/file names are the ground-truth labels.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Write Single Register ×2212; dangerous-operation matches: 2212 (top sources: 172.27.224.250 ×2212); top conversations in eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap: 172.27.224.250↔172.27.224.251 (15,399 pkts), 0.0.0.0↔255.255.255.255 (133 pkts), 10.12.70.141↔172.27.224.250 (1 pkts) (basis: 3 of 37 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Dataset credit: Frazão, I., Abreu, P. H., Cruz, T., Araújo, H., Simões, P. — University of Coimbra (ATENA H2020) (2018) — doi:10.1007/978-3-030-05849-4_19 · License: CC BY 3.0 (repository content)._

</details>

## Dataset & credit

**Frazão, I., Abreu, P. H., Cruz, T., Araújo, H., Simões, P. — University of Coimbra (ATENA H2020) (2018) — doi:10.1007/978-3-030-05849-4_19** — license: CC BY 3.0 (repository content)

- [Dataset source — University of Coimbra — Modbus/TCP SCADA dataset #1 (CRITIS ](https://github.com/tjcruz-dei/ICS_PCAPS)
- [DOI 10.1007/978-3-030-05849-4_19](https://doi.org/10.1007/978-3-030-05849-4_19)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-1m-12h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-30m-12h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-5m-12h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-6h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap`
- `data/coimbra-modbus-tcp-scada/captures3/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-6h_1.pcap`

</details>
