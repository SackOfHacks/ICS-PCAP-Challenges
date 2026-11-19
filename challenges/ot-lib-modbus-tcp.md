# Protocol deep-dive — Modbus/TCP (33 unique captures)

**Protocol library** · **Medium** · 0.48 GB · 33 capture file(s)

> A deduplicated library of 33 Modbus/TCP captures from 7 public collections. Learn the protocol's grammar, then hunt its dangerous operations.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

Every public Modbus/TCP sample in this range, deduplicated by SHA-256 across automayt-ics-pcap, cisa-icsnpp-test-traces, emreekin-ics-pcaps, inl-malcolm-ot-artifacts, iti-ics-security-tools-pcaps, s7comm-scenarios-jenilv07, suricata-verify-ics-tests. Use it to learn what the protocol looks like on the wire — roles, operations, normal cadence — and to practice spotting the operations attackers abuse: writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

## Objectives

- Identify clients/masters and servers/outstations across the samples.
- Enumerate the Modbus/TCP operations present.
- Flag every dangerous operation and its source.
- Map findings to ATT&CK for ICS (T0855 Unauthorized Command Message · T0836 Modify Parameter · T0861 Point & Tag Identification · T0888 Remote System Information Discovery).

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' --overview
```

**2. Deep-dive with Pcapper (--modbus)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' --modbus --ot-commands
```

**3. Sweep the whole library**

```bash
pcapper data/automayt-ics-pcap/ --modbus --ot-commands
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap'
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' -q -z io,phs | head -40
```

**2. Map the Modbus/TCP conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' -Y mbtcp -T fields -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering).

```bash
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Sweep the whole library**

```bash
for f in 'data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbus.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbusSmall.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/fuzz-72.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/fuzz-1011.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbusBig.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/Combined/Plant1.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/modbus_test_data_part2.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/mb2.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/ModbusTCP.pcap'; do echo "== $f"; tshark -r "$f" -Y 'modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}' 2>/dev/null | head -3; done
```

## Hints

<details><summary>Hint 1</summary>

Wireshark display filter for the protocol: mbtcp

</details>

<details><summary>Hint 2</summary>

Dangerous-operation filter: modbus.func_code in {5, 6, 15, 16, 22, 23, 8, 43, 90}

</details>

<details><summary>Hint 3</summary>

Many library files are tiny protocol samples — read them packet by packet in Wireshark.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

A library, not a single puzzle: the deliverable is a per-capture table of roles and operations, with the dangerous ones flagged (writes (FC 5/6/15/16/22/23), diagnostics (FC 8 — restart / force-listen-only), device identification (FC 43/14, recon) and Schneider UMAS (FC 90, engineering)). ATT&CK for ICS: T0855 Unauthorized Command Message · T0836 Modify Parameter · T0861 Point & Tag Identification · T0888 Remote System Information Discovery. Sources are credited per collection in each folder's PROVENANCE.md.

**Computed evidence (auto-extracted with tshark — verify it yourself):** Modbus/TCP operations — Device Identification (MEI) ×2, Mask Write Register ×2, Read/Write Multiple Registers ×2; dangerous-operation matches: 6 (top sources: 127.0.0.1 ×6) (basis: 3 of 33 capture file(s), first 300,000 packets each, smallest files carrying Modbus/TCP chosen)

_Captures credited to: ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CISA ICSNPP — Zeek ICS parser test traces — CISA and Idaho National Laboratory (ICSNPP project) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign · ICS sample collection (jenilv-07) — S7comm scenarios, ControlLogix attack attempts, BACnet, Modbus, Omron, Tridium — jenilv-07 (GitHub) · Suricata-verify — ICS protocol test captures — OISF (Open Information Security Foundation)._

</details>

## Dataset & credit

**ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CISA ICSNPP — Zeek ICS parser test traces — CISA and Idaho National Laboratory (ICSNPP project) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign · ICS sample collection (jenilv-07) — S7comm scenarios, ControlLogix attack attempts, BACnet, Modbus, Omron, Tridium — jenilv-07 (GitHub) · Suricata-verify — ICS protocol test captures — OISF (Open Information Security Foundation)** — license: varies by collection — see each folder's PROVENANCE.md

- [Dataset source — ICS-pcap collection (automayt / Jason Smith)](https://github.com/automayt/ICS-pcap)
- [Dataset source — CISA ICSNPP — Zeek ICS parser test traces](https://github.com/cisagov/ICSNPP)
- [Dataset source — ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset](https://github.com/EmreEkin/ICS-Pcaps)
- [Dataset source — INL Malcolm test artifacts — OT protocol samples](https://github.com/idaholab/Malcolm-Test-Artifacts)
- [Dataset source — ITI ICS-Security-Tools — sample ICS protocol captures](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps)
- [Dataset source — ICS sample collection (jenilv-07) — S7comm scenarios, Contro](https://github.com/jenilv-07/ICS-pcap-files)
- [Dataset source — Suricata-verify — ICS protocol test captures](https://github.com/OISF/suricata-verify)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/cisa-icsnpp-test-traces/icsnpp-modbus/modbus_example.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbus.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbusSmall.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/fuzz-72.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/fuzz-1011.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/modbus/modbusBig.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/Combined/Plant1.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/modbus_test_data_part2.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/mb2.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/ModbusTCP.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/modbus_test_data_part1.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/Modbus/modbus_test.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/ModbusTCP/Modbus/modbus_test_2.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/modicon/modicon_test.pcap`
- `data/automayt-ics-pcap/MODBUS/Modbus/Modbus.pcap`
- `data/automayt-ics-pcap/Additional Captures/4SICS-GeekLounge-151021/4SICS-GeekLounge-151021.pcap`
- `data/automayt-ics-pcap/Additional Captures/4SICS-GeekLounge-151022/4SICS-GeekLounge-151022.pcap`
- `data/emreekin-ics-pcaps/MODBUS/crash.pcap`
- `data/emreekin-ics-pcaps/MODBUS/modbus-encapsulated-transport.pcap`
- `data/emreekin-ics-pcaps/MODBUS/FC1-permit.pcap`
- `data/emreekin-ics-pcaps/MODBUS/modbus-read-write-multiple-registers.pcap`
- `data/emreekin-ics-pcaps/MODBUS/modbus-mask-write-register.pcap`
- `data/emreekin-ics-pcaps/EtherCat/valve.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/ModbusFloat.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/ReadCoil.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/İllegalFunction.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/modbusAnalog.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/WriteMultipleCoil.pcap`
- `data/emreekin-ics-pcaps/S7COMM/ıcs.pcap`
- `data/emreekin-ics-pcaps/S7COMM/S7.pcap`
- `data/s7comm-scenarios-jenilv07/comman/Modbus 1.pcap`
- `data/suricata-verify-ics-tests/tests/modbus/modbus.pcap`
- `data/inl-malcolm-ot-artifacts/Malcolm-Test-Artifacts-main/pcap/protocols/Modbus.pcap`

</details>
