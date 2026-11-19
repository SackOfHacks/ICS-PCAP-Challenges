# Protocol deep-dive — IEC-104 (25 unique captures)

**Protocol library** · **Medium** · 58.6 MB · 25 capture file(s)

> A deduplicated library of 25 IEC-104 captures from 5 public collections. Learn the protocol's grammar, then hunt its dangerous operations.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

Every public IEC-104 sample in this range, deduplicated by SHA-256 across automayt-ics-pcap, cip-enip-engage-svg, emreekin-ics-pcaps, inl-malcolm-ot-artifacts, iti-ics-security-tools-pcaps. Use it to learn what the protocol looks like on the wire — roles, operations, normal cadence — and to practice spotting the operations attackers abuse: control commands (TypeID 45 single, 46 double, 47 regulating step, 48–50 set-points, 51 bitstring, 58–64 time-tagged variants), interrogations (100 general, 101 counter), read (102), clock sync (103) and reset process (105).

## Objectives

- Identify clients/masters and servers/outstations across the samples.
- Enumerate the IEC-104 operations present.
- Flag every dangerous operation and its source.
- Map findings to ATT&CK for ICS (T0855 Unauthorized Command Message · T0831 Manipulation of Control · T0846 Remote System Discovery · T0816 Device Restart/Shutdown).

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' --overview
```

**2. Deep-dive with Pcapper (--iec104)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' --iec104 --ot-commands
```

**3. Sweep the whole library**

```bash
pcapper data/automayt-ics-pcap/ --iec104 --ot-commands
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap'
tshark -r 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' -q -z io,phs | head -40
```

**2. Map the IEC-104 conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' -Y iec60870_asdu -T fields -e ip.src -e ip.dst -e iec60870_asdu.typeid -e iec60870_asdu.causetx | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag control commands (TypeID 45 single, 46 double, 47 regulating step, 48–50 set-points, 51 bitstring, 58–64 time-tagged variants), interrogations (100 general, 101 counter), read (102), clock sync (103) and reset process (105).

```bash
tshark -r 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' -Y 'iec60870_asdu.typeid in {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64, 100, 101, 102, 103, 105}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Sweep the whole library**

```bash
for f in 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/090813_diverse.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/TestDissectIec104.pcap' 'data/automayt-ics-pcap/IEC 60870/iec104/iec104.pcap' 'data/automayt-ics-pcap/IEC 60870/IEC104_SQ/IEC104_SQ.pcapng' 'data/emreekin-ics-pcaps/IEC60870-104/58_59.pcap' 'data/emreekin-ics-pcaps/IEC60870-104/104IPValue.pcap' 'data/emreekin-ics-pcaps/IEC60870-104/62.pcap' 'data/emreekin-ics-pcaps/IEC60870-104/104deneme2.pcap' 'data/emreekin-ics-pcaps/IEC60870-104/104deneme.pcap'; do echo "== $f"; tshark -r "$f" -Y 'iec60870_asdu.typeid in {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64, 100, 101, 102, 103, 105}' 2>/dev/null | head -3; done
```

## Hints

<details><summary>Hint 1</summary>

Wireshark display filter for the protocol: iec60870_104

</details>

<details><summary>Hint 2</summary>

Dangerous-operation filter: iec60870_asdu.typeid in {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64, 100, 101, 102, 103, 105}

</details>

<details><summary>Hint 3</summary>

Many library files are tiny protocol samples — read them packet by packet in Wireshark.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

A library, not a single puzzle: the deliverable is a per-capture table of roles and operations, with the dangerous ones flagged (control commands (TypeID 45 single, 46 double, 47 regulating step, 48–50 set-points, 51 bitstring, 58–64 time-tagged variants), interrogations (100 general, 101 counter), read (102), clock sync (103) and reset process (105)). ATT&CK for ICS: T0855 Unauthorized Command Message · T0831 Manipulation of Control · T0846 Remote System Discovery · T0816 Device Restart/Shutdown. Sources are credited per collection in each folder's PROVENANCE.md.

**Computed evidence (auto-extracted with tshark — verify it yourself):** IEC-104 operations — M_ME_TF_1 ×6, M_SP_NA_1 ×4, 33 ×3; dangerous-operation matches: 0 for the IEC-104 filter (13 IEC-104 packets present, so the zero is real) (basis: 3 of 25 capture file(s), first 300,000 packets each, smallest files carrying IEC-104 chosen)

_Captures credited to: ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CIP / EtherNet-IP captures (incl. controller reboot) — engage-svg (GitHub) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign._

</details>

## Dataset & credit

**ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CIP / EtherNet-IP captures (incl. controller reboot) — engage-svg (GitHub) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign** — license: varies by collection — see each folder's PROVENANCE.md

- [Dataset source — ICS-pcap collection (automayt / Jason Smith)](https://github.com/automayt/ICS-pcap)
- [Dataset source — CIP / EtherNet-IP captures (incl. controller reboot)](https://github.com/engage-svg/ICS-PCAPs)
- [Dataset source — ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset](https://github.com/EmreEkin/ICS-Pcaps)
- [Dataset source — INL Malcolm test artifacts — OT protocol samples](https://github.com/idaholab/Malcolm-Test-Artifacts)
- [Dataset source — ITI ICS-Security-Tools — sample ICS protocol captures](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/090813_diverse.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/IEC60870-5-104/TestDissectIec104.pcap`
- `data/automayt-ics-pcap/IEC 60870/iec104/iec104.pcap`
- `data/automayt-ics-pcap/IEC 60870/IEC104_SQ/IEC104_SQ.pcapng`
- `data/emreekin-ics-pcaps/IEC60870-104/58_59.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/104IPValue.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/62.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/104deneme2.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/104deneme.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/33.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/61.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/63.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/104LocalValue.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/63_1.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/60.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/Logfile IEC104.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/iec104_baselines.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/50.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/64.pcap`
- `data/emreekin-ics-pcaps/IEC60870-104/59.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/vinci104.pcap`
- `data/emreekin-ics-pcaps/LocalPCAP/similator.pcap`
- `data/cip-enip-engage-svg/Malware/industroyer2-full.pcapng`
- `data/inl-malcolm-ot-artifacts/Malcolm-Test-Artifacts-main/pcap/protocols/IEC104.pcap`

</details>
