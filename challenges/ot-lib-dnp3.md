# Protocol deep-dive — DNP3 (221 unique captures)

**Protocol library** · **Medium** · 0.3 MB · 80 capture file(s)

> A deduplicated library of 221 DNP3 captures from 6 public collections. Learn the protocol's grammar, then hunt its dangerous operations.

> ⚠️ **Safety:** OT capture analysis is passive and safe. Never replay this traffic onto a real industrial network or send these commands to a real controller.

## Scenario

Every public DNP3 sample in this range, deduplicated by SHA-256 across automayt-ics-pcap, cisa-icsnpp-test-traces, emreekin-ics-pcaps, inl-malcolm-ot-artifacts, iti-ics-security-tools-pcaps, suricata-verify-ics-tests. Use it to learn what the protocol looks like on the wire — roles, operations, normal cadence — and to practice spotting the operations attackers abuse: WRITE (2), SELECT/OPERATE (3/4), DIRECT_OPERATE (5/6), COLD/WARM_RESTART (13/14), INITIALIZE_DATA/APPL (15/16), START/STOP_APPL (17/18), DISABLE_UNSOLICITED (21), OPEN/DELETE_FILE (25/27), ACTIVATE_CONFIG (31).

## Objectives

- Identify clients/masters and servers/outstations across the samples.
- Enumerate the DNP3 operations present.
- Flag every dangerous operation and its source.
- Map findings to ATT&CK for ICS (T0855 Unauthorized Command Message · T0816 Device Restart/Shutdown · T0814 Denial of Service · T0856 Spoof Reporting Message).

## Work it step by step

Two complete walkthroughs — pick your tool. Run every command from the repo root.

### With Pcapper

[Pcapper](https://github.com/SackOfHacks/pcapper) runs the OT protocol analyzers for you.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in. Pcapper's overview auto-detects the OT protocols and runs the matching analyzers.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' --overview
```

**2. Deep-dive with Pcapper (--dnp3)**

Pcapper's protocol analyzer decodes the operations, flags anomalies, and --ot-commands normalizes every control/write across protocols.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' --dnp3 --ot-commands
```

**3. Sweep the whole library**

```bash
pcapper data/automayt-ics-pcap/ --dnp3 --ot-commands
```

**4. Map it to ATT&CK for ICS**

Pcapper maps its detections to MITRE ATT&CK (Enterprise + ICS) and draws the attack path.

```bash
pcapper 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' --mitre
```

### With tshark / Wireshark

The by-hand route: display filters, field extraction and statistics.

**1. Triage the capture**

Duration, endpoints and protocol mix before you dive in.

```bash
capinfos 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap'
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' -q -z io,phs | head -40
```

**2. Map the DNP3 conversation**

Who polls whom? Masters/clients vs. outstations/servers, and the operation mix per pair.

```bash
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' -Y dnp3 -T fields -e ip.src -e ip.dst -e dnp3.src -e dnp3.dst -e dnp3.al.func | sort | uniq -c | sort -rn | head -25
```

**3. Hunt the dangerous operations**

Flag WRITE (2), SELECT/OPERATE (3/4), DIRECT_OPERATE (5/6), COLD/WARM_RESTART (13/14), INITIALIZE_DATA/APPL (15/16), START/STOP_APPL (17/18), DISABLE_UNSOLICITED (21), OPEN/DELETE_FILE (25/27), ACTIVATE_CONFIG (31).

```bash
tshark -r 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' -Y 'dnp3.al.func in {2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 21, 25, 27, 31}' -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info | head -40
```

**4. Sweep the whole library**

```bash
for f in 'data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_rec_time.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_file_write.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_read.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_file_read.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_link_only.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_del_measure.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_write.pcap' 'data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_en_spon.pcap'; do echo "== $f"; tshark -r "$f" -Y 'dnp3.al.func in {2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 21, 25, 27, 31}' 2>/dev/null | head -3; done
```

## Hints

<details><summary>Hint 1</summary>

Wireshark display filter for the protocol: dnp3

</details>

<details><summary>Hint 2</summary>

Dangerous-operation filter: dnp3.al.func in {2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 21, 25, 27, 31}

</details>

<details><summary>Hint 3</summary>

Many library files are tiny protocol samples — read them packet by packet in Wireshark.

</details>

## Solution

<details><summary>Reveal walkthrough / answer</summary>

A library, not a single puzzle: the deliverable is a per-capture table of roles and operations, with the dangerous ones flagged (WRITE (2), SELECT/OPERATE (3/4), DIRECT_OPERATE (5/6), COLD/WARM_RESTART (13/14), INITIALIZE_DATA/APPL (15/16), START/STOP_APPL (17/18), DISABLE_UNSOLICITED (21), OPEN/DELETE_FILE (25/27), ACTIVATE_CONFIG (31)). ATT&CK for ICS: T0855 Unauthorized Command Message · T0816 Device Restart/Shutdown · T0814 Denial of Service · T0856 Spoof Reporting Message. Sources are credited per collection in each folder's PROVENANCE.md.

**Computed evidence (auto-extracted with tshark — verify it yourself):** DNP3 operations — DIRECT_OPERATE ×2, WRITE ×1; dangerous-operation matches: 3 (top sources: 192.168.10.3 ×2, 192.168.247.131 ×1) (basis: 3 of 80 capture file(s), first 300,000 packets each, smallest files carrying DNP3 chosen)

_Captures credited to: ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CISA ICSNPP — Zeek ICS parser test traces — CISA and Idaho National Laboratory (ICSNPP project) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign · Suricata-verify — ICS protocol test captures — OISF (Open Information Security Foundation)._

</details>

## Dataset & credit

**ICS-pcap collection (automayt / Jason Smith) — Jason Smith (automayt) · CISA ICSNPP — Zeek ICS parser test traces — CISA and Idaho National Laboratory (ICSNPP project) · ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset — Emre Ekin (ICS Defense, icsdefense.net) · INL Malcolm test artifacts — OT protocol samples — Idaho National Laboratory (Malcolm) · ITI ICS-Security-Tools — sample ICS protocol captures — Information Trust Institute (ITI), University of Illinois Urbana-Champaign · Suricata-verify — ICS protocol test captures — OISF (Open Information Security Foundation)** — license: varies by collection — see each folder's PROVENANCE.md

- [Dataset source — ICS-pcap collection (automayt / Jason Smith)](https://github.com/automayt/ICS-pcap)
- [Dataset source — CISA ICSNPP — Zeek ICS parser test traces](https://github.com/cisagov/ICSNPP)
- [Dataset source — ICS-Pcaps (Emre Ekin / ICS Defense) — OT protocol subset](https://github.com/EmreEkin/ICS-Pcaps)
- [Dataset source — INL Malcolm test artifacts — OT protocol samples](https://github.com/idaholab/Malcolm-Test-Artifacts)
- [Dataset source — ITI ICS-Security-Tools — sample ICS protocol captures](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps)
- [Dataset source — Suricata-verify — ICS protocol test captures](https://github.com/OISF/suricata-verify)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

<details><summary>Capture files</summary>

- `data/cisa-icsnpp-test-traces/icsnpp-dnp3/dnp3_example.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_rec_time.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_file_write.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_read.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_file_read.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_link_only.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_del_measure.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_write.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_en_spon.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_select_operate.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/bro/dnp3/dnp3_file_del.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/assign_class.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/immediate_freeze.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/select_operate_and_responses.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/dataset_exchange.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/serial_time_sync.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/enable_unsolicited_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/dnp3_test_data_part1.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/auth_control_challenge_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/file_list_directory.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/direct_operate_analog_output.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/operate_aggressive_mode.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/unsolcited_response_and_confirm.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/file_write.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/write_vto_empty_string.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/write_binary_output.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/warm_restart_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/file_delete.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/disable_unsolcited_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/write_iin_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/dnp3_test_data_part2.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/auth_change_session_keys.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/directoperate_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/full_exchange.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/cold_restart_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/direct_operate_crob_malform_but_good_crc.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/read_and_response.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/file_read.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/lan_time_sync.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/direct_operate_no_ack_crob.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/6.6.2.5/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.14.2.5/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.19.2.1/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/6.6.2.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.9.2.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.11.2.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.6.5.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.2.1.2.10/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.4.1.2.6/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.7.1.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.4.1.2.8/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.22.2.4/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.19.2.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.22.2.5/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.13.2.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.6.5.3/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.2.2.2.3/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/7.2/dump.pcap`
- `data/iti-ics-security-tools-pcaps/pcaps/dnp3/opendnp3-3/conformance/8.22.2.8/dump.pcap`

</details>
