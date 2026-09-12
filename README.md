<div align="center">

# SBT-DF203 · Lab 3 — SYN Flood Attack Investigation Using TShark

**Network Forensics · TCP Analysis · Incident Investigation**

</div>

---

## Author

| Field | Detail |
| :--- | :--- |
| **Author** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Instructor** | Aminu Idris, AMCPN |
| **Submission Date** | 12 September 2026 |
| **Case ID** | `SBT-DF203-Lab3-2025-FWSD-11521` |

<div align="center">

[![Course](https://img.shields.io/badge/course-SBT--DF203-blue)](https://icdfa.edu.ng)
[![Institution](https://img.shields.io/badge/institution-ICDFA-darkred)](https://icdfa.edu.ng)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kali-linux&logoColor=white)](https://kali.org)
[![Tool](https://img.shields.io/badge/tool-TShark%204.6.6-blue?logo=wireshark&logoColor=white)](https://wireshark.org)
[![Tool](https://img.shields.io/badge/tool-Scapy%202.7.0-ffcc00)](https://scapy.net)
[![License](https://img.shields.io/badge/license-Academic-lightgrey)](#license)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Methodology](#methodology)
- [Key Findings](#key-findings)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Analysis Commands](#analysis-commands)
- [Evidence and Chain of Custody](#evidence-and-chain-of-custody)
- [Detection and Mitigation](#detection-and-mitigation)
- [Safety and Ethics](#safety-and-ethics)
- [References](#references)
- [License](#license)

---

## Overview

This repository contains the complete evidence package, analysis outputs, simulation scripts, and forensic report for **Lab 3 of SBT-DF203 — Basic Networking Skills for Digital Forensics**.

The investigation establishes a **normal HTTP handshake baseline** against a local Apache service on the loopback interface, then performs a **strictly bounded four-packet SYN simulation** using Scapy. TShark display filters are applied to isolate SYN, SYN-ACK, ACK, and RST behaviour, quantify counts and unique source ports, and produce a defensible forensic timeline.

The analysis distinguishes the *packet pattern* of a SYN flood from proof of an actual denial-of-service event — a key forensic distinction examined in detail in the report.

---

## Objectives

1. Differentiate a complete TCP three-way handshake from an incomplete (half-open) connection attempt.
2. Apply TShark display filters to isolate SYN, SYN-ACK, ACK, and RST packets.
3. Quantify SYN counts, unique source ports, response behaviour, and incomplete-handshake indicators.
4. Execute a strictly bounded four-packet loopback SYN simulation with Scapy.
5. Develop a defensible forensic timeline and incident finding from PCAP evidence.
6. Recommend detection and mitigation controls for SYN flood activity.

---

## Methodology

The lab was conducted in three sequential phases, all executed against `127.0.0.1:80` on the loopback interface.

| Phase | Description | Output |
| :---: | :--- | :--- |
| **1** | Normal HTTP handshake baseline captured while `curl` requests the Apache default page | `evidence/normal_http.pcapng` |
| **2** | Bounded four-packet SYN simulation crafted with Scapy and captured simultaneously | `evidence/bounded_syn_activity.pcapng` |
| **3** | TShark display filters extract SYN / SYN-ACK / ACK / RST indicators, counts, ports, and expert info | `reports/*.tsv`, `reports/*.txt` |

### Environment

| Component | Version |
| :--- | :--- |
| OS | Kali Linux (ICDFA lab VM) |
| Apache2 | `2.4.68-1` — listening on TCP/80 |
| TShark | `4.6.6-1` |
| Wireshark | `4.6.6-1` |
| Python3-Scapy | `2.7.0+dfsg1-1` |
| Interface | `lo` (loopback only) |

---

## Key Findings

| Indicator | Normal HTTP | Bounded SYN | Forensic Meaning |
| :--- | :---: | :---: | :--- |
| Initial SYN count | 1 | 4 | Multiple SYNs from the same source |
| SYN-ACK count | 1 | 4 | Server responded to each SYN |
| Completed handshakes | 1 | 0 | No final ACK sent |
| Unique source ports | 1 (`40464`) | 4 (`2359`, `49115`, `29548`, `55744`) | Random ephemeral ports |
| HTTP request present | Yes | No | No application data |
| RST packets | 0 | 4 | Connections rejected by client OS |
| Observed duration | ~8.6 ms | ~3.0 ms | Brief burst of half-open attempts |
| TCP analysis events | 0 | 0 | No retransmissions or lost segments |

### Verdict

The capture demonstrates the **packet pattern** of a SYN flood — incomplete handshakes with no final ACK — but does **not** establish a denial-of-service event. A genuine SYN flood requires **scale, rate, persistence, and measurable service impact**, none of which are present in a four-packet bounded simulation.

The absence of `tcp.analysis.*` events (retransmissions, lost segments, duplicate ACKs) further confirms that the simulation was **clean at the transport-analysis level**: the only indicators present are the application-layer incomplete handshakes.

---

## Repository Structure

### Top-level layout

```
SBT-DF203-Lab3-SYN-Flood-Pattern-Investigation/
├── README.md
├── SBT-DF203-Lab3_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf
├── evidence/
├── working/
├── exported/
├── reports/
├── screenshots/
└── scripts/
```

### Directory contents

| Directory | Contents | Purpose |
| :--- | :--- | :--- |
| `evidence/` | `normal_http.pcapng` (13 KB)<br>`bounded_syn_activity.pcapng` (1.3 KB) | Original captures — preserved unmodified |
| `working/` | `bounded_syn_activity_working.pcapng` | Timestamp-preserved analysis copy |
| `exported/` | *(reserved)* | Exported objects from captures |
| `reports/` | 10 × `.tsv` / `.txt` files | TShark analysis outputs and evidence hashes |
| `screenshots/` | 16 × `.png` figures | Numbered evidence screenshots referenced in the report |
| `scripts/` | `syn_probe_lab.py` | Bounded Scapy SYN simulation |

### `reports/` — analysis output files

| File | Description |
| :--- | :--- |
| `normal_handshake_flags.tsv` | Baseline SYN / SYN-ACK / FIN flags |
| `bounded_capture_hashes.txt` | SHA-256 of original and working copy |
| `initial_syns.tsv` | Frames 1, 4, 7, 10 — SYN packets |
| `syn_ack_responses.tsv` | Frames 2, 5, 8, 11 — SYN-ACK responses |
| `ack_reset_candidates.tsv` | Alternating SYN-ACK / RST packets |
| `syn_counts_by_pair.txt` | SYN counts grouped by source / destination |
| `unique_syn_source_ports.txt` | 4 unique client ports |
| `expert_info.txt` | Wireshark expert analysis summary |
| `tcp_analysis_events.tsv` | Empty by design — no transport anomalies |
| `syn_capture_sha256.txt` | SHA-256 of the (optional) supplied training PCAP |

### `screenshots/` — numbered evidence figures

| Group | Files |
| :--- | :--- |
| **Section 3 — Environment** | `fig_3.1_folder_structure.png` · `fig_3.2_tools_installed.png` · `fig_3.3_wget_404.png` |
| **Section 4 — Baseline** | `fig_4.1_capture_running.png` · `fig_4.2_handshake_tsv.png` · `fig_4.3_wireshark_handshake.png` |
| **Section 5 — Simulation** | `fig_5.1_scapy_script.png` · `fig_5.2_simulation_run.png` · `fig_5.3_bounded_hashes.png` |
| **Section 6 — Indicators** | `fig_6.1_initial_syns.png` · `fig_6.2_syn_acks.png` · `fig_6.3_rst.png` |
| **Section 7 — Quantification** | `fig_7.1_counts.png` · `fig_7.2_unique_ports.png` · `fig_7.3_expert_info.png` · `fig_7.4_tcp_events.png` |

---

## Getting Started

### Prerequisites

- Kali Linux (or Debian-based distribution)
- `sudo` privileges
- Apache2 running locally

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Disehdon/SBT-DF203-Lab3-SYN-Flood-Pattern-Investigation.git
cd SBT-DF203-Lab3-SYN-Flood-Pattern-Investigation

# 2. Install dependencies
sudo apt update
sudo apt install -y apache2 tshark wireshark python3-scapy

# 3. Enable and start Apache
sudo systemctl enable --now apache2

# 4. Verify port 80 is listening
sudo ss -lntp | grep ':80'
```

### Running the Analysis

See [Analysis Commands](#analysis-commands) for the complete TShark command set used to regenerate the outputs in `reports/`.

---

## Analysis Commands

The following commands regenerate every artefact in the `reports/` directory.

### Initial SYN Packets

```bash
PCAP=working/bounded_syn_activity_working.pcapng

tshark -r "$PCAP" \
  -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.seq \
  | tee reports/initial_syns.tsv
```

### SYN-ACK Responses

```bash
tshark -r "$PCAP" \
  -Y 'tcp.flags.syn==1 && tcp.flags.ack==1' \
  -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.ack \
  | tee reports/syn_ack_responses.tsv
```

### ACK/RST Candidates

```bash
tshark -r "$PCAP" \
  -Y 'tcp.flags.reset==1 || (tcp.flags.ack==1 && tcp.len==0)' \
  -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.flags \
  | tee reports/ack_reset_candidates.tsv
```

### Counts by Source / Destination

```bash
tshark -r "$PCAP" \
  -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e ip.src -e ip.dst -e tcp.dstport \
  | sort | uniq -c | sort -nr \
  | tee reports/syn_counts_by_pair.txt
```

### Expert Information

```bash
tshark -r "$PCAP" -q -z expert | tee reports/expert_info.txt
```

### Integrity Verification

```bash
sha256sum evidence/normal_http.pcapng evidence/bounded_syn_activity.pcapng \
  | tee reports/bounded_capture_hashes.txt
```

---

## Evidence and Chain of Custody

Original captures were preserved unmodified. All analysis was performed on a timestamp-preserved working copy. Hashes are recorded below and stored in `reports/bounded_capture_hashes.txt`.

| File | Size | SHA-256 |
| :--- | :---: | :--- |
| `evidence/normal_http.pcapng` | 13 KB | `6123b37efcb889f9d8f749c47549a09313db372749898a025272250982c5c7d5` |
| `evidence/bounded_syn_activity.pcapng` | 1.3 KB | `ed678f8f1b2d8a232024885605ae4f11e27ee67d15f20a114aa3d6685eacc0d1` |
| `working/bounded_syn_activity_working.pcapng` | 1.3 KB | `ed678f8f1b2d8a232024885605ae4f11e27ee67d15f20a114aa3d6685eacc0d1` |

**Integrity confirmed.** The original and working copy of the bounded capture are byte-identical. The optional supplied training PCAP was unavailable — the download URL returned `HTTP 404 Not Found` at execution time.

### Case Metadata

| Field | Value |
| :--- | :--- |
| Case ID | `SBT-DF203-Lab3-2025-FWSD-11521` |
| Analyst | Ibrahim Diseh Garba |
| Registration No. | `2025/FWSD/11521` |
| Date / Time Started | 12 September 2026, 11:03 EDT |
| Analysis Workstation | Kali Linux VM (ICDFA lab) |

---

## Detection and Mitigation

### Detection Controls

| Control | Description |
| :--- | :--- |
| SYN-to-completed ratio | Alert when initial SYN count significantly exceeds completed handshakes per source |
| SYN backlog monitoring | Track `SYN-RECEIVED` queue growth and exhaustion |
| Rate-based detection | Alert on SYN rates exceeding established baselines |
| Flow telemetry | Analyse NetFlow / IPFIX records for anomalous SYN patterns |

### Mitigation Controls

| Control | Description |
| :--- | :--- |
| SYN cookies | Stateless handling of incomplete connections, preventing backlog allocation |
| Backlog tuning | Adjust TCP backlog and timeout parameters per workload profile |
| Upstream rate limiting | Rate-limit at the network edge or load balancer |
| DDoS protection | Deploy dedicated mitigation services for high-volume attacks |

### Forensic Practice

- Retain full packet capture during incident response.
- Synchronise system clocks across all endpoints for accurate timeline reconstruction.
- Correlate packet evidence with web server, firewall, and load balancer logs.
- Document chain of custody throughout evidence handling.

---

## Safety and Ethics

This lab was executed **exclusively** within the ICDFA-approved isolated Kali Linux virtual machine, in full compliance with the SBT-DF203 legal and ethical guidelines.

- Target scope: **loopback only** (`127.0.0.1:80`)
- Packet limit: **four SYN packets maximum** — strictly bounded
- **No spoofing**, no external targets, no continuous sending
- No credentials, personal data, or confidential traffic collected
- All firewall, ARP, forwarding, and network settings restored after the lab
- SHA-256 hashes recorded for chain of custody

> **Warning:** The `scripts/syn_probe_lab.py` script is intended for **authorised training only**. Do not modify the packet count, do not target external systems, and do not automate repeated execution. Unauthorised use may violate computer misuse legislation.

---

## References

1. ICDFA. (2026). *SBT-DF203 — Module 2: HTTP, tshark, SYN Flood — Course Materials*.
2. ICDFA. (2026). *SBT-DF203 Lab 3 — SYN Flood Pattern Investigation Using TShark — Official Lab Manual*.
3. RFC 793. (1981). *Transmission Control Protocol*. [IETF](https://tools.ietf.org/html/rfc793)
4. RFC 4987. (2007). *TCP SYN Flooding Attacks and Common Mitigations*. [IETF](https://tools.ietf.org/html/rfc4987)
5. Wireshark Foundation. (2026). *Wireshark User Guide*. [wireshark.org/docs](https://www.wireshark.org/docs/)
6. Scapy Project. (2026). *Scapy Documentation*. [scapy.net](https://scapy.net/)

---

## License

This repository is submitted as academic coursework for **SBT-DF203 Lab 3** at ICDFA. The contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.

---

<div align="center">
<sub>SBT-DF203 · Lab 3 · Delivery Block 1/3 · September 2026</sub>
</div>
