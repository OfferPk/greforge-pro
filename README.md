# GREForge Pro (v1.0.0)

**Zero-Trust Generic Routing Encapsulation (RFC 2784 / RFC 2890), GRE-in-UDP (RFC 8086\) & DMVPN Studio**

[![License](https://img.shields.io/badge/license-Commercial-blue.svg)](http://LICENSE) [![RFC Standard](https://img.shields.io/badge/RFC-2784%20%2F%202890%20%2F%208086-cyan.svg)](https://datatracker.ietf.org/doc/html/rfc2784) [![Cisco Compatibility](https://img.shields.io/badge/Cisco-DMVPN%20Phase%203%20Catalyst%208000-indigo.svg)](https://www.cisco.com/) [![Python](https://img.shields.io/badge/python-3.8+-emerald.svg)](http://build/greforge-cli.py)

---

## 1\. Product Overview

Generic Routing Encapsulation (GRE, standardized in IETF RFC 2784 and extended by RFC 2890 and RFC 8086\) is the fundamental tunneling protocol underpinning enterprise branch connectivity, Cisco Dynamic Multipoint VPNs (DMVPN), SD-WAN overlays, Cloudflare Magic Transit, and cloud interconnects.

GRE encapsulates arbitrary Layer-3 or Layer-2 protocols (IPv4, IPv6, MPLS, Ethernet/NVGRE) inside standard IP packets, allowing enterprise overlays to transport private subnets, multicast routing updates (OSPF, EIGRP), and multi-tenant VRFs across untrusted public backbones.

However, real-world GRE and DMVPN deployments face critical operational and security hazards:

1. **Cleartext Transmission**: GRE provides zero native encryption (IP Protocol 47). Without IPsec ESP encapsulation or MACsec, overlay routing sessions and internal subscriber data are vulnerable to wiretapping, tampering, and rogue packet injection.  
2. **Path MTU (PMTU) Blackholing**: GRE adds 28–80 bytes of overhead. Unclamped 1500-byte client packets with the Don't Fragment (DF=1) bit set are silently dropped on transit underlays without 9100B Jumbo frames or TCP MSS clamping (`ip tcp adjust-mss 1360`).  
3. **Recursive Routing Loops (`%TUNRECURSEREG`)**: If a router advertises its physical tunnel endpoint IP via the overlay routing protocol running inside the tunnel, the router attempts to reach the tunnel destination through the tunnel itself, causing continuous interface flaps and CPU spikes.  
4. **Sluggish Keepalive Failover**: Traditional GRE keepalives (`keepalive 10 3`) take up to 30 seconds to detect a severed physical link, blackholing traffic. Bidirectional Forwarding Detection (BFD, RFC 5880\) must be deployed for sub-second failover.  
5. **Lack of Underlay ECMP Load Balancing**: Standard GRE lacks Layer-4 port numbers, preventing underlay spine-leaf switches from balancing traffic across ECMP links. **RFC 8086 (GRE-in-UDP)** encapsulates GRE inside UDP port **4754** with entropy-hashed source ports to resolve this bottleneck.

**GREForge Pro** is an all-in-one client-side visual engineering studio and standalone DevSecOps CLI tool that models RFC 2784 / 2890 / 8086 binary datagrams, calculates exact encapsulation overheads and safe TCP MSS clamping values, audits configurations against a 10-point Zero-Trust rubric, and synthesizes production configurations for Cisco IOS-XE, Linux `ip link`, Juniper Junos, Cloudflare Magic Transit, and Prometheus.

---

## 2\. Key Capabilities & Architectural Highlights

### 2.1 RFC 2784 / 2890 GRE & RFC 8086 GRE-in-UDP Dissector (UDP Port 4754\)

- **Base Header Inspection**: Models Checksum Present (`C`), Key Present (`K`), Sequence Present (`S`), and EtherType protocol fields (IPv4, IPv6, Ethernet/NVGRE, MPLS).  
- **RFC 2890 Key Demultiplexing**: Models 32-bit Key tags (\$0 \\le \\text{Key} \\le 4,294,967,295\$) for multi-tenant VRF isolation.  
- **RFC 8086 GRE-in-UDP Framing**: Enforces UDP destination port 4754 and dynamic inner 5-tuple entropy hashing into the ephemeral source port range (\$49152 \\le \\text{SrcPort} \\le 65535\$).

### 2.2 Encapsulation Overhead Waterfall & MTU Sizer

- **Multi-Mode Overhead Derivation**: Calculates exact overhead across Native GRE (28B), GRE-in-UDP (36B), GRE over IPsec Transport (64B), and DMVPN Tunnel Mode (80B).  
- **Safe TCP MSS Clamping**: Derives safe clamped MSS values (\$1360\\text{B} / 1400\\text{B}\$) for standard 1500B underlays to eliminate PMTU drops.  
- **Failover Latency Comparison**: Compares 30-second legacy keepalives against 900ms hardware BFD tracking.

### 2.3 10-Point Zero-Trust GRE Security Auditor

- Audits tunnel deployments across 10 critical criteria (0–100%, Grades A+ to F):  
  1. Cryptographic Protection over Public Underlays (IPsec / MACsec) (10 pts)  
  2. Underlay MTU Headroom (9100B) & Safe TCP MSS Clamping (12 pts)  
  3. Recursive Routing Loop Prevention (`TUNRECURSEREG` Filter) (10 pts)  
  4. Sub-Second Hardware BFD Tunnel Health Monitoring (10 pts)  
  5. RFC 2890 Key Field Tenant Isolation (10 pts)  
  6. Sequence Number (S-Bit) Out-of-Order Policy (10 pts)  
  7. RFC 8086 GRE-in-UDP Source Port Entropy & NAT Traversal (10 pts)  
  8. Ingress Tunnel uRPF & Source Anti-Spoofing (10 pts)  
  9. RFC 2784 GRE Checksum Verification & Drop (10 pts)  
  10. Control-Plane Policing (CoPP) on IP Protocol 47 (8 pts)

### 2.4 Multi-Platform Configuration Synthesizer

- **Cisco IOS-XE**: Generates DMVPN Phase 3 mGRE scripts with IPsec profile, BFD, and recursion route-maps.  
- **Linux Kernel `ip link`**: Produces native GRE and Foo-over-UDP (FOU) scripts with `iptables` TCP MSS clamping.  
- **Juniper Junos**: Generates `gr-` tunnel interface configuration with BFD and family inet MTU.  
- **Cloudflare Magic Transit**: Exports Terraform HCL resources for Anycast GRE endpoints and health checks.  
- **Prometheus Alerts**: Ready-to-deploy alerting rules for tunnel down, recursive routing loops, and PMTU drops.

---

## 3\. Directory Layout

2026-10-03 — GREForge Pro/

├── README.md

├── source-code/

│   ├── index.html                  \# Interactive Single-Page Web Studio

│   ├── gre-forge.css               \# Cyber Defense & Enterprise WAN Dark UI

│   ├── gre-protocol-engine.js      \# RFC 2784/2890/8086 Protocol Engine

│   ├── gre-security-auditor.js     \# 10-Point Zero-Trust GRE Auditor

│   ├── gre-config-synthesizer.js   \# Multi-Platform Configuration Synthesizer

│   └── app.js                      \# Application Controller & Presets

├── build/

│   ├── greforge-cli.py             \# Standalone Python 3 DevSecOps CLI Tool

│   └── greforge-pro-v1.0.0.zip     \# Distributable Bundle (Self-Contained)

├── documentation/

│   ├── ARCHITECTURE.md             \# Deep RFC 2784 / DMVPN Technical Manual

│   ├── USER\_GUIDE.md               \# User & CLI Operations Manual

│   └── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md \# Commercialization & Go-To-Market

└── screenshots/

    ├── gre-studio-preview.svg      \# Visual Web Studio Interface Mockup

    └── gre-architecture.svg        \# Zero-Trust GRE / DMVPN Flow Diagram

---

## 4\. Quick Start Guide

### Running the Web Studio

Open `source-code/index.html` in any modern web browser. Zero server dependencies or external build chains required.

### Using the Python CLI

\# 1\. Encode an RFC 2784 / RFC 2890 GRE Datagram

python3 build/greforge-cli.py encode \--key 10001 \--protocol-type 0x0800

\# 2\. Encode an RFC 8086 GRE-in-UDP Datagram

python3 build/greforge-cli.py encode \--key 20005 \--gre-in-udp \--src-port 52145

\# 3\. Decode Raw Hex Wireframe

python3 build/greforge-cli.py decode \--hex "20 00 08 00 00 00 27 11 43 55 53 54 4F 4D 45 52"

\# 4\. Calculate Encapsulation Overhead Waterfall & MTU Sizing

python3 build/greforge-cli.py calculate \--outer-ip IPv4 \--payload-mtu 1500 \--underlay-mtu 9100 \--ipsec

\# 5\. Run 10-Point Zero-Trust Audit with CI/CD Gating

python3 build/greforge-cli.py audit \--preset cisco-dmvpn-ipsec \--check-grade A

\# 6\. Synthesize Multi-Platform Configurations

python3 build/greforge-cli.py synthesize \--framework cisco \--key 10001

python3 build/greforge-cli.py synthesize \--framework linux \--key 10001

---

## 5\. Commercial Licensing & Pricing

- **Enterprise Network Engineer Solo**: \$49.00 (One-time, lifetime personal use)  
- **Enterprise WAN & Cloud Edge Team License**: \$99.00 (One-time, unlimited commercial use \+ CI/CD templates)  
- **Hosted Tunnel Sentinel & BFD Telemetry Micro-SaaS**: \$29.00/month (Continuous Prometheus monitoring & alerts)