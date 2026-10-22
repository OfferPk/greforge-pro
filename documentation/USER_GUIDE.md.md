# GREForge Pro v1.0.0 — User & Operations Manual

## 1\. Quick Start Guide

### 1.1 Web Studio Usage

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **Cisco Enterprise DMVPN Phase 3 (mGRE \+ IPsec)**: Models mGRE tunnel with 32-bit Key, IPsec ESP protection, sub-second BFD monitoring, 9100B underlay, Grade A+ (100%).  
   - **Cloudflare Magic Transit Anycast DDoS Shield**: Models RFC 8086 GRE-in-UDP, Anycast BGP routing, MSS clamping, Grade A+ (100%).  
   - **Vulnerable Cleartext Insecure GRE**: Models public Internet GRE without IPsec, 1500B underlay without MSS clamping, missing BFD, Grade F (0%).  
3. Inspect and edit the **RFC 2784 / RFC 2890 GRE Dissector**:  
   - Set 32-bit Tunnel Key (RFC 2890\) and Sequence Number.  
   - Select inner protocol (IPv4, IPv6, Ethernet/NVGRE, MPLS).  
   - Toggle Checksum (C), Key (K), Sequence (S), and RFC 8086 GRE-in-UDP modes.  
   - Observe live hex wireframe output and packet size calculation.  
4. Review the **Encapsulation Overhead Waterfall & MTU Sizer**:  
   - Select outer IP version (IPv4 / IPv6).  
   - Toggle IPsec ESP encryption and BFD health monitoring.  
   - Observe total overhead (28B–80B), required underlay MTU, and safe clamped TCP MSS.  
5. Click **Run Zero-Trust Audit** to evaluate configurations across the 10-point Zero-Trust rubric (Grades A+ to F).  
6. Switch tabs in the **Multi-Platform Synthesizer** to export production scripts:  
   - **Cisco IOS-XE (DMVPN Phase 3 mGRE \+ IPsec \+ BFD)**  
   - **Linux Kernel `ip link` & `iptables` (Native GRE / GRE-in-UDP)**  
   - **Juniper Junos (`gr-` interface)**  
   - **Cloudflare Magic Transit (Terraform HCL)**  
   - **Prometheus Alerting Rules**  
7. Use **Export Profile JSON** and **Import Profile** to archive and reload configurations.

---

## 2\. Command Line Interface (`greforge-cli.py`)

The standalone Python CLI tool requires zero external dependencies and runs natively on Python 3.8+.

### 2.1 Encode an RFC 2784 / RFC 2890 GRE Datagram

python3 build/greforge-cli.py encode \--key 10001 \--protocol-type 0x0800

### 2.2 Encode an RFC 8086 GRE-in-UDP Datagram

python3 build/greforge-cli.py encode \--key 20005 \--gre-in-udp \--src-port 52145

### 2.3 Decode and Dissect Raw Hex Bytes

python3 build/greforge-cli.py decode \--hex "20 00 08 00 00 00 27 11 43 55 53 54 4F 4D 45 52"

### 2.4 Calculate Encapsulation Overhead Waterfall & MTU

\# Encrypted DMVPN (GRE \+ IPsec)

python3 build/greforge-cli.py calculate \--outer-ip IPv4 \--payload-mtu 1500 \--underlay-mtu 9100 \--ipsec

\# GRE-in-UDP

python3 build/greforge-cli.py calculate \--outer-ip IPv4 \--payload-mtu 1500 \--underlay-mtu 9100 \--gre-in-udp

### 2.5 Run 10-Point Zero-Trust GRE Audit with CI/CD Gating

\# Passing compliance gate

python3 build/greforge-cli.py audit \--preset cisco-dmvpn-ipsec \--check-grade A

\# Failing compliance gate (exits with code 1\)

python3 build/greforge-cli.py audit \--preset vulnerable-gre \--check-grade A

### 2.6 Synthesize Multi-Platform Configurations

python3 build/greforge-cli.py synthesize \--framework cisco \--key 10001

python3 build/greforge-cli.py synthesize \--framework linux \--key 10001

python3 build/greforge-cli.py synthesize \--framework junos \--key 10001

python3 build/greforge-cli.py synthesize \--framework cloudflare \--key 10001

python3 build/greforge-cli.py synthesize \--framework prometheus