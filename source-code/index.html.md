  
G

# 

GREForge Pro **v1.0.0**

Zero-Trust Generic Routing Encapsulation (RFC 2784 / 2890\) & DMVPN Studio  
Export Profile JSON Import Profile Run Zero-Trust Audit  
Cisco Enterprise DMVPN Phase 3 (mGRE \+ IPsec \+ BFD \+ 9100B Jumbo Underlay) Cloudflare Magic Transit Anycast DDoS Shield (RFC 8086 GRE-in-UDP \+ Key) Vulnerable Cleartext GRE (Missing IPsec & Unclamped 1500B Underlay)

RFC 2784 / RFC 2890 GRE & RFC 8086 GRE-in-UDP Dissector  
Valid RFC 2890 GRE

RFC 2890 Tunnel Key (32-bit / Hex)  
Sequence Number (32-bit)

Inner Encapsulated Protocol IPv4 (EtherType 0x0800) IPv6 (EtherType 0x86DD) Transparent Ethernet / NVGRE (EtherType 0x6558) MPLS Unicast (EtherType 0x8847)  
Outer UDP Port (GRE-in-UDP 4754\)  
Key Present (K=1, RFC 2890\) Checksum Present (C=1, RFC 2784\)  
Sequence Number Present (S=1) RFC 8086 GRE-in-UDP Mode (UDP 4754\)

RAW GRE DATAGRAM WIREFRAME 35 Bytes  
20 00 08 00 00 00 27 11 43 55 53 54 4F 4D 45 52 ...

8 B  
GRE Header

0x00002711  
Tunnel Key

0x0800  
Protocol Type

35 B  
Total Wire Size

Encapsulation Overhead Waterfall & Path MTU Sizer  
Jumbo Frame Verified

Outer Underlay IP Version IPv4 Underlay (20B IP Header) IPv6 Underlay (40B IP Header)  
Underlay Physical MTU (Bytes)  
IPsec ESP Encryption Active (36B Overhead) Sub-Second BFD Active (300ms x 3 \= 900ms)

64 B  
Total Overhead

1564 B  
Req Underlay MTU

1360 B  
Safe Clamped MSS

0.9 s  
Failover Detection

**Underlay Capacity Adequate:** 9100B Jumbo underlay accommodates 64B GRE+IPsec overhead without fragmentation or PMTU blackholing.

10-Point Zero-Trust GRE & Tunnel Security Auditor  
Grade A+ (100%)

Multi-Platform Configuration Synthesizer  
Copy Code  
Cisco IOS-XE (DMVPN) Linux \`ip link\` Juniper Junos Cloudflare Magic Transit Prometheus Alerts  
`! Synthesizing Cisco DMVPN Configuration...`