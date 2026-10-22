# GREForge Pro v1.0.0 — Architecture & RFC 2784 / RFC 2890 / RFC 8086 Engineering Manual

## 1\. Executive Summary: Generic Routing Encapsulation (GRE) in Enterprise Overlays

Generic Routing Encapsulation (GRE, standardized by IETF RFC 2784 and extended by RFC 2890 and RFC 8086\) is the foundational tunneling mechanism for enterprise WANs, Cisco Dynamic Multipoint VPNs (DMVPN), SD-WAN overlays, Cloudflare Magic Transit, AWS Direct Connect, and DDoS scrubbing networks.

GRE allows any arbitrary Layer-3 or Layer-2 protocol (IPv4, IPv6, MPLS, Ethernet) to be encapsulated within a routable underlay IP datagram. Because standard IP routing cannot route non-routable private subnets or carry broadcast/multicast routing updates (e.g. OSPF, EIGRP) over public Internet backbones, GRE provides an indispensable virtual point-to-point or multipoint link.

However, real-world enterprise GRE deployments suffer from persistent architectural failure modes:

1. **Cleartext Transmission**: GRE provides zero native cryptographic security. Data is sent as raw IP protocol 47\. Without IPsec ESP encapsulation or MACsec, overlay routing sessions and internal subscriber data are vulnerable to on-path interception, packet modification, and injection.  
2. **Path MTU (PMTU) Blackholing**: Adding GRE (4–12B), outer IP (20–40B), and IPsec (36–52B) increases packet size. Without 9100B Jumbo frames or TCP MSS clamping (\$\\text{MSS} \\le 1360\\text{B}\$), 1500-byte client packets with the Don't Fragment (DF=1) bit set are silently dropped on transit underlays.  
3. **Recursive Routing Loops (`%TUNRECURSEREG`)**: If a router advertises its physical underlay tunnel endpoint IP via the overlay IGP/BGP running inside the tunnel, the router attempts to reach the tunnel destination *through the tunnel itself*. This triggers infinite interface flapping, high CPU spikes, and network blackouts.  
4. **Slow Keepalive Failover**: Traditional GRE keepalives (`keepalive 10 3`) take up to 30 seconds to detect a severed physical link, blackholing traffic. Bidirectional Forwarding Detection (BFD, RFC 5880\) must be deployed for sub-second failover.  
5. **Lack of ECMP Load Balancing on Underlays**: Standard GRE uses raw IP Protocol 47 without L4 port numbers, preventing underlay spine-leaf switches from balancing traffic across ECMP links. **RFC 8086 (GRE-in-UDP)** encapsulates GRE inside UDP port **4754** with entropy-hashed source ports to resolve this bottleneck.

---

## 2\. Protocol Anatomy: RFC 2784 & RFC 2890 Wireframe Header

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|C| |K|S| Reserved0       | Ver |         Protocol Type         |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|      Checksum (optional)      |       Reserved1 (Optional)    |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                         Key (optional)                        |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    Sequence Number (Optional)                 |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                                                               |

|                  Inner Encapsulated Payload                   |

|                                                               |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

### 2.1 4-Byte Base GRE Header (RFC 2784\)

- **`C` Bit (Checksum Present, Bit 0\)**: When set, a 16-bit ones-complement Checksum field followed by a 16-bit Reserved1 field follows the base header (4 bytes total).  
- **`K` Bit (Key Present, Bit 2, RFC 2890\)**: When set, a 32-bit Key field follows the Checksum field.  
- **`S` Bit (Sequence Number Present, Bit 3, RFC 2890\)**: When set, a 32-bit Sequence Number field follows the Key field.  
- **`Reserved0` (Bits 4–12)**: Must be zero.  
- **`Ver` (Bits 13–15)**: Version 0x0 for standard GRE.  
- **`Protocol Type` (Bytes 2–3)**: 16-bit EtherType identifying inner payload (`0x0800` IPv4, `0x86DD` IPv6, `0x6558` Ethernet / NVGRE, `0x8847` MPLS).

---

## 3\. RFC 8086: GRE-in-UDP Encapsulation (UDP Port 4754\)

Standard GRE uses IP Protocol 47\. Many stateful firewalls and carrier CGNAT middleboxes drop non-TCP/non-UDP IP protocols. Furthermore, multi-path underlays cannot hash on L4 ports.

RFC 8086 defines encapsulation of GRE inside UDP:

- Outer UDP Destination Port: **4754** (`gre-in-udp`).  
- Outer UDP Source Port: Hashed from the inner packet 5-tuple into the ephemeral port range (\$49152 \\le \\text{SrcPort} \\le 65535\$).  
- Benefits:  
  1. Full ECMP hashing across spine-leaf and transit optical backbones.  
  2. Seamless traversal of NAT routers without requiring complex ALGs.

---

## 4\. Encapsulation Overhead Waterfall & MTU Sizing

| Encapsulation Mode | Outer IP | Outer UDP | GRE Header | IPsec ESP | Total Overhead | Req Underlay (1500B Payload) | Safe Clamped MSS |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **Native GRE (IPv4)** | 20 B | 0 B | 8 B (Base+Key) | 0 B | **28 Bytes** | 1528 Bytes | 1432 Bytes |
| **Native GRE (IPv6)** | 40 B | 0 B | 8 B (Base+Key) | 0 B | **48 Bytes** | 1548 Bytes | 1412 Bytes |
| **RFC 8086 GRE-in-UDP** | 20 B | 8 B | 8 B (Base+Key) | 0 B | **36 Bytes** | 1536 Bytes | 1424 Bytes |
| **GRE over IPsec (Transport)** | 20 B | 0 B | 8 B (Base+Key) | 36 B | **64 Bytes** | 1564 Bytes | 1396 Bytes |
| **DMVPN (mGRE \+ IPsec Tunnel)** | 20 B | 0 B | 8 B (Base+Key) | 52 B | **80 Bytes** | 1580 Bytes | 1360 Bytes |

If physical links use standard 1500-byte MTU, edge routers must apply TCP MSS clamping: \$\$\\text{MSS}\_{\\text{safe}} \= 1500 \- 80 \- 40 \= \\mathbf{1360\\text{ Bytes}}\$\$ Using `ip tcp adjust-mss 1360` completely eliminates Path MTU drops on encrypted DMVPN overlays.