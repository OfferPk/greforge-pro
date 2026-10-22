/**
 * GREForge Pro - 10-Point Zero-Trust GRE & Tunnel Security Auditor
 * Standards: RFC 2784, RFC 2890, RFC 8086, RFC 7637, NIST SP 800-77
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GreSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_RULES = [
    {
      id: 'gre_crypto_protection',
      weight: 10,
      title: 'Cryptographic Protection over Public Underlays (IPsec / MACsec)',
      standard: 'NIST SP 800-77 / RFC 2784 Security',
      description: 'GRE provides zero native encryption. Tunnels traversing public Internet or shared carrier links must enforce IPsec (ESP) or MACsec.',
      evaluate: (config) => {
        if (!config.ipsecProtected && config.isPublicUnderlay) {
          return {
            passed: false,
            score: 0,
            feedback: 'Critical Vulnerability: Cleartext GRE on public Internet. Overlay routing protocols (BGP/OSPF) and subscriber data are exposed to wiretapping.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Tunnel traffic is protected by IPsec ESP / MACsec wire-speed encryption.'
        };
      }
    },
    {
      id: 'gre_mtu_mss_clamping',
      weight: 12,
      title: 'Underlay MTU Headroom & TCP MSS Clamping',
      standard: 'RFC 2784 / RFC 8086 Path MTU',
      description: 'Underlay MTU must accommodate 28B–76B encapsulation overhead, or TCP MSS must be clamped to <= 1360B.',
      evaluate: (config) => {
        const overhead = (config.isGreInUdp ? 36 : 28) + (config.ipsecProtected ? 36 : 0);
        const requiredMtu = 1500 + overhead;
        const underlayMtu = Number(config.underlayMtu) || 1500;
        const mssClamped = !!config.tcpMssClamping;

        if (underlayMtu < requiredMtu && !mssClamped) {
          return {
            passed: false,
            score: 0,
            feedback: `Path MTU Blackhole Risk: Underlay MTU (${underlayMtu}B) cannot carry 1500B payload + ${overhead}B GRE overhead without fragmentation or MSS clamping.`
          };
        }
        if (underlayMtu >= requiredMtu) {
          return {
            passed: true,
            score: 12,
            feedback: `Compliant: Underlay MTU (${underlayMtu}B) exceeds required headroom (${requiredMtu}B). Jumbo frames active.`
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Mitigated: Underlay MTU is standard 1500B, but TCP MSS clamping (MSS <= 1360B) prevents PMTU blackholes.'
        };
      }
    },
    {
      id: 'gre_recursive_routing_protection',
      weight: 10,
      title: 'Recursive Routing Loop Prevention (TUNRECURSEREG)',
      standard: 'RFC 2784 Section 2.1',
      description: 'Routing filters must strictly prevent the physical tunnel destination IP from being advertised into or learned via the overlay.',
      evaluate: (config) => {
        if (!config.recursiveRoutingFilter) {
          return {
            passed: false,
            score: 0,
            feedback: 'Catastrophic Risk: Omission of recursive routing filter allows tunnel destination to route via tunnel itself, causing flap storms.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Explicit route-map filter prevents physical tunnel endpoint from recursive overlay resolution.'
        };
      }
    },
    {
      id: 'gre_subsecond_bfd_monitoring',
      weight: 10,
      title: 'Sub-Second Hardware BFD Tunnel Health Monitoring',
      standard: 'RFC 5880 / RFC 5881 BFD',
      description: 'Replace sluggish 10s/3s keepalives with sub-second BFD (e.g. 300ms x 3 = 900ms) to eliminate 30-second traffic blackholes.',
      evaluate: (config) => {
        if (!config.bfdEnabled) {
          return {
            passed: false,
            score: 0,
            feedback: 'Sluggish Failover: Traditional keepalives take up to 30 seconds to detect fiber cuts. Hardware BFD required for sub-second failover.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Sub-second BFD hardware session tracking active on GRE tunnel interface.'
        };
      }
    },
    {
      id: 'gre_key_validation',
      weight: 10,
      title: 'RFC 2890 Key Field Tenant Isolation',
      standard: 'RFC 2890 Section 2',
      description: 'Enforce strict 32-bit Key validation on ingress to segregate multi-tenant VRFs and prevent cross-tunnel injection.',
      evaluate: (config) => {
        if (!config.validateKeyField) {
          return {
            passed: false,
            score: 0,
            feedback: 'Isolation Failure: Missing Key validation allows cross-tenant packet injection or accidental misdelivery between VRFs.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: RFC 2890 32-bit Key tag verified and mapped to isolated VRF namespace.'
        };
      }
    },
    {
      id: 'gre_sequence_policy',
      weight: 10,
      title: 'Sequence Number (S-Bit) Out-of-Order Policy',
      standard: 'RFC 2890 Section 3',
      description: 'If S=1 is enabled, sliding-window reordering must be configured, or S-bit disabled over ECMP multipath underlays.',
      evaluate: (config) => {
        if (config.hasSeq && config.underlayIsMultipath && !config.slidingWindowReordering) {
          return {
            passed: false,
            score: 0,
            feedback: 'Packet Drop Risk: Strict sequence checking over multipath underlay drops valid out-of-order packets. Configure sliding window or disable S-bit.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Sequence number policy aligned with underlay multipath characteristics.'
        };
      }
    },
    {
      id: 'gre_udp_ecmp_entropy',
      weight: 10,
      title: 'RFC 8086 GRE-in-UDP Source Port Entropy & NAT Traversal',
      standard: 'RFC 8086 Section 3',
      description: 'Outer UDP source port must be hashed from inner 5-tuple into ephemeral range (49152–65535) for spine-leaf ECMP balance.',
      evaluate: (config) => {
        if (config.isGreInUdp && !config.ecmpEntropyEnabled) {
          return {
            passed: false,
            score: 0,
            feedback: 'Link Polarization Hazard: Static outer UDP source port causes all GRE-in-UDP traffic to bottleneck on a single spine uplink.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Inner 5-tuple entropy hashing active on outer UDP port (range 49152–65535).'
        };
      }
    },
    {
      id: 'gre_ingress_urpf',
      weight: 10,
      title: 'Ingress Tunnel uRPF & Source Anti-Spoofing',
      standard: 'BCP 38 / RFC 2827 Ingress Filtering',
      description: 'Enforce strict Unicast Reverse Path Forwarding (uRPF) on tunnel interface to reject spoofed internal IPs.',
      evaluate: (config) => {
        if (!config.urpfEnabled) {
          return {
            passed: false,
            score: 0,
            feedback: 'Spoofing Vulnerability: Ingress packets with arbitrary source IPs accepted into overlay network without uRPF verification.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: Strict uRPF active on tunnel interface, rejecting spoofed packets.'
        };
      }
    },
    {
      id: 'gre_checksum_verification',
      weight: 10,
      title: 'RFC 2784 GRE Checksum Verification & Drop',
      standard: 'RFC 2784 Section 2.2',
      description: 'Ensure GRE checksum is verified and corrupted frames dropped before decapsulating inner payload.',
      evaluate: (config) => {
        if (!config.checksumVerified) {
          return {
            passed: false,
            score: 0,
            feedback: 'Data Corruption Risk: Corrupted frames with bit flips are forwarded into overlay without checksum validation.'
          };
        }
        return {
          passed: true,
          score: 10,
          feedback: 'Compliant: RFC 2784 16-bit ones-complement checksum generated and verified.'
        };
      }
    },
    {
      id: 'gre_copp_rate_limiting',
      weight: 8,
      title: 'Control-Plane Policing (CoPP) on IP Protocol 47',
      standard: 'RFC 6192 Router Control Plane Protection',
      description: 'Rate-limit IP protocol 47 datagrams addressed to router control plane to mitigate CPU exhaustion attacks.',
      evaluate: (config) => {
        if (!config.coppRateLimiting) {
          return {
            passed: false,
            score: 0,
            feedback: 'DoS Vulnerability: Unmetered IP protocol 47 traffic can exhaust router CPU receive queues during flood attacks.'
          };
        }
        return {
          passed: true,
          score: 8,
          feedback: 'Compliant: Control-Plane Policing (CoPP) class-map active for IP protocol 47.'
        };
      }
    }
  ];

  function runZeroTrustAudit(config) {
    let totalScore = 0;
    const maxScore = 100;
    const results = [];

    for (const rule of AUDIT_RULES) {
      const res = rule.evaluate(config);
      totalScore += res.score;
      results.push({
        id: rule.id,
        title: rule.title,
        standard: rule.standard,
        weight: rule.weight,
        score: res.score,
        passed: res.passed,
        feedback: res.feedback
      });
    }

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 70) grade = 'B';
    else if (totalScore >= 50) grade = 'C';

    return {
      totalScore,
      maxScore,
      percentage: totalScore,
      grade,
      passed: totalScore >= 85,
      results
    };
  }

  return {
    AUDIT_RULES,
    runZeroTrustAudit
  };
}));
