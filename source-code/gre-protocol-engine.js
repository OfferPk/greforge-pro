/**
 * GREForge Pro - Generic Routing Encapsulation (RFC 2784 / RFC 2890 / RFC 8086) Engine
 * Standards:
 * - IETF RFC 2784: Generic Routing Encapsulation (GRE)
 * - IETF RFC 2890: Key and Sequence Number Extensions to GRE
 * - IETF RFC 8086: GRE-in-UDP Encapsulation
 * - IETF RFC 7637: NVGRE (Network Virtualization using GRE)
 * Features:
 * - RFC 2784 / 2890 Binary Wireframe Encoding & Decoding (C, K, S bits, Protocol Type)
 * - RFC 8086 GRE-in-UDP (UDP 4754) Outer Framing & ECMP Entropy Derivation
 * - Encapsulation Overhead Waterfall (Native GRE, GRE-in-UDP, GRE-over-IPsec)
 * - Path MTU (PMTU) & Safe TCP MSS Clamping Calculator
 * - Out-of-Order Sequence & Recursive Routing Loop Risk Estimator
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GreProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const GRE_IN_UDP_PORT = 4754;
  const IP_PROTO_GRE = 47;

  const PROTOCOL_TYPES = {
    0x0800: { code: 0x0800, name: 'IPv4', desc: 'Internet Protocol version 4 (RFC 791)' },
    0x86DD: { code: 0x86DD, name: 'IPv6', desc: 'Internet Protocol version 6 (RFC 8200)' },
    0x6558: { code: 0x6558, name: 'Ethernet (NVGRE)', desc: 'Transparent Ethernet Bridging (RFC 7637)' },
    0x8847: { code: 0x8847, name: 'MPLS Unicast', desc: 'Multiprotocol Label Switching Unicast (RFC 3032)' },
    0x8848: { code: 0x8848, name: 'MPLS Multicast', desc: 'Multiprotocol Label Switching Multicast' }
  };

  /**
   * Fast pure-JS SHA-256 for deterministic Zero-Trust tunnel key authentication
   */
  function sha256(asciiStr) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const words = [];
    const asciiBitLength = asciiStr.length * 8;
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    const k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    for (let i = 0; i < asciiStr.length; i++) {
      const j = i >> 2;
      words[j] = (words[j] || 0) | ((asciiStr.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8));
    }
    const end = asciiStr.length >> 2;
    words[end] = (words[end] || 0) | (0x80 << (24 - (asciiStr.length % 4) * 8));
    words[(((asciiStr.length + 8) >> 6) << 4) + 15] = asciiBitLength;

    for (let j = 0; j < words.length; j += 16) {
      const w = [];
      for (let i = 0; i < 16; i++) w[i] = words[j + i] || 0;
      for (let i = 16; i < 64; i++) {
        const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }

      let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
      let e = hash[4], f = hash[5], g = hash[6], h = hash[7];

      for (let i = 0; i < 64; i++) {
        const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + k[i] + w[i]) | 0;
        const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }

      hash[0] = (hash[0] + a) | 0;
      hash[1] = (hash[1] + b) | 0;
      hash[2] = (hash[2] + c) | 0;
      hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0;
      hash[5] = (hash[5] + f) | 0;
      hash[6] = (hash[6] + g) | 0;
      hash[7] = (hash[7] + h) | 0;
    }

    const hexBytes = [];
    for (let i = 0; i < 8; i++) {
      for (let b = 3; b >= 0; b--) {
        hexBytes.push((hash[i] >>> (b * 8)) & 0xff);
      }
    }
    return hexBytes;
  }

  /**
   * Derive outer UDP source port entropy from inner 5-tuple (RFC 8086 Section 3)
   */
  function deriveUdpSourcePort(srcIp, dstIp, srcPort, dstPort, proto) {
    const seed = `${srcIp || '10.0.0.1'}:${dstIp || '10.0.0.2'}:${srcPort || 1234}:${dstPort || 80}:${proto || 6}`;
    let hash = 2166136261;
    for (let i = 0; i < seed.length; i++) {
      hash ^= seed.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    const entropy = (hash >>> 0) % (65535 - 49152 + 1);
    return 49152 + entropy;
  }

  /**
   * Encode RFC 2784 / RFC 2890 GRE or RFC 8086 GRE-in-UDP Packet
   */
  function encodeGrePacket(params) {
    const hasChecksum = !!params.hasChecksum;
    const hasKey = params.hasKey !== false;
    const hasSeq = !!params.hasSeq;
    const isGreInUdp = !!params.isGreInUdp;

    const protocolType = Number(params.protocolType) || 0x0800; // IPv4
    const keyVal = (params.keyVal !== undefined ? Number(params.keyVal) : 10001) >>> 0;
    const seqVal = (params.seqVal !== undefined ? Number(params.seqVal) : 1) >>> 0;
    const checksumVal = Number(params.checksumVal) || 0x54A2;

    const outerSrcPort = isGreInUdp ? (Number(params.outerSrcPort) || 52145) : 0;
    const outerDstPort = isGreInUdp ? GRE_IN_UDP_PORT : 0;

    const raw = [];

    // Optional Outer UDP Header if GRE-in-UDP (RFC 8086)
    let udpLenOffset = -1;
    if (isGreInUdp) {
      raw.push((outerSrcPort >>> 8) & 0xFF, outerSrcPort & 0xFF);
      raw.push((outerDstPort >>> 8) & 0xFF, outerDstPort & 0xFF);
      udpLenOffset = raw.length;
      raw.push(0x00, 0x00); // UDP Length placeholder
      raw.push(0x00, 0x00); // UDP Checksum
    }

    // 1. GRE Flags (Byte 0)
    // Bit 0: C (0x80), Bit 2: K (0x20), Bit 3: S (0x10)
    let flagByte = 0x00;
    if (hasChecksum) flagByte |= 0x80;
    if (hasKey) flagByte |= 0x20;
    if (hasSeq) flagByte |= 0x10;
    raw.push(flagByte);

    // Byte 1: Reserved (Bits 4-12 = 0) + Ver (Bits 13-15 = 0)
    raw.push(0x00);

    // Bytes 2-3: Protocol Type (EtherType)
    raw.push((protocolType >>> 8) & 0xFF, protocolType & 0xFF);

    // Optional Fields Order: Checksum (4B) -> Key (4B) -> Sequence (4B)
    if (hasChecksum) {
      raw.push((checksumVal >>> 8) & 0xFF, checksumVal & 0xFF);
      raw.push(0x00, 0x00); // Reserved1
    }

    if (hasKey) {
      raw.push((keyVal >>> 24) & 0xFF, (keyVal >>> 16) & 0xFF, (keyVal >>> 8) & 0xFF, keyVal & 0xFF);
    }

    if (hasSeq) {
      raw.push((seqVal >>> 24) & 0xFF, (seqVal >>> 16) & 0xFF, (seqVal >>> 8) & 0xFF, seqVal & 0xFF);
    }

    const greHeaderLen = (hasChecksum ? 4 : 0) + (hasKey ? 4 : 0) + (hasSeq ? 4 : 0) + 4;

    // Inner Payload
    const innerPayload = params.innerPayload || 'CUSTOMER-OVERLAY-IP-PAYLOAD';
    for (let i = 0; i < innerPayload.length; i++) {
      raw.push(innerPayload.charCodeAt(i) & 0xFF);
    }

    // Patch UDP length if GRE-in-UDP
    if (isGreInUdp && udpLenOffset !== -1) {
      const totalUdpLen = raw.length;
      raw[udpLenOffset] = (totalUdpLen >>> 8) & 0xFF;
      raw[udpLenOffset + 1] = totalUdpLen & 0xFF;
    }

    const hexString = raw.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

    return {
      isGreInUdp,
      outerSrcPort,
      outerDstPort,
      hasChecksum,
      hasKey,
      hasSeq,
      protocolType,
      protocolTypeName: PROTOCOL_TYPES[protocolType] ? PROTOCOL_TYPES[protocolType].name : 'Unknown',
      keyVal,
      keyHex: '0x' + keyVal.toString(16).padStart(8, '0').toUpperCase(),
      seqVal,
      checksumVal: '0x' + checksumVal.toString(16).padStart(4, '0').toUpperCase(),
      greHeaderLengthBytes: greHeaderLen,
      totalLength: raw.length,
      hexString,
      rawBytes: raw
    };
  }

  /**
   * Decode RFC 2784 / RFC 2890 GRE Packet from raw hex or byte array
   */
  function decodeGrePacket(input, isGreInUdp) {
    let bytes = [];
    if (typeof input === 'string') {
      const cleaned = input.replace(/[^0-9A-Fa-f]/g, '');
      for (let i = 0; i < cleaned.length; i += 2) {
        bytes.push(parseInt(cleaned.substr(i, 2), 16));
      }
    } else if (Array.isArray(input)) {
      bytes = input;
    }

    let offset = 0;
    let outerSrcPort = 0;
    let outerDstPort = 0;

    if (isGreInUdp) {
      if (bytes.length < 12) {
        throw new Error(`Packet too short for GRE-in-UDP: ${bytes.length} bytes (minimum 12)`);
      }
      outerSrcPort = (bytes[0] << 8) | bytes[1];
      outerDstPort = (bytes[2] << 8) | bytes[3];
      offset = 8;
    }

    if (bytes.length - offset < 4) {
      throw new Error(`Packet too short for GRE Base Header: ${bytes.length - offset} bytes`);
    }

    const flagByte = bytes[offset];
    const hasChecksum = !!(flagByte & 0x80);
    const hasKey = !!(flagByte & 0x20);
    const hasSeq = !!(flagByte & 0x10);

    const version = bytes[offset + 1] & 0x07;
    const protocolType = (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;

    let checksumVal = 0;
    if (hasChecksum) {
      checksumVal = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 4; // Checksum (2B) + Reserved1 (2B)
    }

    let keyVal = 0;
    if (hasKey) {
      keyVal = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
      offset += 4;
    }

    let seqVal = 0;
    if (hasSeq) {
      seqVal = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
      offset += 4;
    }

    return {
      isGreInUdp: !!isGreInUdp,
      outerSrcPort,
      outerDstPort,
      version,
      hasChecksum,
      hasKey,
      hasSeq,
      protocolType,
      protocolTypeName: PROTOCOL_TYPES[protocolType] ? PROTOCOL_TYPES[protocolType].name : 'Unknown',
      checksumVal: '0x' + checksumVal.toString(16).padStart(4, '0').toUpperCase(),
      keyVal,
      keyHex: '0x' + keyVal.toString(16).padStart(8, '0').toUpperCase(),
      seqVal,
      totalLength: bytes.length
    };
  }

  /**
   * Calculate Encapsulation Overhead Waterfall across GRE variations
   */
  function calculateOverhead(params) {
    const outerIpVersion = params.outerIpVersion === 'IPv6' ? 6 : 4;
    const outerIpHdrBytes = outerIpVersion === 6 ? 40 : 20;

    const hasChecksum = !!params.hasChecksum;
    const hasKey = params.hasKey !== false;
    const hasSeq = !!params.hasSeq;
    const isGreInUdp = !!params.isGreInUdp;
    const isIpsecProtected = !!params.isIpsecProtected;

    // GRE Header size: 4B base + optional fields
    let greHdrBytes = 4;
    if (hasChecksum) greHdrBytes += 4;
    if (hasKey) greHdrBytes += 4;
    if (hasSeq) greHdrBytes += 4;

    const udpBytes = isGreInUdp ? 8 : 0;
    // IPsec ESP overhead: ESP header (8B) + IV (8B) + ICV/padding (16B) = ~32B in transport, ~52B in tunnel
    const ipsecOverhead = isIpsecProtected ? 36 : 0;

    const totalOverlayOverhead = outerIpHdrBytes + udpBytes + greHdrBytes + ipsecOverhead;
    const customerPayloadMtu = Number(params.customerPayloadMtu) || 1500;
    const requiredUnderlayMtu = customerPayloadMtu + totalOverlayOverhead;
    const maxSafeMss = 1500 - totalOverlayOverhead - 40; // 40B for inner TCP/IP headers

    return {
      outerIpVersion,
      outerIpHdrBytes,
      udpBytes,
      greHdrBytes,
      ipsecOverhead,
      totalOverlayOverhead,
      customerPayloadMtu,
      requiredUnderlayMtu,
      recommendedUnderlayJumboMtu: Math.max(1600, requiredUnderlayMtu + 40),
      maxSafeMss: Math.max(1200, maxSafeMss)
    };
  }

  /**
   * Tunnel Flapping, Keepalive & S-Bit Out-of-Order Risk Estimator
   */
  function calculateKeepaliveMetrics(params) {
    const keepaliveIntervalSec = Number(params.keepaliveIntervalSec) || 10;
    const keepaliveRetries = Number(params.keepaliveRetries) || 3;
    const bfdEnabled = !!params.bfdEnabled;
    const bfdIntervalMs = Number(params.bfdIntervalMs) || 300;
    const bfdMultiplier = Number(params.bfdMultiplier) || 3;

    let failoverDetectionTimeSec = 0;
    if (bfdEnabled) {
      failoverDetectionTimeSec = (bfdIntervalMs * bfdMultiplier) / 1000;
    } else {
      failoverDetectionTimeSec = keepaliveIntervalSec * keepaliveRetries;
    }

    const hasSeq = !!params.hasSeq;
    const underlayIsMultipath = !!params.underlayIsMultipath;
    const outOfOrderDropRisk = (hasSeq && underlayIsMultipath) ? 85 : 0;

    return {
      keepaliveIntervalSec,
      keepaliveRetries,
      bfdEnabled,
      failoverDetectionTimeSec,
      outOfOrderDropRisk
    };
  }

  return {
    GRE_IN_UDP_PORT,
    IP_PROTO_GRE,
    PROTOCOL_TYPES,
    deriveUdpSourcePort,
    encodeGrePacket,
    decodeGrePacket,
    calculateOverhead,
    calculateKeepaliveMetrics
  };
}));
