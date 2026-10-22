/**
 * GREForge Pro - Application Controller & Interactive UI State Engine
 */

(function () {
  'use strict';

  const PRESETS = {
    'cisco-dmvpn-ipsec': {
      name: 'Cisco Enterprise DMVPN Phase 3 (mGRE + IPsec)',
      keyVal: 10001,
      seqVal: 1,
      protocolType: 2048, // 0x0800 IPv4
      hasKey: true,
      hasChecksum: false,
      hasSeq: false,
      isGreInUdp: false,
      outerIpVersion: 'IPv4',
      underlayMtu: 9100,
      ipsecProtected: true,
      bfdEnabled: true,
      tcpMssClamping: true,
      audit: {
        ipsecProtected: true,
        isPublicUnderlay: true,
        recursiveRoutingFilter: true,
        bfdEnabled: true,
        validateKeyField: true,
        hasSeq: false,
        underlayIsMultipath: false,
        slidingWindowReordering: true,
        isGreInUdp: false,
        ecmpEntropyEnabled: true,
        urpfEnabled: true,
        checksumVerified: true,
        coppRateLimiting: true
      }
    },
    'cloudflare-magic-transit': {
      name: 'Cloudflare Magic Transit Anycast DDoS Shield',
      keyVal: 20005,
      seqVal: 1,
      protocolType: 2048,
      hasKey: true,
      hasChecksum: false,
      hasSeq: false,
      isGreInUdp: true,
      outerIpVersion: 'IPv4',
      underlayMtu: 9000,
      ipsecProtected: true,
      bfdEnabled: true,
      tcpMssClamping: true,
      audit: {
        ipsecProtected: true,
        isPublicUnderlay: true,
        recursiveRoutingFilter: true,
        bfdEnabled: true,
        validateKeyField: true,
        hasSeq: false,
        underlayIsMultipath: false,
        slidingWindowReordering: true,
        isGreInUdp: true,
        ecmpEntropyEnabled: true,
        urpfEnabled: true,
        checksumVerified: true,
        coppRateLimiting: true
      }
    },
    'vulnerable-gre': {
      name: 'Vulnerable Cleartext Insecure GRE',
      keyVal: 0,
      seqVal: 10,
      protocolType: 2048,
      hasKey: false,
      hasChecksum: false,
      hasSeq: true,
      isGreInUdp: false,
      outerIpVersion: 'IPv4',
      underlayMtu: 1500,
      ipsecProtected: false,
      bfdEnabled: false,
      tcpMssClamping: false,
      audit: {
        ipsecProtected: false,
        isPublicUnderlay: true,
        recursiveRoutingFilter: false,
        bfdEnabled: false,
        validateKeyField: false,
        hasSeq: true,
        underlayIsMultipath: true,
        slidingWindowReordering: false,
        isGreInUdp: false,
        ecmpEntropyEnabled: false,
        urpfEnabled: false,
        checksumVerified: false,
        coppRateLimiting: false
      }
    }
  };

  let currentPresetKey = 'cisco-dmvpn-ipsec';
  let activeTab = 'cisco';

  // DOM Elements
  const inputKey = document.getElementById('input-key');
  const inputSeq = document.getElementById('input-seq');
  const selectProtocolType = document.getElementById('select-protocol-type');
  const inputSrcPort = document.getElementById('input-src-port');
  const checkFlagKey = document.getElementById('check-flag-key');
  const checkFlagChecksum = document.getElementById('check-flag-checksum');
  const checkFlagSeq = document.getElementById('check-flag-seq');
  const checkFlagGreInUdp = document.getElementById('check-flag-greinudp');

  const wireframeHexEl = document.getElementById('wireframe-hex-output');
  const labelWireBytesEl = document.getElementById('label-wire-bytes');
  const valGreLenEl = document.getElementById('val-gre-len');
  const valKeyHexEl = document.getElementById('val-key-hex');
  const valProtoHexEl = document.getElementById('val-proto-hex');
  const valWireLenEl = document.getElementById('val-wire-len');

  const selectOuterIp = document.getElementById('select-outer-ip');
  const inputUnderlayMtu = document.getElementById('input-underlay-mtu');
  const checkIpsecProtect = document.getElementById('check-ipsec-protect');
  const checkBfdActive = document.getElementById('check-bfd-active');

  const valOverheadBytesEl = document.getElementById('val-overhead-bytes');
  const valReqUnderlayEl = document.getElementById('val-req-underlay');
  const valSafeMssEl = document.getElementById('val-safe-mss');
  const valFailoverTimeEl = document.getElementById('val-failover-time');
  const badgeMtuStatusEl = document.getElementById('badge-mtu-status');
  const labelMtuVerdictEl = document.getElementById('label-mtu-verdict');

  const auditChecklistEl = document.getElementById('audit-checklist-el');
  const badgeAuditGradeEl = document.getElementById('badge-audit-grade');
  const btnRunAudit = document.getElementById('btn-run-audit');

  const codeOutputEl = document.getElementById('code-output-el');
  const btnCopyCode = document.getElementById('btn-copy-code');
  const tabButtons = document.querySelectorAll('.tab-btn');
  const presetButtons = document.querySelectorAll('.btn-preset');

  const btnExportJson = document.getElementById('btn-export-json');
  const btnImportJson = document.getElementById('btn-import-json');
  const fileImport = document.getElementById('file-import');

  function getFormValues() {
    const keyVal = parseInt(inputKey.value, 10) || 10001;
    const seqVal = parseInt(inputSeq.value, 10) || 1;
    const protocolType = parseInt(selectProtocolType.value, 10) || 0x0800;
    const outerSrcPort = parseInt(inputSrcPort.value, 10) || 52145;
    const hasKey = checkFlagKey.checked;
    const hasChecksum = checkFlagChecksum.checked;
    const hasSeq = checkFlagSeq.checked;
    const isGreInUdp = checkFlagGreInUdp.checked;
    const outerIpVersion = selectOuterIp.value;
    const underlayMtu = parseInt(inputUnderlayMtu.value, 10) || 9100;
    const isIpsecProtected = checkIpsecProtect.checked;
    const bfdEnabled = checkBfdActive.checked;

    return {
      keyVal,
      seqVal,
      protocolType,
      outerSrcPort,
      hasKey,
      hasChecksum,
      hasSeq,
      isGreInUdp,
      outerIpVersion,
      underlayMtu,
      isIpsecProtected,
      bfdEnabled
    };
  }

  function updateDissectorAndOverhead() {
    const vals = getFormValues();

    // 1. Protocol Dissector
    const packet = GreProtocolEngine.encodeGrePacket({
      keyVal: vals.keyVal,
      seqVal: vals.seqVal,
      protocolType: vals.protocolType,
      outerSrcPort: vals.outerSrcPort,
      hasKey: vals.hasKey,
      hasChecksum: vals.hasChecksum,
      hasSeq: vals.hasSeq,
      isGreInUdp: vals.isGreInUdp
    });

    wireframeHexEl.textContent = packet.hexString;
    labelWireBytesEl.textContent = `${packet.totalLength} Bytes`;
    valGreLenEl.textContent = `${packet.greHeaderLengthBytes} B`;
    valKeyHexEl.textContent = packet.keyHex;
    valProtoHexEl.textContent = '0x' + packet.protocolType.toString(16).padStart(4, '0').toUpperCase();
    valWireLenEl.textContent = `${packet.totalLength} B`;

    // 2. Overhead Waterfall
    const overhead = GreProtocolEngine.calculateOverhead({
      outerIpVersion: vals.outerIpVersion,
      customerPayloadMtu: 1500,
      hasKey: vals.hasKey,
      hasChecksum: vals.hasChecksum,
      hasSeq: vals.hasSeq,
      isGreInUdp: vals.isGreInUdp,
      isIpsecProtected: vals.isIpsecProtected
    });

    valOverheadBytesEl.textContent = `${overhead.totalOverlayOverhead} B`;
    valReqUnderlayEl.textContent = `${overhead.requiredUnderlayMtu} B`;
    valSafeMssEl.textContent = `${overhead.maxSafeMss} B`;

    if (vals.underlayMtu >= overhead.requiredUnderlayMtu) {
      badgeMtuStatusEl.className = 'badge badge-green';
      badgeMtuStatusEl.textContent = 'Jumbo Frame Verified';
      labelMtuVerdictEl.innerHTML = `<span style="color: var(--accent-green); font-weight: 700;">Underlay Capacity Adequate:</span> ${vals.underlayMtu}B Jumbo underlay accommodates ${overhead.totalOverlayOverhead}B GRE overhead without fragmentation or PMTU blackholing.`;
    } else {
      badgeMtuStatusEl.className = 'badge badge-rose';
      badgeMtuStatusEl.textContent = 'Path MTU Hazard';
      labelMtuVerdictEl.innerHTML = `<span style="color: var(--accent-rose); font-weight: 700;">Path MTU Blackhole Hazard:</span> Underlay MTU (${vals.underlayMtu}B) cannot carry 1500B payload + ${overhead.totalOverlayOverhead}B GRE overhead. Configure TCP MSS clamping (MSS <= ${overhead.maxSafeMss}B) immediately.`;
    }

    // 3. Keepalive / Failover Metrics
    const keepalive = GreProtocolEngine.calculateKeepaliveMetrics({
      keepaliveIntervalSec: 10,
      keepaliveRetries: 3,
      bfdEnabled: vals.bfdEnabled,
      bfdIntervalMs: 300,
      bfdMultiplier: 3,
      hasSeq: vals.hasSeq,
      underlayIsMultipath: false
    });
    valFailoverTimeEl.textContent = `${keepalive.failoverDetectionTimeSec} s`;

    // 4. Update Code Output
    updateCodeOutput();
  }

  function runAudit() {
    const vals = getFormValues();
    const preset = PRESETS[currentPresetKey] || PRESETS['cisco-dmvpn-ipsec'];

    const config = Object.assign({}, preset.audit, {
      ipsecProtected: vals.isIpsecProtected,
      outerIpVersion: vals.outerIpVersion,
      underlayMtu: vals.underlayMtu,
      isGreInUdp: vals.isGreInUdp,
      bfdEnabled: vals.bfdEnabled,
      hasSeq: vals.hasSeq,
      tcpMssClamping: vals.underlayMtu >= 1576 ? true : preset.tcpMssClamping
    });

    const report = GreSecurityAuditor.runZeroTrustAudit(config);

    badgeAuditGradeEl.textContent = `Grade ${report.grade} (${report.percentage}%)`;
    if (report.grade.startsWith('A')) {
      badgeAuditGradeEl.className = 'badge badge-green';
    } else if (report.grade === 'B') {
      badgeAuditGradeEl.className = 'badge badge-blue';
    } else if (report.grade === 'C') {
      badgeAuditGradeEl.className = 'badge badge-amber';
    } else {
      badgeAuditGradeEl.className = 'badge badge-rose';
    }

    auditChecklistEl.innerHTML = '';
    report.results.forEach(item => {
      const row = document.createElement('div');
      row.className = 'audit-item';
      row.innerHTML = `
        <div class="audit-left">
          <div class="audit-title">${item.title} (${item.score}/${item.weight} pts)</div>
          <div class="audit-desc">${item.feedback}</div>
        </div>
        <div class="audit-badge ${item.passed ? 'badge-green' : 'badge-rose'}">
          ${item.passed ? 'PASSED' : 'FAILED'}
        </div>
      `;
      auditChecklistEl.appendChild(row);
    });
  }

  function updateCodeOutput() {
    const vals = getFormValues();
    const params = {
      tunnelId: 1,
      dev: 'gre0',
      localIp: '198.51.100.1',
      remoteIp: '203.0.113.2',
      overlayIp: '10.255.255.1',
      keyVal: vals.keyVal,
      isMultipoint: true,
      isGreInUdp: vals.isGreInUdp
    };

    let code = '';
    switch (activeTab) {
      case 'cisco':
        code = GreConfigSynthesizer.generateCiscoConfig(params);
        break;
      case 'linux':
        code = GreConfigSynthesizer.generateLinuxConfig(params);
        break;
      case 'junos':
        code = GreConfigSynthesizer.generateJunosConfig(params);
        break;
      case 'cloudflare':
        code = GreConfigSynthesizer.generateCloudflareConfig(params);
        break;
      case 'prometheus':
        code = GreConfigSynthesizer.generatePrometheusConfig(params);
        break;
      default:
        code = GreConfigSynthesizer.generateCiscoConfig(params);
    }
    codeOutputEl.textContent = code;
  }

  function loadPreset(key) {
    const preset = PRESETS[key];
    if (!preset) return;
    currentPresetKey = key;

    inputKey.value = preset.keyVal;
    inputSeq.value = preset.seqVal;
    selectProtocolType.value = preset.protocolType;
    checkFlagKey.checked = preset.hasKey;
    checkFlagChecksum.checked = preset.hasChecksum;
    checkFlagSeq.checked = preset.hasSeq;
    checkFlagGreInUdp.checked = preset.isGreInUdp;
    selectOuterIp.value = preset.outerIpVersion;
    inputUnderlayMtu.value = preset.underlayMtu;
    checkIpsecProtect.checked = preset.ipsecProtected;
    checkBfdActive.checked = preset.bfdEnabled;

    presetButtons.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.preset === key);
    });

    updateDissectorAndOverhead();
    runAudit();
  }

  function exportProfile() {
    const vals = getFormValues();
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(vals, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `greforge-profile-key-${vals.keyVal}.json`);
    dlAnchor.click();
  }

  function initListeners() {
    const inputs = [
      inputKey, inputSeq, selectProtocolType, inputSrcPort,
      checkFlagKey, checkFlagChecksum, checkFlagSeq, checkFlagGreInUdp,
      selectOuterIp, inputUnderlayMtu, checkIpsecProtect, checkBfdActive
    ];

    inputs.forEach(el => {
      el.addEventListener('input', updateDissectorAndOverhead);
      el.addEventListener('change', updateDissectorAndOverhead);
    });

    btnRunAudit.addEventListener('click', runAudit);

    presetButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        loadPreset(btn.dataset.preset);
      });
    });

    tabButtons.forEach(tab => {
      tab.addEventListener('click', () => {
        tabButtons.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        activeTab = tab.dataset.tab;
        updateCodeOutput();
      });
    });

    btnCopyCode.addEventListener('click', () => {
      navigator.clipboard.writeText(codeOutputEl.textContent).then(() => {
        const orig = btnCopyCode.textContent;
        btnCopyCode.textContent = 'Copied!';
        setTimeout(() => { btnCopyCode.textContent = orig; }, 1500);
      });
    });

    btnExportJson.addEventListener('click', exportProfile);
    btnImportJson.addEventListener('click', () => fileImport.click());

    fileImport.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const imported = JSON.parse(event.target.result);
          if (imported.keyVal !== undefined) inputKey.value = imported.keyVal;
          if (imported.seqVal !== undefined) inputSeq.value = imported.seqVal;
          updateDissectorAndOverhead();
          runAudit();
        } catch (err) {
          alert('Invalid JSON profile file.');
        }
      };
      reader.readAsText(file);
    });
  }

  // Init on load
  initListeners();
  loadPreset('cisco-dmvpn-ipsec');
})();
