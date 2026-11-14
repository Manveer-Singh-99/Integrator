// Integrator Dashboard UI Logic (Tauri v2)

let isDisplayActive = false;
let isTestingSpeed = false;
let lastTestedSpeed = null;
let latestStatus = null;
let shareInputDirty = false;
let lastGpuSignature = '';
let lastRoutesSignature = '';
let lastInterfacesSignature = '';
let lastManualIpsSignature = '';
let lastDiscoveredPeersSignature = '';
let lastSavedTrustSignature = '';

// Fallback invoke helper for Tauri v2
async function invokeCmd(command, args = {}) {
  try {
    if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
      return await window.__TAURI__.core.invoke(command, args);
    } else if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) {
      return await window.__TAURI_INTERNALS__.invoke(command, args);
    } else {
      console.warn('Tauri IPC not available in standard browser mode:', command, args);
      return null;
    }
  } catch (err) {
    console.error(`Error invoking ${command}:`, err);
    throw err;
  }
}

function clearElement(el) {
  if (!el) return;
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

function formatOsLabel(os) {
  switch ((os || '').toLowerCase()) {
    case 'macos':
      return 'macOS';
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    default:
      return os ? String(os) : 'Workstation';
  }
}

function formatShortOs(os, fallback = 'Local') {
  switch ((os || '').toLowerCase()) {
    case 'macos':
      return 'Mac';
    case 'windows':
      return 'PC';
    case 'linux':
      return 'Linux';
    default:
      return fallback;
  }
}

function osIcon(os) {
  switch ((os || '').toLowerCase()) {
    case 'macos':
      return '💻';
    case 'windows':
      return '🖥️';
    case 'linux':
      return '🐧';
    default:
      return '📡';
  }
}

function formatDisplay(disp) {
  if (disp && disp.width > 0 && disp.height > 0) {
    const fps = disp.fps > 0 ? disp.fps : 60;
    return `${disp.width}x${disp.height}@${fps}Hz`;
  }
  return 'Display Unknown';
}

function formatSpeedMbps(mbps) {
  if (typeof mbps === 'number' && Number.isFinite(mbps) && mbps > 0) {
    if (mbps >= 1000) {
      return mbps % 1000 === 0 ? `${mbps / 1000} Gbps` : `${(mbps / 1000).toFixed(1)} Gbps`;
    }
    return `${mbps} Mbps`;
  }
  return 'Link Active';
}

function formatTransport(transport) {
  switch ((transport || '').toLowerCase()) {
    case 'direct_usb':
      return 'USB-C Direct';
    case 'thunderbolt':
      return 'Thunderbolt';
    case 'ethernet':
      return 'Ethernet';
    case 'wifi':
      return 'Wi-Fi';
    default:
      return 'Network';
  }
}

function inferVendorKey(text) {
  const lower = String(text || '').toLowerCase();
  if (lower.includes('nvidia') || lower.includes('geforce') || lower.includes('rtx') || lower.includes('gtx') || lower.includes('quadro')) {
    return 'nvidia';
  }
  if (lower.includes('amd') || lower.includes('radeon')) {
    return 'amd';
  }
  if (lower.includes('intel') || lower.includes('arc') || lower.includes('iris') || lower.includes('uhd')) {
    return 'intel';
  }
  if (lower.includes('apple')) {
    return 'apple';
  }
  return '';
}

function appendLog(message, type = 'info') {
  const container = document.getElementById('logs-container');
  if (!container) return;
  const now = new Date();
  const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

  const line = document.createElement('div');
  line.className = `log-line ${type}`;

  const timeSpan = document.createElement('span');
  timeSpan.className = 'log-time';
  timeSpan.textContent = timeStr;

  line.appendChild(timeSpan);
  line.appendChild(document.createTextNode(` ${String(message)}`));

  container.appendChild(line);
  while (container.childNodes.length > 200) {
    container.removeChild(container.firstChild);
  }
  container.scrollTop = container.scrollHeight;
}

function setCardPill(pillEl, text, pillClass) {
  if (!pillEl) return;
  pillEl.setAttribute('data-original-text', text);
  pillEl.setAttribute('data-original-class', pillClass);
  const card = pillEl.closest('.card');
  if (card && card.classList.contains('card-disabled')) {
    pillEl.textContent = 'Disabled';
    pillEl.className = 'pill pill-idle';
    return;
  }
  pillEl.textContent = text;
  pillEl.className = `pill ${pillClass}`;
}

function updateFilterTabCounts() {
  const cards = Array.from(document.querySelectorAll('.grid .card'));
  document.querySelectorAll('.filter-tab').forEach((tab) => {
    const filter = tab.getAttribute('data-filter');
    const countSpan = tab.querySelector('.tab-count');
    if (!countSpan) return;
    let count = 0;
    if (filter === 'all') {
      count = cards.length;
    } else if (filter === 'active') {
      count = cards.filter((c) => c.getAttribute('data-status') === 'active').length;
    } else {
      count = cards.filter((c) => {
        const cats = (c.getAttribute('data-category') || '').split(/\s+/);
        return cats.includes(filter);
      }).length;
    }
    countSpan.textContent = String(count);
  });
}

function buildGpuOptions(selectEl, gpuEntries) {
  clearElement(selectEl);

  const defaults = [
    { value: 'auto', label: 'Auto (System Default)', vendor: '' },
    { value: 'discrete', label: 'Auto Discrete (High Performance)', vendor: '' },
    { value: 'integrated', label: 'Auto Integrated (Power Saving)', vendor: '' },
  ];

  defaults.forEach((optDef) => {
    const opt = document.createElement('option');
    opt.value = optDef.value;
    opt.textContent = optDef.label;
    selectEl.appendChild(opt);
  });

  gpuEntries.forEach((gpu) => {
    if (!gpu || !gpu.name) return;
    const opt = document.createElement('option');
    opt.value = gpu.name;
    let label = gpu.name;
    if (typeof gpu.is_discrete === 'boolean') {
      label += gpu.is_discrete ? ' [Discrete]' : ' [Integrated]';
    }
    if (typeof gpu.vram_mb === 'number' && gpu.vram_mb > 0) {
      label += ` (${(gpu.vram_mb / 1024).toFixed(1)} GB)`;
    }
    opt.textContent = label;
    opt.dataset.vendor = inferVendorKey(`${gpu.vendor || ''} ${gpu.name}`);
    selectEl.appendChild(opt);
  });
}

function syncSelectGpuValue(selectEl, rawPref) {
  if (!selectEl || document.activeElement === selectEl) return;
  const target = String(rawPref || 'auto').trim();
  const lower = target.toLowerCase();
  const options = Array.from(selectEl.options);

  const exact = options.find((o) => o.value.toLowerCase() === lower);
  if (exact) {
    selectEl.value = exact.value;
    return;
  }

  const vendorMatch = options.find((o) => (o.dataset.vendor || '') === lower && lower !== '');
  if (vendorMatch) {
    selectEl.value = vendorMatch.value;
    return;
  }

  const substrMatch = options.find(
    (o) => lower && o.value !== 'auto' && o.value !== 'discrete' && o.value !== 'integrated' && o.value.toLowerCase().includes(lower)
  );
  if (substrMatch) {
    selectEl.value = substrMatch.value;
    return;
  }

  if (target && target !== 'auto') {
    const custom = document.createElement('option');
    custom.value = target;
    custom.textContent = target;
    selectEl.appendChild(custom);
    selectEl.value = target;
    return;
  }

  selectEl.value = 'auto';
}

function renderGpuControls(status) {
  const gpuControls = document.getElementById('gpu-controls');
  const selectEncodeGpu = document.getElementById('select-encode-gpu');
  const selectDecodeGpu = document.getElementById('select-decode-gpu');
  const gpuNote = document.getElementById('gpu-controls-note');
  if (!gpuControls || !selectEncodeGpu || !selectDecodeGpu) return;

  const isLocalWindows = !!status.gpu_controls_supported;
  const peerIsWindows = status.peer_connected && (status.peer_os || '').toLowerCase() === 'windows';
  const peerGpus = Array.isArray(status.peer_gpus) ? status.peer_gpus.filter(Boolean) : [];

  if (!isLocalWindows && !(peerIsWindows && peerGpus.length > 0)) {
    gpuControls.style.display = 'none';
    selectEncodeGpu.disabled = true;
    selectDecodeGpu.disabled = true;
    if (gpuNote) gpuNote.style.display = 'none';
    return;
  }

  gpuControls.style.display = 'flex';

  let gpuEntries = [];
  if (isLocalWindows) {
    const rawLocal = Array.isArray(status.local_gpus) ? status.local_gpus : [];
    const realLocal = rawLocal.filter(
      (g) => g && g.name && !(g.vendor === 'System' && g.name === 'Default System GPU')
    );
    gpuEntries = realLocal.length > 0 ? realLocal : rawLocal;
  } else {
    gpuEntries = peerGpus.map((name) => ({ name, vendor: inferVendorKey(name) }));
  }

  const sig = JSON.stringify({
    supported: isLocalWindows,
    gpus: gpuEntries.map((g) => ({ n: g.name, d: g.is_discrete ?? null, v: g.vram_mb ?? null })),
  });

  if (sig !== lastGpuSignature) {
    lastGpuSignature = sig;
    buildGpuOptions(selectEncodeGpu, gpuEntries);
    buildGpuOptions(selectDecodeGpu, gpuEntries);
  }

  if (isLocalWindows) {
    selectEncodeGpu.disabled = false;
    selectDecodeGpu.disabled = false;
    syncSelectGpuValue(selectEncodeGpu, status.encode_gpu);
    syncSelectGpuValue(selectDecodeGpu, status.decode_gpu);
    if (gpuNote) gpuNote.style.display = 'none';
  } else {
    selectEncodeGpu.disabled = true;
    selectDecodeGpu.disabled = true;
    if (document.activeElement !== selectEncodeGpu) selectEncodeGpu.value = 'auto';
    if (document.activeElement !== selectDecodeGpu) selectDecodeGpu.value = 'auto';
    if (gpuNote) {
      const peerLabel = status.peer_name || status.peer_ip || 'Windows peer';
      gpuNote.textContent = `DirectX GPU routing is configured on ${peerLabel} (Windows host).`;
      gpuNote.style.display = 'block';
    }
  }
}

function renderNetworkRoutes(status) {
  const container = document.getElementById('network-routes');
  if (!container) return;

  const discovered = Array.isArray(status.discovered_peers) ? status.discovered_peers : [];
  const sig = JSON.stringify({
    connected: status.peer_connected,
    ip: status.peer_ip,
    localIp: status.peer_local_ip_used,
    transport: status.transport_label,
    desc: status.link_description,
    speed: status.link_speed_mbps,
    rtt: status.rtt_ms,
    ifCount: Array.isArray(status.local_interfaces) ? status.local_interfaces.length : 0,
    others: discovered
      .filter((p) => p.ip !== status.peer_ip)
      .map((p) => [p.ip, p.hostname, p.transport_label, p.link_description, p.link_speed_mbps, p.rtt_ms]),
  });

  if (sig === lastRoutesSignature) return;
  lastRoutesSignature = sig;

  clearElement(container);

  if (status.peer_connected && status.peer_ip) {
    const activeRow = document.createElement('div');
    activeRow.className = 'route-item active';

    const dot = document.createElement('span');
    dot.className = 'route-dot green';

    const details = document.createElement('div');
    details.className = 'route-details';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'route-name';
    nameSpan.textContent = `${status.transport_label || 'Active Link'} — ${status.link_description || 'Connected'}`;

    const ipSpan = document.createElement('span');
    ipSpan.className = 'route-ip';
    const localSide = status.peer_local_ip_used || 'Local';
    const speedLabel = status.link_speed_mbps != null && status.link_speed_mbps > 0
      ? formatSpeedMbps(status.link_speed_mbps)
      : 'Link Active';
    ipSpan.textContent = `${localSide} ⇄ ${status.peer_ip} • ${speedLabel}`;

    details.appendChild(nameSpan);
    details.appendChild(ipSpan);

    const pingSpan = document.createElement('span');
    pingSpan.className = 'route-ping';
    pingSpan.id = 'usb-ping';
    pingSpan.textContent = typeof status.rtt_ms === 'number' && Number.isFinite(status.rtt_ms)
      ? `${status.rtt_ms.toFixed(1)} ms`
      : '-- ms';

    activeRow.appendChild(dot);
    activeRow.appendChild(details);
    activeRow.appendChild(pingSpan);
    container.appendChild(activeRow);

    const secondaryPeers = discovered.filter((p) => p.ip && p.ip !== status.peer_ip);
    secondaryPeers.forEach((peer) => {
      const row = document.createElement('div');
      row.className = 'route-item';

      const pDot = document.createElement('span');
      pDot.className = 'route-dot yellow';

      const pDetails = document.createElement('div');
      pDetails.className = 'route-details';

      const pName = document.createElement('span');
      pName.className = 'route-name';
      pName.textContent = `${peer.hostname || peer.ip} (${peer.transport_label || 'Standby'})`;

      const pIp = document.createElement('span');
      pIp.className = 'route-ip';
      const pSpeed = peer.link_speed_mbps != null && peer.link_speed_mbps > 0
        ? formatSpeedMbps(peer.link_speed_mbps)
        : 'Link Active';
      pIp.textContent = `${peer.local_ip_used || 'Local'} ⇄ ${peer.ip} • ${peer.link_description || pSpeed}`;

      pDetails.appendChild(pName);
      pDetails.appendChild(pIp);

      const pPing = document.createElement('span');
      pPing.className = 'route-ping';
      pPing.textContent = typeof peer.rtt_ms === 'number' && Number.isFinite(peer.rtt_ms)
        ? `${peer.rtt_ms.toFixed(1)} ms`
        : '-- ms';

      row.appendChild(pDot);
      row.appendChild(pDetails);
      row.appendChild(pPing);
      container.appendChild(row);
    });
  } else {
    const emptyRow = document.createElement('div');
    emptyRow.className = 'route-item';

    const dot = document.createElement('span');
    dot.className = 'route-dot yellow';

    const details = document.createElement('div');
    details.className = 'route-details';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'route-name';
    nameSpan.textContent = status.link_description || 'No peer connected';

    const ipSpan = document.createElement('span');
    ipSpan.className = 'route-ip';
    const ifCount = Array.isArray(status.local_interfaces) ? status.local_interfaces.length : 0;
    ipSpan.textContent = `Listening across ${ifCount} local IPv4 interface(s)`;

    details.appendChild(nameSpan);
    details.appendChild(ipSpan);

    const pingSpan = document.createElement('span');
    pingSpan.className = 'route-ping';
    pingSpan.id = 'usb-ping';
    pingSpan.textContent = '-- ms';

    emptyRow.appendChild(dot);
    emptyRow.appendChild(details);
    emptyRow.appendChild(pingSpan);
    container.appendChild(emptyRow);
  }
}

function renderLocalInterfaces(interfaces) {
  const container = document.getElementById('local-interfaces-list');
  if (!container) return;

  const list = Array.isArray(interfaces) ? interfaces : [];
  const sig = JSON.stringify(list.map((i) => [i.name, i.friendly_name, i.ip, i.cidr_prefix, i.transport, i.link_speed_mbps]));
  if (sig === lastInterfacesSignature) return;
  lastInterfacesSignature = sig;

  clearElement(container);
  if (list.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'empty-hint';
    empty.textContent = 'No active IPv4 network interfaces detected';
    container.appendChild(empty);
    return;
  }

  list.forEach((iface) => {
    const row = document.createElement('div');
    row.className = 'interface-item';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'interface-name';
    const label = iface.friendly_name || iface.name || 'Interface';
    nameSpan.textContent = `${label} (${formatTransport(iface.transport)})`;

    const metaSpan = document.createElement('span');
    metaSpan.className = 'interface-meta selectable';
    const speedPart = iface.link_speed_mbps != null && iface.link_speed_mbps > 0
      ? ` • ${formatSpeedMbps(iface.link_speed_mbps)}`
      : '';
    metaSpan.textContent = `${iface.ip}/${iface.cidr_prefix}${speedPart}`;

    row.appendChild(nameSpan);
    row.appendChild(metaSpan);
    container.appendChild(row);
  });
}

function renderManualPeerIps(ips) {
  const container = document.getElementById('manual-peer-ips-list');
  if (!container) return;

  const list = Array.isArray(ips) ? ips : [];
  const sig = JSON.stringify(list);
  if (sig === lastManualIpsSignature) return;
  lastManualIpsSignature = sig;

  clearElement(container);
  if (list.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'empty-hint';
    empty.textContent = 'No manual peer IPs configured';
    container.appendChild(empty);
    return;
  }

  list.forEach((ip) => {
    const chip = document.createElement('span');
    chip.className = 'ip-chip selectable';

    const text = document.createElement('span');
    text.textContent = ip;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chip-remove';
    btn.title = `Remove ${ip}`;
    btn.textContent = '×';
    btn.addEventListener('click', async () => {
      try {
        btn.disabled = true;
        await invokeCmd('remove_manual_peer_ip', { ip });
        appendLog(`🌐 Removed manual peer IP ${ip}`, 'info');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Failed to remove peer IP: ${err}`, 'error');
      }
    });

    chip.appendChild(text);
    chip.appendChild(btn);
    container.appendChild(chip);
  });
}

function renderDiscoveredPeers(peers) {
  const container = document.getElementById('discovered-peers-list');
  if (!container) return;

  const list = Array.isArray(peers) ? peers : [];
  const sig = JSON.stringify(
    list.map((p) => [p.device_id, p.hostname, p.os, p.hardware_model, p.ip, p.transport_label, p.rtt_ms, p.trusted, p.blocked])
  );
  if (sig === lastDiscoveredPeersSignature) return;
  lastDiscoveredPeersSignature = sig;

  clearElement(container);
  if (list.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'empty-hint';
    empty.textContent = 'Listening for peer beacons...';
    container.appendChild(empty);
    return;
  }

  list.forEach((peer) => {
    const item = document.createElement('div');
    item.className = 'peer-item';

    const top = document.createElement('div');
    top.className = 'peer-item-top';

    const name = document.createElement('span');
    name.className = 'peer-item-name';
    const modelStr = peer.hardware_model ? ` • ${peer.hardware_model}` : '';
    name.textContent = `${peer.hostname || peer.ip} (${formatOsLabel(peer.os)}${modelStr})`;

    const statePill = document.createElement('span');
    if (peer.blocked) {
      statePill.className = 'pill pill-idle';
      statePill.textContent = 'Blocked';
    } else if (peer.trusted) {
      statePill.className = 'pill pill-active';
      statePill.textContent = 'Trusted';
    } else {
      statePill.className = 'pill pill-warning';
      statePill.textContent = 'Untrusted';
    }

    top.appendChild(name);
    top.appendChild(statePill);

    const meta = document.createElement('div');
    meta.className = 'peer-item-meta selectable';
    const rttStr = typeof peer.rtt_ms === 'number' && Number.isFinite(peer.rtt_ms)
      ? `${peer.rtt_ms.toFixed(1)} ms`
      : '-- ms';
    const dispStr = peer.display && peer.display.width > 0 ? ` • ${formatDisplay(peer.display)}` : '';
    meta.textContent = `${peer.ip} • ${peer.transport_label || 'Network'} • ${rttStr}${dispStr}`;

    const actions = document.createElement('div');
    actions.className = 'peer-item-actions';

    if (!peer.trusted || peer.blocked) {
      const btnTrust = document.createElement('button');
      btnTrust.type = 'button';
      btnTrust.className = 'btn-xs btn-xs-trust';
      btnTrust.textContent = peer.blocked ? 'Unblock & Trust' : 'Trust';
      btnTrust.addEventListener('click', async () => {
        try {
          btnTrust.disabled = true;
          const res = await invokeCmd('trust_peer_device', {
            deviceId: peer.device_id,
            hostname: peer.hostname || peer.ip,
            ip: peer.ip,
            viaCable: !!peer.is_direct_cable,
          });
          appendLog(`🛡️ ${res}`, 'success');
          await updateStatus();
        } catch (err) {
          appendLog(`❌ Trust action failed: ${err}`, 'error');
        }
      });
      actions.appendChild(btnTrust);

      if (!peer.blocked) {
        const btnUsePin = document.createElement('button');
        btnUsePin.type = 'button';
        btnUsePin.className = 'btn-xs';
        btnUsePin.textContent = 'Pair with PIN';
        btnUsePin.addEventListener('click', () => {
          const inputPairIp = document.getElementById('input-pair-ip');
          const inputPairPin = document.getElementById('input-pair-pin');
          if (inputPairIp) inputPairIp.value = peer.ip;
          if (inputPairPin) inputPairPin.focus();
        });
        actions.appendChild(btnUsePin);
      }
    } else {
      const btnUntrust = document.createElement('button');
      btnUntrust.type = 'button';
      btnUntrust.className = 'btn-xs';
      btnUntrust.textContent = 'Untrust';
      btnUntrust.addEventListener('click', async () => {
        try {
          btnUntrust.disabled = true;
          const res = await invokeCmd('untrust_or_block_peer', {
            deviceId: peer.device_id,
            block: false,
          });
          appendLog(`🛡️ ${res}`, 'warn');
          await updateStatus();
        } catch (err) {
          appendLog(`❌ Untrust action failed: ${err}`, 'error');
        }
      });
      actions.appendChild(btnUntrust);
    }

    if (!peer.blocked) {
      const btnBlock = document.createElement('button');
      btnBlock.type = 'button';
      btnBlock.className = 'btn-xs btn-xs-danger';
      btnBlock.textContent = 'Block';
      btnBlock.addEventListener('click', async () => {
        try {
          btnBlock.disabled = true;
          const res = await invokeCmd('untrust_or_block_peer', {
            deviceId: peer.device_id,
            block: true,
          });
          appendLog(`🚫 ${res}`, 'warn');
          await updateStatus();
        } catch (err) {
          appendLog(`❌ Block action failed: ${err}`, 'error');
        }
      });
      actions.appendChild(btnBlock);
    }

    item.appendChild(top);
    item.appendChild(meta);
    item.appendChild(actions);
    container.appendChild(item);
  });
}

function renderSavedTrustedPeers(trustInfo, discoveredPeers) {
  const container = document.getElementById('saved-trusted-list');
  if (!container) return;

  const onlineIds = new Set((Array.isArray(discoveredPeers) ? discoveredPeers : []).map((p) => p.device_id));
  const offlineTrusted = (trustInfo && Array.isArray(trustInfo.trusted_peers) ? trustInfo.trusted_peers : [])
    .filter((p) => p && p.device_id && !onlineIds.has(p.device_id));
  const offlineBlocked = (trustInfo && Array.isArray(trustInfo.blocked_device_ids) ? trustInfo.blocked_device_ids : [])
    .filter((id) => id && !onlineIds.has(id));

  const sig = JSON.stringify({ offlineTrusted, offlineBlocked });
  if (sig === lastSavedTrustSignature) return;
  lastSavedTrustSignature = sig;

  clearElement(container);
  if (offlineTrusted.length === 0 && offlineBlocked.length === 0) {
    container.style.display = 'none';
    return;
  }

  container.style.display = 'flex';

  offlineTrusted.forEach((rec) => {
    const item = document.createElement('div');
    item.className = 'peer-item';

    const top = document.createElement('div');
    top.className = 'peer-item-top';

    const name = document.createElement('span');
    name.className = 'peer-item-name';
    name.textContent = `${rec.hostname || rec.device_id} (Saved Offline)`;

    const pill = document.createElement('span');
    pill.className = 'pill pill-idle';
    pill.textContent = 'Trusted';

    top.appendChild(name);
    top.appendChild(pill);

    const meta = document.createElement('div');
    meta.className = 'peer-item-meta selectable';
    meta.textContent = `Last IP: ${rec.last_ip || 'Unknown'}`;

    const actions = document.createElement('div');
    actions.className = 'peer-item-actions';

    const btnUntrust = document.createElement('button');
    btnUntrust.type = 'button';
    btnUntrust.className = 'btn-xs';
    btnUntrust.textContent = 'Untrust';
    btnUntrust.addEventListener('click', async () => {
      try {
        const res = await invokeCmd('untrust_or_block_peer', { deviceId: rec.device_id, block: false });
        appendLog(`🛡️ ${res}`, 'warn');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Untrust failed: ${err}`, 'error');
      }
    });

    const btnBlock = document.createElement('button');
    btnBlock.type = 'button';
    btnBlock.className = 'btn-xs btn-xs-danger';
    btnBlock.textContent = 'Block';
    btnBlock.addEventListener('click', async () => {
      try {
        const res = await invokeCmd('untrust_or_block_peer', { deviceId: rec.device_id, block: true });
        appendLog(`🚫 ${res}`, 'warn');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Block failed: ${err}`, 'error');
      }
    });

    actions.appendChild(btnUntrust);
    actions.appendChild(btnBlock);
    item.appendChild(top);
    item.appendChild(meta);
    item.appendChild(actions);
    container.appendChild(item);
  });

  offlineBlocked.forEach((devId) => {
    const item = document.createElement('div');
    item.className = 'peer-item';

    const top = document.createElement('div');
    top.className = 'peer-item-top';

    const name = document.createElement('span');
    name.className = 'peer-item-name selectable';
    name.textContent = `Blocked Device (${devId.slice(0, 12)})`;

    const btnUnblock = document.createElement('button');
    btnUnblock.type = 'button';
    btnUnblock.className = 'btn-xs';
    btnUnblock.textContent = 'Unblock';
    btnUnblock.addEventListener('click', async () => {
      try {
        const res = await invokeCmd('untrust_or_block_peer', { deviceId: devId, block: false });
        appendLog(`🛡️ ${res}`, 'info');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Unblock failed: ${err}`, 'error');
      }
    });

    top.appendChild(name);
    top.appendChild(btnUnblock);
    item.appendChild(top);
    container.appendChild(item);
  });
}

function resetTouchbarTelemetryVisuals(labelText = 'Peer Offline') {
  const visGpu = document.getElementById('tb-vis-gpu');
  const visTemp = document.getElementById('tb-vis-temp');
  const visPower = document.getElementById('tb-vis-power');
  const visClock = document.getElementById('tb-vis-clock');
  const visVram = document.getElementById('tb-vis-vram');
  const visFps = document.getElementById('tb-vis-fps');

  if (visGpu) visGpu.textContent = labelText;
  if (visTemp) visTemp.textContent = '🌡️ --°C';
  if (visPower) visPower.textContent = '⚡ --W';
  if (visClock) visClock.textContent = '🚀 -- MHz';
  if (visVram) visVram.textContent = '💾 -- / -- GB';
  if (visFps) visFps.textContent = '📊 --% GPU';
}

async function updateStatus() {
  try {
    const status = await invokeCmd('get_status');
    if (!status) return;
    latestStatus = status;

    // 0. Local Machine Summary in Header
    const localSummary = document.getElementById('local-machine-summary');
    if (localSummary) {
      const modelPart = status.hardware_model ? ` (${status.hardware_model})` : '';
      localSummary.textContent = `${status.hostname || 'Workstation'} • ${formatOsLabel(status.local_os)}${modelPart} • ${formatDisplay(status.primary_display)}`;
    }

    // 1. Peer & Link Header Status
    const connBadge = document.getElementById('connection-badge');
    const connText = document.getElementById('connection-text');
    const connSpeed = document.getElementById('connection-speed');
    const btnQuickSpeed = document.getElementById('btn-quick-speedtest');

    if (status.peer_connected && status.peer_ip) {
      if (connBadge) {
        connBadge.className = status.peer_trusted ? 'badge badge-connected' : 'badge badge-untrusted';
      }
      if (connText) {
        const peerName = status.peer_name ? `${status.peer_name} (${status.peer_ip})` : status.peer_ip;
        connText.textContent = status.peer_trusted ? peerName : `${peerName} • Untrusted`;
      }
      if (connSpeed) {
        const dynamicSpeed = status.link_speed_mbps != null && status.link_speed_mbps > 0
          ? formatSpeedMbps(status.link_speed_mbps)
          : 'Link Active';
        connSpeed.textContent = lastTestedSpeed ? `⚡ ${lastTestedSpeed} (Tested)` : `⚡ ${dynamicSpeed}`;
        connSpeed.style.display = 'inline-block';
      }
      if (btnQuickSpeed) btnQuickSpeed.style.display = 'inline-block';
    } else {
      if (connBadge) connBadge.className = 'badge badge-disconnected';
      if (connText) connText.textContent = 'Searching for Peer...';
      if (connSpeed) connSpeed.style.display = 'none';
      if (btnQuickSpeed) btnQuickSpeed.style.display = 'none';
    }

    // 2. Display Status & Dynamic Machine Context
    isDisplayActive = !!status.display_active;
    const dispDesc = document.getElementById('display-desc');
    const devLeftIcon = document.getElementById('dev-left-icon');
    const devLeftName = document.getElementById('dev-left-name');
    const devLeftRole = document.getElementById('dev-left-role');
    const streamArrowSpeed = document.getElementById('stream-arrow-speed');
    const devRightIcon = document.getElementById('dev-right-icon');
    const devRightName = document.getElementById('dev-right-name');
    const devRightRole = document.getElementById('dev-right-role');

    const dispBadge = document.getElementById('display-status-badge');
    const btnDisp = document.getElementById('btn-toggle-display');
    const btnDispLabel = document.getElementById('btn-display-label');
    const streamArrow = document.getElementById('stream-arrow');

    if (devLeftIcon) devLeftIcon.textContent = osIcon(status.local_os);
    if (devLeftName) devLeftName.textContent = status.hostname || 'Local Workstation';
    if (devLeftRole) {
      const modelStr = status.hardware_model ? ` • ${status.hardware_model}` : '';
      devLeftRole.textContent = `${formatOsLabel(status.local_os)}${modelStr} • ${formatDisplay(status.primary_display)}`;
    }

    if (status.peer_connected) {
      const peerLabel = status.peer_name || status.peer_ip || 'Peer';
      const peerModelStr = status.peer_hardware_model ? ` • ${status.peer_hardware_model}` : '';
      const peerDispStr = status.peer_display ? ` • ${formatDisplay(status.peer_display)}` : '';

      if (devRightIcon) devRightIcon.textContent = osIcon(status.peer_os);
      if (devRightName) devRightName.textContent = peerLabel;
      if (devRightRole) {
        devRightRole.textContent = `${formatOsLabel(status.peer_os)}${peerModelStr}${peerDispStr}`;
      }
      if (streamArrowSpeed) {
        streamArrowSpeed.textContent = isDisplayActive
          ? (status.active_mode || 'Streaming Active')
          : (status.peer_display ? formatDisplay(status.peer_display) : 'Ready');
      }
      if (dispDesc) {
        if (isDisplayActive && status.active_mode) {
          dispDesc.textContent = `Active: ${status.active_mode}`;
        } else {
          const dispTarget = status.peer_display ? formatDisplay(status.peer_display) : 'native display resolution';
          dispDesc.textContent = `Extend ${status.hostname || formatOsLabel(status.local_os)} desktop to ${peerLabel} (${dispTarget})`;
        }
      }
    } else {
      if (devRightIcon) devRightIcon.textContent = '📡';
      if (devRightName) devRightName.textContent = 'No Peer Connected';
      if (devRightRole) devRightRole.textContent = 'Connect cable or add peer IP';
      if (streamArrowSpeed) streamArrowSpeed.textContent = 'Offline';
      if (dispDesc) {
        dispDesc.textContent = `Extend ${status.hostname || formatOsLabel(status.local_os)} (${formatDisplay(status.primary_display)}) to a discovered peer`;
      }
    }

    renderGpuControls(status);

    if (isDisplayActive) {
      setCardPill(dispBadge, 'Streaming Active', 'pill-active');
      if (btnDisp) btnDisp.className = 'btn btn-primary btn-active-stop';
      if (btnDispLabel) btnDispLabel.textContent = 'Disconnect Extended Desktop';
      if (streamArrow) streamArrow.style.opacity = '1';
    } else {
      setCardPill(dispBadge, 'Idle', 'pill-idle');
      if (btnDisp) btnDisp.className = 'btn btn-primary';
      if (btnDispLabel) {
        if (status.peer_connected) {
          const localShort = formatShortOs(status.local_os, status.hostname || 'Local');
          const peerShort = status.peer_name || formatShortOs(status.peer_os, 'Peer');
          const dispSuffix = status.peer_display && status.peer_display.width > 0
            ? ` (${formatDisplay(status.peer_display)})`
            : '';
          btnDispLabel.textContent = `${localShort} -> ${peerShort}${dispSuffix}`;
        } else {
          btnDispLabel.textContent = 'Start Display Bridge';
        }
      }
      if (streamArrow) streamArrow.style.opacity = '0.4';
    }

    // 3. Touch Bar HUD State & Hardware Detection
    const tbStateBadge = document.getElementById('touchbar-state-badge');
    const btnTb = document.getElementById('btn-toggle-touchbar');
    const btnTbLabel = document.getElementById('btn-touchbar-label');
    const chkTbScope = document.getElementById('chk-touchbar-scope');
    const chkTbGlass = document.getElementById('chk-touchbar-liquid-glass');

    if (tbStateBadge && btnTb && btnTbLabel) {
      if (!status.has_touch_bar) {
        setCardPill(tbStateBadge, 'Not detected on this Mac', 'pill-idle');
        btnTb.className = 'btn btn-primary';
        btnTb.disabled = true;
        btnTbLabel.textContent = 'Not detected on this Mac';
        if (chkTbScope) chkTbScope.disabled = true;
        if (chkTbGlass) chkTbGlass.disabled = true;
      } else {
        btnTb.disabled = false;
        if (chkTbScope) chkTbScope.disabled = false;
        if (chkTbGlass) chkTbGlass.disabled = false;

        if (status.touchbar_active) {
          setCardPill(tbStateBadge, 'Liquid Glass Active', 'pill-active');
          btnTb.className = 'btn btn-primary btn-active-stop';
          btnTbLabel.textContent = 'Disable Touch Bar GPU HUD';
        } else {
          btnTb.className = 'btn btn-primary';
          if (status.is_windows_master) {
            setCardPill(tbStateBadge, 'Peer Master Active', 'pill-active');
            btnTbLabel.textContent = 'Enable Touch Bar GPU HUD';
          } else {
            setCardPill(tbStateBadge, 'Peer Master Inactive', 'pill-idle');
            btnTbLabel.textContent = 'Enable Touch Bar GPU HUD (Peer Master Only)';
          }
        }
      }
    }

    // 4. True Tone & Ambient Light Sensor
    const valAmbientCct = document.getElementById('val-ambient-cct');
    const valAmbientLux = document.getElementById('val-ambient-lux');
    const truetonePill = document.getElementById('truetone-status-pill');

    if (status.ambient_supported) {
      if (valAmbientCct) {
        valAmbientCct.textContent = status.ambient_cct != null ? `${status.ambient_cct} K` : '-- K';
      }
      if (valAmbientLux) {
        valAmbientLux.textContent = status.ambient_lux != null ? `${Math.round(status.ambient_lux)} Lux` : '-- Lux';
      }
      setCardPill(truetonePill, 'ALS Active', 'pill-active');
    } else {
      if (valAmbientCct) valAmbientCct.textContent = '-- K';
      if (valAmbientLux) valAmbientLux.textContent = 'Unsupported';
      setCardPill(truetonePill, 'Manual CCT', 'pill-idle');
    }

    // 5. Shared Storage Status & Override Input
    const storageStatusPill = document.getElementById('storage-status-pill');
    const storageMountPath = document.getElementById('storage-mount-path');
    const storageMountSub = document.getElementById('storage-mount-sub');
    const storageRemoteShare = document.getElementById('storage-remote-share');
    const storageRemoteSub = document.getElementById('storage-remote-sub');
    const btnMountLabel = document.getElementById('btn-mount-storage-label');
    const inputPeerShare = document.getElementById('input-peer-share');

    const st = status.storage_status || {};
    if (status.storage_mounted || st.is_mounted) {
      setCardPill(storageStatusPill, 'Mounted Active', 'pill-active');
    } else {
      setCardPill(storageStatusPill, 'Volume Ready', 'pill-idle');
    }

    if (storageMountPath) {
      storageMountPath.textContent = (st.is_mounted && st.mount_path) ? st.mount_path : 'Not mounted';
    }
    if (storageMountSub) {
      storageMountSub.textContent = st.message || 'Ready to mount peer shared folder';
    }

    const remoteIp = st.remote_ip || status.peer_ip || '';
    const effectiveShare = (st.remote_share && st.remote_share !== 'Not configured')
      ? st.remote_share
      : (status.preferred_peer_share || status.peer_share_name || '');

    if (storageRemoteShare) {
      if (remoteIp && effectiveShare) {
        storageRemoteShare.textContent = `//${remoteIp}/${effectiveShare}`;
      } else if (effectiveShare) {
        storageRemoteShare.textContent = effectiveShare;
      } else {
        storageRemoteShare.textContent = 'Not configured';
      }
    }

    if (storageRemoteSub) {
      if (status.preferred_peer_share) {
        storageRemoteSub.textContent = `Manual override active: ${status.preferred_peer_share}`;
      } else if (status.peer_share_name) {
        storageRemoteSub.textContent = `Discovered from peer: ${status.peer_share_name}`;
      } else if (Array.isArray(status.local_share_names) && status.local_share_names.length > 0) {
        storageRemoteSub.textContent = `Local shares: ${status.local_share_names.join(', ')}`;
      } else {
        storageRemoteSub.textContent = 'Enter override or enable SMB file sharing on peer';
      }
    }

    if (btnMountLabel) {
      if (remoteIp && effectiveShare) {
        btnMountLabel.textContent = `Mount //${remoteIp}/${effectiveShare}`;
      } else if (effectiveShare) {
        btnMountLabel.textContent = `Mount ${effectiveShare}`;
      } else {
        btnMountLabel.textContent = 'Mount Shared Peer Volume';
      }
    }

    if (inputPeerShare && !shareInputDirty && document.activeElement !== inputPeerShare) {
      inputPeerShare.value = status.preferred_peer_share || '';
    }

    // 6. Route & Link Telemetry Card
    const benchmarkBadge = document.getElementById('benchmark-status-badge');
    const btnRunSpeedtest = document.getElementById('btn-run-speedtest');
    if (status.peer_connected) {
      setCardPill(benchmarkBadge, 'Link Active', 'pill-active');
    } else {
      setCardPill(benchmarkBadge, 'Searching', 'pill-idle');
    }
    if (btnRunSpeedtest) {
      btnRunSpeedtest.disabled = isTestingSpeed || !status.peer_connected;
    }
    renderNetworkRoutes(status);

    // 7. Direct & LAN Peer Setup + Trust Card
    const peerTrustPill = document.getElementById('peer-trust-pill');
    if (peerTrustPill) {
      if (status.peer_connected && status.peer_trusted) {
        setCardPill(peerTrustPill, 'Peer Trusted', 'pill-active');
      } else if (status.peer_connected && !status.peer_trusted) {
        setCardPill(peerTrustPill, 'Approval Needed', 'pill-warning');
      } else {
        setCardPill(peerTrustPill, 'Pairing Ready', 'pill-idle');
      }
    }

    renderLocalInterfaces(status.local_interfaces);
    renderManualPeerIps(status.manual_peer_ips);
    renderDiscoveredPeers(status.discovered_peers);
    renderSavedTrustedPeers(status.trust, status.discovered_peers);

    const trust = status.trust || {};
    const pairingPinCode = document.getElementById('pairing-pin-code');
    if (pairingPinCode) {
      pairingPinCode.textContent = trust.pairing_pin || '------';
    }

    const chkAutoTrustCable = document.getElementById('chk-auto-trust-cable');
    const chkRequireLanPairing = document.getElementById('chk-require-lan-pairing');
    if (chkAutoTrustCable && document.activeElement !== chkAutoTrustCable && typeof trust.auto_trust_direct_cable === 'boolean') {
      chkAutoTrustCable.checked = trust.auto_trust_direct_cable;
    }
    if (chkRequireLanPairing && document.activeElement !== chkRequireLanPairing && typeof trust.require_pairing_on_lan === 'boolean') {
      chkRequireLanPairing.checked = trust.require_pairing_on_lan;
    }

    // 8. Launch at Login Sync
    const toggleAutostart = document.getElementById('toggle-autostart');
    if (toggleAutostart && document.activeElement !== toggleAutostart) {
      toggleAutostart.checked = !!status.autostart_enabled;
    }
  } catch (e) {
    // ignore polling error
  }
}

document.addEventListener('DOMContentLoaded', () => {
  updateFilterTabCounts();
  appendLog('🚀 Integrator dashboard initialized — listening across active interfaces', 'info');

  const btnToggleDisplay = document.getElementById('btn-toggle-display');
  const btnOpenCache = document.getElementById('btn-open-cache');
  const btnClearLogs = document.getElementById('btn-clear-logs');
  const btnHideWindow = document.getElementById('btn-hide-window');
  const selectEncodeGpu = document.getElementById('select-encode-gpu');
  const selectDecodeGpu = document.getElementById('select-decode-gpu');
  const btnRunSpeedtest = document.getElementById('btn-run-speedtest');
  const btnQuickSpeedtest = document.getElementById('btn-quick-speedtest');
  const toggleAutostart = document.getElementById('toggle-autostart');

  if (toggleAutostart) {
    toggleAutostart.addEventListener('change', async () => {
      const enable = toggleAutostart.checked;
      try {
        appendLog(enable ? '🚀 Configuring Launch at Login...' : '🚀 Removing Launch at Login...', 'info');
        const res = await invokeCmd('set_autostart', { enabled: enable });
        toggleAutostart.checked = !!res;
        appendLog(res ? '🚀 Launch at Login ENABLED' : '🚀 Launch at Login DISABLED', 'success');
      } catch (e) {
        appendLog(`❌ Failed to update Launch at Login: ${e}`, 'error');
        toggleAutostart.checked = !enable;
      }
    });
  }

  async function executeSpeedTest() {
    if (isTestingSpeed) return;
    isTestingSpeed = true;

    const btnLabel = document.getElementById('speedtest-btn-label');
    const btnIcon = document.getElementById('speedtest-btn-icon');
    const subtitle = document.getElementById('speedtest-subtitle');
    const metricMax = document.getElementById('metric-max-speed');
    const metricUp = document.getElementById('metric-upload-speed');
    const metricDown = document.getElementById('metric-download-speed');
    const metricLatency = document.getElementById('metric-latency');

    if (btnRunSpeedtest) btnRunSpeedtest.disabled = true;
    if (btnQuickSpeedtest) btnQuickSpeedtest.disabled = true;
    if (btnLabel) btnLabel.textContent = 'Testing...';
    if (btnIcon) {
      btnIcon.textContent = '⏳';
      btnIcon.classList.add('testing-pulse');
    }
    if (subtitle) subtitle.textContent = 'Streaming 64 MB zero-copy buffers over TCP port 58285...';

    appendLog('⚡ Starting live link throughput benchmark (zero-copy TCP)...', 'info');

    try {
      const res = await invokeCmd('run_speed_test');
      if (res && res.success) {
        const peakGbps = res.max_gbps.toFixed(2);
        lastTestedSpeed = `${peakGbps} Gbps`;

        if (metricMax) {
          metricMax.textContent = `${peakGbps} Gbps`;
          metricMax.classList.add('highlight');
        }
        if (metricUp) {
          metricUp.textContent = `${res.upload_mb_s.toFixed(0)} MB/s`;
        }
        if (metricDown) {
          metricDown.textContent = `${res.download_mb_s.toFixed(0)} MB/s`;
        }
        if (metricLatency) {
          metricLatency.textContent = `${res.latency_ms.toFixed(2)} ms`;
        }

        const connSpeed = document.getElementById('connection-speed');
        if (connSpeed) {
          connSpeed.textContent = `⚡ ${peakGbps} Gbps (Tested)`;
        }

        if (subtitle) subtitle.textContent = `Tested: ${res.summary}`;
        appendLog(`⚡ Benchmark Complete: ${res.summary}`, 'success');
      } else {
        appendLog('⚠️ Benchmark did not return success', 'warn');
      }
    } catch (err) {
      appendLog(`❌ Speed test failed: ${err}`, 'error');
      if (subtitle) subtitle.textContent = `Benchmark error: ${err}`;
    } finally {
      isTestingSpeed = false;
      if (btnRunSpeedtest) btnRunSpeedtest.disabled = !latestStatus?.peer_connected;
      if (btnQuickSpeedtest) btnQuickSpeedtest.disabled = false;
      if (btnLabel) btnLabel.textContent = 'Test Speed';
      if (btnIcon) {
        btnIcon.textContent = '⚡';
        btnIcon.classList.remove('testing-pulse');
      }
    }
  }

  if (btnRunSpeedtest) btnRunSpeedtest.addEventListener('click', executeSpeedTest);
  if (btnQuickSpeedtest) btnQuickSpeedtest.addEventListener('click', executeSpeedTest);

  async function handleGpuChange() {
    if (!selectEncodeGpu || !selectDecodeGpu) return;
    if (!latestStatus || !latestStatus.gpu_controls_supported) return;
    try {
      const res = await invokeCmd('set_gpu_preferences', {
        encodeGpu: selectEncodeGpu.value,
        decodeGpu: selectDecodeGpu.value,
      });
      appendLog(`⚙️ ${res}`, 'success');
      await updateStatus();
    } catch (e) {
      appendLog(`❌ Failed to update GPU preferences: ${e}`, 'error');
    }
  }

  if (selectEncodeGpu) selectEncodeGpu.addEventListener('change', handleGpuChange);
  if (selectDecodeGpu) selectDecodeGpu.addEventListener('change', handleGpuChange);

  if (btnToggleDisplay) {
    btnToggleDisplay.addEventListener('click', async () => {
      try {
        appendLog(isDisplayActive ? 'Stopping extended display...' : 'Starting extended display...', 'info');
        btnToggleDisplay.disabled = true;
        const res = await invokeCmd('toggle_display');
        if (res) appendLog(`🖥️ ${res}`, 'success');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Display toggle failed: ${err}`, 'error');
      } finally {
        btnToggleDisplay.disabled = false;
      }
    });
  }

  if (btnOpenCache) {
    btnOpenCache.addEventListener('click', async () => {
      try {
        await invokeCmd('open_cache_folder');
        appendLog('📁 Opened clipboard cache directory', 'info');
      } catch (err) {
        appendLog(`❌ Failed to open cache: ${err}`, 'error');
      }
    });
  }

  if (btnHideWindow) {
    btnHideWindow.addEventListener('click', async () => {
      try {
        await invokeCmd('hide_window');
      } catch (e) {
        console.error(e);
      }
    });
  }

  if (btnClearLogs) {
    btnClearLogs.addEventListener('click', () => {
      clearElement(document.getElementById('logs-container'));
    });
  }

  // Filter Tabs Logic
  const filterTabs = document.querySelectorAll('.filter-tab');
  const allCards = document.querySelectorAll('.grid .card');

  filterTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      filterTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');

      const filter = tab.getAttribute('data-filter');
      allCards.forEach((card) => {
        const cats = (card.getAttribute('data-category') || '').split(/\s+/);
        const status = card.getAttribute('data-status') || '';

        if (filter === 'all') {
          card.style.display = 'flex';
        } else if (filter === 'active') {
          card.style.display = status === 'active' ? 'flex' : 'none';
        } else if (cats.includes(filter)) {
          card.style.display = 'flex';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });

  // Segmented Controls (Roadmap KVM edge preview)
  document.querySelectorAll('.segmented-control').forEach((control) => {
    control.querySelectorAll('.segment').forEach((btn) => {
      btn.addEventListener('click', () => {
        control.querySelectorAll('.segment').forEach((s) => s.classList.remove('active'));
        btn.classList.add('active');
        const edge = btn.getAttribute('data-edge');
        appendLog(`🖱️ Edge boundary set to: ${edge === 'right' ? 'Right (Local ➔ Peer)' : 'Left (Peer ➔ Local)'}`, 'info');
      });
    });
  });

  // Audio Topology Preview Selection
  document.querySelectorAll('.audio-topology-item').forEach((item) => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.audio-topology-item').forEach((i) => i.classList.remove('active'));
      item.classList.add('active');
      const title = item.querySelector('.topology-title')?.textContent || 'Audio Preview';
      appendLog(`🔊 Audio sink preview mode selected: ${title}`, 'info');
    });
  });

  // Live Sliders
  const sliderHopDelay = document.getElementById('slider-hop-delay');
  const valHopDelay = document.getElementById('val-hop-delay');
  if (sliderHopDelay && valHopDelay) {
    sliderHopDelay.addEventListener('input', () => {
      valHopDelay.textContent = `${sliderHopDelay.value} ms`;
    });
  }

  const sliderGammaComp = document.getElementById('slider-gamma-comp');
  const valGammaComp = document.getElementById('val-gamma-comp');
  if (sliderGammaComp && valGammaComp) {
    sliderGammaComp.addEventListener('input', () => {
      valGammaComp.textContent = `${(sliderGammaComp.value / 100).toFixed(2)}×`;
    });
  }

  const sliderAudioOffset = document.getElementById('slider-audio-offset');
  const valAudioOffset = document.getElementById('val-audio-offset');
  if (sliderAudioOffset && valAudioOffset) {
    sliderAudioOffset.addEventListener('input', () => {
      valAudioOffset.textContent = `${sliderAudioOffset.value} ms`;
    });
  }

  // Storage Mount / Unmount / Preferred Peer Share Override
  const btnMountStorage = document.getElementById('btn-mount-storage');
  const btnUnmountStorage = document.getElementById('btn-unmount-storage');
  const inputPeerShare = document.getElementById('input-peer-share');
  const btnSavePeerShare = document.getElementById('btn-save-peer-share');
  const btnClearPeerShare = document.getElementById('btn-clear-peer-share');

  if (inputPeerShare) {
    inputPeerShare.addEventListener('input', () => {
      shareInputDirty = true;
    });
    inputPeerShare.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        btnSavePeerShare?.click();
      }
    });
  }

  if (btnSavePeerShare) {
    btnSavePeerShare.addEventListener('click', async () => {
      const val = inputPeerShare ? inputPeerShare.value.trim() : '';
      try {
        btnSavePeerShare.disabled = true;
        const saved = await invokeCmd('set_preferred_peer_share', { share: val || null });
        shareInputDirty = false;
        if (inputPeerShare) inputPeerShare.value = saved || '';
        appendLog(saved ? `📂 Peer SMB share override saved: ${saved}` : '📂 Cleared peer SMB share override (using auto-discovery)', 'success');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Failed to save peer share override: ${e}`, 'error');
      } finally {
        btnSavePeerShare.disabled = false;
      }
    });
  }

  if (btnClearPeerShare) {
    btnClearPeerShare.addEventListener('click', async () => {
      try {
        btnClearPeerShare.disabled = true;
        await invokeCmd('set_preferred_peer_share', { share: null });
        shareInputDirty = false;
        if (inputPeerShare) inputPeerShare.value = '';
        appendLog('📂 Reset peer SMB share override to auto-discovery', 'info');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Failed to reset peer share override: ${e}`, 'error');
      } finally {
        btnClearPeerShare.disabled = false;
      }
    });
  }

  if (btnMountStorage) {
    btnMountStorage.addEventListener('click', async () => {
      try {
        appendLog('📂 Mounting shared peer SMB volume...', 'info');
        btnMountStorage.disabled = true;
        const res = await invokeCmd('mount_shared_storage');
        if (res && res.is_mounted) {
          appendLog(`📂 ${res.message}`, 'success');
        } else if (res) {
          appendLog(`ℹ️ ${res.message}`, 'info');
        }
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Storage mount error: ${e}`, 'error');
      } finally {
        btnMountStorage.disabled = false;
      }
    });
  }

  if (btnUnmountStorage) {
    btnUnmountStorage.addEventListener('click', async () => {
      try {
        appendLog('⏏️ Unmounting shared network storage...', 'info');
        btnUnmountStorage.disabled = true;
        const res = await invokeCmd('unmount_shared_storage');
        if (res) appendLog(`⏏️ ${res.message}`, 'info');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Storage unmount error: ${e}`, 'error');
      } finally {
        btnUnmountStorage.disabled = false;
      }
    });
  }

  // Peer Setup + Trust Actions
  const btnRegeneratePin = document.getElementById('btn-regenerate-pin');
  const chkAutoTrustCable = document.getElementById('chk-auto-trust-cable');
  const chkRequireLanPairing = document.getElementById('chk-require-lan-pairing');
  const inputManualPeerIp = document.getElementById('input-manual-peer-ip');
  const btnAddManualIp = document.getElementById('btn-add-manual-ip');
  const inputPairIp = document.getElementById('input-pair-ip');
  const inputPairPin = document.getElementById('input-pair-pin');
  const btnPairPeer = document.getElementById('btn-pair-peer');

  if (btnRegeneratePin) {
    btnRegeneratePin.addEventListener('click', async () => {
      try {
        btnRegeneratePin.disabled = true;
        const newPin = await invokeCmd('regenerate_pairing_pin');
        const pairingPinCode = document.getElementById('pairing-pin-code');
        if (pairingPinCode && newPin) pairingPinCode.textContent = newPin;
        appendLog('🔑 Generated new 6-digit pairing PIN', 'info');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Failed to regenerate PIN: ${e}`, 'error');
      } finally {
        btnRegeneratePin.disabled = false;
      }
    });
  }

  async function handleTrustPolicyChange() {
    if (!chkAutoTrustCable || !chkRequireLanPairing) return;
    try {
      const res = await invokeCmd('set_trust_policy', {
        autoTrustCable: chkAutoTrustCable.checked,
        requireLanPairing: chkRequireLanPairing.checked,
      });
      if (res) appendLog(`🛡️ ${res}`, 'success');
      await updateStatus();
    } catch (e) {
      appendLog(`❌ Failed to update trust policy: ${e}`, 'error');
    }
  }

  if (chkAutoTrustCable) chkAutoTrustCable.addEventListener('change', handleTrustPolicyChange);
  if (chkRequireLanPairing) chkRequireLanPairing.addEventListener('change', handleTrustPolicyChange);

  if (btnAddManualIp) {
    btnAddManualIp.addEventListener('click', async () => {
      const ip = inputManualPeerIp ? inputManualPeerIp.value.trim() : '';
      if (!ip) {
        appendLog('⚠️ Enter a peer IPv4 address first', 'warn');
        return;
      }
      try {
        btnAddManualIp.disabled = true;
        await invokeCmd('add_manual_peer_ip', { ip });
        if (inputManualPeerIp) inputManualPeerIp.value = '';
        appendLog(`🌐 Added manual peer IP ${ip}`, 'success');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Invalid or unreachable peer IP: ${e}`, 'error');
      } finally {
        btnAddManualIp.disabled = false;
      }
    });
  }

  if (inputManualPeerIp) {
    inputManualPeerIp.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        btnAddManualIp?.click();
      }
    });
  }

  if (btnPairPeer) {
    btnPairPeer.addEventListener('click', async () => {
      const ip = inputPairIp ? inputPairIp.value.trim() : '';
      const pin = inputPairPin ? inputPairPin.value.trim() : '';
      if (!ip || !pin) {
        appendLog('⚠️ Enter both peer IPv4 and 6-digit PIN', 'warn');
        return;
      }
      try {
        btnPairPeer.disabled = true;
        const res = await invokeCmd('pair_with_peer', { ip, pin });
        if (inputPairPin) inputPairPin.value = '';
        appendLog(`🔑 ${res}`, 'success');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ Pairing failed: ${e}`, 'error');
      } finally {
        btnPairPeer.disabled = false;
      }
    });
  }

  if (inputPairPin) {
    inputPairPin.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        btnPairPeer?.click();
      }
    });
  }

  // True Tone & Audio Actions
  const btnCalibrateTruetone = document.getElementById('btn-calibrate-truetone');
  const btnTestChime = document.getElementById('btn-test-chime');

  if (btnCalibrateTruetone) {
    btnCalibrateTruetone.addEventListener('click', async () => {
      try {
        appendLog('🎨 Reading Ambient Light Sensor and computing Bradford CAT matrix...', 'info');
        btnCalibrateTruetone.disabled = true;
        const als = await invokeCmd('get_ambient_light');
        const cct = (als && als.supported && als.cct_kelvin) ? als.cct_kelvin : 6500;
        const gammaComp = sliderGammaComp ? (sliderGammaComp.value / 100) : 1.05;

        const res = await invokeCmd('apply_truetone_calibration', {
          cct,
          compFactor: gammaComp,
        });
        appendLog(`🎨 ${res}`, 'success');
        await updateStatus();
      } catch (e) {
        appendLog(`❌ True Tone calibration error: ${e}`, 'error');
      } finally {
        btnCalibrateTruetone.disabled = false;
      }
    });
  }

  if (btnTestChime) {
    btnTestChime.addEventListener('click', async () => {
      try {
        appendLog('🎵 Synthesizing 24-bit 48kHz test chime...', 'info');
        btnTestChime.disabled = true;
        const res = await invokeCmd('play_spatial_chime');
        appendLog(`🔊 ${res}`, 'success');
      } catch (e) {
        appendLog(`❌ Audio playback error: ${e}`, 'error');
      } finally {
        btnTestChime.disabled = false;
      }
    });
  }

  // Mock Action Buttons for Roadmap Preview Cards
  document.querySelectorAll('.btn-mock').forEach((btn) => {
    btn.addEventListener('click', () => {
      const action = btn.getAttribute('data-action');
      const localHost = latestStatus?.hostname || 'local workstation';
      const peerHost = latestStatus?.peer_name || latestStatus?.peer_ip || 'peer workstation';
      switch (action) {
        case 'test-kvm':
          appendLog(`🖱️ Roadmap preview: Cursor edge-hop simulated between ${localHost} and ${peerHost}`, 'info');
          break;
        case 'test-dragdrop':
          appendLog(`🪂 Roadmap preview: Cross-border drop simulated between ${localHost} and ${peerHost}`, 'info');
          break;
        case 'test-touchid':
          appendLog('🔑 Roadmap preview: Biometric challenge simulation triggered', 'info');
          break;
        case 'test-camera':
          appendLog(`🎥 Roadmap preview: Camera & mic pipeline preview (${localHost} ⇄ ${peerHost})`, 'info');
          break;
        case 'test-multiwan':
          appendLog('🌐 Roadmap preview: Multi-WAN route aggregation simulation triggered', 'info');
          break;
        default:
          appendLog(`⚡ Preview triggered: ${action}`, 'info');
      }
    });
  });

  // Touch Bar HUD Toggle
  const btnToggleTouchbar = document.getElementById('btn-toggle-touchbar');
  const chkTouchbarScope = document.getElementById('chk-touchbar-scope');

  if (btnToggleTouchbar) {
    btnToggleTouchbar.addEventListener('click', async () => {
      if (latestStatus && !latestStatus.has_touch_bar) {
        appendLog('⚠️ Touch Bar hardware was not detected on this device', 'warn');
        return;
      }
      try {
        const strictScope = chkTouchbarScope ? chkTouchbarScope.checked : true;
        appendLog('📊 Toggling Touch Bar GPU HUD...', 'info');
        btnToggleTouchbar.disabled = true;

        const res = await invokeCmd('toggle_touchbar_hud', { force: !strictScope });
        appendLog(`🚀 ${res}`, 'success');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Touch Bar requirement error: ${err}`, 'warn');
      } finally {
        if (!latestStatus || latestStatus.has_touch_bar) {
          btnToggleTouchbar.disabled = false;
        }
      }
    });
  }

  // Periodic GPU Telemetry Updater for Dashboard Visualizer
  async function updateGpuTelemetry() {
    if (latestStatus && !latestStatus.peer_connected && latestStatus.local_os !== 'windows') {
      resetTouchbarTelemetryVisuals('Peer Offline');
      return;
    }
    try {
      const data = await invokeCmd('get_gpu_telemetry');
      if (data) {
        const visGpu = document.getElementById('tb-vis-gpu');
        const visTemp = document.getElementById('tb-vis-temp');
        const visPower = document.getElementById('tb-vis-power');
        const visClock = document.getElementById('tb-vis-clock');
        const visVram = document.getElementById('tb-vis-vram');
        const visFps = document.getElementById('tb-vis-fps');

        if (visGpu) visGpu.textContent = data.gpu_name || 'GPU';
        if (visTemp) visTemp.textContent = data.temperature_c > 0 ? `🌡️ ${data.temperature_c}°C` : '🌡️ --°C';
        if (visPower) visPower.textContent = data.power_usage_watts > 0 ? `⚡ ${data.power_usage_watts.toFixed(1)}W` : '⚡ --W';
        if (visClock) visClock.textContent = data.core_clock_mhz > 0 ? `🚀 ${data.core_clock_mhz} MHz` : '🚀 -- MHz';
        if (visVram) {
          if (data.memory_total_mb > 0) {
            const usedGb = (data.memory_used_mb / 1024).toFixed(1);
            const totalGb = (data.memory_total_mb / 1024).toFixed(1);
            visVram.textContent = `💾 ${usedGb} / ${totalGb} GB`;
          } else {
            visVram.textContent = '💾 -- / -- GB';
          }
        }
        if (visFps) {
          const hasLiveLoad = data.gpu_utilization_percent > 0 || data.temperature_c > 0 || data.core_clock_mhz > 0;
          visFps.textContent = hasLiveLoad ? `📊 ${data.gpu_utilization_percent}% GPU` : '📊 --% GPU';
        }
      } else {
        resetTouchbarTelemetryVisuals('Peer Offline');
      }
    } catch (_) {
      resetTouchbarTelemetryVisuals('Telemetry N/A');
    }
  }

  // Master Feature On/Off Switches
  function applyFeatureFlagsToUI(flags) {
    document.querySelectorAll('.feature-master-toggle').forEach((toggle) => {
      const feature = toggle.getAttribute('data-feature');
      const isEnabled = flags[feature] !== false;
      toggle.checked = isEnabled;

      const card = toggle.closest('.card');
      if (!card) return;

      const pill = card.querySelector('.pill');
      if (pill && !pill.getAttribute('data-original-text')) {
        pill.setAttribute('data-original-text', pill.textContent);
        pill.setAttribute('data-original-class', pill.className);
      }

      if (isEnabled) {
        card.classList.remove('card-disabled');
        if (pill && pill.getAttribute('data-original-text')) {
          pill.textContent = pill.getAttribute('data-original-text');
          if (pill.getAttribute('data-original-class')) {
            pill.className = pill.getAttribute('data-original-class');
          }
        }
      } else {
        card.classList.add('card-disabled');
        if (pill) {
          pill.textContent = 'Disabled';
          pill.className = 'pill pill-idle';
        }
      }
    });
  }

  async function initFeatureFlags() {
    try {
      const flags = await invokeCmd('get_feature_flags');
      if (flags) {
        applyFeatureFlagsToUI(flags);
      }
    } catch (e) {
      console.warn('Failed to load feature flags:', e);
    }
  }

  document.querySelectorAll('.feature-master-toggle').forEach((toggle) => {
    toggle.addEventListener('change', async (e) => {
      e.stopPropagation();
      const feature = toggle.getAttribute('data-feature');
      const enabled = toggle.checked;
      const card = toggle.closest('.card');
      const title = card?.querySelector('h2')?.textContent || feature;

      const pill = card?.querySelector('.pill');
      if (enabled) {
        card?.classList.remove('card-disabled');
        if (pill && pill.getAttribute('data-original-text')) {
          pill.textContent = pill.getAttribute('data-original-text');
          if (pill.getAttribute('data-original-class')) {
            pill.className = pill.getAttribute('data-original-class');
          }
        }
        appendLog(`🟢 Master Switch: Enabled "${title}"`, 'success');
      } else {
        card?.classList.add('card-disabled');
        if (pill) {
          if (!pill.getAttribute('data-original-text')) {
            pill.setAttribute('data-original-text', pill.textContent);
            pill.setAttribute('data-original-class', pill.className);
          }
          pill.textContent = 'Disabled';
          pill.className = 'pill pill-idle';
        }
        appendLog(`⚪ Master Switch: Disabled "${title}"`, 'warn');
      }

      try {
        const updated = await invokeCmd('set_feature_flag', { feature, enabled });
        if (updated) {
          applyFeatureFlagsToUI(updated);
        }
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Failed to set master switch: ${err}`, 'error');
      }
    });
  });

  // Poll status every 2 seconds & telemetry every 3 seconds
  initFeatureFlags();
  updateStatus();
  updateGpuTelemetry();
  setInterval(updateStatus, 2000);
  setInterval(updateGpuTelemetry, 3000);
});
