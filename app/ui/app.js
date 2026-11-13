// Mac-Windows Fusion Bridge UI Logic (Tauri v2)

let isDisplayActive = false;
let isTestingSpeed = false;
let lastTestedSpeed = null;

// Fallback invoke helper for Tauri v2
async function invokeCmd(command, args = {}) {
  try {
    if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
      return await window.__TAURI__.core.invoke(command, args);
    } else if (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke) {
      return await window.__TAURI_INTERNALS__.invoke(command, args);
    } else {
      console.warn("Tauri IPC not available in standard browser mode:", command, args);
      return null;
    }
  } catch (err) {
    console.error(`Error invoking ${command}:`, err);
    throw err;
  }
}

function appendLog(message, type = 'info') {
  const container = document.getElementById('logs-container');
  if (!container) return;
  const now = new Date();
  const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
  
  const line = document.createElement('div');
  line.className = `log-line ${type}`;
  line.innerHTML = `<span class="log-time">${timeStr}</span> ${message}`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

async function updateStatus() {
  try {
    const status = await invokeCmd('get_status');
    if (!status) return;

    // 1. Peer & Link Status
    const connBadge = document.getElementById('connection-badge');
    const connText = document.getElementById('connection-text');
    const connSpeed = document.getElementById('connection-speed');
    const btnQuickSpeed = document.getElementById('btn-quick-speedtest');
    const usbPing = document.getElementById('usb-ping');

    if (status.peer_connected) {
      connBadge.className = 'badge badge-connected';
      connText.innerText = status.peer_ip;
      if (connSpeed) {
        connSpeed.innerText = lastTestedSpeed ? `⚡ ${lastTestedSpeed} (Tested)` : `⚡ ${status.link_speed}`;
        connSpeed.style.display = 'inline-block';
      }
      if (btnQuickSpeed) btnQuickSpeed.style.display = 'inline-block';
      if (usbPing) usbPing.innerText = status.rtt_ms ? `${status.rtt_ms.toFixed(1)} ms` : '< 1 ms';
    } else {
      connBadge.className = 'badge';
      connBadge.style.background = 'rgba(239, 68, 68, 0.15)';
      connBadge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
      connBadge.style.color = '#f87171';
      connText.innerText = 'Searching for Peer...';
      if (connSpeed) connSpeed.style.display = 'none';
      if (btnQuickSpeed) btnQuickSpeed.style.display = 'none';
    }

    // 2. Display Status & Machine Context
    isDisplayActive = status.display_active;
    const isWindows = status.local_os === 'windows';

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
    const gpuControls = document.getElementById('gpu-controls');
    const selectEncodeGpu = document.getElementById('select-encode-gpu');
    const selectDecodeGpu = document.getElementById('select-decode-gpu');

    if (isWindows) {
      if (dispDesc) dispDesc.innerText = 'Stream Windows Desktop to MacBook Pro via Intel QuickSync @ 60Hz';
      if (devLeftIcon) devLeftIcon.innerText = '🎮';
      if (devLeftName) devLeftName.innerText = 'HP OMEN 16" (Host)';
      if (devLeftRole) devLeftRole.innerText = status.encode_gpu === 'nvidia' ? 'NVIDIA RTX 5070 NVENC' : 'Intel Arc 140T QuickSync';
      if (streamArrowSpeed) streamArrowSpeed.innerText = status.encode_gpu === 'nvidia' ? '60Hz NVIDIA NVENC' : '60Hz Intel QuickSync';
      if (devRightIcon) devRightIcon.innerText = '💻';
      if (devRightName) devRightName.innerText = 'MacBook Pro (M1)';
      if (devRightRole) devRightRole.innerText = 'Second Screen (VideoToolbox)';

      if (gpuControls) gpuControls.style.display = 'flex';
      if (selectEncodeGpu && !selectEncodeGpu.matches(':focus')) {
        selectEncodeGpu.value = status.encode_gpu || 'intel';
      }
      if (selectDecodeGpu && !selectDecodeGpu.matches(':focus')) {
        selectDecodeGpu.value = status.decode_gpu || 'nvidia';
      }
    } else {
      if (dispDesc) dispDesc.innerText = 'Stream macOS Desktop to HP OMEN via VideoToolbox Hardware Encoder @ 165Hz';
      if (devLeftIcon) devLeftIcon.innerText = '💻';
      if (devLeftName) devLeftName.innerText = 'MacBook Pro (M1)';
      if (devLeftRole) devLeftRole.innerText = 'Host Desktop (VideoToolbox)';
      if (streamArrowSpeed) streamArrowSpeed.innerText = '165Hz VideoToolbox';
      if (devRightIcon) devRightIcon.innerText = '🎮';
      if (devRightName) devRightName.innerText = 'HP OMEN 16" (RTX 5070)';
      if (devRightRole) devRightRole.innerText = 'Second Screen (HW Decode)';

      if (gpuControls) gpuControls.style.display = 'none';
    }

    if (isDisplayActive) {
      dispBadge.className = 'pill pill-active';
      dispBadge.innerText = 'Streaming Active';
      btnDisp.className = 'btn btn-primary btn-active-stop';
      btnDispLabel.innerText = 'Disconnect Extended Desktop';
      if (streamArrow) streamArrow.style.opacity = '1';
    } else {
      dispBadge.className = 'pill pill-idle';
      dispBadge.innerText = 'Idle';
      btnDisp.className = 'btn btn-primary';
      if (isWindows) {
        btnDispLabel.innerText = status.encode_gpu === 'nvidia'
          ? 'Extend to MacBook Pro (NVENC 60Hz)'
          : 'Extend to MacBook Pro (QuickSync 60Hz)';
      } else {
        btnDispLabel.innerText = 'Extend Desktop to HP OMEN (VideoToolbox 165Hz)';
      }
      if (streamArrow) streamArrow.style.opacity = '0.4';
    }
  } catch (e) {
    // ignore polling error
  }
}

document.addEventListener('DOMContentLoaded', () => {
  appendLog('🚀 Dashboard UI loaded', 'info');

  const btnToggleDisplay = document.getElementById('btn-toggle-display');
  const btnOpenCache = document.getElementById('btn-open-cache');
  const btnClearLogs = document.getElementById('btn-clear-logs');
  const btnHideWindow = document.getElementById('btn-hide-window');
  const selectEncodeGpu = document.getElementById('select-encode-gpu');
  const selectDecodeGpu = document.getElementById('select-decode-gpu');
  const btnRunSpeedtest = document.getElementById('btn-run-speedtest');
  const btnQuickSpeedtest = document.getElementById('btn-quick-speedtest');

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
    if (btnLabel) btnLabel.innerText = 'Testing...';
    if (btnIcon) {
      btnIcon.innerText = '⏳';
      btnIcon.classList.add('testing-pulse');
    }
    if (subtitle) subtitle.innerText = 'Streaming 64 MB zero-copy buffers over TCP port 58285...';

    appendLog('⚡ Starting live link throughput benchmark (zero-copy TCP)...', 'info');

    try {
      const res = await invokeCmd('run_speed_test');
      if (res && res.success) {
        const peakGbps = res.max_gbps.toFixed(2);
        lastTestedSpeed = `${peakGbps} Gbps`;

        if (metricMax) {
          metricMax.innerText = `${peakGbps} Gbps`;
          metricMax.classList.add('highlight');
        }
        if (metricUp) {
          metricUp.innerText = `${res.upload_mb_s.toFixed(0)} MB/s`;
        }
        if (metricDown) {
          metricDown.innerText = `${res.download_mb_s.toFixed(0)} MB/s`;
        }
        if (metricLatency) {
          metricLatency.innerText = `${res.latency_ms.toFixed(2)} ms`;
        }

        const connSpeed = document.getElementById('connection-speed');
        if (connSpeed) {
          connSpeed.innerText = `⚡ ${peakGbps} Gbps (Tested)`;
        }

        if (subtitle) subtitle.innerText = `Tested: ${res.summary}`;
        appendLog(`⚡ Benchmark Complete: ${res.summary}`, 'success');
      } else {
        appendLog('⚠️ Benchmark did not return success', 'warn');
      }
    } catch (err) {
      appendLog(`❌ Speed test failed: ${err}`, 'error');
      if (subtitle) subtitle.innerText = `Benchmark error: ${err}`;
    } finally {
      isTestingSpeed = false;
      if (btnRunSpeedtest) btnRunSpeedtest.disabled = false;
      if (btnQuickSpeedtest) btnQuickSpeedtest.disabled = false;
      if (btnLabel) btnLabel.innerText = 'Test Speed';
      if (btnIcon) {
        btnIcon.innerText = '⚡';
        btnIcon.classList.remove('testing-pulse');
      }
    }
  }

  if (btnRunSpeedtest) btnRunSpeedtest.addEventListener('click', executeSpeedTest);
  if (btnQuickSpeedtest) btnQuickSpeedtest.addEventListener('click', executeSpeedTest);

  async function handleGpuChange() {
    if (!selectEncodeGpu || !selectDecodeGpu) return;
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
        appendLog(`🖥️ ${res}`, 'success');
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
      const container = document.getElementById('logs-container');
      if (container) container.innerHTML = '';
    });
  }

  // 1. Filter Tabs Logic
  const filterTabs = document.querySelectorAll('.filter-tab');
  const allCards = document.querySelectorAll('.grid .card');

  filterTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      filterTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const filter = tab.getAttribute('data-filter');
      allCards.forEach(card => {
        const cat = card.getAttribute('data-category') || '';
        const status = card.getAttribute('data-status') || '';

        if (filter === 'all') {
          card.style.display = 'flex';
        } else if (filter === 'active') {
          card.style.display = status === 'active' ? 'flex' : 'none';
        } else if (cat.includes(filter)) {
          card.style.display = 'flex';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });

  // 2. Segmented Controls
  document.querySelectorAll('.segmented-control').forEach(control => {
    control.querySelectorAll('.segment').forEach(btn => {
      btn.addEventListener('click', () => {
        control.querySelectorAll('.segment').forEach(s => s.classList.remove('active'));
        btn.classList.add('active');
        const edge = btn.getAttribute('data-edge');
        appendLog(`🖱️ Edge boundary set to: ${edge === 'right' ? 'Right (Mac ➔ PC)' : 'Left (PC ➔ Mac)'}`, 'info');
      });
    });
  });

  // 3. Audio Topology Selection
  document.querySelectorAll('.audio-topology-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.audio-topology-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      const title = item.querySelector('.topology-title')?.innerText || 'Audio Sink';
      appendLog(`🔊 Audio routing topology switched to: ${title}`, 'success');
    });
  });

  // 4. Live Sliders
  const sliderHopDelay = document.getElementById('slider-hop-delay');
  const valHopDelay = document.getElementById('val-hop-delay');
  if (sliderHopDelay && valHopDelay) {
    sliderHopDelay.addEventListener('input', () => {
      valHopDelay.innerText = `${sliderHopDelay.value} ms`;
    });
  }

  const sliderGammaComp = document.getElementById('slider-gamma-comp');
  const valGammaComp = document.getElementById('val-gamma-comp');
  if (sliderGammaComp && valGammaComp) {
    sliderGammaComp.addEventListener('input', () => {
      valGammaComp.innerText = `${(sliderGammaComp.value / 100).toFixed(2)}×`;
    });
  }

  const sliderAudioOffset = document.getElementById('slider-audio-offset');
  const valAudioOffset = document.getElementById('val-audio-offset');
  if (sliderAudioOffset && valAudioOffset) {
    sliderAudioOffset.addEventListener('input', () => {
      valAudioOffset.innerText = `${sliderAudioOffset.value} ms`;
    });
  }

  // 5. Mock Action Buttons for Roadmap Preview
  document.querySelectorAll('.btn-mock').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.getAttribute('data-action');
      switch (action) {
        case 'test-kvm':
          appendLog('🖱️ Simulated edge-hop: Cursor transitioned across border to HP OMEN (vmulti Precision Touchpad active)', 'info');
          break;
        case 'test-dragdrop':
          appendLog('🪂 Simulated cross-border drop: 120 MB project folder streamed to ~/Downloads in 18ms', 'success');
          break;
        case 'test-mount':
          appendLog('📂 Network Volumes mounted: /Volumes/HP-OMEN on macOS and M:\\ on Windows over 10.99.99.x', 'success');
          break;
        case 'test-touchid':
          appendLog('🔑 Touch ID prompt dispatched to MacBook Secure Enclave (Nonce signed & validated, 118ms)', 'success');
          break;
        case 'test-truetone':
          appendLog('🎨 Ambient CCT 5400K read from Mac bezel sensor; Bradford CAT applied to Windows GPU LUT', 'info');
          break;
        case 'test-camera':
          appendLog('🎥 Camera pipeline preview: MacBook FaceTime HD 1080p60 bridged to Windows DirectShow', 'info');
          break;
        case 'test-audio':
          appendLog('🎵 Played 24-bit test chime via Mac Spatial Audio soundbar sink (offset 0ms)', 'success');
          break;
        case 'test-touchbar':
          appendLog('📊 Off-screen NVIDIA telemetry rendered to MacBook Touch Bar (NVML: 64°C, 115W, 165 FPS)', 'info');
          break;
        case 'test-multiwan':
          appendLog('🌐 Multi-WAN route benchmark: Mac Wi-Fi (100 Mbps) + OMEN (150 Mbps) = 250 Mbps combined', 'success');
          break;
        default:
          appendLog(`⚡ Triggered ${action}`, 'info');
      }
    });
  });

  // Touch Bar HUD Toggle
  const btnToggleTouchbar = document.getElementById('btn-toggle-touchbar');
  const btnTouchbarLabel = document.getElementById('btn-touchbar-label');

  if (btnToggleTouchbar) {
    btnToggleTouchbar.addEventListener('click', async () => {
      try {
        appendLog('📊 Toggling Touch Bar NVIDIA Performance HUD on physical OLED strip...', 'info');
        const res = await invokeCmd('toggle_touchbar_hud');
        appendLog(`🚀 ${res}`, 'success');
        if (btnTouchbarLabel) {
          btnTouchbarLabel.innerText = res.includes('active')
            ? 'Dismiss Touch Bar NVIDIA Overlay'
            : 'Bring NVIDIA Overlay to MacBook Touch Bar';
        }
      } catch (err) {
        appendLog(`❌ Touch Bar error: ${err}`, 'error');
      }
    });
  }

  // Periodic GPU Telemetry Updater for Dashboard Visualizer
  async function updateGpuTelemetry() {
    try {
      const data = await invokeCmd('get_gpu_telemetry');
      if (data) {
        const visTemp = document.getElementById('tb-vis-temp');
        const visPower = document.getElementById('tb-vis-power');
        const visClock = document.getElementById('tb-vis-clock');
        const visVram = document.getElementById('tb-vis-vram');
        const visFps = document.getElementById('tb-vis-fps');

        if (visTemp) visTemp.innerText = `🌡️ ${data.temperature_c}°C`;
        if (visPower) visPower.innerText = `⚡ ${data.power_usage_watts.toFixed(1)}W`;
        if (visClock) visClock.innerText = `🚀 ${data.core_clock_mhz} MHz`;
        if (visVram) {
          const usedGb = (data.memory_used_mb / 1024).toFixed(1);
          const totalGb = (data.memory_total_mb / 1024).toFixed(1);
          visVram.innerText = `💾 ${usedGb} / ${totalGb} GB`;
        }
        if (visFps) visFps.innerText = `📊 ${data.gpu_utilization_percent}% GPU`;
      }
    } catch (_) {
      // ignore when offline
    }
  }

  // Poll status every 2 seconds & telemetry every 3 seconds
  updateStatus();
  updateGpuTelemetry();
  setInterval(updateStatus, 2000);
  setInterval(updateGpuTelemetry, 3000);
});
