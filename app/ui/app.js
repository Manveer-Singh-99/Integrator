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

    // 3. Touch Bar HUD State & Scope Tracking
    const tbStateBadge = document.getElementById('touchbar-state-badge');
    const btnTb = document.getElementById('btn-toggle-touchbar');
    const btnTbLabel = document.getElementById('btn-touchbar-label');

    if (tbStateBadge && btnTb && btnTbLabel) {
      if (status.touchbar_active) {
        tbStateBadge.className = 'pill pill-active';
        tbStateBadge.innerText = 'Liquid Glass Active';
        btnTb.className = 'btn btn-primary btn-active-stop';
        btnTbLabel.innerText = 'Disable Touch Bar NVIDIA HUD';
      } else {
        btnTb.className = 'btn btn-primary';
        if (status.is_windows_master) {
          tbStateBadge.className = 'pill pill-active';
          tbStateBadge.innerText = 'Windows Master Active';
          btnTbLabel.innerText = 'Enable Touch Bar NVIDIA HUD';
        } else {
          tbStateBadge.className = 'pill pill-idle';
          tbStateBadge.innerText = 'Windows Master Inactive';
          btnTbLabel.innerText = 'Enable Touch Bar NVIDIA HUD (Windows Master Only)';
        }
      }
    }

    // 4. True Tone & Ambient Light Sensor
    const valAmbientCct = document.getElementById('val-ambient-cct');
    const valAmbientLux = document.getElementById('val-ambient-lux');
    if (status.ambient_cct && valAmbientCct) {
      valAmbientCct.innerText = `${status.ambient_cct} K`;
    }
    if (status.ambient_lux && valAmbientLux) {
      valAmbientLux.innerText = `${Math.round(status.ambient_lux)} Lux`;
    }

    // 5. Shared Storage Status
    const storageStatusPill = document.getElementById('storage-status-pill');
    if (storageStatusPill) {
      if (status.storage_mounted) {
        storageStatusPill.className = 'pill pill-active';
        storageStatusPill.innerText = 'Mounted Active';
      } else {
        storageStatusPill.className = 'pill pill-idle';
        storageStatusPill.innerText = 'Volume Ready';
      }
    }

    // 6. Launch at Login Sync
    const toggleAutostart = document.getElementById('toggle-autostart');
    if (toggleAutostart && !toggleAutostart.matches(':focus')) {
      toggleAutostart.checked = !!status.autostart_enabled;
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
  const toggleAutostart = document.getElementById('toggle-autostart');

  if (toggleAutostart) {
    toggleAutostart.addEventListener('change', async () => {
      const enable = toggleAutostart.checked;
      try {
        appendLog(enable ? '🚀 Configuring Launch at Login...' : '🚀 Removing Launch at Login...', 'info');
        const res = await invokeCmd('set_autostart', { enabled: enable });
        toggleAutostart.checked = res;
        appendLog(res ? '🚀 Launch at Login ENABLED (registered in System Login Items)' : '🚀 Launch at Login DISABLED', 'success');
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

  // 5. Active Feature Event Handlers
  const btnMountStorage = document.getElementById('btn-mount-storage');
  const btnUnmountStorage = document.getElementById('btn-unmount-storage');
  const btnCalibrateTruetone = document.getElementById('btn-calibrate-truetone');
  const btnTestChime = document.getElementById('btn-test-chime');

  if (btnMountStorage) {
    btnMountStorage.addEventListener('click', async () => {
      try {
        appendLog('📂 Mounting shared network volume over USB-C...', 'info');
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

  if (btnCalibrateTruetone) {
    btnCalibrateTruetone.addEventListener('click', async () => {
      try {
        appendLog('🎨 Reading Ambient Light Sensor and computing Bradford CAT matrix...', 'info');
        btnCalibrateTruetone.disabled = true;
        const als = await invokeCmd('get_ambient_light');
        const cct = als ? als.cct_kelvin : 5500;
        const gammaComp = sliderGammaComp ? (sliderGammaComp.value / 100) : 1.05;
        
        const res = await invokeCmd('apply_truetone_calibration', {
          cct: cct,
          compFactor: gammaComp
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
        appendLog('🎵 Synthesizing 24-bit 48kHz Spatial Audio room chime...', 'info');
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

  // 6. Mock Action Buttons for Roadmap Preview
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
        case 'test-touchid':
          appendLog('🔑 Touch ID prompt dispatched to MacBook Secure Enclave (Nonce signed & validated, 118ms)', 'success');
          break;
        case 'test-camera':
          appendLog('🎥 Camera pipeline preview: MacBook FaceTime HD 1080p60 bridged to Windows DirectShow', 'info');
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
  const chkTouchbarScope = document.getElementById('chk-touchbar-scope');

  if (btnToggleTouchbar) {
    btnToggleTouchbar.addEventListener('click', async () => {
      try {
        const strictScope = chkTouchbarScope ? chkTouchbarScope.checked : true;
        appendLog('📊 Toggling Touch Bar NVIDIA Performance HUD (Liquid Glass)...', 'info');
        btnToggleTouchbar.disabled = true;

        const res = await invokeCmd('toggle_touchbar_hud', { force: !strictScope });
        appendLog(`🚀 ${res}`, 'success');
        await updateStatus();
      } catch (err) {
        appendLog(`❌ Touch Bar requirement error: ${err}`, 'warn');
      } finally {
        btnToggleTouchbar.disabled = false;
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

  // 7. Master Feature On/Off Switches
  let activeFeatureFlags = {};

  async function initFeatureFlags() {
    try {
      const flags = await invokeCmd('get_feature_flags');
      if (flags) {
        activeFeatureFlags = flags;
        applyFeatureFlagsToUI(flags);
      }
    } catch (e) {
      console.warn('Failed to load feature flags:', e);
    }
  }

  function applyFeatureFlagsToUI(flags) {
    document.querySelectorAll('.feature-master-toggle').forEach(toggle => {
      const feature = toggle.getAttribute('data-feature');
      const isEnabled = flags[feature] !== false;
      toggle.checked = isEnabled;

      const card = toggle.closest('.card');
      if (!card) return;

      const pill = card.querySelector('.pill');
      if (pill && !pill.getAttribute('data-original-text')) {
        pill.setAttribute('data-original-text', pill.innerText);
      }

      if (isEnabled) {
        card.classList.remove('card-disabled');
        if (pill && pill.getAttribute('data-original-text') && pill.innerText === 'Disabled') {
          pill.innerText = pill.getAttribute('data-original-text');
        }
      } else {
        card.classList.add('card-disabled');
        if (pill) {
          pill.innerText = 'Disabled';
        }
      }
    });
  }

  document.querySelectorAll('.feature-master-toggle').forEach(toggle => {
    toggle.addEventListener('change', async (e) => {
      e.stopPropagation();
      const feature = toggle.getAttribute('data-feature');
      const enabled = toggle.checked;
      const card = toggle.closest('.card');
      const title = card?.querySelector('h2')?.innerText || feature;

      if (enabled) {
        card?.classList.remove('card-disabled');
        const pill = card?.querySelector('.pill');
        if (pill && pill.getAttribute('data-original-text')) {
          pill.innerText = pill.getAttribute('data-original-text');
        }
        appendLog(`🟢 Master Switch: Enabled "${title}"`, 'success');
      } else {
        card?.classList.add('card-disabled');
        const pill = card?.querySelector('.pill');
        if (pill) {
          if (!pill.getAttribute('data-original-text')) {
            pill.setAttribute('data-original-text', pill.innerText);
          }
          pill.innerText = 'Disabled';
        }
        appendLog(`⚪ Master Switch: Disabled "${title}"`, 'warn');
      }

      try {
        const updated = await invokeCmd('set_feature_flag', { feature, enabled });
        if (updated) {
          activeFeatureFlags = updated;
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
