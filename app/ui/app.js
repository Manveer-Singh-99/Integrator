// Mac-Windows Fusion Bridge UI Logic (Tauri v2)

let isDisplayActive = false;

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
    const usbPing = document.getElementById('usb-ping');

    if (status.peer_connected) {
      connBadge.className = 'badge badge-connected';
      connText.innerText = `Connected (${status.peer_ip})`;
      if (usbPing) usbPing.innerText = status.rtt_ms ? `${status.rtt_ms.toFixed(1)} ms` : '< 1 ms';
    } else {
      connBadge.className = 'badge';
      connBadge.style.background = 'rgba(239, 68, 68, 0.15)';
      connBadge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
      connBadge.style.color = '#f87171';
      connText.innerText = 'Searching for Peer...';
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

    if (isWindows) {
      if (dispDesc) dispDesc.innerText = 'Stream Windows Desktop to MacBook Pro via VideoToolbox @ 60Hz';
      if (devLeftIcon) devLeftIcon.innerText = '🎮';
      if (devLeftName) devLeftName.innerText = 'HP OMEN 16" (RTX 5070)';
      if (devLeftRole) devLeftRole.innerText = 'Host Desktop';
      if (streamArrowSpeed) streamArrowSpeed.innerText = '60Hz VideoToolbox';
      if (devRightIcon) devRightIcon.innerText = '💻';
      if (devRightName) devRightName.innerText = 'MacBook Pro (M1)';
      if (devRightRole) devRightRole.innerText = 'Second Screen';
    } else {
      if (dispDesc) dispDesc.innerText = 'Stream macOS Desktop to HP OMEN at native 1920×1200 @ 165Hz';
      if (devLeftIcon) devLeftIcon.innerText = '💻';
      if (devLeftName) devLeftName.innerText = 'MacBook Pro (M1)';
      if (devLeftRole) devLeftRole.innerText = 'Host Desktop';
      if (streamArrowSpeed) streamArrowSpeed.innerText = '165Hz NVENC';
      if (devRightIcon) devRightIcon.innerText = '🎮';
      if (devRightName) devRightName.innerText = 'HP OMEN 16" (RTX 5070)';
      if (devRightRole) devRightRole.innerText = 'Second Screen';
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
      btnDispLabel.innerText = isWindows 
        ? 'Extend to MacBook Pro (VideoToolbox 60Hz)' 
        : 'Extend Desktop to HP OMEN (165Hz)';
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

  if (btnToggleDisplay) {
    btnToggleDisplay.addEventListener('click', async () => {
      try {
        appendLog(isDisplayActive ? 'Stopping extended display...' : 'Starting extended display (1920x1200 @ 165Hz)...', 'info');
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

  // Poll status every 2 seconds
  updateStatus();
  setInterval(updateStatus, 2000);
});
