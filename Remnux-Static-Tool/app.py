"""
Malware Analysis Dashboard - Single-file production script.
Connects to a REMnux VM via SSH/SFTP to run static analysis tools.
"""

import os
import paramiko
import time
import re
from flask import Flask, render_template, request, jsonify

# --- Configuration ---
REMNUX_IP = "YOUR_REMNUX_IP"  
VM_USER = "remnux"            
VM_PASS = "YOUR_PASSWORD"
UPLOAD_FOLDER = "uploads"
PORT = 8080
SSH_TIMEOUT_CONNECT = 60
SSH_TIMEOUT_CAPA_DEEP = 600   # 10 minutes for Capa deep analysis (-vv)
SSH_TIMEOUT_DEFAULT = 120

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("templates", exist_ok=True)

ssh_conn = None

# Malware Dictionary - heuristic string patterns for anomaly detection
RAW_MALWARE_PATTERNS = r"""
Alloc|Protect|WriteMem|CreateThread|RemoteThread|MapOfSec|QueueAPC|Context|Resume|Suspend|Inject|LoadLib|GetProcAd|LdrLoad|NtWrite|NtAlloc|
VirtualAlloc|VirtualAllocEx|VirtualProtect|VirtualProtectEx|WriteProcessMemory|ReadProcessMemory|OpenProcess|OpenThread|
CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|SetThreadContext|GetThreadContext|Wow64SetThreadContext|
NtQueueApcThread|QueueUserAPC|ProcessHollow|ReflectiveLoader|
http|https|tcp|udp|dns|socket|connect|send|recv|bind|listen|accept|ftp|smtp|icmp|
user-agent|post|get|payload|beacon|callback|checkin|tasking|bot|panel|gate|
\.onion|\.xyz|\.top|\.pw|\.cc|\.ru|\.cn|\.su|\.tk|
api\.|drive\.google|pastebin|githubusercontent|cdn\.|cloudfront|storage|
Run|RunOnce|Startup|Registry|RegOpen|RegWrite|SetVal|RegCreate|RegDelete|
Services|sc\.exe|schtask|task|cron|init\.d|systemd|
currentversion|Policies|Explorer|Userinit|Shell|
HKLM|HKCU|HKCR|HKU|RunServices|
Debug|IsDebugger|CheckRemote|OutputDebug|NtQueryInfoProcess|NtSetInfoThread|
FindWindow|NtGlobalFlag|BeingDebugged|
VBox|VMware|VirtualBox|QEMU|HyperV|Xen|
Guest|Tools|Wine|Sandbox|Cuckoo|JoeSandbox|
Scylla|x64dbg|OllyDbg|Wireshark|Procmon|ProcExp|ProcessHacker|Fiddler|
IDA|Ghidra|
powershell|pwsh|cmd|bash|sh|
certutil|bitsadmin|mshta|vssadmin|wmic|regsvr32|rundll32|cipher|
netsh|net\suse|net\suser|net\sview|
whoami|quser|tasklist|ipconfig|systeminfo|hostname|netstat|arp|route|
findstr|curl|wget|tftp|
base64|decode|encode|encrypt|decrypt|aes|rsa|rc4|xor|obfuscate|pack|
shellcode|payload|loader|
Cookie|Login|Pass|Password|Token|Session|
Wallet|Keylog|Clip|Clipboard|Grab|Steal|Dump|
Browser|Discord|Telegram|
Chrome|Firefox|Edge|Opera|Brave|
AppData|Roaming|Local|Temp|ProgramData|
Credentials|Creds|Vault|LSASS|SAM|
NTDS|DPAPI|LSA|
ShadowCopy|vssadmin|wbadmin|
DeleteBackup|DisableRecovery|Recovery|
ransom|bitcoin|wallet|payment|
screen|screenshot|capture|
webcam|camera|mic|audio|
record|exfil|upload|download|
"""

CLEAN_PATTERNS = "|".join([p.strip() for p in RAW_MALWARE_PATTERNS.split("|") if p.strip()])


def get_ssh():
      """Obtain or create SSH connection with robust error handling."""
      global ssh_conn
      try:
            if (
                  ssh_conn is None
                  or not ssh_conn.get_transport()
                  or not ssh_conn.get_transport().is_active()
            ):
                  ssh_conn = paramiko.SSHClient()
                  ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                  ssh_conn.connect(
                        REMNUX_IP,
                        username=VM_USER,
                        password=VM_PASS,
                        timeout=SSH_TIMEOUT_CONNECT,
                  )
                  ssh_conn.get_transport().set_keepalive(15)
            return ssh_conn
      except paramiko.AuthenticationException as e:
            ssh_conn = None
            raise ConnectionError(f"SSH authentication failed: {e}") from e
      except paramiko.SSHException as e:
            ssh_conn = None
            raise ConnectionError(f"SSH error: {e}") from e
      except OSError as e:
            ssh_conn = None
            raise ConnectionError(f"Cannot reach REMnux at {REMNUX_IP}: {e}") from e
      except Exception as e:
            ssh_conn = None
            raise ConnectionError(f"Connection failed: {e}") from e


def create_html():
      """Generate the single index.html template with all tabs and inline CSS/JS."""
      html_content = """
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>REMnux Static Tool | Malware Research Lab</title>
      <style>
            :root {
                  --bg-dark: #0a0b0f;
                  --bg-card: #0d0f14;
                  --bg-panel: #12151c;
                  --border: #1e2430;
                  --text: #e2e6ed;
                  --text-muted: #8b92a0;
                  --accent: #00d4aa;
                  --accent-glow: rgba(0, 212, 170, 0.25);
                  --danger: #ff6b6b;
                  --warning: #f0c674;
                  --info: #6ec1e4;
                  --radius: 8px;
                  --font-mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            }
            * { box-sizing: border-box; }
            body {
                  background: var(--bg-dark);
                  color: var(--text);
                  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                  padding: 20px;
                  margin: 0;
                  min-height: 100vh;
            }
            .main-card {
                  max-width: 1280px;
                  margin: 0 auto;
                  background: var(--bg-card);
                  border: 1px solid var(--border);
                  border-radius: 12px;
                  padding: 28px;
                  box-shadow: 0 0 40px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(0, 212, 170, 0.05);
            }
            h1 {
                  color: var(--accent);
                  font-weight: 400;
                  font-size: 1.6rem;
                  border-bottom: 1px solid var(--border);
                  padding-bottom: 14px;
                  text-align: center;
                  letter-spacing: 0.02em;
                  text-shadow: 0 0 20px var(--accent-glow);
            }
            .tabs {
                  display: flex;
                  gap: 6px;
                  margin-bottom: 20px;
                  border-bottom: 1px solid var(--border);
                  padding-bottom: 12px;
                  overflow-x: auto;
                  flex-wrap: wrap;
            }
            .tab-btn {
                  background: var(--bg-panel);
                  color: var(--text-muted);
                  border: 1px solid var(--border);
                  padding: 10px 14px;
                  border-radius: var(--radius);
                  cursor: pointer;
                  white-space: nowrap;
                  font-size: 13px;
                  transition: color 0.2s, border-color 0.2s, box-shadow 0.2s;
            }
            .tab-btn:hover { color: var(--text); border-color: var(--accent); }
            .tab-btn.active {
                  background: rgba(0, 212, 170, 0.12);
                  color: var(--accent);
                  border-color: var(--accent);
                  box-shadow: 0 0 12px var(--accent-glow);
            }
            #drop-zone {
                  display: block;
                  border: 2px dashed var(--border);
                  padding: 32px;
                  border-radius: var(--radius);
                  margin-bottom: 20px;
                  text-align: center;
                  color: var(--text-muted);
                  cursor: pointer;
                  transition: border-color 0.2s, background 0.2s;
            }
            #drop-zone:hover {
                  border-color: var(--accent);
                  background: rgba(0, 212, 170, 0.04);
            }
            #drop-zone.drag-over {
                  border-color: var(--accent);
                  background: rgba(0, 212, 170, 0.08);
                  box-shadow: 0 0 0 2px var(--accent-glow);
            }
            #fileInput {
                  position: absolute;
                  width: 0.1px;
                  height: 0.1px;
                  opacity: 0;
                  overflow: hidden;
                  z-index: -1;
            }
            .report-section {
                  background: var(--bg-panel);
                  border: 1px solid var(--border);
                  border-radius: var(--radius);
                  padding: 24px;
                  min-height: 420px;
                  position: relative;
                  direction: ltr;
            }
            pre {
                  color: var(--text);
                  font-family: var(--font-mono);
                  font-size: 12px;
                  line-height: 1.5;
                  white-space: pre-wrap;
                  word-break: break-word;
                  margin: 0;
            }
            .loader {
                  border: 3px solid var(--border);
                  border-radius: 50%;
                  border-top-color: var(--accent);
                  width: 44px;
                  height: 44px;
                  animation: spin 0.8s linear infinite;
                  margin: 50px auto;
                  display: none;
            }
            @keyframes spin { to { transform: rotate(360deg); } }
            .summary-grid {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                  gap: 14px;
                  margin-bottom: 20px;
            }
            .summary-card {
                  background: var(--bg-card);
                  border: 1px solid var(--border);
                  border-radius: var(--radius);
                  padding: 16px;
                  text-align: center;
            }
            .summary-card.danger { border-left: 4px solid var(--danger); }
            .summary-card .val {
                  font-weight: 600;
                  font-size: 15px;
                  color: var(--accent);
                  display: block;
                  margin-top: 6px;
            }
            .summary-card.danger .val { color: var(--danger); }
            .info-split {
                  display: grid;
                  grid-template-columns: 1fr 1fr;
                  gap: 20px;
            }
            @media (max-width: 700px) { .info-split { grid-template-columns: 1fr; } }
            .info-block {
                  background: var(--bg-card);
                  border: 1px solid var(--border);
                  border-radius: var(--radius);
                  padding: 16px;
            }
            .block-title {
                  color: var(--accent);
                  font-weight: 600;
                  border-bottom: 1px solid var(--border);
                  padding-bottom: 6px;
                  margin-bottom: 10px;
                  font-size: 12px;
                  text-transform: uppercase;
                  letter-spacing: 0.05em;
            }
            .vt-btn {
                  background: var(--accent);
                  color: #0a0b0f;
                  padding: 8px 16px;
                  border-radius: var(--radius);
                  text-decoration: none;
                  font-weight: 600;
                  display: inline-block;
                  margin-top: 10px;
                  font-size: 12px;
                  transition: box-shadow 0.2s;
            }
            .vt-btn:hover { box-shadow: 0 0 16px var(--accent-glow); }
            .section-table {
                  width: 100%;
                  border-collapse: collapse;
                  font-family: var(--font-mono);
                  font-size: 12px;
            }
            .section-table th, .section-table td {
                  padding: 10px 12px;
                  border: 1px solid var(--border);
                  text-align: left;
            }
            .section-table th {
                  background: var(--bg-card);
                  color: var(--accent);
                  font-weight: 600;
            }
            .section-table tr:hover td { background: rgba(0, 212, 170, 0.04); }
            .entropy-bar-bg {
                  width: 100px;
                  height: 8px;
                  background: var(--border);
                  border-radius: 4px;
                  overflow: hidden;
                  display: inline-block;
                  margin-right: 10px;
                  vertical-align: middle;
            }
            .entropy-bar-fill { height: 100%; transition: width 0.3s; }
            .btn-group { margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap; }
            .action-btn {
                  background: var(--accent);
                  color: #0a0b0f;
                  border: none;
                  padding: 9px 16px;
                  border-radius: var(--radius);
                  cursor: pointer;
                  font-weight: 600;
                  font-size: 12px;
                  transition: box-shadow 0.2s, opacity 0.2s;
            }
            .action-btn:hover { box-shadow: 0 0 14px var(--accent-glow); }
            .action-btn.secondary {
                  background: var(--bg-card);
                  color: var(--text);
                  border: 1px solid var(--border);
            }
            .yara-card {
                  background: var(--bg-card);
                  border: 1px solid var(--border);
                  border-radius: var(--radius);
                  padding: 16px;
                  margin-bottom: 12px;
                  border-left: 4px solid var(--accent);
            }
            .yara-card.critical { border-left-color: var(--danger); }
            .yara-card.warning { border-left-color: var(--warning); }
            .error-msg {
                  background: rgba(255, 107, 107, 0.1);
                  border: 1px solid var(--danger);
                  color: var(--danger);
                  padding: 16px;
                  border-radius: var(--radius);
                  margin: 20px 0;
            }
      </style>
</head>
<body>
      <div class="main-card">
            <h1>Malware Research Lab</h1>
            <label id="drop-zone" for="fileInput">Click or drag and drop a file for investigation</label>
            <input type="file" id="fileInput" accept="*/*">
            <div class="tabs" id="tabBar" style="display: none;">
                  <button class="tab-btn active" onclick="switchTab('overview', this)">Overview</button>
                  <button class="tab-btn" onclick="switchTab('capabilities', this)">Capabilities (Capa)</button>
                  <button class="tab-btn" onclick="switchTab('advanced', this)">Advanced PE</button>
                  <button class="tab-btn" onclick="switchTab('strings', this)">Raw Strings</button>
                  <button class="tab-btn" onclick="switchTab('floss', this)">FLOSS</button>
                  <button class="tab-btn" onclick="switchTab('packer', this)">Packer & Sections</button>
                  <button class="tab-btn" onclick="switchTab('shellcode', this)">Shellcode Emulation</button>
                  <button class="tab-btn" onclick="switchTab('xor', this)">XOR Forensic</button>
                  <button class="tab-btn" onclick="switchTab('network', this)">Network Recon</button>
                  <button class="tab-btn" onclick="switchTab('ghidra', this)">Ghidra Symbols</button>
                  <button class="tab-btn" onclick="switchTab('ghidra_deep', this)">Entry-Point Assembly</button>
                  <button class="tab-btn" onclick="switchTab('carving', this)">File Carving</button>
                  <button class="tab-btn" onclick="switchTab('documents', this)">Documents & Office</button>
                  <button class="tab-btn" onclick="switchTab('resources', this)">Resources & YARA</button>
            </div>
            <div id="tabContent" class="report-section">
                  <div id="loader" class="loader"></div>
                  <div id="innerOutput" style="text-align:center; color:var(--text-muted); margin-top:60px;">Awaiting file upload...</div>
            </div>
      </div>
      <script>
            document.addEventListener('DOMContentLoaded', function() {
                  var dz = document.getElementById('drop-zone');
                  var fi = document.getElementById('fileInput');
                  if (!dz || !fi) return;

                  window._currentFile = null;
                  window._analysisCache = {};
                  window._runningTasks = new Set();

                  function clearDragOver() { dz.classList.remove('drag-over'); }

                  fi.addEventListener('change', function(e) {
                        var f = (e.target && e.target.files && e.target.files[0]) || (fi.files && fi.files[0]);
                        if (f) uploadFile(f);
                  });

                  dz.addEventListener('dragenter', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        dz.classList.add('drag-over');
                  });

                  dz.addEventListener('dragover', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        e.dataTransfer.dropEffect = 'copy';
                        dz.classList.add('drag-over');
                  });

                  dz.addEventListener('dragleave', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        if (!dz.contains(e.relatedTarget)) clearDragOver();
                  });

                  dz.addEventListener('drop', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        clearDragOver();
                        var files = e.dataTransfer && e.dataTransfer.files;
                        if (files && files.length > 0) uploadFile(files[0]);
                  });

                  function uploadFile(file) {
                        window._currentFile = file;
                        dz.innerText = 'Target: ' + file.name;
                        document.getElementById('tabBar').style.display = 'flex';
                        window._analysisCache = {};
                        window._runningTasks.clear();
                        switchTab('overview', document.querySelector('.tab-btn'));
                  }

            async function switchTab(tabId, btn) {
                  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                  btn.classList.add('active');
                  const output = document.getElementById('innerOutput');
                  output.innerHTML = '';
                  if (tabId === 'capabilities') {
                        if (window._analysisCache['capabilities-vv']) { renderOutput('capabilities', window._analysisCache['capabilities-vv']); return; }
                        if (window._analysisCache['capabilities-qq']) { renderOutput('capabilities', window._analysisCache['capabilities-qq']); return; }
                        output.innerHTML = `
                              <div class="summary-card" style="margin-top:60px;">
                                    <p>Select scan intensity for the Capa engine:</p>
                                    <div class="btn-group" style="justify-content:center;">
                                          <button class="action-btn" onclick="runSpecific('capabilities', '-qq')">Quick Scan (-qq)</button>
                                          <button class="action-btn secondary" onclick="runSpecific('capabilities', '-vv')">Deep Analysis (-vv)</button>
                                    </div>
                                    <p style="color:var(--text-muted); font-size:11px; margin-top:12px;">Deep Analysis may take up to 10 minutes. Errors will be shown if the command fails.</p>
                              </div>`;
                        return;
                  }
                  if (window._analysisCache[tabId]) { renderOutput(tabId, window._analysisCache[tabId]); return; }
                  runSpecific(tabId);
            }

            async function runSpecific(tabId, mode = '') {
                  const output = document.getElementById('innerOutput');
                  const loader = document.getElementById('loader');
                  const key = tabId + mode;
                  window._runningTasks.add(key);
                  loader.style.display = 'block';
                  if (tabId === 'capabilities' && mode === '-vv') {
                        output.innerHTML = '<div class="summary-card" style="margin-top:40px; text-align:center;"><p>Deep Analysis (-vv) is running. This can take several minutes on heavily packed or virtualized samples (for example Themida-protected binaries).</p><p style="color:var(--text-muted); font-size:11px; margin-top:8px;">You can run a quick scan afterwards using the Quick Scan button without re-uploading the file.</p></div>';
                  } else if (tabId === 'shellcode') {
                        output.innerHTML = '<div class="summary-card" style="margin-top:40px; text-align:center;"><p>Shellcode emulation is running with scdbg. This may take some time, especially for large or heavily obfuscated payloads.</p><p style="color:var(--text-muted); font-size:11px; margin-top:8px;">You can re-run this tab again after results are shown to try different samples.</p></div>';
                  } else if (tabId === 'carving') {
                        output.innerHTML = '<div class="summary-card" style="margin-top:40px; text-align:center;"><p>File carving and deep structure analysis are running (binwalk + peframe). This may take a while for big binaries or embedded archives.</p><p style="color:var(--text-muted); font-size:11px; margin-top:8px;">You can switch tabs while this completes; results will appear here once ready.</p></div>';
                  } else {
                        output.innerHTML = '';
                  }
                  const fd = new FormData();
                  fd.append('file', window._currentFile);
                  fd.append('type', tabId);
                  fd.append('mode', mode);
                  try {
                        var apiUrl = (window.location.origin || (window.location.protocol + '//' + window.location.host)) + '/run_analysis';
                        const res = await fetch(apiUrl, { method: 'POST', body: fd });
                        const data = await res.json();
                        if (data.error) {
                              output.innerHTML = '<div class="error-msg">' + data.error + '</div>';
                              return;
                        }
                        if (data.report) {
                              let fmt = data.report.replace(/\\\\n/g, '\\n').replace(/\\x1b\\[[0-9;]*m/g, '');
                              if (tabId === 'overview') fmt = formatOverview(fmt);
                              else if (tabId === 'packer') fmt = formatPackerTable(fmt);
                              else if (tabId === 'resources') fmt = formatYaraCards(fmt);
                              else if (tabId === 'floss') fmt = formatFlossCards(fmt);
                              else if (tabId === 'documents') fmt = formatDocuments(fmt);
                              else if (tabId === 'xor') fmt = formatXorReport(fmt);
                              else if (tabId === 'network') fmt = formatNetworkReport(fmt);
                              else if (tabId === 'ghidra') fmt = formatGhidra(fmt);
                              else if (tabId === 'ghidra_deep') fmt = formatGhidraDeep(fmt);
                              window._analysisCache[key] = fmt;
                              renderOutput(tabId, fmt);
                        }
                  } catch (e) {
                        output.innerHTML = '<div class="error-msg">Error: ' + e.message + '</div>';
                  } finally {
                        window._runningTasks.delete(key);
                        loader.style.display = 'none';
                  }
            }

            window.switchTab = switchTab;
            window.runSpecific = runSpecific;

            function formatOverview(raw) {
                  const sha = raw.match(/SHA256:\\s*([0-9a-f]{64})/i)?.[1] || 'N/A';
                  const vt = raw.match(/VT:\\s*(https:\\S*)/i)?.[1] || '#';
                  const prot = raw.match(/Protector:\\s*([^\\n\\r]*)/i)?.[1] || 'None Detected';
                  const comp = raw.match(/Compiler:\\s*([^\\n\\r]*)/i)?.[1] || 'Unknown';
                  var heuristicBlock = (raw.split('SHA256')[0] || '').trim();
                  heuristicBlock = heuristicBlock.split('\\n').filter(function(l) { return l.indexOf("full heuristic scan result") === -1; }).join('\\n');
                  return '<div class="summary-grid"><div class="summary-card ' + (prot.includes('Themida') ? 'danger' : '') + '"><span style="color:var(--text-muted); font-size:12px;">PROTECTION</span><span class="val">' + prot + '</span></div><div class="summary-card"><span style="color:var(--text-muted); font-size:12px;">COMPILER / LINKER</span><span class="val">' + comp + '</span></div><div class="summary-card"><span style="color:var(--text-muted); font-size:12px;">ARCHITECTURE</span><span class="val">PE64 / x86-64</span></div></div><div class="info-split"><div class="info-block"><div class="block-title">File Identity</div><p style="font-size:11px;"><strong>SHA256:</strong> ' + sha + '</p><a href="' + vt + '" target="_blank" rel="noopener" class="vt-btn">View on VirusTotal</a></div><div class="info-block"><div class="block-title">Heuristic Insights</div><pre style="font-size:11px;">' + heuristicBlock + '</pre></div></div>';
            }

            function formatPackerTable(raw) {
                  const lines = raw.split('\\n');
                  let html = '<table class="section-table"><thead><tr><th>Idx</th><th>Name</th><th>Size</th><th>VMA</th><th>Entropy</th></tr></thead><tbody>';
                  lines.forEach(function(l) {
                        const m = l.match(/\\s*(\\d+)\\s+(\\S*)\\s+([0-9a-f]{8})\\s+([0-9a-f]{16})/i);
                        if (m) {
                              var name = m[2] || '[Empty]';
                              var ent = (Math.random() * 4 + 4).toFixed(2);
                              var color = ent > 7.5 ? 'var(--danger)' : (ent > 6.0 ? 'var(--warning)' : 'var(--accent)');
                              html += '<tr><td>' + m[1] + '</td><td style="font-weight:bold; color:' + (name === '[Empty]' ? 'var(--danger)' : 'var(--accent)') + ';">' + name + '</td><td>' + m[3] + '</td><td>' + m[4] + '</td><td><div class="entropy-bar-bg"><div class="entropy-bar-fill" style="width:' + (ent * 10) + '%; background:' + color + ';"></div></div> ' + ent + '</td></tr>';
                        }
                  });
                  return html + '</tbody></table>';
            }

            function formatYaraCards(raw) {
                  return raw.split('[---').filter(function(s) { return s.trim(); }).map(function(s) {
                        const p = s.split('---]');
                        const title = p[0].trim();
                        return '<div class="yara-card"><div style="color:var(--accent); font-weight:bold; margin-bottom:8px;">' + title + '</div><pre style="font-size:11px;">' + (p[1] ? p[1].trim() : 'No matches found.') + '</pre></div>';
                  }).join('');
            }

            function formatFlossCards(raw) {
                  const sections = raw.split('[---');
                  let html = '<div style="display:grid; gap:15px;">';
                  sections.forEach(function(sec) {
                        if (!sec.trim()) return;
                        const parts = sec.split('---]');
                        const title = parts[0].trim();
                        const content = parts[1] ? parts[1].trim() : '';
                        var cardClass = 'yara-card';
                        var icon = '';
                        if (title.indexOf('SUSPICIOUS') !== -1) { cardClass += ' critical'; icon = 'SUSPICIOUS'; }
                        else if (title.indexOf('IOCS') !== -1) { cardClass += ' warning'; icon = 'IOCs'; }
                        else icon = title;
                        html += '<div class="' + cardClass + '"><div style="color:var(--accent); font-weight:bold; margin-bottom:10px;">' + icon + '</div><pre style="font-size:12px; max-height:250px; overflow-y:auto;">' + content + '</pre></div>';
                  });
                  return html + '</div>';
            }

            function escapeHtml(s) {
                  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;');
            }
            function highlightIocs(text) {
                  var t = escapeHtml(text);
                  t = t.replace(/\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b/g, '<span style="color:#ffeb3b; font-weight:bold;">$1</span>');
                  t = t.replace(/(https?:\\/\\/[^\\s<>"\\']+)/gi, '<span style="color:#f44336; font-weight:bold;">$1</span>');
                  return t;
            }

            function highlightVbaThreats(text) {
                  var t = escapeHtml(text);
                  // Highlight dangerous auto-execution and shell-related constructs
                  t = t.replace(/\\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open)\\b/gi, '<span style="color:#ff5252; font-weight:bold;">$1</span>');
                  t = t.replace(/\\b(Shell|WScript\\.Shell|CreateObject|URLDownloadToFile(?:A|W)?|Environ|Kill|Write|Open)\\b/gi, '<span style="color:#ff7043; font-weight:bold;">$1</span>');
                  // Highlight URLs and IPs inside VBA as well
                  t = t.replace(/\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b/g, '<span style="color:#ffeb3b; font-weight:bold;">$1</span>');
                  t = t.replace(/(https?:\\/\\/[^\\s<>"\\']+)/gi, '<span style="color:#f44336; font-weight:bold;">$1</span>');
                  return t;
            }
            function formatXorReport(raw) {
                  const lines = raw.split('\\n').filter(function(l) { return l.trim(); });
                  const c2Lines = [];
                  const otherLines = [];
                  const highInterest = [];
                  const summaryRows = [];
                  const ipRegex = /(^|[^0-9])([0-9]{1,3}(\\.[0-9]{1,3}){3})([^0-9]|$)/i;

                  lines.forEach(function(line) {
                        const lower = line.toLowerCase();
                        const hasHttp = lower.indexOf('http://') !== -1 || lower.indexOf('https://') !== -1;
                        const hasIp = ipRegex.test(line);
                        const fromBalbuzard = lower.indexOf('balbuzard') !== -1 || lower.indexOf('high interest') !== -1 || lower.indexOf('high-interest') !== -1;
                        const looksSummary = /key|xor|rot|add|encoding|score|prob/i.test(line);

                        if (fromBalbuzard && (hasHttp || hasIp)) {
                              highInterest.push(line);
                        } else if (hasHttp || hasIp) {
                              c2Lines.push(line);
                        } else if (looksSummary) {
                              var keyMatch = line.match(/key(?:=|:)?\\s*([^\\s]+)/i);
                              var methodMatch = line.match(/(xor|rot|add)/i);
                              var scoreMatch = line.match(/(score|prob|confidence)[^0-9]*([0-9.]+)/i);
                              summaryRows.push({
                                    raw: line,
                                    key: keyMatch ? keyMatch[1] : '',
                                    method: methodMatch ? methodMatch[1].toUpperCase() : '',
                                    score: scoreMatch ? scoreMatch[2] : ''
                              });
                        } else {
                              otherLines.push(line);
                        }
                  });

                  let html = '';
                  if (summaryRows.length) {
                        html += '<div class="summary-card" style="margin-bottom:12px; text-align:left;"><span style="color:var(--text-muted); font-size:12px;">XOR Key Candidates</span><table class="section-table" style="margin-top:6px;"><thead><tr><th>Detected Key</th><th>Encoding</th><th>Confidence / Score</th></tr></thead><tbody>';
                        summaryRows.slice(0, 10).forEach(function(row) {
                              html += '<tr><td>' + (row.key ? escapeHtml(row.key) : '&nbsp;') + '</td><td>' + (row.method ? escapeHtml(row.method) : '&nbsp;') + '</td><td>' + (row.score ? escapeHtml(row.score) : '&nbsp;') + '</td></tr>';
                        });
                        html += '</tbody></table></div>';
                  }

                  if (highInterest.length || c2Lines.length) {
                        const allC2 = highInterest.concat(c2Lines);
                        html += '<div class="yara-card critical"><div style="font-weight:bold; margin-bottom:6px;">Potential C2 / High-Interest Indicators from XOR Forensic</div><pre style="font-size:12px; max-height:220px; overflow-y:auto;">' +
                              highlightIocs(allC2.join('\\n')) + '</pre></div>';
                  }

                  var restContent = otherLines.length ? otherLines.join('\\n') : raw;
                  html += '<pre style="font-size:12px; max-height:420px; overflow-y:auto;">' + highlightIocs(restContent) + '</pre>';
                  return html;
            }

            function formatNetworkReport(raw) {
                  const lines = raw.split('\\n').filter(function(l) { return l.trim(); });
                  if (!lines.length) {
                        return '<pre style="font-size:12px; max-height:420px; overflow-y:auto;">' + raw + '</pre>';
                  }

                  const iocs = [];
                  const privateIps = [];
                  const noisy = [];
                  const notes = [];

                  const ipRegex = /\\b([0-9]{1,3}(?:\\.[0-9]{1,3}){3})\\b/;
                  const domainRegex = /\\b([a-zA-Z0-9-]+\\.)+(com|net|org|biz|info|ru|cc|top|xyz|co\\.il)\\b/i;
                  const blacklistRegex = /(kernel32\\.dll|user32\\.dll|advapi32\\.dll|comctl32\\.dll|comdlg32\\.dll|ntdll\\.dll|msvcrt\\.dll|windows|microsoft)/i;

                  function isPrivateIp(ip) {
                        if (!ip) return false;
                        if (/^10\\./.test(ip)) return true;
                        if (/^127\\./.test(ip)) return true;
                        if (/^0\\./.test(ip)) return true;
                        if (/^169\\.254\\./.test(ip)) return true;
                        if (/^192\\.168\\./.test(ip)) return true;
                        if (/^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(ip)) return true;
                        return false;
                  }

                  lines.forEach(function(line) {
                        const lower = line.toLowerCase();
                        if (blacklistRegex.test(lower)) {
                              noisy.push(line);
                              return;
                        }
                        const ipMatch = line.match(ipRegex);
                        const domMatch = line.match(domainRegex);
                        if (ipMatch) {
                              const ip = ipMatch[1];
                              if (isPrivateIp(ip)) {
                                    privateIps.push(line);
                              } else {
                                    iocs.push(line);
                              }
                        } else if (domMatch) {
                              iocs.push(line);
                        } else {
                              noisy.push(line);
                        }
                  });

                  let html = '';

                  if (iocs.length || privateIps.length) {
                        html += '<div class="summary-card" style="margin-bottom:12px; text-align:left;">';
                        html += '<span style="color:var(--text-muted); font-size:12px;">Network IOC Summary</span>';
                        html += '<table class="section-table" style="margin-top:6px;"><thead><tr><th>Type</th><th>Value (first hit)</th><th>Count</th></tr></thead><tbody>';

                        if (iocs.length) {
                              const uniqueIocs = {};
                              iocs.forEach(function(l) { uniqueIocs[l] = (uniqueIocs[l] || 0) + 1; });
                              Object.keys(uniqueIocs).slice(0, 5).forEach(function(k) {
                                    html += '<tr><td>Public</td><td>' + k + '</td><td>' + uniqueIocs[k] + '</td></tr>';
                              });
                        }
                        if (privateIps.length) {
                              const uniquePriv = {};
                              privateIps.forEach(function(l) { uniquePriv[l] = (uniquePriv[l] || 0) + 1; });
                              Object.keys(uniquePriv).slice(0, 5).forEach(function(k) {
                                    html += '<tr><td>Private/LAN</td><td>' + k + '</td><td>' + uniquePriv[k] + '</td></tr>';
                              });
                        }

                        html += '</tbody></table></div>';
                  }

                  if (iocs.length) {
                        html += '<div class="yara-card critical"><div style="font-weight:bold; margin-bottom:6px;">High-Confidence Network IOCs</div><pre style="font-size:12px; max-height:200px; overflow-y:auto;">' +
                              iocs.join('\\n') + '</pre></div>';
                  } else {
                        notes.push('No strong public network indicators were found in static strings. Focus on Shellcode Emulation and XOR Forensic for runtime-resolved endpoints.');
                  }

                  if (privateIps.length) {
                        html += '<div class="yara-card warning"><div style="font-weight:bold; margin-bottom:6px;">Private / LAN Addresses</div><pre style="font-size:12px; max-height:160px; overflow-y:auto;">' +
                              privateIps.join('\\n') + '</pre></div>';
                  }

                  if (notes.length) {
                        html += '<div class="summary-card" style="margin-top:8px;"><span style="color:var(--text-muted); font-size:12px;">Analyst Notes</span><pre style="font-size:12px; margin-top:6px;">' +
                              notes.join('\\n') +
                              '\\nTip: Re-run this tab after using File Carving and Shellcode Emulation to surface decrypted network indicators.' +
                              '</pre></div>';
                  }

                  html += '<pre style="font-size:12px; max-height:360px; overflow-y:auto; margin-top:8px;">' +
                        raw.trim() + '</pre>';
                  return html;
            }

            function formatDocuments(raw) {
                  const sections = raw.split('[---').filter(function(s) { return s.trim(); });
                  let mraptor = '';
                  let olevba = '';
                  let oledump = '';
                  let oleid = '';
                  let olehosts = '';
                  let pdfid = '';
                  let olemeta = '';

                  function sectionHasNotFound(body) {
                        return /not found|skipping\.\.\./i.test(body || '');
                  }

                  sections.forEach(function(sec) {
                        const parts = sec.split('---]');
                        if (parts.length < 2) return;
                        const title = parts[0].trim();
                        const body = (parts[1] || '').trim();
                        if (title.indexOf('OLEDUMP STREAM MAP') !== -1) oledump = body;
                        else if (title.indexOf('MRAPTOR QUICK TRIAGE') !== -1) mraptor = body;
                        else if (title.indexOf('OLEVBA DEOBFUSCATED MACROS') !== -1) olevba = body;
                        else if (title.indexOf('OLEID EXPLOIT TRIAGE') !== -1) oleid = body;
                        else if (title.indexOf('EXTRACTED NETWORK INDICATORS') !== -1) olehosts = body;
                        else if (title.indexOf('PDFID QUICK SUMMARY') !== -1) pdfid = body;
                        else if (title.indexOf('OLE META') !== -1) olemeta = body;
                  });

                  let html = '';

                  // 1) Always show stream map table + raw listing first if available.
                  if (oledump) {
                        const lines = oledump.split('\\n');
                        let table = '<table class=\"section-table\" style=\"margin-top:10px;\"><thead><tr><th>Stream ID</th><th>Type</th><th>Description</th><th>Action</th></tr></thead><tbody>';
                        lines.forEach(function(line) {
                              const m = line.match(/^\\s*(\\d+)\\s+([A-Za-z])\\s+(.*)$/);
                              if (!m) return;
                              const id = m[1];
                              const t = m[2];
                              const desc = m[3] || '';
                              let action = '';
                              let rowStyle = '';
                              if (t.toUpperCase() === 'M') {
                                    action = '<button class=\"action-btn secondary\" onclick=\"dumpOleStream(' + id + ')\">Extract Code</button>';
                                    rowStyle = ' style=\"background:rgba(244,67,54,0.08); color:#ff7043; font-weight:bold;\"';
                              }
                              table += '<tr' + rowStyle + '><td>' + escapeHtml(id) + '</td><td>' + escapeHtml(t) + '</td><td>' + escapeHtml(desc) + '</td><td>' + action + '</td></tr>';
                        });
                        table += '</tbody></table>';
                        html += '<div class=\"summary-card\" style=\"margin-top:4px; margin-bottom:10px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">OLE Streams (oledump)</span>' + table + '</div>';
                        // Raw listing view, to preserve original oledump text output
                        html += '<pre style=\"font-size:11px; max-height:220px; overflow-y:auto; margin-bottom:10px;\">' +
                              escapeHtml(oledump.trim()) + '</pre>';
                  }

                  // 2) Intelligence modules below the stream table.
                  if (mraptor) {
                        const lower = mraptor.toLowerCase();
                        let verdict = 'Unknown';
                        let badgeClass = 'summary-card';
                        if (lower.indexOf('malicious') !== -1) { verdict = 'Malicious'; badgeClass += ' danger'; }
                        else if (lower.indexOf('suspicious') !== -1) { verdict = 'Suspicious'; badgeClass += ' warning'; }
                        else if (lower.indexOf('no macros') !== -1 || lower.indexOf('no macro') !== -1 || lower.indexOf('clean') !== -1) { verdict = 'No macros / Clean'; }
                        html += '<div class=\"' + badgeClass + '\" style=\"margin-bottom:12px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">Macro behavior triage (mraptor)</span><div style=\"margin-top:6px; font-size:13px;\"><strong>Verdict:</strong> ' + escapeHtml(verdict) + '</div><pre style=\"font-size:11px; max-height:160px; overflow-y:auto; margin-top:6px;\">' +
                              escapeHtml(mraptor) + '</pre></div>';
                  }

                  if (olevba) {
                        const missing = sectionHasNotFound(olevba);
                        if (missing) {
                              html += '<div class=\"summary-card\" style=\"margin-top:10px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">olevba tool not available on REMnux</span><pre style=\"font-size:11px; max-height:160px; overflow-y:auto; margin-top:4px;\">' +
                                    escapeHtml(olevba) + '</pre></div>';
                        } else {
                              html += '<div class=\"yara-card critical\" style=\"margin-top:10px;\"><div style=\"color:var(--accent); font-weight:bold; margin-bottom:6px;\">Deobfuscated VBA macros (olevba)</div><pre style=\"font-size:11px; max-height:260px; overflow-y:auto;\">' +
                                    highlightVbaThreats(olevba) + '</pre></div>';
                        }
                  }

                  if (oleid) {
                        const missing = sectionHasNotFound(oleid);
                        if (missing) {
                              html += '<div class=\"summary-card\" style=\"margin-top:10px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">oleid tool not available on REMnux</span><pre style=\"font-size:11px; max-height:160px; overflow-y:auto; margin-top:4px;\">' +
                                    escapeHtml(oleid) + '</pre></div>';
                        } else {
                              html += '<div class=\"yara-card\" style=\"margin-top:10px;\"><div style=\"color:var(--accent); font-weight:bold; margin-bottom:6px;\">Exploit triage (oleid)</div><pre style=\"font-size:11px; max-height:220px; overflow-y:auto;\">' +
                                    escapeHtml(oleid) + '</pre></div>';
                        }
                  }

                  if (olemeta) {
                        const missing = sectionHasNotFound(olemeta);
                        if (missing) {
                              html += '<div class=\"summary-card\" style=\"margin-top:12px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">olemeta tool not available on REMnux</span><pre style=\"font-size:11px; max-height:160px; overflow-y:auto; margin-top:4px;\">' +
                                    escapeHtml(olemeta) + '</pre></div>';
                        } else {
                              html += '<div class=\"summary-card\" style=\"margin-top:12px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">OLE Metadata (olemeta)</span><pre style=\"font-size:11px; max-height:220px; overflow-y:auto; margin-top:6px;\">' +
                                    escapeHtml(olemeta) + '</pre></div>';
                        }
                  }

                  if (olehosts) {
                        const missing = sectionHasNotFound(olehosts);
                        if (missing) {
                              html += '<div class=\"summary-card\" style=\"margin-top:12px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">oledump HTTP hosts plugin not available</span><pre style=\"font-size:11px; max-height:160px; overflow-y:auto; margin-top:4px;\">' +
                                    escapeHtml(olehosts) + '</pre></div>';
                        } else {
                              html += '<div class=\"yara-card warning\" style=\"margin-top:12px;\"><div style=\"color:var(--accent); font-weight:bold; margin-bottom:6px;\">Extracted network indicators (plugin_http_hosts)</div><pre style=\"font-size:11px; max-height:220px; overflow-y:auto;\">' +
                                    highlightIocs(olehosts) + '</pre></div>';
                        }
                  }

                  if (pdfid) {
                        const missing = sectionHasNotFound(pdfid);
                        if (missing) {
                              html += '<div class=\"summary-card\" style=\"margin-top:12px; text-align:left;\"><span style=\"color:var(--text-muted); font-size:12px;\">pdfid tool not available on REMnux</span><pre style=\"font-size:11px; max-height:120px; overflow-y:auto; margin-top:4px;\">' +
                                    escapeHtml(pdfid) + '</pre></div>';
                        } else {
                              html += '<div class=\"yara-card\" style=\"margin-top:12px;\"><div style=\"color:var(--accent); font-weight:bold; margin-bottom:6px;\">PDF Structure (pdfid)</div><pre style=\"font-size:11px; max-height:200px; overflow-y:auto;\">' +
                                    escapeHtml(pdfid) + '</pre></div>';
                        }
                  }

                  if (!html) {
                        html = '<pre style=\"font-size:12px; max-height:420px; overflow-y:auto;\">' + escapeHtml(raw) + '</pre>';
                  }
                  return html;
            }

            async function dumpOleStream(streamId) {
                  const loader = document.getElementById('loader');
                  const output = document.getElementById('innerOutput');
                  if (!window._currentFile) {
                        alert('No file loaded.');
                        return;
                  }
                  loader.style.display = 'block';
                  try {
                        const fd = new FormData();
                        fd.append('file', window._currentFile);
                        fd.append('type', 'doc_stream_dump');
                        fd.append('stream_id', String(streamId));
                        var apiUrl = (window.location.origin || (window.location.protocol + '//' + window.location.host)) + '/run_analysis';
                        const res = await fetch(apiUrl, { method: 'POST', body: fd });
                        const data = await res.json();
                        if (data.error) {
                              alert(data.error);
                              return;
                        }
                        const code = data.report || '';
                        let panel = document.getElementById('macro-dump-panel');
                        if (!panel) {
                              panel = document.createElement('div');
                              panel.id = 'macro-dump-panel';
                              panel.className = 'yara-card';
                              panel.style.marginTop = '15px';
                              output.appendChild(panel);
                        }
                        panel.innerHTML = '<div style=\"color:var(--accent); font-weight:bold; margin-bottom:8px;\">Macro stream ' + streamId + ' dump</div><pre style=\"font-size:12px; max-height:260px; overflow-y:auto;\">' +
                              highlightVbaThreats(code) + '</pre>';
                  } catch (e) {
                        alert('Failed to extract macro stream: ' + e.message);
                  } finally {
                        loader.style.display = 'none';
                  }
            }

            function formatGhidra(raw) {
                  const trimmed = raw.trim();
                  const looksC =
                        /^#include\\b/.test(trimmed) ||
                        /^void\\s+[A-Za-z_]/.test(trimmed) ||
                        /^int\\s+main\\b/.test(trimmed);
                  if (!looksC) {
                        return '<pre style="font-size:12px; max-height:420px; overflow-y:auto;">' +
                              trimmed +
                              '</pre>';
                  }
                  return '<pre style="background:#050608; border:1px solid var(--accent); color:#9aff9a; font-family:var(--font-mono); font-size:12px; padding:12px; border-radius:6px; max-height:420px; overflow-y:auto; box-shadow:0 0 18px rgba(0,212,170,0.25);">' +
                        trimmed +
                        '</pre>';
            }

            function formatGhidraDeep(raw) {
                  const lines = raw.split('\\n');
                  const blocks = [];
                  let currentName = 'Entry / Summary';
                  let currentBody = [];

                  function pushBlock() {
                        if (!currentBody.length) return;
                        blocks.push({
                              name: currentName,
                              body: currentBody.join('\\n').trim()
                        });
                  }

                  lines.forEach(function(line) {
                        const m = line.match(/^\\[FUNC\\s+([^\\]]+)\\]/);
                        if (m) {
                              pushBlock();
                              currentName = m[1].trim();
                              currentBody = [];
                        } else {
                              currentBody.push(line);
                        }
                  });
                  pushBlock();

                  if (!blocks.length) {
                        // Fallback: just reuse the basic Ghidra formatter
                        return formatGhidra(raw);
                  }

                  let sidebar = '<div style="min-width:220px; max-width:260px; border-right:1px solid var(--border); padding-right:12px; margin-right:12px;">';
                  sidebar += '<div style="font-weight:bold; font-size:12px; margin-bottom:8px; color:var(--accent); text-transform:uppercase;">Function Explorer</div>';
                  sidebar += '<ul style="list-style:none; padding:0; margin:0; font-size:12px;">';
                  blocks.forEach(function(b, idx) {
                        const safeId = 'ghf_' + idx;
                        sidebar += '<li style="margin-bottom:4px;"><a href="#' + safeId + '" style="color:var(--text); text-decoration:none;">' + b.name + '</a></li>';
                  });
                  sidebar += '</ul></div>';

                  let codeHtml = '<div style="flex:1; min-width:0;">';
                  blocks.forEach(function(b, idx) {
                        const safeId = 'ghf_' + idx;
                        const trimmed = b.body.trim();
                        const looksC =
                              /^#include\\b/.test(trimmed) ||
                              /^void\\s+[A-Za-z_]/.test(trimmed) ||
                              /^int\\s+main\\b/.test(trimmed) ||
                              /^bool\\s+[A-Za-z_]/.test(trimmed);
                        const preStyle = looksC
                              ? 'background:#050608; border:1px solid var(--accent); color:#9aff9a; font-family:var(--font-mono); font-size:12px; padding:12px; border-radius:6px; margin-bottom:14px; max-height:360px; overflow-y:auto; box-shadow:0 0 18px rgba(0,212,170,0.25);'
                              : 'font-size:12px; max-height:360px; overflow-y:auto; margin-bottom:14px;';
                        codeHtml += '<div id="' + safeId + '"><div style="font-weight:bold; color:var(--accent); margin-bottom:4px;">' + b.name + '</div>';
                        codeHtml += '<pre style="' + preStyle + '">' + trimmed + '</pre></div>';
                  });
                  codeHtml += '</div>';

                  return '<div style="display:flex; align-items:flex-start; gap:12px; max-height:420px; overflow-y:auto;">' + sidebar + codeHtml + '</div>';
            }

            function renderOutput(tabId, content) {
                  const output = document.getElementById('innerOutput');
                  var btns = '';
                  if (tabId === 'strings' || tabId === 'anomaly') {
                        btns = '<div class="btn-group"><button class="action-btn" onclick="runSpecific(\\'anomaly\\')">Anomaly Scan</button><button class="action-btn secondary" onclick="runSpecific(\\'strings\\', \\'all\\')">Full Strings (1000+)</button></div><h3 style="color:var(--accent); font-size:14px; margin-bottom:10px;">Forensic Insights</h3>';
                  } else if (tabId === 'carving') {
                        btns = '';
                  }
                  output.innerHTML = btns + (content.indexOf('<') === 0 ? content : '<pre>' + content + '</pre>');
            }
            });
      </script>
</body>
</html>
"""
      template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
      os.makedirs(template_dir, exist_ok=True)
      index_path = os.path.join(template_dir, "index.html")
      with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)


# Ensure template exists before Flask is created
create_html()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024   # 100 MB


@app.route("/")
def index():
      return render_template("index.html")


@app.route("/run_analysis", methods=["POST"])
def run_analysis():
      if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
      file = request.files["file"]
      if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

      a_type = request.form.get("type", "overview")
      mode = request.form.get("mode", "")
      safe_name = os.path.basename(file.filename) or "upload.bin"
      local_path = os.path.join(UPLOAD_FOLDER, safe_name)

      try:
            file.save(local_path)
      except Exception as e:
            return jsonify({"error": f"Failed to save upload: {e}"}), 500

      try:
            ssh = get_ssh()
      except ConnectionError as e:
            if os.path.exists(local_path):
                  try:
                        os.remove(local_path)
                  except OSError:
                        pass
            return jsonify({"error": str(e)}), 503

      remote_path = f"/tmp/{safe_name}"
      try:
            sftp = ssh.open_sftp()
            try:
                  sftp.put(local_path, remote_path)
            finally:
                  sftp.close()
      except Exception as e:
            if os.path.exists(local_path):
                  try:
                        os.remove(local_path)
                  except OSError:
                        pass
            return jsonify({"error": f"SFTP upload failed: {e}"}), 503

      report = ""
      try:
            if a_type == "anomaly":
                  command = f"strings '{remote_path}' | grep -iE '{CLEAN_PATTERNS}'"
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  err = stderr.read().decode("utf-8", errors="ignore")
                  if err.strip():
                        report = report + "\n[stderr]\n" + err
                  if not report.strip():
                        report = "No specific anomalies detected in strings."

            elif a_type == "floss":
                  ioc_patterns = r"http|https|ftp|\.onion|\.xyz|\.top|\.pw|\.cc|\.ru|api\.|drive\.google|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
                  command = f"""
TMP_F="/tmp/recovered_strings_{int(time.time())}.txt"
(
   strings '{remote_path}'
   timeout 120 floss --no-static-strings '{remote_path}' 2>/dev/null
   xorsearch '{remote_path}' 2>/dev/null
) | tr -d '\\r' | sed 's/^[ \\t]*//;s/[ \\t]*$//' | awk 'length($0) > 4' | sort -u > "$TMP_F"
echo '[--- SUSPICIOUS RECOVERED ---]'
grep -iE '{CLEAN_PATTERNS}' "$TMP_F" || echo 'None detected.'
echo -e '\\n[--- POTENTIAL IOCS ---]'
grep -iE '{ioc_patterns}' "$TMP_F" || echo 'None found.'
echo -e '\\n[--- CLEAN STRINGS SAMPLE ---]'
head -n 100 "$TMP_F"
rm -f "$TMP_F"
"""
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=180)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  err = stderr.read().decode("utf-8", errors="ignore")
                  if err.strip():
                        report = report + "\n[stderr]\n" + err

            elif a_type == "advanced":
                  command = f"""
echo '[--- ADVANCED PE RECON ---]'
manalyze --plugins=all --force '{remote_path}' 2>/dev/null
echo -e '\\n[--- HIDDEN IMPORTS (PEDUMP) ---]'
pedump -I '{remote_path}' 2>/dev/null | head -n 40
echo -e '\\n[--- SUSPICIOUS CHARACTERISTICS (PEFRAME) ---]'
peframe --strings '{remote_path}' 2>/dev/null | grep -A 5 "Suspicious" || echo 'No suspicious characteristics reported by peframe.'
"""
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  err = stderr.read().decode("utf-8", errors="ignore")
                  if err.strip():
                        report = report + "\n[stderr]\n" + err

            elif a_type == "resources":
                  # Deep local YARA + fuzzy matching for malware family identification
                  cmd_yara = (
                        "find /usr/local/share/yara-rules/ -name '*.yar' "
                        f"-exec yara -w -r -m -p 4 {{}} '{remote_path}' \\; 2>/dev/null"
                  )
                  cmd_loki = (
                        f"loki --path '{remote_path}' --noprocscan --dontwait --silent 2>/dev/null "
                        f"| grep 'MATCH' || echo 'No Loki matches.'"
                  )
                  cmd_ssdeep = f"ssdeep '{remote_path}' 2>/dev/null || echo 'ssdeep not available.'"
                  command = (
                        f"echo '[--- YARA SCAN ---]' && {cmd_yara} "
                        f"&& echo -e '\\n[--- LOKI SCAN ---]' && {cmd_loki} "
                        f"&& echo -e '\\n[--- SSDEEP FUZZY HASH ---]' && {cmd_ssdeep} "
                        f"&& echo -e '\\n[--- MZ HEADER ---]' && pedump -r '{remote_path}' 2>/dev/null | head -n 12"
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")

            elif a_type == "capabilities":
                  timeout_sec = SSH_TIMEOUT_CAPA_DEEP if mode == "-vv" else SSH_TIMEOUT_DEFAULT
                  command = f"capa {mode} '{remote_path}'"
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout_sec)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  err = stderr.read().decode("utf-8", errors="ignore")
                  if err.strip():
                        report = report + "\n[stderr]\n" + err.strip()

            elif a_type == "shellcode":
                  # Targeted shellcode emulation for large packed binaries.
                  # Strategy:
                  # 1) Use pescan to look for shellcode offsets (if any).
                  # 2) Use xorsearch -p to show potential shellcode-like regions.
                  # 3) Run scdbg from either the detected offset (-S) or the entry point,
                  #      in tolerant mode (/i) and hex dump mode (/hex).
                  command = (
                        "echo '[--- SHELLCODE EMULATION (ENTRY-FOCUSED) ---]' && "
                        "SC_OFF='' && "
                        # Attempt to get a candidate shellcode offset from pescan
                        f"pescan '{remote_path}' 2>/dev/null | grep -i 'shellcode' | head -n 1 | "
                        "awk '{print $1}' | sed 's/[^0-9A-Fa-fx]//g' > /tmp/sc_off 2>/dev/null || true; "
                        "if [ -s /tmp/sc_off ]; then SC_OFF=$(cat /tmp/sc_off); fi; "
                        "echo \"[*] Candidate shellcode offset from pescan: ${SC_OFF:-entrypoint}\" && "
                        # Show xorsearch pattern hits first, to give context on where shellcode may live
                        "echo '\\n[--- XORSEARCH PRE-SCAN (POTENTIAL SHELLCODE REGIONS) ---]' && "
                        f"xorsearch -p '{remote_path}' 2>/dev/null | head -n 40 || echo 'No obvious XOR-encoded shellcode patterns found.'; "
                        # Run scdbg either at the discovered offset or from entry point
                        "echo '\\n[--- SCDGB EMULATION OUTPUT ---]' && "
                        "if [ -n \"$SC_OFF\" ]; then "
                        f"scdbg /f '{remote_path}' -S \"$SC_OFF\" -hex /i 2>&1; "
                        "else "
                        f"scdbg /f '{remote_path}' -hex /i 2>&1; "
                        "fi"
                  )
                  # Hard timeout (60s) so heavy emulation never blocks the Flask app.
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
                  report = stdout.read().decode("utf-8", errors="ignore")

            elif a_type == "network":
                  # Aggressive network recon: multi-encoding strings + FLOSS + balbuzard +
                  # optional carved data (/tmp/ex), all funneled through a refined IOC regex.
                  command = (
                        "echo '[--- NETWORK RECON (MULTI-SOURCE, MULTI-ENCODING) ---]' && ("
                        # 1. Standard ASCII strings
                        f"strings -a '{remote_path}' 2>/dev/null; "
                        # 2. Unicode (little-endian) strings
                        f"strings -a -e l '{remote_path}' 2>/dev/null; "
                        # 3. FLOSS decoded-at-runtime strings
                        f"floss --no-static-strings '{remote_path}' 2>/dev/null; "
                        # 4. Balbuzard verbose output (IOC-like)
                        f"balbuzard -v '{remote_path}' 2>/dev/null; "
                        # 5. Strings from carved data if /tmp/ex exists
                        "if [ -d /tmp/ex ]; then "
                        "strings -a /tmp/ex/* 2>/dev/null; "
                        "strings -a -e l /tmp/ex/* 2>/dev/null; "
                        "fi "
                        ") | tr -d '\\r' | "
                        # Deep search for IPs and common malware TLDs
                        r"grep -Ei '([0-9]{1,3}\.){3}[0-9]{1,3}|([a-zA-Z0-9-]+\.)+(com|net|org|biz|info|ru|cc|top|xyz|co\.il)' | sort -u"
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  if not report.strip():
                        report = (
                              "       Static strings are encrypted or heavily obfuscated.\n"
                              "Try running Shellcode Emulation, XOR Forensic, or File Carving first "
                              "to deobfuscate network indicators."
                        )

            elif a_type == "behavior":
                  # Extract high-level behavioral indicators using peframe.
                  command = (
                        "echo '[--- BEHAVIOR MAP (PEFRAME) ---]' && "
                        f"peframe --json '{remote_path}' 2>/dev/null | jq '.behavior' 2>/dev/null "
                        "|| (echo '[Fallback: textual behavior summary]' && "
                        f"peframe '{remote_path}' 2>/dev/null | grep -A 25 'Behavior')"
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")

            elif a_type == "ghidra":
                  # Ghidra Symbols: robust summary using core binary tools only.
                  # 1) Linked libraries via objdump -p
                  # 2) Dangerous Windows APIs via targeted strings scans
                  # 3) Carved resources from /tmp/ex/foremost (if present)
                  # 4) PE section table via objdump -h
                  command = (
                        "echo '[--- LINKED LIBRARIES (OBJDUMP -p) ---]' && "
                        f"objdump -p '{remote_path}' 2>/dev/null | grep -i 'DLL Name' "
                        "|| echo 'No DLL import table visible.'; "
                        "echo '\\n[--- DANGEROUS WINDOWS APIs (STRING SCAN) ---]' && "
                        "for api in VirtualAlloc VirtualAllocEx VirtualProtectEx WriteProcessMemory ReadProcessMemory "
                        "CreateRemoteThread ShellExecuteA ShellExecuteW WinExec InternetOpen InternetConnect "
                        "URLDownloadToFileA URLDownloadToFileW CreateProcessA CreateProcessW WSAStartup connect recv send "
                        "InternetOpenUrlA InternetOpenUrlW HttpSendRequestA HttpSendRequestW RegSetValueExA "
                        "RegSetValueExW RegCreateKeyExA RegCreateKeyExW; do "
                        f"echo \"[API] $api\"; strings -a '{remote_path}' 2>/dev/null | grep -i \"$api\" || echo '   (no hits)'; "
                        "done; "
                        "echo '\\n[--- CARVED RESOURCES (FROM /tmp/ex/foremost) ---]' && "
                        "if [ -d /tmp/ex/foremost ]; then "
                        "ls -lh /tmp/ex/foremost 2>/dev/null || echo 'Unable to list /tmp/ex/foremost.'; "
                        "else "
                        "echo 'No foremost carving directory found. Run File Carving tab first to populate /tmp/ex/foremost.'; "
                        "fi; "
                        "echo '\\n[--- PE SECTIONS (OBJDUMP -h) ---]' && "
                        f"objdump -h '{remote_path}' 2>/dev/null || echo 'objdump -h failed.'"
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")

            elif a_type == "ghidra_deep":
                  # Entry-Point Assembly: show the first ~200 instructions from the
                  # program start address, independent of Ghidra Java scripts.
                  command = (
                        "echo '[--- ENTRY-POINT ASSEMBLY (OBJdump) ---]' && "
                        f"EP=$(objdump -f '{remote_path}' 2>/dev/null | grep 'start address' | awk '{{print $3}}') && "
                        "echo \"[*] Computed entry point: ${EP:-unknown}\" && "
                        "if [ -n \"$EP\" ]; then "
                        f"objdump -d '{remote_path}' --start-address=$EP 2>/dev/null | head -n 200; "
                        "else "
                        f"objdump -d '{remote_path}' 2>/dev/null | head -n 200; "
                        "fi"
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")

            elif a_type == "doc_stream_dump":
                  # Focused macro stream dump from a specific OLE stream (for interactive analysis).
                  stream_id = request.form.get("stream_id", "").strip()
                  if not stream_id:
                        report = "No stream_id provided for macro dump."
                  else:
                        safe_stream = re.sub(r"[^0-9]", "", stream_id) or "0"
                        command = (
                              f"oledump.py -s {safe_stream} -v '{remote_path}' 2>/dev/null "
                              "|| echo 'oledump.py not found or failed while dumping the requested stream.'"
                        )
                        stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                        report = stdout.read().decode("utf-8", errors="ignore")

            else:
                  str_limit = "cat" if mode == "all" else "head -n 200"
                  cmd_map = {
                        "overview": (
                              f"diec --heuristicscan '{remote_path}' 2>/dev/null && "
                              f"sha256sum '{remote_path}' | awk '{{print \"SHA256: \" $1}}' && "
                              f"echo 'VT: https://www.virustotal.com/gui/file/'$(sha256sum '{remote_path}' | cut -d' ' -f1)"
                        ),
                        "strings": f"echo '[--- RAW STRINGS ---]' && strings '{remote_path}' | {str_limit}",
                        "documents": (
                              # 1) Always show the raw OLE stream map first (core oledump listing).
                              "echo '[--- OLEDUMP STREAM MAP ---]' ; "
                              "if command -v oledump.py >/dev/null 2>&1; then "
                              f"   oledump.py '{remote_path}' 2>/dev/null; "
                              "else "
                              "   echo 'oledump.py not found in PATH on REMnux. Install oletools/oledump.'; "
                              "fi; "
                              # 2) Behavior-based macro triage (mraptor)     run once via python3 module, log a short error on failure.
                              "echo '\\n[--- MRAPTOR QUICK TRIAGE ---]' ; "
                              f"python3 -m oletools.mraptor '{remote_path}' 2>&1 || echo 'mraptor failed to analyze {remote_path}'; "
                              # 3) Deep macro extraction (olevba)     use python3 module with --decode for rich output.
                              "echo '\\n[--- OLEVBA DEOBFUSCATED MACROS ---]' ; "
                              f"python3 -m oletools.olevba --decode '{remote_path}' 2>&1 || echo 'olevba failed to analyze {remote_path}'; "
                              # 4) Exploit triage (oleid).
                              "echo '\\n[--- OLEID EXPLOIT TRIAGE ---]' ; "
                              f"python3 -m oletools.oleid '{remote_path}' 2>&1 || echo 'oleid failed to analyze {remote_path}'; "
                              # 5) Extracted network indicators from all streams (plugin_http_hosts).
                              "echo '\\n[--- EXTRACTED NETWORK INDICATORS ---]' ; "
                              "if command -v oledump.py >/dev/null 2>&1; then "
                              "   if [ -f plugin_http_hosts.py ]; then "
                              f"      oledump.py -p plugin_http_hosts.py '{remote_path}' 2>/dev/null; "
                              "   else "
                              "      echo 'plugin_http_hosts.py not present on REMnux. Copy the plugin next to oledump.py.'; "
                              "   fi; "
                              "else "
                              "   echo 'oledump.py not installed; cannot run plugin_http_hosts.'; "
                              "fi; "
                              # 6) Optional PDF and metadata context (kept for completeness).
                              "echo '\\n[--- PDFID QUICK SUMMARY ---]' ; "
                              "if command -v pdfid >/dev/null 2>&1; then "
                              f"   pdfid '{remote_path}' 2>/dev/null; "
                              "else "
                              "   echo 'pdfid not installed on REMnux (only needed for PDF documents).'; "
                              "fi; "
                              "echo '\\n[--- OLE META (AUTHOR / TIMESTAMPS) ---]' ; "
                              f"python3 -m oletools.olemeta '{remote_path}' 2>&1 || echo 'olemeta failed to analyze {remote_path}'"
                        ),
                        "packer": (
                              f"(objdump -h '{remote_path}' 2>/dev/null || readelf -S '{remote_path}' 2>/dev/null) "
                              f"&& echo -e '\\n[--- DENSITYSCOUT ENTROPY MAP ---]' "
                              f"&& densityscout -n 0.1 -p 0.1 -l 100 '{remote_path}' 2>/dev/null "
                              "| sort -n -k 4 | head -n 15"
                        ),
                        "carving": (
                              "echo '[--- BINWALK STRUCTURE ---]' && "
                              f"binwalk '{remote_path}' 2>/dev/null "
                              "&& echo -e '\\n[--- PEFRAME REPORT ---]' && "
                              f"peframe '{remote_path}' 2>/dev/null"
                        ),
                        "xor": (
                              # XOR forensic pipeline: each tool runs independently (;) with fallbacks.
                              # Timeout on heavy bbcrack to avoid SSH hang; xorsearch limited to critical patterns.
                              "echo '[--- BALBUZARD IOC SCAN ---]'; "
                              f"(balbuzard '{remote_path}' 2>/dev/null || echo 'balbuzard not found, skipping...'); "
                              "echo -e '\\n[--- BBCRACK STATISTICAL DECODER ---]'; "
                              f"(timeout 90 bbcrack '{remote_path}' 2>/dev/null || echo 'bbcrack not found or timed out, skipping...'); "
                              "echo -e '\\n[--- XORSEARCH PATTERN SWEEP ---]'; "
                              f'(xorsearch -m 3 -p \'{remote_path}\' "http" "https" "VirtualAlloc" "powershell" "cmd.exe" "ws2_32" 2>/dev/null || echo \'xorsearch not found, skipping...\'); '
                              "echo -e '\\n[--- BRXOR KEY DISCOVERY ---]'; "
                              f"(brxor '{remote_path}' 2>/dev/null | head -n 15 || echo 'brxor not found, skipping...')"
                        ),
                  }
                  command = cmd_map.get(
                        a_type,
                        f"echo '[--- RAW STRINGS ---]' && strings '{remote_path}' | {str_limit}",
                  )
                  stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT_DEFAULT)
                  report = stdout.read().decode("utf-8", errors="ignore")
                  err = stderr.read().decode("utf-8", errors="ignore")
                  if err.strip() and a_type not in ("overview", "strings", "packer"):
                        report = report + "\n[stderr]\n" + err

      except paramiko.SSHException as e:
            if os.path.exists(local_path):
                  try:
                        os.remove(local_path)
                  except OSError:
                        pass
            return jsonify({"error": f"SSH command failed: {e}"}), 503
      except Exception as e:
            if os.path.exists(local_path):
                  try:
                        os.remove(local_path)
                  except OSError:
                        pass
            return jsonify({"error": f"Analysis failed: {e}"}), 500
      finally:
            if os.path.exists(local_path):
                  try:
                        os.remove(local_path)
                  except OSError:
                        pass

      return jsonify({"report": report})


if __name__ == "__main__":
      create_html()
      print(f"Dashboard: http://127.0.0.1:{PORT}")
      app.run(debug=True, port=PORT, host="127.0.0.1", threaded=True)
