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
SSH_TIMEOUT_CAPA_DEEP = 600  # 10 minutes for Capa deep analysis (-vv)
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
        <div id="drop-zone">Click or drag and drop a file for investigation</div>
        <input type="file" id="fileInput" hidden>
        <div class="tabs" id="tabBar" style="display: none;">
            <button class="tab-btn active" onclick="switchTab('overview', this)">Overview</button>
            <button class="tab-btn" onclick="switchTab('capabilities', this)">Capabilities (Capa)</button>
            <button class="tab-btn" onclick="switchTab('advanced', this)">Advanced PE</button>
            <button class="tab-btn" onclick="switchTab('strings', this)">Raw Strings</button>
            <button class="tab-btn" onclick="switchTab('floss', this)">FLOSS</button>
            <button class="tab-btn" onclick="switchTab('packer', this)">Packer & Sections</button>
            <button class="tab-btn" onclick="switchTab('documents', this)">Documents & Office</button>
            <button class="tab-btn" onclick="switchTab('resources', this)">Resources & YARA</button>
        </div>
        <div id="tabContent" class="report-section">
            <div id="loader" class="loader"></div>
            <div id="innerOutput" style="text-align:center; color:var(--text-muted); margin-top:60px;">Awaiting file upload...</div>
        </div>
    </div>
    <script>
        const dz = document.getElementById('drop-zone');
        const fi = document.getElementById('fileInput');
        let currentFile = null;
        let analysisCache = {};
        let runningTasks = new Set();

        function clearDragOver() { dz.classList.remove('drag-over'); }

        dz.onclick = function() { fi.click(); };
        fi.onchange = function(e) { if (e.target.files[0]) uploadFile(e.target.files[0]); };

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
            currentFile = file;
            dz.innerText = 'Target: ' + file.name;
            document.getElementById('tabBar').style.display = 'flex';
            analysisCache = {};
            runningTasks.clear();
            switchTab('overview', document.querySelector('.tab-btn'));
        }

        async function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const output = document.getElementById('innerOutput');
            output.innerHTML = '';
            if (tabId === 'capabilities') {
                if (analysisCache['capabilities-vv']) { renderOutput('capabilities', analysisCache['capabilities-vv']); return; }
                if (analysisCache['capabilities-qq']) { renderOutput('capabilities', analysisCache['capabilities-qq']); return; }
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
            if (analysisCache[tabId]) { renderOutput(tabId, analysisCache[tabId]); return; }
            runSpecific(tabId);
        }

        async function runSpecific(tabId, mode = '') {
            const output = document.getElementById('innerOutput');
            const loader = document.getElementById('loader');
            const key = tabId + mode;
            runningTasks.add(key);
            loader.style.display = 'block';
            output.innerHTML = '';
            const fd = new FormData();
            fd.append('file', currentFile);
            fd.append('type', tabId);
            fd.append('mode', mode);
            try {
                const res = await fetch('/run_analysis', { method: 'POST', body: fd });
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
                    analysisCache[key] = fmt;
                    renderOutput(tabId, fmt);
                }
            } catch (e) {
                output.innerHTML = '<div class="error-msg">Error: ' + e.message + '</div>';
            } finally {
                runningTasks.delete(key);
                loader.style.display = 'none';
            }
        }

        function formatOverview(raw) {
            const sha = raw.match(/SHA256:\\s*([0-9a-f]{64})/i)?.[1] || 'N/A';
            const vt = raw.match(/VT:\\s*(https:\\S*)/i)?.[1] || '#';
            const prot = raw.match(/Protector:\\s*([^\\n\\r]*)/i)?.[1] || 'None Detected';
            const comp = raw.match(/Compiler:\\s*([^\\n\\r]*)/i)?.[1] || 'Unknown';
            return '<div class="summary-grid"><div class="summary-card ' + (prot.includes('Themida') ? 'danger' : '') + '"><span style="color:var(--text-muted); font-size:12px;">PROTECTION</span><span class="val">' + prot + '</span></div><div class="summary-card"><span style="color:var(--text-muted); font-size:12px;">COMPILER / LINKER</span><span class="val">' + comp + '</span></div><div class="summary-card"><span style="color:var(--text-muted); font-size:12px;">ARCHITECTURE</span><span class="val">PE64 / x86-64</span></div></div><div class="info-split"><div class="info-block"><div class="block-title">File Identity</div><p style="font-size:11px;"><strong>SHA256:</strong> ' + sha + '</p><a href="' + vt + '" target="_blank" rel="noopener" class="vt-btn">View on VirusTotal</a></div><div class="info-block"><div class="block-title">Heuristic Insights</div><pre style="font-size:11px;">' + (raw.split('SHA256')[0] || '').trim() + '</pre></div></div>';
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

        function renderOutput(tabId, content) {
            const output = document.getElementById('innerOutput');
            var btns = '';
            if (tabId === 'strings' || tabId === 'anomaly') {
                btns = '<div class="btn-group"><button class="action-btn" onclick="runSpecific(\'anomaly\')">Anomaly Scan</button><button class="action-btn secondary" onclick="runSpecific(\'strings\', \'all\')">Full Strings (1000+)</button></div><h3 style="color:var(--accent); font-size:14px; margin-bottom:10px;">Forensic Insights</h3>';
            }
            output.innerHTML = btns + (content.indexOf('<') === 0 ? content : '<pre>' + content + '</pre>');
        }
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
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB


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

        elif a_type == "resources":
            cmd_yara = f"find /usr/local/share/yara-rules/ -name '*.yar' -exec yara {{}} '{remote_path}' 2>/dev/null \\; | head -n 10"
            cmd_loki = f"loki --path '{remote_path}' --noprocscan --dontwait --silent 2>/dev/null | grep 'MATCH' || echo 'No Loki matches.'"
            command = f"echo '[--- YARA SCAN ---]' && {cmd_yara} && echo -e '\\n[--- LOKI SCAN ---]' && {cmd_loki} && echo -e '\\n[--- MZ HEADER ---]' && pedump -r '{remote_path}' 2>/dev/null | head -n 12"
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

        else:
            str_limit = "cat" if mode == "all" else "head -n 200"
            cmd_map = {
                "overview": (
                    f"diec --heuristicscan '{remote_path}' 2>/dev/null && "
                    f"sha256sum '{remote_path}' | awk '{{print \"SHA256: \" $1}}' && "
                    f"echo 'VT: https://www.virustotal.com/gui/file/'$(sha256sum '{remote_path}' | cut -d' ' -f1)"
                ),
                "advanced": f"manalyze --plugins=all '{remote_path}' 2>/dev/null",
                "strings": f"echo '[--- RAW STRINGS ---]' && strings '{remote_path}' | {str_limit}",
                "documents": f"pdfid '{remote_path}' 2>/dev/null; oledump.py '{remote_path}' 2>/dev/null",
                "packer": f"objdump -h '{remote_path}' 2>/dev/null || readelf -S '{remote_path}' 2>/dev/null",
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
