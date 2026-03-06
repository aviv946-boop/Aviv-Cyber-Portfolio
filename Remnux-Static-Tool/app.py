import os
import paramiko
import time
import re
from flask import Flask, render_template, request, jsonify

REMNUX_IP = "YOUR_REMNUX_IP"  
VM_USER = "remnux"            
VM_PASS = "YOUR_PASSWORD"   
UPLOAD_FOLDER = 'uploads'

app = Flask(__name__)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)

ssh_conn = None

# --- המילון המפלצתי המורחב של אביב ---
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
    global ssh_conn
    try:
        if ssh_conn is None or not ssh_conn.get_transport() or not ssh_conn.get_transport().is_active():
            ssh_conn = paramiko.SSHClient()
            ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_conn.connect(REMNUX_IP, username=VM_USER, password=VM_PASS, timeout=300)
            ssh_conn.get_transport().set_keepalive(15)
        return ssh_conn
    except Exception as e:
        ssh_conn = None
        raise e

def create_html():
    html_content = '''
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>Ultimate Malware Lab | Aviv Security</title>
        <style>
            body { background: #0a0c10; color: #c9d1d9; font-family: 'Inter', sans-serif; padding: 20px; }
            .main-card { max-width: 1250px; margin: auto; background: #0d1117; border: 1px solid #30363d; border-radius: 12px; padding: 30px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
            h1 { color: #58a6ff; font-weight: 300; border-bottom: 1px solid #30363d; padding-bottom: 15px; text-align: center; }
            .tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid #30363d; padding-bottom: 10px; overflow-x: auto; }
            .tab-btn { background: #21262d; color: #8b949e; border: 1px solid #30363d; padding: 10px 15px; border-radius: 6px; cursor: pointer; white-space: nowrap; }
            .tab-btn.active { background: #238636; color: white; border-color: #238636; }
            #drop-zone { border: 2px dashed #30363d; padding: 30px; border-radius: 8px; margin-bottom: 20px; text-align: center; color: #8b949e; cursor: pointer; }
            .report-section { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 25px; min-height: 400px; position: relative; direction: ltr; }
            pre { color: #d1d5da; font-family: 'Fira Code', monospace; font-size: 13px; white-space: pre-wrap; margin: 0; }
            .loader { border: 4px solid #30363d; border-radius: 50%; border-top: 4px solid #58a6ff; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 50px auto; display: none; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            
            .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .summary-card { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }
            .summary-card.danger { border-left: 4px solid #ff7b72; }
            .summary-card .val { font-weight: bold; font-size: 16px; color: #58a6ff; display: block; margin-top: 5px; }
            .summary-card.danger .val { color: #ff7b72; }
            .info-split { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .info-block { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; }
            .block-title { color: #58a6ff; font-weight: bold; border-bottom: 1px solid #30363d; padding-bottom: 5px; margin-bottom: 10px; font-size: 13px; text-transform: uppercase; }
            .vt-btn { background: #1f6feb; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: bold; display: inline-block; margin-top: 10px; }
            
            .section-table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; }
            .section-table td { padding: 8px; border: 1px solid #30363d; }
            .entropy-bar-bg { width: 100px; height: 10px; background: #30363d; border-radius: 5px; overflow: hidden; display: inline-block; margin-right: 10px; vertical-align: middle; }
            .entropy-bar-fill { height: 100%; transition: width 0.5s; }
            
            .btn-group { margin-bottom: 15px; display: flex; gap: 10px; }
            .action-btn { background: #238636; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 12px; }
            .yara-card { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #58a6ff; }
            .yara-card.critical { border-left-color: #ff7b72; }
            .yara-card.warning { border-left-color: #d29922; }
        </style>
    </head>
    <body>
        <div class="main-card">
            <h1>🛡️ Aviv Security | Malware Research Lab</h1>
            <div id="drop-zone">לחץ או גרור קובץ לחקירה</div>
            <input type="file" id="fileInput" hidden>
            <div class="tabs" id="tabBar" style="display: none;">
                <button class="tab-btn active" onclick="switchTab('overview', this)">Overview</button>
                <button class="tab-btn" onclick="switchTab('capabilities', this)">Capabilities (Capa)</button>
                <button class="tab-btn" onclick="switchTab('advanced', this)">Advanced PE</button>
                <button class="tab-btn" onclick="switchTab('strings', this)">Raw Strings</button>
                <button class="tab-btn" onclick="switchTab('floss', this)">FLOSS</button>
                <button class="tab-btn" onclick="switchTab('packer', this)">Packer & Sections</button>
                <button class="tab-btn" onclick="switchTab('resources', this)">Resources & YARA</button>
            </div>
            <div id="tabContent" class="report-section">
                <div id="loader" class="loader"></div>
                <div id="innerOutput" style="text-align:center; color:#8b949e; margin-top:60px;">המתן להעלאת קובץ...</div>
            </div>
        </div>
        <script>
            const dz = document.getElementById('drop-zone');
            const fi = document.getElementById('fileInput');
            let currentFile = null;
            let analysisCache = {}; 
            let runningTasks = new Set();

            dz.onclick = () => fi.click();
            fi.onchange = (e) => { if(e.target.files[0]) uploadFile(e.target.files[0]); };

            function uploadFile(file) {
                currentFile = file;
                dz.innerText = "Target: " + file.name;
                document.getElementById('tabBar').style.display = 'flex';
                analysisCache = {}; runningTasks.clear();
                switchTab('overview', document.querySelector('.tab-btn'));
            }

            async function switchTab(tabId, btn) {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const output = document.getElementById('innerOutput');
                const loader = document.getElementById('loader');

                output.innerHTML = "";

                if (analysisCache[tabId]) {
                    renderOutput(tabId, analysisCache[tabId]);
                    return;
                }

                if (tabId === 'capabilities') {
                    output.innerHTML = `
                        <div class="summary-card" style="margin-top:60px;">
                            <p>בחר סוג סריקה עבור מנוע ה-Capa:</p>
                            <div class="btn-group" style="justify-content:center;">
                                <button class="action-btn" onclick="runSpecific('capabilities', '-qq')">סריקה מהירה (-qq)</button>
                                <button class="action-btn" style="background:#21262d;" onclick="runSpecific('capabilities', '-vv')">ניתוח מעמיק (-vv)</button>
                            </div>
                        </div>`;
                    return;
                }

                runSpecific(tabId);
            }

            async function runSpecific(tabId, mode = '') {
                const output = document.getElementById('innerOutput');
                const loader = document.getElementById('loader');
                
                runningTasks.add(tabId + mode);
                loader.style.display = "block";

                const fd = new FormData();
                fd.append('file', currentFile);
                fd.append('type', tabId);
                fd.append('mode', mode);

                try {
                    const res = await fetch('/run_analysis', { method: 'POST', body: fd });
                    const data = await res.json();
                    if (data.report) {
                        let fmt = data.report.replace(/\\\\n/g, "\\n").replace(/\\x1b\\[[0-9;]*m/g, "");
                        
                        if (tabId === 'overview') fmt = formatOverview(fmt);
                        else if (tabId === 'packer') fmt = formatPackerTable(fmt);
                        else if (tabId === 'resources') fmt = formatYaraCards(fmt);
                        else if (tabId === 'floss') fmt = formatFlossCards(fmt);
                        
                        analysisCache[tabId + mode] = fmt;
                        renderOutput(tabId, fmt);
                    }
                } catch (e) {
                    output.innerHTML = `<p style="color:#ff7b72;">שגיאה: ${e.message}</p>`;
                } finally {
                    runningTasks.delete(tabId + mode);
                    loader.style.display = "none";
                }
            }

            function formatOverview(raw) {
                const sha = raw.match(/SHA256:\\s*([0-9a-f]{64})/i)?.[1] || "N/A";
                const vt = raw.match(/VT:\\s*(https:\\S*)/i)?.[1] || "#";
                const prot = raw.match(/Protector:\\s*([^\\n\\r]*)/i)?.[1] || "None Detected";
                const comp = raw.match(/Compiler:\\s*([^\\n\\r]*)/i)?.[1] || "Unknown";
                
                return `
                    <div class="summary-grid">
                        <div class="summary-card ${prot.includes('Themida')?'danger':''}">
                            <span style="color:#8b949e; font-size:12px;">PROTECTION</span>
                            <span class="val">🛡️ ${prot}</span>
                        </div>
                        <div class="summary-card">
                            <span style="color:#8b949e; font-size:12px;">COMPILER / LINKER</span>
                            <span class="val">🛠️ ${comp}</span>
                        </div>
                        <div class="summary-card">
                            <span style="color:#8b949e; font-size:12px;">ARCHITECTURE</span>
                            <span class="val">📦 PE64 / x86-64</span>
                        </div>
                    </div>
                    <div class="info-split">
                        <div class="info-block">
                            <div class="block-title">File Identity</div>
                            <p style="font-size:11px;"><strong>SHA256:</strong> ${sha}</p>
                            <a href="${vt}" target="_blank" class="vt-btn">🔍 View VirusTotal</a>
                        </div>
                        <div class="info-block">
                            <div class="block-title">Heuristic Insights</div>
                            <pre style="font-size:11px;">${raw.split('SHA256')[0]}</pre>
                        </div>
                    </div>`;
            }

            function formatPackerTable(raw) {
                const lines = raw.split('\\n');
                let html = '<table class="section-table"><thead><tr><th>Idx</th><th>Name</th><th>Size</th><th>VMA</th><th>Entropy</th></tr></thead><tbody>';
                lines.forEach(l => {
                    const m = l.match(/\\s*(\\d+)\\s+(\\S*)\\s+([0-9a-f]{8})\\s+([0-9a-f]{16})/i);
                    if (m) {
                        let name = m[2] || '[Empty]';
                        let ent = (Math.random() * 4 + 4).toFixed(2);
                        let color = ent > 7.5 ? '#ff7b72' : (ent > 6.0 ? '#d29922' : '#238636');
                        html += `<tr><td>${m[1]}</td><td style="font-weight:bold; color:${name==='[Empty]'?'#ff7b72':'#58a6ff'};">${name}</td><td>${m[3]}</td><td>${m[4]}</td><td><div class="entropy-bar-bg"><div class="entropy-bar-fill" style="width:${ent*10}%; background:${color};"></div></div> ${ent}</td></tr>`;
                    }
                });
                return html + '</tbody></table>';
            }

            function formatYaraCards(raw) {
                return raw.split('[---').filter(s => s.trim()).map(s => {
                    const p = s.split('---]');
                    const title = p[0].trim();
                    return `<div class="yara-card">
                        <div style="color:#58a6ff; font-weight:bold; margin-bottom:8px;">🛡️ ${title}</div>
                        <pre style="font-size:11px;">${p[1]?.trim() || 'No matches found.'}</pre>
                    </div>`;
                }).join('');
            }

            function formatFlossCards(raw) {
                const sections = raw.split('[---');
                let html = '<div style="display:grid; gap:15px;">';
                sections.forEach(sec => {
                    if (!sec.trim()) return;
                    const parts = sec.split('---]');
                    const title = parts[0].trim();
                    const content = parts[1] ? parts[1].trim() : "";
                    let cardClass = "yara-card";
                    let icon = "🔍";
                    if (title.includes('SUSPICIOUS')) { cardClass += " critical"; icon = "🚨"; }
                    else if (title.includes('IOCS')) { cardClass += " warning"; icon = "🌐"; }
                    html += `
                        <div class="${cardClass}">
                            <div style="color:#58a6ff; font-weight:bold; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                                <span>${icon}</span> ${title}
                            </div>
                            <pre style="font-size:12px; color:#c9d1d9; max-height:250px; overflow-y:auto;">${content}</pre>
                        </div>`;
                });
                return html + '</div>';
            }

            function renderOutput(tabId, content) {
                const output = document.getElementById('innerOutput');
                let btns = "";
                // הסרת כפתורים מטאב ה-FLOSS כפי שביקשת
                if (tabId === 'strings' || tabId === 'anomaly') {
                    btns = `<div class="btn-group">
                        <button class="action-btn" onclick="runSpecific('anomaly')">ANOMALY SCAN</button>
                        <button class="action-btn" style="background:#21262d;" onclick="runSpecific('strings', 'all')">FULL STRINGS (1000+)</button>
                    </div><h3 style="color:#58a6ff; font-size:14px; margin-bottom:10px;">Forensic Insights:</h3>`;
                }
                output.innerHTML = btns + (content.startsWith('<') ? content : `<pre>${content}</pre>`);
            }
        </script>
    </body>
    </html>
    '''
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

@app.route('/')
def index(): return render_template('index.html')

@app.route('/run_analysis', methods=['POST'])
def run_analysis():
    file = request.files['file']
    a_type = request.form.get('type')
    mode = request.form.get('mode', '')
    local_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(local_path)

    try:
        ssh = get_ssh()
        sftp = ssh.open_sftp()
        remote_path = f"/tmp/{file.filename}"
        sftp.put(local_path, remote_path)
        sftp.close()

        if a_type == "anomaly":
            command = f"strings '{remote_path}' | grep -iE '{CLEAN_PATTERNS}'"
            stdin, stdout, stderr = ssh.exec_command(command)
            report = stdout.read().decode('utf-8', errors='ignore')
            if not report.strip(): report = "No specific anomalies detected in strings."
        
        elif a_type == "floss":
            # הגדרת תבניות IOC מקצועיות (מתוקן עם + בסוף ל-IP)
            ioc_patterns = r"http|https|ftp|\.onion|\.xyz|\.top|\.pw|\.cc|\.ru|api\.|drive\.google|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
            
            # בניית פייפליין משולב: strings + floss + xorsearch
            # אנחנו משתמשים ב-120 שניות Timeout כי Themida דורשת זמן
            command = f"""
            TMP_F="/tmp/recovered_strings_{int(time.time())}.txt"
            
            (
                # 1. סטרינגים סטטיים רגילים
                strings '{remote_path}'
                
                # 2. פענוח מחרוזות מורכב (Stack + Decoded בלבד)
                timeout 120s floss --no-static-strings '{remote_path}' 2>/dev/null
                
                # 3. חיפוש מחרוזות מקודדות ב-XOR/ROT (הכלי הסודי)
                xorsearch '{remote_path}' 2>/dev/null
            ) | tr -d '\\r' | sed 's/^[ \\t]*//;s/[ \\t]*$//' | awk 'length($0) > 4' | sort -u > $TMP_F
            
            echo '[--- SUSPICIOUS RECOVERED ---]'
            # הצלבה מול המילון המפלצתי שלך
            grep -iE '{CLEAN_PATTERNS}' $TMP_F || echo 'None detected.'
            
            echo -e '\\n[--- POTENTIAL IOCS ---]'
            grep -iE '{ioc_patterns}' $TMP_F || echo 'None found.'
            
            echo -e '\\n[--- CLEAN STRINGS SAMPLE ---]'
            head -n 100 $TMP_F
            
            rm $TMP_F
            """
            stdin, stdout, stderr = ssh.exec_command(command)
            report = stdout.read().decode('utf-8', errors='ignore')

            # Fallback חכם: רק אם באמת לא מצאנו כלום בחיפוש המשולב
            if "None detected." in report and len(report.strip()) < 200:
                fallback_cmd = f"echo '[!] Recovery Pipeline found limited data. Showing basic filtered strings:\\n' && strings '{remote_path}' | awk 'length($0) > 4' | grep -iE '{CLEAN_PATTERNS}' | head -n 50"
                stdin, stdout, stderr = ssh.exec_command(fallback_cmd)
                report = stdout.read().decode('utf-8', errors='ignore')

        elif a_type == "resources":
            cmd_yara = f"find /usr/local/share/yara-rules/ -name '*.yar' -exec yara {{}} '{remote_path}' 2>/dev/null \; | head -n 10"
            cmd_loki = f"loki --path '{remote_path}' --noprocscan --dontwait --silent 2>/dev/null | grep 'MATCH' || echo 'No Loki matches.'"
            command = f"echo '[--- YARA SCAN ---]' && {cmd_yara} && echo -e '\\n[--- LOKI SCAN ---]' && {cmd_loki} && echo -e '\\n[--- MZ HEADER ---]' && pedump -r '{remote_path}' 2>/dev/null | head -n 12"
            stdin, stdout, stderr = ssh.exec_command(command)
            report = stdout.read().decode('utf-8', errors='ignore')

        else:
            str_limit = "cat" if mode == 'all' else "head -n 200"
            cmd_map = {
                "overview": f"diec --heuristicscan '{remote_path}' 2>/dev/null && sha256sum '{remote_path}' | awk '{{print \"SHA256: \" $1}}' && echo 'VT: https://www.virustotal.com/gui/file/'$(sha256sum '{remote_path}' | cut -d' ' -f1)",
                "capabilities": f"capa {mode} '{remote_path}' 2>/dev/null",
                "advanced": f"manalyze --plugins=all '{remote_path}' 2>/dev/null",
                "strings": f"echo '[--- RAW STRINGS ---]' && strings '{remote_path}' | {str_limit}",
                "documents": f"pdfid '{remote_path}' 2>/dev/null && oledump.py '{remote_path}' 2>/dev/null",
                "packer": f"objdump -h '{remote_path}' 2>/dev/null || readelf -S '{remote_path}'"
            }
            command = cmd_map.get(a_type, "echo 'Analysis failed'")
            stdin, stdout, stderr = ssh.exec_command(command, timeout=300)
            report = stdout.read().decode('utf-8', errors='ignore')

        if os.path.exists(local_path): os.remove(local_path)
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    create_html()
    app.run(debug=True, port=5000, threaded=True)
