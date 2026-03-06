# 🛡️ Remnux Static Tool

**Advanced Web-Based Static Analysis Dashboard**

Remnux Static Tool is a forensic-grade malware analysis platform designed to automate and streamline static data extraction. By bridging a Python Flask backend with the advanced forensic toolset of **REMnux**, it provides deep, actionable insights into PE files, specifically engineered to bypass complex obfuscation and packing.

## 📑 Feature Breakdown by Forensic Importance

### 1. Capabilities - Capa (Behavioral Mapping) 🔍

Maps malware functionality to the MITRE ATT&CK® framework without the need for execution.

* **Tactical Analysis**: Identifies capabilities such as "Process Injection," "Credential Stealing," or "Anti-VM" techniques.
* **Variable Verbosity**: User-selectable modes between high-level summaries (`-qq`) and deep-dive technical breakdowns (`-vv`).

### 2. FLOSS - Strings Recovery Pipeline (Deep Intelligence) 🚨

A specialized multi-stage engine built for active de-obfuscation and IOC harvesting.

* **Recovery Pipeline**: Orchestrates a combined attack using `strings`, `FLOSS` (Stack Strings), and `XORSearch` to bypass static encoding.
* **IOC Extraction**: Automated harvesting of network indicators, including IPs, domains, and suspicious URLs.
* **Forensic Filtering**: Aggressive noise reduction to highlight potential C2 commands and cryptographic constants.

### 3. Overview (File Identity & Reputation) 🛡️

The primary entry point for any investigation, providing immediate situational awareness.

* **Technical Metadata**: Instant identification of architecture (x86/x64), subsystem, and compiler/linker details.
* **Heuristic Analysis**: Automated detection of protectors and packers to determine if the sample is packed.
* **Reputation Check**: Direct integration for pivoting to VirusTotal for global threat intelligence.
  
### 4. Packer & Sections (Entropy & Structural Integrity) 📦

Analyzes file sections to pinpoint anomalies and hidden payloads.

* **Visual Entropy Mapping**: Detailed visualization of data density to locate encrypted or compressed regions.
* **Structural Analysis**: Detects non-standard section names or zeroed-out headers indicative of custom packers.

### 5. Resources & YARA (Signature Matching) 🛡️

Leverages industry-standard signature sets for rapid family identification.

* **Signature Scans**: Real-time matching against `YARA` and `LOKI` rulebases to identify known malware families.
* **Artifact Inspection**: Analyzes embedded resources and the MZ header for forensic consistency.

### 6. Advanced PE & Raw Strings 🛠️

Specialized tools for the experienced forensic investigator.

* **Advanced PE Analysis**: Deep-dive into the Import Address Table (IAT) using `Manalyze` to find critical API calls.
* **Raw Strings**: Full, unfiltered access to all ASCII/Unicode strings for manual discovery and pattern hunting.

## 🛠️ Prerequisites

* **REMnux VM**: Running with an active SSH server (`sudo systemctl enable --now ssh`).
* **System Updates**: Ensure the toolset is current via `remnux-update`.
* **Python 3.10+**: Installed on the host machine.

## ⚙️ Installation & Usage

1. **Clone**: the repository to your host machine.
2. **Install**: dependencies: `pip install -r requirements.txt`.
3. **Configure**: Update the REMNUX_IP, VM_USER, and VM_PASS variables in app.py with your VM's credentials.
4. **Launch**: Run the dashboard using `python app.py`.
5. **Access**: Open your browser at `http://127.0.0.1:5000`.
