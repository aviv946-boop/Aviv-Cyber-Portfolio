# 🛡️ StoicSentinel: Advanced Malware Static-Analysis Workbench

**StoicSentinel** is a high-performance, single-file production dashboard designed for Malware Researchers and **DFIR** professionals. It bridges the gap between your analysis host (e.g., FLARE-VM) and a specialized **REMnux** backend, automating the extraction of "gold-standard" forensic metadata in seconds.

Built with the philosophy of **Objective Representation**, StoicSentinel is engineered to strip away the "armor" of modern malware—including advanced protectors like **Themida**—to reveal the binary's true functional essence.

---

## 🚀 The Elite Power-Tabs

### ⚡ Deep Auto-Ghidra Scan

The system's "Brain." Instead of waiting minutes for the Ghidra GUI auto-analysis, this tab runs a unified pipeline of **Recursive File Carving** and **Symbol Extraction**. It scans for dangerous Windows APIs (e.g., `VirtualAllocEx`, `CreateRemoteThread`) across both the original binary and every single carved artifact simultaneously.

### 🔐 XOR Forensic Pipeline

A multi-stage engine designed for modern loaders that conceal C2 configurations behind custom XOR/ROT loops. It utilizes **Balbuzard IOC Scanning** to detect hidden MZ/PE signatures and employs **Statistical Frequency Analysis** (`brxor` & `bbcrack`) to automatically discover encryption keys.

### 🐚 Shellcode Emulation (Entry-Focused)

A surgical tool for analyzing packed samples. It uses `pescan` and `xorsearch -p` to map candidate shellcode regions before executing **scdbg** in "Tolerant Mode" (`/i`). This surfaces runtime-resolved APIs that are invisible to standard static string scanners.

---

## 🛠️ Complete Feature Matrix

| Tab | Forensic Engine / Logic | Intent & Output |
| --- | --- | --- |
| **Overview** | `diec` Heuristics + SHA256 | Instant triage: identifies compilers, packers, and provides a direct VirusTotal pivot. Cleaned for High Signal-to-Noise Ratio (SNR). |
| **Capabilities** | `capa` engine | Maps binary functionality directly to the **MITRE ATT&CK®** framework to identify the malware's goals. |
| **Advanced PE** | `pedump` + `peframe` | Deep-dive into PE headers, identifying hidden imports and suspicious file characteristics. |
| **Raw Strings** | `strings` (Optimized) | Rapid extraction of ASCII strings with a custom anomaly filter for high-interest patterns. |
| **FLOSS** | Mandiant `FLOSS` | Deobfuscates "stack strings" and strings decoded at runtime that standard extraction misses. |
| **Packer & Sections** | `objdump` + `densityscout` | Visual mapping of file sections and **Shannon Entropy** analysis to locate hidden encrypted payloads. |
| **Shellcode Emulation** | `scdbg` + `pescan` | Emulates execution to hook resolved APIs and reveal shellcode behavior without a debugger. |
| **XOR Forensic** | `balbuzard` + `bbcrack` | Breaks bitwise obfuscation and reveals hidden configuration blocks/C2 data. |
| **Network Recon** | Multi-Source Grep | Aggressive search across ASCII, Unicode LE, and FLOSS outputs for IPs, domains, and malware-specific TLDs. |
| **Ghidra Symbols** | `pelook` + `wrestool` | A robust summary of linked libraries, dynamic symbol tables, and dangerous Windows API hits. |
| **Entry-Point Assembly** | `objdump -d` | Direct disassembly starting exactly at the program's Entry Point (EP) for rapid structural review. |
| **Deep Auto-Ghidra** | Unified Pipeline | **The Master Scan:** Automated carving followed by cross-referenced symbol and API analysis. |
| **File Carving** | `binwalk` + `foremost` | Recovers embedded binaries, scripts, or images hidden within the primary file structure. |
| **Documents & Office** | `pdfid` + `oledump.py` | Specialized analysis for malicious PDFs and Office documents (Macros/OLE objects). |
| **Resources & YARA** | `yara` + `loki` | Scans against global signature databases to identify specific malware families and known IOCs. |

---

## 🏗️ Architecture

* **Frontend:** Modern, dark-themed responsive UI with dynamic highlighting for IOCs.
* **Backend:** Flask-powered asynchronous Python controller.
* **Transport:** Encrypted SSH/SFTP via `Paramiko` for remote execution on REMnux.

---

**Developed for the Cyber Security Community. Stay Stoic. Analyze Deeper.**

---
