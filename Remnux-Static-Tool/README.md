# 🛡️ StoicSentinel: Advanced Malware Static-Analysis Workbench

**StoicSentinel** is a high-performance, single-file production dashboard designed for Malware Researchers and **DFIR** professionals. It bridges the gap between your analysis host (e.g., FLARE-VM) and a specialized **REMnux** backend, automating the extraction of "gold-standard" forensic metadata in seconds.

Built with the philosophy of **Objective Representation**, StoicSentinel is engineered to strip away the "armor" of modern malware—including advanced protectors like **Themida**—to reveal the binary's true functional essence.

---

## 🛠️ Complete Feature Matrix

TabForensic Engines & ToolsIntent & Analytical OutputOverviewdiec, sha256sum, cutInstant Triage: Identifies file type, compiler, and packer signatures. Automatically generates a pivot link to VirusTotal based on the file hash.Capabilitiescapa (Standard & Deep)Behavior Mapping: Uses the Capa engine to map binary functionality to the MITRE ATT&CK® framework. Identifies high-level goals like "Steal Credentials" or "Inject Code."Advanced PEmanalyze, pedump, peframeDeep Structural Recon: Identifies hidden imports, verifies digital signatures, and flags suspicious PE characteristics (e.g., unusual section names).Raw Stringsstrings + Anomaly GrepHeuristic Scanning: Extracts ASCII strings and filters them against a massive custom dictionary of dangerous keywords (APIs, C2 patterns, registry keys).FLOSSMandiant FLOSS, xorsearchDe-obfuscation: Decodes "stack strings" and strings obfuscated at runtime. Bypasses standard anti-forensic techniques that hide configuration data.Packer & Sectionsobjdump, readelf, densityscoutEntropy Analysis: Maps file sections and calculates Shannon Entropy. Locates hidden, encrypted payloads by identifying areas of high randomness (>7.0).Shellcode Emulationscdbg, pescan, xorsearch -pAPI Hooking: Emulates code execution in a safe environment. Reveals which Windows APIs the code tries to resolve (e.g., URLDownloadToFile, WinExec) without using a debugger.XOR Forensicbalbuzard, bbcrack, xorsearch, brxorCipher Breaking: Brute-forces bitwise obfuscation. Statistically decodes XOR/ROT encrypted blocks to reveal hidden C2 URLs or shellcode.Network ReconAggressive Multi-Source GrepC2 Identification: Aggregates data from ASCII, Unicode LE, FLOSS, and Balbuzard. Targets IPs, public domains, and malware-specific TLDs (e.g., .ru, .onion).Ghidra Symbolsobjdump -p, strings, foremostLibrary Analysis: Summarizes linked DLLs and scans for dangerous system APIs. Includes a list of carved resources extracted from the binary.Entry-Point Assemblyobjdump -f, objdump -dLow-Level Review: Computes the exact Entry Point (EP) of the program and provides a disassembly of the first 200 instructions for rapid code flow review.File Carvingbinwalk, peframeArtifact Recovery: Scans for embedded files (droppers, icons, scripts) "sewn" into the primary binary structure. Identifies the offset and size of hidden data.Documents & Officeoledump, olevba, mraptor, oleid, olemeta, plugin_http_hostsOffice Weaponization Lab: Maps OLE streams, de-obfuscates VBA macros, extracts metadata (attribution), and automatically pulls network IOCs from document streams.Resources & YARAyara, loki, ssdeep, pedump -rSignature Scanning: Matches the file against thousands of global YARA rules to identify specific malware families and compares fuzzy hashes for similarity.
---

## 🏗️ Architecture

* **Frontend:** Modern, dark-themed responsive UI with dynamic highlighting for IOCs.
* **Backend:** Flask-powered asynchronous Python controller.
* **Transport:** Encrypted SSH/SFTP via `Paramiko` for remote execution on REMnux.

---

**Developed for the Cyber Security Community. Stay Stoic. Analyze Deeper.**

---
