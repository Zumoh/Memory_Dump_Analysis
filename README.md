# Memory_Dump_Analysis

## Objective

The objective of this investigation is to analyze suspicious activity flagged by the SIEM on a workstation with access to sensitive financial data. The goal is to identify the malicious process, its parent process, and network connections, while assessing potential indicators of compromise (IOCs).

Using tools like MemProcFS, netstat, and VirusTotal, the investigation aims to confirm malicious activity, trace the attack’s origin, and determine if the system communicated with a Command and Control (C2) server. By mapping the attack to the MITRE ATT&CK framework, the investigation seeks to define the attack chain, ensure containment, and provide recommendations to strengthen security.

### Skills Learned

- **Threat Analysis and Detection**:
   - Identifying malicious processes and their parent-child relationships in memory dumps.
   - Analyzing network connections to detect potential Command and Control (C2) activity.
   - Using VirusTotal and AbuseIPDB to assess the reputation of suspicious IP addresses.

- **Memory Forensics**
   - Extracting and mounting memory dumps for investigation using MemProcFS.
   - Navigating process directories to analyze active and terminated processes.
   - Identifying the parent process ID (PPID) of malicious processes to understand attack flow.
 
- **Network Forensics**
   - Examining network telemetry using netstat outputs within memory dumps.
   - Detecting abnormal outbound connections and analyzing network traffic for potential threats.
   - Recognizing unusual ports and unauthorized access attempts.

- **Threat Intelligence and Attribution**
   - Leveraging open-source intelligence (OSINT) tools like VirusTotal to identify malware families.
   - Mapping attack behaviors to the MITRE ATT&CK framework to classify tactics and techniques.
   - Identifying known malware indicators such as StrelaStealer and Danabot.

### 🛠️ Tools Used

- **MemProcFS**: Used to parse and mount the memory dump for analysis.
- **Dokany**: Required for MemProcFS to function as a file system.
- **7-Zip**: Used to extract the memory dump file.
- **PowerShell**: Used to execute commands and navigate the investigation directories.
- **Netstat (via MemProcFS)**: Used to analyze network connections and detect suspicious activity.
- **VirusTotal**: Used to check the reputation of suspicious IP addresses and processes.
- **AbuseIPDB**: Used to check IP addresses for past reports of malicious activity.
- **MITRE ATT&CK Framework**: Used to map attack techniques and sub-techniques.
- **File Explorer**: Used to verify mounted memory dumps and navigate investigation files.
- **Web Browser**: Used to access online threat intelligence resources such as VirusTotal and AbuseIPDB.

---

### Preparation

**Download and Install MemProcFS**:

1) Open your web browser and visit MemProcFS GitHub repository ```https://github.com/ufrisk/MemProcFS```. 
2) Navigate to the ‘Releases’ section and download the latest release. The latest release at the time of my investigation is Version 5.14.
