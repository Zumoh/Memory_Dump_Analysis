# Memory_Dump_Analysis

<img width="739" alt="Screenshot 2025-02-01 at 4 59 57 PM" src="https://github.com/user-attachments/assets/3a569898-92ad-40b5-bfb7-1cc380939870" />

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
2) Navigate to the ‘**Releases**’ section and download the latest release. The latest release at the time of my investigation is Version 5.14.

<img width="730" alt="Screenshot 2025-02-01 at 5 01 41 PM" src="https://github.com/user-attachments/assets/e63e220a-5442-46e8-a2df-6b97213d9887" />


<img width="733" alt="Screenshot 2025-02-01 at 5 03 35 PM" src="https://github.com/user-attachments/assets/98a788c0-dc89-4df3-b092-48c97993a6d7" />


**Download and Install Dependencies**:

1) From your web browser, visit the Dokany GitHub releases page ```https://github.com/dokan-dev/dokany/releases/latest``` to download the DOKANY file system library.
2) Select the DokanSetup.exe file.

<img width="731" alt="Screenshot 2025-02-01 at 5 07 23 PM" src="https://github.com/user-attachments/assets/7ad19674-2806-4b42-ad91-5988bf95eb8e" />


3) Navigate to the directory in which the downloaded file was saved and run the file.

<img width="732" alt="Screenshot 2025-02-01 at 5 09 01 PM" src="https://github.com/user-attachments/assets/a570facd-fb4d-430c-8fea-f1211b132677" />

<img width="432" alt="Screenshot 2025-02-01 at 5 18 23 PM" src="https://github.com/user-attachments/assets/317aaccb-5945-481d-ac18-6ced3a1b531c" />

---

- Download the lab file (memory dump) from cyberdefenders.org.
- Password: cyberdefenders.org.

<img width="727" alt="Screenshot 2025-02-01 at 5 21 46 PM" src="https://github.com/user-attachments/assets/a435586f-8153-4c19-aebb-e55fe0be76d0" />

#

**Download and install 7zip**:

1) From your web browser, visit 7-zip download page ```https://www.7-zip.org/download.html```.
2) Click the download link that corresponds with your system.

<img width="724" alt="Screenshot 2025-02-01 at 5 24 05 PM" src="https://github.com/user-attachments/assets/aee14289-5057-4dff-bb22-821d940a62bb" />

3) Navigate to the directory in which the downloaded file was saved and run the file.

<img width="732" alt="Screenshot 2025-02-01 at 5 24 56 PM" src="https://github.com/user-attachments/assets/d08d8e8b-af6e-4761-a60e-ff816edfdb2d" />

<img width="304" alt="Screenshot 2025-02-01 at 5 25 41 PM" src="https://github.com/user-attachments/assets/0441dc1f-243f-43ae-9dc3-09ad136de1f4" />


Use **7-Zip** to extract the memory dump file. When prompted for a password, enter ‘**cyberdefenders.org**’ to proceed with the extraction. This step ensures that the memory dump is accessible for further analysis.










