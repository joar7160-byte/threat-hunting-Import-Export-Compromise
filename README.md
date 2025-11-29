# Threat Hunt Report: Export/Import Compromise   
**Participant:** Joarder Rashid  
**Date:** November 2025  

---

## Platforms and Languages Leveraged
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)  

---

## Scenario
Azuki Import/Export (梓貿易株式会社) is a mid-size maritime logistics and shipping coordination firm based in Japan and Southeast Asia. In November 2025, internal financial documents, supplier pricing contracts, and routing data surfaced on underground forums.

The compromise impacted the AZUKI-SL administrative workstation — a privileged IT management machine.

---

## High-Level IoC Discovery Plan
- DeviceLogonEvents — external login source + account used
- DeviceProcessEvents — execution chain and LOLBIN abuse
- DeviceFileEvents — malicious file creation & staging behavior
- DeviceNetworkEvents — C2 traffic & exfiltration
- DeviceRegistryEvents — persistence & antivirus exclusions

---

## Starting Point
We began the investigation by isolating AZUKI-SL, the compromised IT admin workstation, and pulling process data from the window of 19–20 November 2025. Initial review of these events revealed suspicious remote access activity, credential abuse attempts, and defense-evasion behaviors, establishing AZUKI-SL as the focal point of compromise.

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))

`````

🚩 1. Remote Access Source

Goal: Identify the source IP address of the Remote Desktop Protocol connection.

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc

```

Thought Process:
We filtered logon activity for external interactive logons to determine the origin of the unauthorized RDP connection.

Answer: 88.97.178.12

🚩 2. Compromised User Account

Goal: Identify the user account that was compromised for initial access

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
`````
IMAGE

Thought Process:
We reviewed which account executed processes after remote authentication — confirming credential compromise.****

🚩 3. Network Reconnaissance
Goal: Identify the command and argument used to enumerate network neighbours.

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "ARP"
| where InitiatingProcessAccountName == "kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
`````


Question: Provide the command value tied to this exploit.

Answer: We targeted ARP table enumeration activity — a common step in discovering local machines.

🚩 4. Malware Staging Directory
We searched for reconnaissance commands used to enumerate user sessions.

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName in ("cmd.exe", "powershell.exe")
| where ProcessCommandLine contains "mkdir"
      or ProcessCommandLine contains "md "
      or ProcessCommandLine contains "New-Item"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "attrib"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc

`````


Question: Point out when the last recon attempt occurred.

Answer: 2025-10-09T12:51:44.3425653Z

🚩 5. File Extension Exclusions
After session recon, the attacker enumerated available drives and shares.

`````kql
DeviceRegistryEvents
 | where DeviceName == "azuki-sl"
 | where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
 | where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
 | project Timestamp, RegistryValueName, RegistryValueData, RegistryKey, InitiatingProcessAccountName
`````


Question: Provide the 2nd command tied to this activity.

Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size"

🚩 6. Temporary Folder Exclusion
We verified whether the attacker tested external connectivity using common diagnostic commands.

`````kql
DeviceRegistryEvents
 | where DeviceName == "azuki-sl"
 | where RegistryKey contains @"Windows Defender\Exclusions\Paths"
 | where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
 | project Timestamp, RegistryValueName, RegistryValueData, RegistryKey, InitiatingProcessAccountName
 | order by Timestamp asc
`````

Question: Provide the File Name of the initiating parent process.

Answer: RuntimeBroker.exe

🚩 7. Download Utility Abuse
We inspected any attempts to query active user sessions.

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "http://"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
`````

Question: What is the unique ID of the initiating process?

Answer: 2533274790397065

🚩 8. Scheduled Task Name
Question: Provide the file name of the process that best demonstrates a runtime process enumeration event.

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/create"
| project Timestamp, AccountName, ProcessCommandLine
```
Answer: tasklist.exe

🚩 9. Scheduled Task Target
We searched for privilege enumeration attempts using whoami.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/tr"
| project Timestamp, AccountName, ProcessCommandLine

`````


Question: Identify the timestamp of the first attempt.

Answer: 2025-10-09T12:52:14.3135459Z

🚩 10. C2 Server Address
We checked for outbound connections made by the malicious process to confirm network reachability.

`````kql
DeviceNetworkEvents
| where DeviceName contains "azuki-sl"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFolderPath
`````

Question: Which outbound destination was contacted first?

Answer: www.msftconnecttest.com

🚩 11. C2 Port
We analyzed file operations for evidence of data staging or compression.

`````kql
DeviceNetworkEvents
| where DeviceName contains "azuki-sl"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFolderPath

`````

Question: Provide the full folder path where the artifact was first dropped.

Answer: C:\Users\Public\ReconArtifacts.zip

🚩 12. Credential Theft Tool
We identified simulated outbound data transfer attempts following artifact creation.

`````kql
DeviceFileEvents
| where DeviceName contains "azuki-sl"
| where FileName endswith ".exe"
| where FolderPath contains "ProgramData"
   or FolderPath contains "Temp"
   or FolderPath contains "Public"
   or FolderPath contains "WindowsCache"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
`````


Question: Provide the IP of the last unusual outbound connection.

Answer: 100.29.147.161

🚩 13. Memory Extraction Module
I looked for creation of persistence mechanisms through scheduled tasks.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| extend cmds = extract(@"(\w+::\w+)", 1, ProcessCommandLine)
| where isnotempty(cmds)
| project Timestamp, cmds, ProcessCommandLine
`````


Question: Provide the value of the task name.

Answer: SupportToolUpdater

🚩 14. Data Staging Archive

`````kql
DeviceFileEvents
| where DeviceName contains "azuki-sl"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
`````

Question: What was the name of the registry value associated with autorun persistence?

Answer: RemoteAssistUpdater

🚩 15. Exfiltration Channel
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceNetworkEvents
| where DeviceName contains "azuki-sl"
| where RemoteUrl contains "drive"
    or RemoteUrl contains "dropbox"
    or RemoteUrl contains "google"
    or RemoteUrl contains "one"
    or RemoteUrl contains "mega"
    or RemoteUrl contains "slack"
    or RemoteUrl contains "disc"
| project Timestamp, RemoteUrl, InitiatingProcessFileName
`````

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 16. Log Tampering
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
`````

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 17. Persistence Account
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "localgroup"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
`````

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 18. Malicious Script
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine matches regex @"\w+\.ps1"
| extend script = extract(@"(\w+\.ps1)", 1, ProcessCommandLine)
| project Timestamp, script, ProcessCommandLine
| order by Timestamp asc
`````

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 19. Secondary Target
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "cmdkey"
| project Timestamp, ProcessCommandLine, ProcessRemoteSessionIP
| order by Timestamp asc
`````


Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 20. Remote Access Tool
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "mstsc.exe"
| project Timestamp, ProcessCommandLine, ProcessRemoteSessionIP
| order by Timestamp asc
`````


Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk



| Flag | Category / Description                          | Value                                                   |
|------|-------------------------------------------------|---------------------------------------------------------|
| Start| Compromised Host System                         | AZUKI-SL                                                |
| 1    | Remote Access Source IP                         | 88.97.178.12                                            |
| 2    | Compromised User Account                        | kenji.sato                                              |
| 3    | Network Reconnaissance Command                  | ARP -a                                                  |
| 4    | Malware Staging Directory                       | C:\ProgramData\WindowsCache                             |
| 5    | Defender Excluded File Extensions (count)       | 3                                                       |
| 6    | Defender Temp Folder Exclusion                  | C:\Users\KENJI~1.SAT\AppData\Local\Temp                 |
| 7    | Download Utility Used (LOLBIN)                  | certutil.exe                                            |
| 8    | Scheduled Task Name                             | Windows Update Check                                    |
| 9    | Scheduled Task Execution Binary                 | C:\ProgramData\WindowsCache\svchost.exe                 |
| 10   | C2 External Control Server                      | 78.141.196.6                                            |
| 11   | Command & Control Port                          | 443                                                     |
| 12   | Credential Dumping Executable                   | mm.exe                                                  |
| 13   | Credential Memory Extraction Module             | sekurlsa::logonpasswords                                |
| 14   | Stolen Data Archive                             | export-data.zip                                         |
| 15   | Exfiltration Channel                            | discord                                                 |
| 16   | First Windows Log Cleared                       | Security                                                |
| 17   | Persistence Admin-Level Backdoor Account        | support                                                 |
| 18   | Malicious Automation Script                     | wupdate.ps1                                             |
| 19   | Lateral Movement Target IP                      | 10.1.0.188                                              |
| 20   | Remote Access Tool Used for Pivoting            | mstsc.exe                                               |



Report Completed By: Joarder Rashid
Status: ✅ All 20 flags investigated and confirmed
