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

The compromise impacted the AZUKI-SL administrative workstation (a privileged IT management machine).

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

🚩 1. Remote Access Source: Identify the source IP address of the Remote Desktop Protocol connection

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc

```

<img width="1641" height="710" alt="image" src="https://github.com/user-attachments/assets/9d921210-41a7-4986-80ce-b10ef69ada06" />

Thought Process:
We filtered logon activity for external interactive logons to determine the origin of the unauthorized RDP connection.

Answer: 88.97.178.12

------------------------------------------------------------------------------------------------------------------------------------
🚩 2. Compromised User Account: Identify the user account that was compromised for initial access

`````kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "88.97.178.12"
| project Timestamp, AccountName, RemoteIP, LogonType, ActionType
`````

<img width="1659" height="837" alt="image" src="https://github.com/user-attachments/assets/c2358fe0-d6d5-491c-b438-590748e2e54f" />

Thought Process:
We reviewed which account executed processes after remote authentication, confirming credential compromise.

Answer: kenji.sato

------------------------------------------------------------------------------------------------------------------------------------

🚩 3. Network Reconnaissance: Identify the command and argument used to enumerate network neighbours

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "ARP"
| where InitiatingProcessAccountName == "kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
`````
<img width="1626" height="920" alt="image" src="https://github.com/user-attachments/assets/71382586-208f-48c9-a85d-2dd0934684be" />

Thought Process:
We targeted ARP table enumeration activity because it's a common step in discovering local machines.

Answer: "ARP.EXE" -a

------------------------------------------------------------------------------------------------------------------------------------
🚩 4. Malware Staging Directory: Identify the PRIMARY staging directory where malware was stored

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
<img width="1598" height="735" alt="image" src="https://github.com/user-attachments/assets/ad7e75ce-1d3f-4c16-b811-3ef0b5bf6ad8" />


Thought process: 
I looked for directory creation and manipulation activity in `DeviceProcessEvents`, focusing on `cmd.exe` / `powershell.exe` commands using `mkdir`, `md`, or `New-Item`, followed by `attrib` to hide folders. This pattern revealed a suspicious folder under `C:\ProgramData\` that was later used as a tool and payload staging location

Answer: C:\ProgramData\WindowsCache

------------------------------------------------------------------------------------------------------------------------------------

🚩 5. File Extension Exclusions:  How many file extensions were excluded from Windows Defender scanning? 

`````kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, RegistryValueName, RegistryValueData, RegistryKey, InitiatingProcessAccountName
`````
<img width="1639" height="856" alt="image" src="https://github.com/user-attachments/assets/c4d9054b-f98e-46da-af11-edf042dbcd45" />

Thought process: 
I pivoted to `DeviceRegistryEvents` and searched under the `Windows Defender\Exclusions\Extensions` key on `azuki-sl` during the incident timeframe. By reviewing the `RegistryValueName`/`RegistryValueData` entries, I counted the distinct extensions that the attacker excluded from Defender scanning.  

Answer: 3

------------------------------------------------------------------------------------------------------------------------------------
🚩 6. Temporary Folder Exclusion:  What temporary folder path was excluded from Windows Defender scanning?

`````kql
DeviceRegistryEvents
 | where DeviceName == "azuki-sl"
 | where RegistryKey contains @"Windows Defender\Exclusions\Paths"
 | where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
 | project Timestamp, RegistryValueName, RegistryValueData, RegistryKey, InitiatingProcessAccountName
 | order by Timestamp asc
`````
<img width="1664" height="883" alt="image" src="https://github.com/user-attachments/assets/2f4aafe1-6b2f-4314-ab6b-e138f8f9eb90" />

Thought process:  
Still in `DeviceRegistryEvents`, I then targeted `Windows Defender\Exclusions\Paths` to identify folder-level exclusions. Sorting by timestamp made it easy to spot a suspicious user temp directory added as an exclusion, clearly used to safely drop and execute tooling.  
Question: Provide the File Name of the initiating parent process.

Answer: C:\Users\KENJI~1.SAT\AppData\Local\Temp

------------------------------------------------------------------------------------------------------------------------------------
🚩 7. Download Utility Abuse: Identify the Windows-native binary the attacker abused to download files

`````kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "http://"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
`````

<img width="1655" height="898" alt="image" src="https://github.com/user-attachments/assets/fd63d746-5b7d-4a22-90cc-4d29dbaa1285" />

Thought process:  
To identify whether the attacker abused built-in Windows utilities to download malicious files, I filtered process executions containing URLs (`http://`). Seeing `certutil.exe` used with remote download parameters confirmed the attacker was leveraging a LOLBIN to evade antivirus detection while fetching additional payloads.

Answer: certutil.exe

------------------------------------------------------------------------------------------------------------------------------------
🚩 8. Scheduled Task Name: Identify the name of the scheduled task created for persistence

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/create"
| project Timestamp, AccountName, ProcessCommandLine
```
Answer: Windows Update Check

------------------------------------------------------------------------------------------------------------------------------------
🚩 9. Scheduled Task Target: Identify the executable path configured in the scheduled task?

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/tr"
| project Timestamp, AccountName, ProcessCommandLine

```
<img width="1662" height="859" alt="image" src="https://github.com/user-attachments/assets/01649e1d-d868-4b75-945f-6c46f78d00a5" />

Thought Process:
Using the same `/create` and `/tr`-based hunting approach in `DeviceProcessEvents`, I focused specifically on entries with `/tr` to extract the “task action” path. The malicious task was configured to execute a binary directly out of the attacker’s staging directory

Answer: C:\ProgramData\WindowsCache\svchost.exe

------------------------------------------------------------------------------------------------------------------------------------
🚩 10. C2 Server Address: Identify the IP address of the command and control server

`````kql
DeviceNetworkEvents
| where DeviceName contains "azuki-sl"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFolderPath
`````
<img width="1634" height="787" alt="image" src="https://github.com/user-attachments/assets/bd8bdf4d-caf4-4ade-a673-fcb172d74056" />

Thought Process:
I pivoted to `DeviceNetworkEvents` and scoped to `azuki-sl`, then filtered on connections where the `InitiatingProcessFolderPath` included `WindowsCache`, tying outbound traffic back to the staged malware. Among those connections, I identified the external `RemoteIP` serving as the C2 endpoint

Answer: 78.141.196.6

------------------------------------------------------------------------------------------------------------------------------------
🚩 11. C2 Port: Identify the destination port used for command and control communications

`````kql
DeviceNetworkEvents
| where DeviceName contains "azuki-sl"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFolderPath

`````
<img width="1634" height="787" alt="image" src="https://github.com/user-attachments/assets/e2f89f3c-1c55-46f0-a101-675697724ed3" />

**Thought process:**  
From the same `DeviceNetworkEvents` rows used for Flag 10, I examined the `RemotePort` column to determine how the malware communicated with the C2. The traffic was tunneled over a commonly allowed encrypted port, helping it blend in with normal HTTPS traffic.  

Answer: 443

------------------------------------------------------------------------------------------------------------------------------------
🚩 12. Credential Theft Tool: Identify the filename of the credential dumping tool

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
<img width="1625" height="635" alt="image" src="https://github.com/user-attachments/assets/26f14df0-5704-4cb3-871d-80a7d875d2ee" />

**Thought process:**  
I searched `DeviceFileEvents` for `.exe` files dropped into sensitive or attacker-typical directories such as `ProgramData`, `Temp`, `Public`, and `WindowsCache`. By sorting these by `Timestamp`, I identified a short, suspiciously named executable that aligned with the credential access phase.  

Answer: mm.exe

------------------------------------------------------------------------------------------------------------------------------------
🚩 13. Memory Extraction Module: Identify the module used to extract logon passwords from memory


`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| extend cmds = extract(@"(\w+::\w+)", 1, ProcessCommandLine)
| where isnotempty(cmds)
| project Timestamp, cmds, ProcessCommandLine
`````
<img width="1584" height="859" alt="image" src="https://github.com/user-attachments/assets/6fe62528-e977-42f4-97a6-26693b76c75d" />


**Thought process:**  
In `DeviceProcessEvents`, I used a regex extraction on `ProcessCommandLine` to pull out `module::command` patterns that are typical of tools like Mimikatz. This surfaced the exact module/command combination used to dump logon passwords from LSASS.  


Answer: sekurlsa::logonpasswords

------------------------------------------------------------------------------------------------------------------------------------
🚩 14. Data Staging Archive:  Identify the compressed archive filename used for data exfiltration

`````kql
DeviceFileEvents
| where DeviceName contains "azuki-sl"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
`````

<img width="1626" height="863" alt="image" src="https://github.com/user-attachments/assets/b7498107-c76d-4fce-bcb8-7faf887fb269" />

**Thought process:**  
I scanned `DeviceFileEvents` for files ending in `.zip` on `azuki-sl` and sorted them chronologically. The suspicious archive created in the staging area around the collection/exfiltration phase clearly matched the attacker’s data bundle

Answer: export-data.zip

------------------------------------------------------------------------------------------------------------------------------------
🚩 15. Exfiltration Channel:  Identify the cloud service used to exfiltrate stolen data

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
<img width="1546" height="835" alt="image" src="https://github.com/user-attachments/assets/1eaef96b-7778-41a0-a9d1-491189d31fa3" />

**Thought process:**  
I hunted in `DeviceNetworkEvents` for `RemoteUrl` values containing common file-sharing and collaboration platforms (`drive`, `dropbox`, `mega`, `slack`, `disc`, etc.). Among these, I identified outbound connections consistent with an exfiltration channel to a popular chat/file-sharing platform

Answer: discord

------------------------------------------------------------------------------------------------------------------------------------
🚩 16. Log Tampering: Identify the first Windows event log cleared by the attacker

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
`````
<img width="1644" height="855" alt="image" src="https://github.com/user-attachments/assets/a9c2dd75-f7fe-4759-bc47-946b681cd4d3" />

**Thought process:**  
I returned to `DeviceProcessEvents` and filtered for `wevtutil` usage on `azuki-sl`, then ordered results by `Timestamp`. The first invocation revealed which log channel the attacker prioritized for clearing to disrupt forensic reconstruction.  

Answer: Security

------------------------------------------------------------------------------------------------------------------------------------
🚩 17. Persistence Account: Identify the backdoor account username created by the attacker

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "localgroup"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
<img width="1650" height="820" alt="image" src="https://github.com/user-attachments/assets/88d923e4-5ab5-4399-b537-ae46947bee35" />

**Thought process:**  
To detect malicious account creation, I searched `DeviceProcessEvents` for `net localgroup` or `localgroup` commands. Reviewing those command lines showed a new local user being added and then placed into privileged groups as a stealthy persistence mechanism.

Answer: Support

------------------------------------------------------------------------------------------------------------------------------------
🚩 18. Malicious Script: Identify the PowerShell script file used to automate the attack chain

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine matches regex @"\w+\.ps1"
| extend script = extract(@"(\w+\.ps1)", 1, ProcessCommandLine)
| project Timestamp, script, ProcessCommandLine
| order by Timestamp asc
```
<img width="1639" height="869" alt="image" src="https://github.com/user-attachments/assets/acf79f8c-1496-4038-8596-79115f50be84" />

**Thought process:**  
I used regex in `DeviceProcessEvents` to extract any `*.ps1` script names from `ProcessCommandLine` across `azuki-sl`, then sorted by `Timestamp` to see which script appeared around the initial execution and automation phase. The identified script clearly chained multiple attacker actions.

Answer: wupdate.ps1

------------------------------------------------------------------------------------------------------------------------------------
🚩 19. Secondary Target: What IP address was targeted for lateral movement?

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "cmdkey"
| project Timestamp, ProcessCommandLine, ProcessRemoteSessionIP
| order by Timestamp asc
`````
<img width="1655" height="856" alt="image" src="https://github.com/user-attachments/assets/c546d018-8800-4236-ae7f-41844b08f488" />

**Thought process:**  
I focused on `DeviceProcessEvents` entries containing `cmdkey`, which is commonly used to store alternate credentials for remote systems. The `ProcessCommandLine` and `ProcessRemoteSessionIP` fields exposed the internal IP that the attacker was preparing or using for lateral movement.

Answer: 10.1.0.188

------------------------------------------------------------------------------------------------------------------------------------
🚩 20. Remote Access Tool: Identify the remote access tool used for lateral movement.  

`````kql
DeviceProcessEvents
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "mstsc.exe"
| project Timestamp, ProcessCommandLine, ProcessRemoteSessionIP
| order by Timestamp asc
`````
<img width="1662" height="846" alt="image" src="https://github.com/user-attachments/assets/7870ec14-d6d8-48d1-9d12-108124e9231f" />

**Thought process:**  
Lastly, I searched `DeviceProcessEvents` for instances of `mstsc.exe` on `azuki-sl`, correlating them with remote IP arguments and the prior `cmdkey` usage. This confirmed that native Remote Desktop was used as the actual lateral movement mechanism.

Answer: mstsc.exe



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
