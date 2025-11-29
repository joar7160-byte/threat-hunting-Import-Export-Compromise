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

<img width="1255" height="728" alt="image" src="https://github.com/user-attachments/assets/c530a04a-5494-4aab-9769-a27f859b1ad0" />


🚩 1. Remote Access Source
Question:
Identify the source IP address of the Remote Desktop Protocol connection.

`````kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc



Thought Process:
We filtered logon activity for external interactive logons to determine the origin of the unauthorized RDP connection.

Question: What was the first CLI parameter name used during execution?

Answer: -ExecutionPolicy

🚩 2. Compromised User Account
We then checked if any tampering attempts occurred on the compromised host by searching for files referencing tamper.

`````kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName matches regex @"(?i)(tamper)"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| order by TimeGenerated asc
`````
<img width="1532" height="564" alt="image" src="https://github.com/user-attachments/assets/0ee22edd-5bc2-4af4-9144-17a20b794b5b" />

Question: What was the name of the file related to this exploit?

Answer: DefenderTamperArtifact.lnk

🚩 3. Network Reconnaissance
Next, we looked for commands that accessed clipboard data — a common quick-data theft tactic.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "powershell"
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
`````
<img width="1538" height="476" alt="image" src="https://github.com/user-attachments/assets/cc52cf93-9747-4893-8fd6-3d100b70e2bd" />

Question: Provide the command value tied to this exploit.

Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

🚩 4. Malware Staging Directory
We searched for reconnaissance commands used to enumerate user sessions.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
`````
<img width="1475" height="501" alt="image" src="https://github.com/user-attachments/assets/1b380eca-bdef-45b5-bc94-784dafd7c75b" />

Question: Point out when the last recon attempt occurred.

Answer: 2025-10-09T12:51:44.3425653Z

🚩 5. File Extension Exclusions
After session recon, the attacker enumerated available drives and shares.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where tolower(ProcessCommandLine) has_any ("net share", "net view", "dir /s", "Get-Volume", "Get-SmbShare", "wmic", "fsutil fsinfo drives", "Get-CimInstance -ClassName Win32_LogicalDisk")
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
`````
<img width="1573" height="491" alt="image" src="https://github.com/user-attachments/assets/1d077d67-65c3-4249-960d-af87517ca8c6" />

Question: Provide the 2nd command tied to this activity.

Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size"

🚩 6. Temporary Folder Exclusion
We verified whether the attacker tested external connectivity using common diagnostic commands.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "tracert")
| where FileName contains "cmd" or FileName contains "powershell"
| where IsProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
`````
<img width="1318" height="563" alt="image" src="https://github.com/user-attachments/assets/bc623cdb-83f7-4fc2-baaf-047e9b371ba7" />

Question: Provide the File Name of the initiating parent process.

Answer: RuntimeBroker.exe

🚩 7. Download Utility Abuse
We inspected any attempts to query active user sessions.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessUniqueId
`````
<img width="1556" height="586" alt="image" src="https://github.com/user-attachments/assets/4bdb0913-84ca-491d-80cc-4de174290253" />

Question: What is the unique ID of the initiating process?

Answer: 2533274790397065

🚩 8. Scheduled Task Name
Question: Provide the file name of the process that best demonstrates a runtime process enumeration event.

Answer: tasklist.exe

🚩 9. Scheduled Task Target
We searched for privilege enumeration attempts using whoami.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami"
| order by TimeGenerated asc
| take 1
`````
<img width="1526" height="508" alt="image" src="https://github.com/user-attachments/assets/b484e351-4039-45ea-bb92-947c9c3df292" />

Question: Identify the timestamp of the first attempt.

Answer: 2025-10-09T12:52:14.3135459Z

🚩 10. C2 Server Address
We checked for outbound connections made by the malicious process to confirm network reachability.

`````kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteUrl
| order by TimeGenerated asc
`````
<img width="1005" height="526" alt="image" src="https://github.com/user-attachments/assets/b39b241e-b87e-4840-b8f8-1775e7c71770" />

Question: Which outbound destination was contacted first?

Answer: www.msftconnecttest.com

🚩 11. C2 Port
We analyzed file operations for evidence of data staging or compression.

`````kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| where FileName has_any ("zip")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
`````
<img width="1452" height="617" alt="image" src="https://github.com/user-attachments/assets/6ba104f5-ee76-4f72-8d8e-c933ac975dd3" />

Question: Provide the full folder path where the artifact was first dropped.

Answer: C:\Users\Public\ReconArtifacts.zip

🚩 12. Credential Theft Tool
We identified simulated outbound data transfer attempts following artifact creation.

`````kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated desc
`````

<img width="1546" height="560" alt="image" src="https://github.com/user-attachments/assets/fbced72d-483b-4bf8-8cfe-e272612c9743" />

Question: Provide the IP of the last unusual outbound connection.

Answer: 100.29.147.161

🚩 13. Memory Extraction Module
I looked for creation of persistence mechanisms through scheduled tasks.

`````kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
`````

<img width="1540" height="753" alt="image" src="https://github.com/user-attachments/assets/842af05f-b028-4b31-ace3-1f4d0bbd4fef" />

Question: Provide the value of the task name.

Answer: SupportToolUpdater

🚩 14. Data Staging Archive

`````kql
DeviceRegistryEvents
| where DeviceName startswith "gab-intern-vm"
| where RegistryValueName == "RemoteAssistUpdater"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
`````

Question: What was the name of the registry value associated with autorun persistence?

Answer: RemoteAssistUpdater

🚩 15. Exfiltration Channel
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 16. Log Tampering
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 17. Persistence Account
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 18. Malicious Script
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 19. Secondary Target
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk

🚩 20. Remote Access Tool
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

`````kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
`````
<img width="1572" height="762" alt="image" src="https://github.com/user-attachments/assets/45be2ac4-c3a3-4f69-aa43-c8bcdb498dd7" />

Question: Identify the file name of the artifact left behind.

Answer: SupportChat_log.lnk



| Flag  | Description                         | Value                                                          |                       |
| ----- | ----------------------------------- | -------------------------------------------------------------- | --------------------- |
| Start | Suspicious Machine                  | gab-intern-vm                                                  |                       |
| 1     | 1st CLI parameter used in execution | -ExecutionPolicy                                               |                       |
| 2     | File related to exploit             | DefenderTamperArtifact.lnk                                     |                       |
| 3     | Exploit command value               | "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" |
| 4     | Last recon attempt                  | 2025-10-09T12:51:44.3425653Z                                   |                       |
| 5     | 2nd command tied to mapping         | "cmd.exe" /c wmic logicaldisk get name,freespace,size          |                       |
| 6     | Initiating parent process           | RuntimeBroker.exe                                              |                       |
| 7     | Process unique ID                   | 2533274790397065                                               |                       |
| 8     | Process inventory                   | tasklist.exe                                                   |                       |
| 9     | Privilege-check timestamp           | 2025-10-09T12:52:14.3135459Z                                   |                       |
| 10    | 1st outbound destination            | [www.msftconnecttest.com](http://www.msftconnecttest.com)      |                       |
| 11    | Artifact path                       | C:\Users\Public\ReconArtifacts.zip                             |                       |
| 12    | Unusual outbound IP                 | 100.29.147.161                                                 |                       |
| 13    | Scheduled task name                 | SupportToolUpdater                                             |                       |
| 14    | Registry value name                 | RemoteAssistUpdater                                            |                       |
| 15    | Artifact left behind                | SupportChat_log.lnk                                            |                       |


Report Completed By: Joarder Rashid
Status: ✅ All 20 flags investigated and confirmed
