# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JacobKingVA/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "ice" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-04-22T14:05:22.5258022Z`. These events began at `2026-04-22T13:50:58.7246323Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessAccountName == "ice"
| where FileName has_any ("tor" , "firefox")
| project TimeGenerated , ActionType , DeviceName , InitiatingProcessAccountName , FileName , FolderPath , InitiatingProcessCommandLine ,InitiatingProcessFileName ,  InitiatingProcessFolderPath , InitiatingProcessParentFileName 
| sort by TimeGenerated asc 
```
<img width="1217" height="291" alt="image" src="https://github.com/user-attachments/assets/2955b783-905c-4330-b4b1-0604ef966c84" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.4.exe". Based on the logs returned, at `2026-04-22T13:52:08.2328648Z`, an employee on the "karan-mde-vm-win" device ran the file `tor-browser-windows-x86_64-portable-15.0.10.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessAccountName == "ice"
| where ProcessCommandLine contains "tor-browser-windows"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1020" height="78" alt="image" src="https://github.com/user-attachments/assets/d5759efe-b747-4e41-a995-16eeb9319b41" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "ice" actually opened the TOR browser. There was evidence that they did open it at `2026-04-22T13:52:50.8619189Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessAccountName == "ice"
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, FolderPath, ProcessCommandLine, SHA256
| sort by TimeGenerated asc
```
<img width="1212" height="327" alt="image" src="https://github.com/user-attachments/assets/ebfa1ef2-0d14-410a-9d3e-c2178f855ac6" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-04-22T13:53:27.689983Z`, an employee on the "jacob-mde-test-" device successfully established a connection to the remote IP address `192.87.28.82` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ice\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were additional connections to sites over port `443` observed.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessFileName has_any ("tor.exe" , "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project TimeGenerated , DeviceName , InitiatingProcessAccountName , ActionType = "ConnectionSuccess" , InitiatingProcessFileName, InitiatingProcessCommandLine , InitiatingProcessParentFileName , LocalIP , LocalPort , RemoteIP , RemotePort ,RemoteUrl
| sort by TimeGenerated asc
```
<img width="1211" height="268" alt="image" src="https://github.com/user-attachments/assets/7341c00f-fdfc-47cf-95a5-d6a92fd3ceaf" />

---

## Chronological Event Timeline
### 1. File Download - TOR Installer
- **Timestamp:** `2026-04-22T13:50:58.7246323Z`
- **Event:** The user "ice" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.10.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ice\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

### 2. Process Execution - TOR Browser Installation
- **Timestamp:** `2026-04-22T13:52:08.2328648Z`
- **Event:** The user "ice" executed the file `tor-browser-windows-x86_64-portable-15.0.10.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.10.exe /S`
- **File Path:** `C:\Users\ice\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

### 3. Process Execution - TOR Browser Launch
- **Timestamp:** `2026-04-22T13:52:50.8619189Z`
- **Event:** User "ice" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ice\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network
- **Timestamp:** `2026-04-22T13:53:27.689983Z`
- **Event:** A network connection to IP `192.87.28.82` on port `9001` by user "ice" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ice\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity
- **Timestamps:**
  - `2026-04-22T13:53:01.8959252Z` - Connected to `192.42.116.70` on port `443`.
  - `2026-04-22T13:53:27.689983Z` - Connected to `192.87.28.82` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ice" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List
- **Timestamp:** `2026-04-22T14:05:22.5258022Z`
- **Event:** The user "ice" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ice\Desktop\tor-shopping-list.txt`

---

## Summary
The user "ice" on the "karan-mde-vm-win" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken
TOR usage was confirmed on the endpoint `karan-mde-vm-win` by the user `ice`. The device was isolated, and the user's direct manager was notified.

---
