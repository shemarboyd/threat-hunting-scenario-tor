# Official Threat Hunting Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

### Threat Hunting Steps Taken
1. File Discovery
The investigation began by reviewing DeviceFileEvents for any files containing the string “tor”. This revealed that user shemarlion on shemar-endpoint appeared to download a Tor Browser installer, followed by multiple Tor-related files being copied or extracted to the desktop.


**Query used to locate events:**

```kql
DeviceFileEvents
|where FileName startswith  "tor"
|where DeviceName == "shemar-endpoint"
|order by Timestamp desc 
|project Timestamp,DeviceName, ActionType, FileName,FolderPath,SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="<img width="1146" height="273" alt="image" src="https://github.com/user-attachments/assets/3a7da9ba-bc5b-4ad1-842b-463c221b399f" />
">

---

### 2. Searched the `DeviceProcessEvents` Table

Installation Execution
Next, DeviceProcessEvents were reviewed for any command line containing the Tor installer filename. This confirmed that the user executed the installer from their Downloads folder, including a second execution using the /S flag, indicating a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "shemar-endpoint"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName

```
<img width="1212" alt="image" src="<img width="1154" height="99" alt="image" src="https://github.com/user-attachments/assets/87288151-dbee-4460-a0ca-b2a25a60ba1b" />
">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Tor Browser Execution
The investigation then pivoted to determine whether the Tor Browser was actually opened. Evidence showed that Tor-related processes including firefox.exe and tor.exe were launched from the Tor Browser directory on the user’s desktop.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "shemar-endpoint"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc

```
<img width="1212" alt="image" src="<img width="1160" height="301" alt="image" src="https://github.com/user-attachments/assets/3ae8dc19-6963-42c8-83fd-1654012cca03" />
">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Tor Network Activity
Finally, DeviceNetworkEvents were reviewed for any outbound connections over known Tor relay ports, particularly port 9001. This confirmed that the device successfully established outbound network connections using tor.exe, strongly indicating that the Tor Browser was actively used.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "shemar-endpoint"
| where InitiatingProcessAccountName != "system"
| where RemotePort == "9001"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="1212" alt="image" src="<img width="1163" height="303" alt="image" src="https://github.com/user-attachments/assets/c8f31595-3045-46b9-a35b-93bde13116b5" />
">

---

## Chronological Event Timeline 

### ⏱️ Chronological Events
March 25, 2026
12:15:08 PM
User shemarlion executed:

 tor-browser-windows-x86_64-portable-15.0.8.exe


File location:

 C:\Users\shemarlion\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe


### This indicates the Tor Browser installer was manually launched from the Downloads folder.

12:21:18 PM
The same installer was executed again, this time with the following command:

 "tor-browser-windows-x86_64-portable-15.0.8.exe" /S


The /S switch indicates a silent installation, meaning the installer was likely run without prompting the user through the normal setup interface.

~12:21 PM – 12:22 PM
Multiple Tor-related files were created/copied to the user’s desktop, indicating that the application was likely extracted or installed into:

 C:\Users\shemarlion\Desktop\Tor Browser\



### 12:22:52 PM
Process tor.exe initiated a successful outbound connection to:
Remote IP: 79.189.125.171
Remote Port: 9001
Port 9001 is commonly associated with Tor relay traffic, indicating Tor network activity.

### 12:22:57 PM
Another successful outbound connection was established by tor.exe to:
Remote IP: 45.157.234.132
Remote Port: 9001

### 12:23:16 PM
A connection attempt by tor.exe to:
Remote IP: 95.145.17.4
Remote Port: 9001
Resulted in:
ConnectionFailed

### 12:23:23 PM
Additional successful outbound connections were made by tor.exe to:
159.195.26.76:9001
212.162.9.166:9001
This confirms that the Tor client was actively attempting to join and communicate with the Tor network through multiple relay nodes.

### Post-Installation Execution
Further process review identified execution of:
firefox.exe
tor.exe
These were launched from:

 C:\Users\shemarlion\Desktop\Tor Browser\Browser\


This confirms that the Tor Browser application itself was opened and used, not merely downloaded or installed.

## Summary
The investigation confirmed that user shemarlion on shemar-endpoint:
Downloaded and executed the Tor Browser installer
Performed a silent installation using the /S switch
Extracted/installed Tor Browser files to the desktop
Launched the Tor Browser
Successfully established multiple outbound Tor relay connections over port 9001
Assessment
This activity demonstrates intentional installation and use of Tor Browser on the endpoint. The presence of:
a silent install,
Tor-specific process execution,
and successful relay traffic
strongly indicates that the user did not simply download the installer, but actively used Tor to establish anonymized network connections.


## Response Taken
TOR usage was confirmed on endpoint “shemar-endpoint”. The device was isolated and the user's direct manager was notified.



---
