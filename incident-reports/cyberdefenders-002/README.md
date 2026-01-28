# Endpoint Compromise & Memory Forensics Investigation  
**Financial Institution Workstation – Multi-Stage Malware Execution**

---

## Executive Summary

A security incident was identified after a SIEM alert flagged unusual activity on a workstation with access to sensitive financial data at a financial institution. Due to the system’s critical role, a forensic investigation was initiated to determine whether the workstation had been compromised.

Memory analysis confirmed the presence of a malicious process executing under a legitimate user context. Further investigation revealed that the attacker abused a signed Windows utility to execute a second-stage payload retrieved from a remote SMB share. Threat intelligence correlation identified the malware family associated with the intrusion.

The findings confirm that the workstation was compromised and executing attacker-controlled code in memory, posing a significant risk to sensitive financial data and internal systems.

---

## Incident Timeline

- **11:05 PM EST** – SIEM flagged unusual activity on a workstation with access to sensitive financial data, triggering the investigation.

- **11:12 PM EST** – Memory analysis identified a suspicious process executing in memory, indicating potential endpoint compromise.  

- **11:16 PM EST** – Process lineage analysis determined the malicious process was spawned by a parent process with **PPID 4120**, establishing the execution chain.

- **11:17 PM EST** – Command-line artifacts revealed execution of a second-stage payload using a legitimate Windows utility, consistent with signed binary proxy execution.  

- **11:25 PM EST** – Network-related artifacts confirmed access to a remote SMB share (`davwwwroot`) and threat intelligence correlation identified the malware family, confirming system compromise.  

---

## Incident Details

- **Incident Type:** Endpoint Compromise with Multi-Stage Malware Execution  
- **Date Observed:** Jan. 27, 2026
- **Affected User(s):** Financial workstation user  
- **Affected System(s):** Compromised workstation  
- **Severity:** High  

---

## How the Incident Was Identified

The incident was initially identified through a SIEM alert indicating anomalous behavior on a workstation with access to sensitive financial data. Given the elevated risk associated with the system, a memory image was acquired immediately to preserve volatile evidence.

SIEM detection combined with forensic analysis suggested post-compromise activity rather than benign user behavior, warranting deeper investigation.

---

## Investigation & Analysis

### Malicious Process Identification

Memory analysis using Volatility identified a suspicious process executing on the workstation. The process was enumerated using the `windows.pslist` plugin, which lists active processes present in memory.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-002/identifyingMaliciousProcess.png)

The execution context and behavior of this process were inconsistent with normal system activity and indicative of malicious execution.

---

### Process Lineage & Parent Process Analysis

Further analysis revealed that the malicious process was spawned by a parent process with **PID 4120**. Identifying the parent process ID helped establish how the malware was launched and confirmed that the execution was part of a coordinated attack sequence rather than an isolated event.

---

### Second-Stage Payload Execution

Command-line analysis using the `windows.cmdline` plugin revealed that the malware leveraged a signed Windows utility to execute a second-stage payload.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-002/identifyingSecondStagePayload.png)

Abusing legitimate system binaries to execute malicious payloads is a common attacker technique used to evade traditional security controls.

---

### Remote SMB Resource Access

Network-related artifacts within memory indicated that the malware accessed a remote SMB share hosted on external infrastructure. The shared directory accessed by the attacker was identified as:

- **Shared Directory Name:** `davwwwroot`

This remote share was used to retrieve or stage malicious components during the attack.

---

### Compromised User Context

Using Volatility’s `getsids` plugin, the user context under which the malicious process was executing was identified.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-002/identifyingCompromisedAccount.png)

The malware ran under a valid user account, increasing the potential impact of the compromise and risk to sensitive financial resources.

---

### Malware Family Identification

Threat intelligence research was conducted using indicators extracted from memory artifacts. Open-source intelligence correlated the malware with a known malware family.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-002/identifiedMalwareFamilyFromOSIntel.png)

Identifying the malware family provided insight into attacker capabilities and informed appropriate response actions.

---

## MITRE ATT&CK Mapping

- **T1059** – Command and Scripting Interpreter  
- **T1218.011** – Signed Binary Proxy Execution: Rundll32  
- **T1021** – Remote Services (SMB)  
- **T1078** – Valid Accounts  

---

## Impact Assessment

The affected workstation was confirmed to be compromised and executing malicious code in memory under a legitimate user context. Given the system’s access to sensitive financial data, the incident posed a significant risk of data exposure, credential abuse, and potential lateral movement.

Although no direct evidence of data exfiltration was identified within the scope of this memory analysis, the attacker’s execution capabilities and access level represented a high-risk condition requiring immediate containment.

---

## Response & Mitigation

Recommended response actions include immediate isolation of the compromised workstation from the network to prevent further attacker interaction. The affected user account should be disabled, and all associated credentials reset.

Indicators of compromise—including malware hashes, command-line artifacts, and remote SMB infrastructure—should be blocked at both the endpoint and network levels. A full reimage of the workstation is recommended to ensure complete remediation.

Additional monitoring should be implemented to detect abuse of signed Windows binaries and anomalous SMB activity.

---

## Lessons Learned & Recommendations

This incident highlights how attackers can abuse legitimate Windows utilities to execute multi-stage malware while evading traditional detection mechanisms. Memory analysis proved critical in identifying malicious activity that may not have been present on disk.

Organizations should prioritize behavioral-based detection, rapid memory acquisition during suspected compromises, and strict enforcement of least-privilege access. Improving detection for anomalous process execution and command-line behavior will reduce both detection and response time in future incidents.
