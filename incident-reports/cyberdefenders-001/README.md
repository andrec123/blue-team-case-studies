# Web Server Compromise & Post-Exploitation Investigation

**TechNova Systems – IIS Server Intrusion**

---

## Executive Summary

TechNova Systems’ Security Operations Center identified suspicious outbound network activity originating from a public-facing IIS web server hosted within the organization’s cloud environment. Initial indicators suggested unauthorized reconnaissance, followed by exploitation and the deployment of a malicious web shell.

Further investigation revealed that an external attacker conducted network scanning, enumerated exposed SMB shares, uploaded a malicious ASP.NET web shell, and established a reverse shell connection to an external command-and-control (C2) server. The attacker subsequently deployed a persistence mechanism and maintained remote access to the compromised system.

Artifacts analyzed during the investigation included a packet capture (PCAP), a full memory image of the affected server, and a recovered malware sample. This report reconstructs the attacker’s activities, confirms compromise, and provides response and mitigation recommendations.

---

## Incident Details

- **Incident Type:** Web Server Compromise with Remote Code Execution
    
- **Date Observed:** 02:12 AM, Jan. 27, 2026
    
- **Affected System(s):** Public-facing IIS Server
    
- **Severity:** Critical
    
- **Artifacts Analyzed:** PCAP, memory dump, malware sample
    

---

## Detection & Initial Triage

The incident was identified through analysis of anomalous outbound network traffic from the IIS server. Traffic patterns suggested external reconnaissance activity followed by persistent connections to an unknown remote host over a non-standard port.

Given the system’s role as a public-facing service, any unexpected outbound traffic warranted immediate investigation due to the potential for web application compromise and data exposure.

---

## Investigation & Analysis

### 1. Network Reconnaissance & Enumeration (PCAP Analysis)

Analysis of the packet capture revealed repeated reconnaissance activity targeting the IIS host. The attacker conducted rapid scanning consistent with automated probing techniques, ultimately identifying accessible services exposed by the server.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/detectingNMAPScans.png)

Targeted enumeration activity aligned with **MITRE ATT&CK technique T1046 – Network Service Discovery**.

---

### 2. SMB Share Access & Web Shell Deployment

Subsequent SMB traffic analysis showed that the attacker accessed multiple file shares on the compromised server. Two SMB Tree Connect requests exposed the initial UNC paths accessed during enumeration.

![[smbAccess.png]]

Within one of the accessed shares, the attacker uploaded a malicious ASP.NET web shell to a web-accessible directory. The uploaded file was identified as:

- **Filename:** `shell.aspx`
    
- **File Size:** 1,015,024 bytes
    

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/webShellUpload.png)

This web shell provided the attacker with remote command execution capabilities via the IIS application.

---

### 3. Reverse Shell Establishment

Network traffic analysis showed that the deployed web shell initiated a reverse shell connection back to the attacker’s infrastructure over TCP port **4443**, an uncommon but firewall-friendly port.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/reverseShellCallback.png)

This connection confirmed that the attacker had achieved interactive access to the compromised server.

---

### 4. Memory Analysis & Persistence Identification

Using **Volatility 3**, analysis of the system memory image provided insight into post-exploitation activity.

The kernel base address was successfully identified, validating the integrity of the memory capture.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/identifyingKernelBaseAddress.png)

Further analysis revealed that a legitimate Windows process was used to spawn an unfamiliar executable located outside the standard IIS directory structure. The malicious executable was placed within a Startup folder, indicating a persistence mechanism designed to execute automatically upon system boot or user logon.

This behavior aligns with **MITRE ATT&CK technique T1547 – Boot or Logon Autostart Execution**.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/identifyingMaliciousProcessesAndPersistence.png)

---

### 5. Reverse Shell Process Attribution

Network connection analysis confirmed that the reverse shell traffic was handled by a built-in Windows process, which also spawned the malicious executable. The associated process and PID were identified using Volatility’s `windows.netscan` plugin.


![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/confirmingConnectionToShellAndPID.png)

This confirmed sustained attacker control over the system.

---

### 6. Malware Sample Analysis

Static analysis of the recovered malware sample revealed that the binary was packed to evade detection and analysis.

- **Packer Identified:** [Detected via Detect It Easy]
    

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/identifyingPackerUsedForMalware.png)

Threat intelligence analysis identified outbound beaconing activity to a known command-and-control domain.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/identifyingFQDNForC2Callback.png)

Open-source intelligence correlated the sample hash with a known commodity Remote Access Trojan (RAT), confirming the malware family associated with the intrusion.

![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/findingOpenSourceIntel.png)  
![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/cyberdefenders-001/identifyingMalwareFamily.png)

---

## MITRE ATT&CK Mapping

- **T1046** – Network Service Discovery
    
- **T1505.003** – Server Software Component: Web Shell
    
- **T1059** – Command and Scripting Interpreter
    
- **T1547** – Boot or Logon Autostart Execution
    
- **T1041** – Exfiltration Over C2 Channel
    

---

## Impact Assessment

The attacker achieved full remote code execution on a public-facing IIS server and established persistence. While no direct evidence of data exfiltration was observed within the provided artifacts, the presence of a functional web shell, reverse shell access, and persistent malware posed a significant risk to system integrity and organizational security.

---

## Response & Mitigation

Immediate response actions should include isolating the affected IIS server from the network to prevent further attacker interaction. All credentials associated with the server should be rotated, and unauthorized files removed.

Indicators of compromise—including malicious IP addresses, domains, file hashes, and web shell artifacts—should be blocked at the network and endpoint levels. A full integrity review of the IIS application directories is recommended.

Long-term mitigations should include restricting SMB access on public-facing servers, enforcing least privilege permissions, deploying web application firewalls (WAF), and implementing enhanced monitoring for abnormal outbound traffic patterns.

---

## Lessons Learned & Recommendations

This incident highlights the risks associated with exposed services on public-facing infrastructure. Proactive monitoring for reconnaissance activity and abnormal outbound connections is critical to early detection.

Organizations should prioritize hardening internet-facing systems, reducing attack surface, and enforcing strict file access controls. Regular vulnerability assessments and continuous monitoring can significantly reduce the likelihood and impact of similar compromises.
