# Executive Summary

On January 6th, 2026, a critical security incident was identified involving a compromised domain user account on workstation *win-3450*. The attacker leveraged PowerShell-based post-exploitation tooling (PowerView.ps1) to enumerate the environment, access sensitive financial records hosted on *FILESRV-01*, and stage the data locally for exfiltration.

The attacker successfully exfiltrated financial records by encoding compressed data into Base64 and transmitting it via DNS queries to an external command-and-control domain. This resulted in confirmed exposure of sensitive company and client financial information.

The incident was detected through behavioral alerts related to suspicious PowerShell execution and anomalous network activity. Immediate containment actions were not observed, allowing the attacker to complete the exfiltration.

# Incident Details
- Incident Type: Data Exfiltration via DNS Tunneling
- Date Observed: Jan 6th 2026 at 02:00 PM EST
- Affected User(s): Domain Users and company clients
- Affected System(s): win-3450 and FILESRV-01
- Severity: Critical

# How the incident was identified.
- First alert was detected from alert queue with a description of: “A Powershell script was created in the Downloads folder”
- The user michael.ascot’s account and device win-3450 was compromised. The threat actor began their post-exploitation with using and executing PowerView.ps1: file path: “C:\Users\michael.ascot\Downloads\**PowerView.ps1**”
- Powershell execution already raises suspicion. PowerView.ps1 is a tool used by penetration testers and red teamers for Windows enumeration and post compromise

# Investigation & Analysis
### Initial PowerShell Execution

- *win-3450*: Infected with *PowerView.ps1* generated an alert.
	- Shortly after the alert, at 02:01 PM EST we can see a Powershell execution, querying DNS for hostnames using PowerView.ps1 script
		- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/dnsHostnameDiscoveryEvidence.png)
	- Later, at 2:02 PM EST we see a directory created called “exfiltration” within “C:\Users\michael.ascot\Downloads\”
		- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/suspiciousDirectoryCreation.png)
### Network Share Access
- A network drive was mapped to a local drive: *C:\Windows\system32\net.exe use Z:\\FILESRV-01\SSF-FinancialRecords* at 02:03 EST
	- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/suspiciousDirectoryCreation.png)
	- An alert was generated for mapping a network drive to a local drive. This raises even more suspicion given the sequence of events. No normal user would download PowerView.ps1, run DNS queries to find hostnames, and create a directory called *exfiltration*.
	- At 2:03:46 PM EST the threat actor then proceeded to Robocopy everything from the Z drive to the current \Downloads\exfiltration\ directory
		- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/robocopyEvidence.png)
	- At 02:04 PM EST, the network drive was unmounted or removed from the local host
		- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/unmountingSensitiveDrive.png)
### Data Staging and Compression
- Then a zip file was created named *exfiltr8me.zip* within *C:\Users\michael.ascot\Downloads\exfiltration\*
- 2:04:44 PM EST, on Splunk, we see the threat actor create a Powershell script where they are reading the bytes of their zipped file (which contains all the financial records extracted from the Z: drive), and encoding that data in base64, and then splitting all that encoded data into an array of 30 indices, or items.
	- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/dataExfiltrationPowershellScript.png)
	- The script then iterates through each item, and performs an `nslookup` to that suspicious looking domain name, appending the base64 data in front of it.
### DNS-Based Data exfiltration
- At 02:04 PM EST, a high number of high severity alerts begin to generate within the alert queue about a suspicious process being detected within the environment.
	- Looking at Splunk within this time frame, we see the threat actor running their script, sending DNS queries to their server *haz4rdw4re.io*, from the infected device
	- ![alt text](https://github.com/andrec123/blue-team-case-studies/blob/main/incident-reports/thm-001/encodedExfilEvidence.png)

# MITRE ATT&CK Mapping
- [T1059.001](https://attack.mitre.org/techniques/T1059/001) - Powershell
- [T1041](https://attack.mitre.org/techniques/T1041) - Exfiltration Over C2 Channel

# Impact Assessment

 The threat actor successfully exfiltrated data to their C2. PII and company data has been compromised.

# Response & Mitigation

Recommended response actions include immediate isolation of the compromised endpoint (win-3450) from the network to prevent further lateral movement and data loss. The affected user account should be disabled and credentials reset to prevent continued abuse.

Indicators of compromise, including the malicious domain (haz4rdw4re.io) and associated PowerShell activity, should be blocked at the network and endpoint level. A review of access permissions on FILESRV-01 is recommended to ensure least-privilege access to sensitive financial records.

PowerShell execution policies should be hardened via Group Policy to restrict unsigned script execution. Additional monitoring and detection logic should be implemented for anomalous DNS activity indicative of data exfiltration.

# Lessons Learned & Recommendations

This incident highlights the importance of rapid containment once post-exploitation behavior is detected. Early isolation of the compromised host would have prevented access to sensitive file shares and stopped data exfiltration.

Detection logic should prioritize behavioral indicators such as suspicious PowerShell execution, unauthorized network share mapping, and abnormal DNS query volume. Implementing these improvements will reduce both detection and response time in future incidents.
