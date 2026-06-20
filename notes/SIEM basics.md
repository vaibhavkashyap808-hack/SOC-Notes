# SIEM: Security Information and Event Management

## What is SIEM?

SIEM = Central system that collects, analyzes, and correlates security events from all sources.

**Core Function**: Detect threats by analyzing logs from multiple sources in real-time.

**Simple Analogy**: Security camera system that watches 1000 cameras simultaneously and alerts only when something suspicious happens.

---

## Why SIEM for SOC?

| Challenge | SIEM Solution |
|-----------|---------------|
| 1000+ systems, 1 million logs/day | Centralize all logs in one place |
| Manually reviewing logs = impossible | Automated alert rules |
| Threats hidden in log noise | Correlation and anomaly detection |
| No timeline visibility | Timestamps and event ordering |
| Multiple tools don't communicate | Unified platform |

---

## SIEM Architecture

```
Data Sources
├─ Servers (Windows, Linux)
├─ Network devices (Firewall, IDS/IPS)
├─ Applications (Web servers, databases)
├─ Cloud platforms (AWS, Azure, GCP)
├─ Security tools (Antivirus, EDR, Proxy)
└─ User activity logs

         ↓ (Send logs via syslog, agents)

  SIEM PLATFORM
├─ Log Ingestion (receive data)
├─ Normalization (standardize format)
├─ Indexing (organize data)
├─ Analysis Engine (correlation rules)
├─ Alerting (generate alerts)
└─ Dashboards (visualization)

         ↓ (Actions)

Detection & Response
├─ SOC alerts
├─ Incident tickets
├─ Escalation
└─ Automated remediation
```

---

## Top SIEM Tools

### 1. Splunk
**Best for**: Large enterprises, advanced analytics

**Pricing**: Expensive ($5,000+ per TB ingested/day)

**Strengths**:
- Powerful search language (SPL)
- Great visualizations
- Excellent for threat hunting
- Large user community

**Weaknesses**:
- High cost
- Resource intensive
- Steep learning curve

### 2. Elastic Stack (ELK)
**Best for**: Cost-conscious organizations, open-source

**Pricing**: Free (open-source) or $100-500/month (managed)

**Strengths**:
- Open-source
- Cost-effective
- Flexible
- Large community

**Weaknesses**:
- Requires technical setup
- Less polished than Splunk
- Smaller security-focused community

### 3. Microsoft Sentinel
**Best for**: Microsoft-heavy environments (Azure, O365, Windows)

**Pricing**: $2.50-5 per GB ingested/day

**Strengths**:
- Integrates with Microsoft products
- Cloud-native
- Good for Azure environments
- AI-powered threat detection

**Weaknesses**:
- Relatively new
- Less mature than Splunk
- Requires Azure subscription

### 4. IBM QRadar
**Best for**: Large enterprises, compliance-heavy organizations

**Pricing**: $10,000+ per year (license-based)

**Strengths**:
- Excellent for compliance
- Good for large-scale deployments
- Strong vulnerability integration

**Weaknesses**:
- Expensive
- Complex setup
- Steep learning curve

### 5. Sumo Logic
**Best for**: Cloud-native organizations

**Pricing**: $120-600 per month

**Strengths**:
- Cloud-native
- Easy to set up
- Good for multi-cloud
- Scalable

**Weaknesses**:
- Less powerful than Splunk
- Can get expensive at scale
- Smaller security community

---

## Key SIEM Concepts

### 1. Events vs Alerts

**Event**: Single log entry
```
Example:
- User login
- File created
- Network connection
- Process execution
- Failed authentication
```

**Alert**: Correlation of multiple events = suspicious pattern
```
Example:
- 50 failed logins in 5 minutes = brute force attempt
- Process spawning child = potential exploitation
- Outbound connection to C2 IP = malware communication
```

### 2. Log Sources

```
EVENT TYPES                    | SOURCE
-------------------------------|----------------------------------
Authentication (login events)  | Active Directory, servers, firewalls
Process execution              | Windows Event logs, EDR
File access/creation           | File servers, EDR
Network traffic                | Firewall, IDS/IPS, proxy
Application activity           | Web servers, databases, apps
Security tool alerts           | Antivirus, EDR, DLP
Cloud activity                 | AWS CloudTrail, Azure logs
Email activity                 | Email gateway, Exchange
Endpoint activity              | Sysmon, EDR, operating system
```

### 3. Log Ingestion

**Methods**:
- **Agent-based**: Software installed on each system sends logs
- **Agentless**: System sends logs via syslog/API
- **API collection**: Query systems via API
- **Syslog**: Standard protocol for log transmission

**Flow**:
```
Source System → Log Forward (agent/syslog) → SIEM Parser → Normalize → Index
```

### 4. Normalization

**Raw Log**:
```
User: john.smith
IP: 192.168.1.100
Status: Successful login
Time: 2024-01-15T10:30:45Z
```

**Normalized**:
```
event_type: authentication
user: john.smith
src_ip: 192.168.1.100
action: successful_login
timestamp: 1705316445
source: active_directory
```

**Why**: Standardize logs from different sources so correlation rules work.

### 5. Correlation Rules

**Simple Rule**:
```
IF failed_login_count > 5 in 5 minutes
THEN alert: "Brute force attempt"
```

**Complex Rule**:
```
IF (failed_login from external_ip) 
AND (user account = admin) 
AND (time = after_hours) 
AND (source = firewall_vpn)
THEN alert: "Unauthorized admin access attempt"
SEVERITY: CRITICAL
```

---

## SIEM Workflow for SOC L1

### Step 1: Receive Alert

SIEM detects suspicious pattern from correlation rule.

**Alert Details**:
- Alert ID: 12847
- Rule: Brute force login attempt
- Severity: High
- Time: 10:30 AM
- Source: Active Directory logs

### Step 2: Investigate

**Questions**:
- Is this a legitimate failed login or attack?
- How many attempts?
- From where (IP address)?
- Which user account targeted?
- Typical for this user/time?

### Step 3: Query SIEM

**Splunk Query Example**:
```
index=windows EventCode=4625 (failed login)
earliest=-24h
| stats count by user, src_ip
| where count > 10
| table user, src_ip, count, _time
```

**Result**:
```
user: john.doe
src_ip: 185.220.101.xxx
count: 47 attempts
time: Last 2 hours
```

### Step 4: Assess Threat

- Is this IP known malicious? (Threat intel check)
- Is john.doe a high-value target?
- Was any successful login?
- Any other suspicious activity from this IP?

### Step 5: Take Action

**If suspicious**:
- Block IP at firewall
- Reset user password
- Check for successful login
- Escalate to Tier 2

**If false positive**:
- Close alert
- Update rule (tune)
- Document reason

---

## Common SIEM Detection Rules

### Rule 1: Brute Force Detection

```
NAME: Brute Force Login Attempt
SOURCE: Windows Event Logs (EventCode 4625)

CONDITION:
Failed login count > 10 in 5 minutes
For same user account
From same source IP

ALERT FIELDS:
- User account
- Source IP
- Failed count
- Time window

ACTION:
- Block IP at firewall
- Reset user password
- Investigation
```

### Rule 2: Privilege Escalation

```
NAME: Suspicious Privilege Escalation
SOURCE: Windows logs (EventCode 4688 - Process creation)

CONDITION:
User privilege level changed from User to Admin
Within 30 seconds of process execution
Process = suspicious (powershell, cmd, exploit)

ACTION:
- Isolate system
- Capture memory dump
- Investigate process
```

### Rule 3: Data Exfiltration

```
NAME: Bulk Data Access/Transfer
SOURCE: File access logs, DLP, Network traffic

CONDITION:
User accessed 100+ sensitive files in 10 minutes
OR
>500 MB data transfer to external IP
During off-hours
From user workstation

ACTION:
- Isolate system
- Block IP
- Preserve evidence
- Escalate to incident response
```

### Rule 4: C2 Communication

```
NAME: Known C2 Server Connection
SOURCE: Firewall, proxy logs

CONDITION:
Outbound connection to known C2 IP/domain
(from threat intelligence feed)

ACTION:
- Block IP/domain immediately
- Investigate system
- Scan for malware
- Check lateral movement
```

### Rule 5: Anomalous Behavior

```
NAME: User Behavior Anomaly
SOURCE: User activity logs

CONDITION:
User accessing unusual resources
At unusual time
From unusual location
Unusual file types accessed
Unusual volume of data

ACTION:
- Investigate
- Contact user
- Check for compromise
```

---

## Detection Examples

### Example 1: Phishing Alert

```
ALERT: Phishing Email Detected

SIEM Shows:
- Email gateway blocked suspicious attachment
- Sender domain: paypa1-security.com (typosquatting)
- Recipients: 50 employees
- Attachment: .docm (macro-enabled)

CORRELATION:
- Domain reputation: Malicious (threat intel)
- Attachment type: Known vector
- Bulk send pattern: Phishing campaign

SOC ACTION:
- Quarantine remaining emails
- Block sender domain
- Check if anyone opened
- Alert users
- Update blocklist
```

### Example 2: Lateral Movement Alert

```
ALERT: Suspicious RDP Connection

SIEM Shows:
- EventCode 4624: Successful logon (RDP)
- User: administrator
- Source: 192.168.1.50 (compromised workstation)
- Destination: db-server.company.local
- Time: 3:47 AM (off-hours)

CORRELATION:
- Same user compromised 2 hours earlier
- Source IP connected to known C2
- Admin credentials used for RDP
- Off-hours unusual activity

SOC ACTION:
- Block RDP from source IP
- Investigate admin logon
- Check database access
- Isolate compromised system
- Review all admin connections
```

### Example 3: Malware Alert

```
ALERT: Malware Execution Detected

SIEM Shows:
- File hash: 8846f7eaee8fb117ad06bdd830b7586c
- VirusTotal: 45 vendors flag as malware
- Process: powershell.exe running obfuscated command
- Child process: C2 connection to 185.220.101.xxx

CORRELATION:
- File hash matches known banking trojan
- Command includes IEX (invoke code execution)
- C2 server in threat feed
- Multiple indicators = high confidence

SOC ACTION:
- Isolate system immediately
- Kill process
- Dump memory
- Scan for persistence
- Hunt for lateral movement
- Reset all passwords
```

---

## SIEM vs Other Security Tools

| Tool | Purpose | Typical Use |
|------|---------|------------|
| **SIEM** | Central log analysis | Detect patterns, correlate events |
| **EDR** | Endpoint monitoring | Detect process execution, file activity |
| **IDS/IPS** | Network traffic analysis | Detect attacks on network |
| **Firewall** | Network access control | Allow/deny traffic |
| **Antivirus** | Malware detection | Detect known malware |
| **Proxy** | Internet gateway | Filter web traffic |
| **DLP** | Data protection | Prevent data theft |

**SIEM Integrates All**: Receives logs from all tools above.

---

## SIEM Best Practices for SOC

### 1. Tuning Detection Rules

**Problem**: Too many false positives = alert fatigue

**Solution**:
- Baseline normal behavior first
- Add exceptions for legitimate activities
- Adjust thresholds based on data
- Regular rule review

**Example**:
```
BEFORE: Alert on ANY failed login
AFTER: Alert on >10 failed logins in 5 minutes 
       from external IP 
       for non-service accounts
```

### 2. Data Retention

**Keep minimum**:
- Critical events (incidents): 1+ year
- Security logs: 90+ days
- Application logs: 30+ days
- Network logs: 30+ days

**Why**: Forensics needs historical data.

### 3. Response Playbooks

For each alert type, document:
- Investigation steps
- Questions to answer
- Tools to use
- Escalation criteria
- Response actions

### 4. Regular Hunting

Don't just wait for alerts. Actively search for:
- Known indicators
- Unusual patterns
- User behavior anomalies
- New attack techniques

### 5. Threat Intelligence Integration

- Subscribe to threat feeds (IP/domain/hash)
- Auto-update blocklists
- Correlate with your environment
- Monitor for known C2, botnets, etc.

---

## Splunk Quick Reference

### Basic Search Syntax

```
index=windows EventCode=4625
| search user=john.doe
| stats count by src_ip
| where count > 5
| sort - count
```

**Breakdown**:
- `index=windows`: Search Windows logs only
- `EventCode=4625`: Failed login events
- `search user=john.doe`: Filter for specific user
- `stats count by src_ip`: Count failures per IP
- `where count > 5`: Show only >5 failures
- `sort - count`: Sort by count descending

### Common Queries

**Brute Force Detection**:
```
index=windows EventCode=4625 
| stats count as failed_logins by user, src_ip 
| where failed_logins > 10
```

**Process Execution - PowerShell**:
```
index=windows EventCode=4688 CommandLine="*powershell*"
| search CommandLine="*IEX*" OR CommandLine="*DownloadString*"
```

**Outbound Connections**:
```
index=proxy dest_ip NOT IN (trusted_ips)
| stats count by src_ip, dest_ip, dest_port
| where count > 100
```

**Failed Authentication Over Time**:
```
index=windows EventCode=4625
| timechart count by user
| where _time >= relative_time(now(), "-24h")
```

---

## Elastic Stack (ELK) Quick Reference

### Basic Query Syntax (KQL - Kibana Query Language)

```
host.os.type:windows AND event.code:4625
| stats count by user.name, source.ip
| filter count > 5
```

### Detection Rule Example

```json
{
  "name": "Brute Force Detection",
  "query": "event.code: 4625 AND event.outcome: failure",
  "aggregation": {
    "group_by": ["user.name", "source.ip"],
    "metrics": [{"count": true}]
  },
  "threshold": {"operator": ">", "value": 10},
  "threshold_window": "5m",
  "severity": "high"
}
```

---

## SOC Daily Tasks with SIEM

**Morning (8-9 AM)**:
- Review overnight alerts
- Check for critical incidents
- Review dashboards
- Verify C2 blocks are in place

**Throughout Day**:
- Monitor incoming alerts
- Investigate suspicious events
- Update detection rules
- Hunt for indicators

**End of Day (5-6 PM)**:
- Document incidents
- Update threat intel
- Review false positives
- Prepare for evening shift

**Weekly**:
- Tune detection rules
- Review metrics (detection rate, false positives)
- Hunt for new threats
- Update procedures

**Monthly**:
- Full security posture review
- Rule optimization
- Capacity planning
- Training/skills improvement

---

## SIEM Metrics (For SOC)

| Metric | Definition | Good Target |
|--------|-----------|-------------|
| **MTTD** | Mean Time to Detect | < 1 hour |
| **MTTR** | Mean Time to Respond | < 4 hours |
| **MTTC** | Mean Time to Contain | < 8 hours |
| **FPR** | False Positive Rate | < 5% |
| **Alert Volume** | Alerts per day | <100 for small org |
| **Detection Rate** | % of attacks detected | > 80% |

---

## Common SIEM Challenges

| Challenge | Solution |
|-----------|----------|
| Too many false positives | Tune rules, add baselines |
| Missing alerts | Review logs, add new sources |
| Slow search | Index optimization, data retention |
| High cost | Choose right tool, optimize data |
| Retention limits | Archive old data, tiered storage |
| Alert fatigue | Correlation rules, automation |
| Skills gap | Training, documentation, tools |

---

## SIEM Implementation Checklist

```
[ ] Define data sources (logs to collect)
[ ] Choose SIEM platform
[ ] Install log collectors/agents
[ ] Configure log forwarding
[ ] Set up data parsing/normalization
[ ] Create initial detection rules
[ ] Baseline normal activity
[ ] Test alert generation
[ ] Set up dashboard
[ ] Document procedures
[ ] Train SOC team
[ ] Monitor and tune
[ ] Regular reviews
[ ] Incident response integration
[ ] Compliance reporting setup
```

---

## Key SIEM Queries for SOC L1

### Query 1: Find All Admin Logons

**Splunk**:
```
index=windows EventCode=4624 Logon_Type=3
| search user=*admin*
| table TimeGenerated, user, Computer, src_ip
```

### Query 2: Detect Downloaded Executables

**Splunk**:
```
index=proxy file_type=exe OR file_type=dll
| stats count by user, dest_ip, file_name
| where count > 5
```

### Query 3: Find Registry Persistence

**Splunk**:
```
index=sysmon EventCode=13 (Registry)
| search TargetObject="*\\Run*" OR TargetObject="*\\RunOnce*"
| table TimeGenerated, User, TargetObject, Details
```

### Query 4: Detect Service Creation

**Splunk**:
```
index=windows EventCode=7045 (Service creation)
| search NOT ImagePath="C:\\Windows*"
| table TimeGenerated, ServiceName, ImagePath, User
```

### Query 5: Find High-Risk File Operations

**Splunk**:
```
index=sysmon EventCode=11 (File creation)
| search TargetFilename="*.exe" OR TargetFilename="*.dll"
| search TargetFilename IN (temp, appdata, public)
| table TimeGenerated, User, TargetFilename, Image
```

---

## Interview Questions on SIEM

**Q1**: What is the difference between an event and an alert?
**A**: Event = single log entry. Alert = correlation of multiple suspicious events.

**Q2**: Why is log normalization important?
**A**: Different sources use different formats. Normalization standardizes format so rules work across all sources.

**Q3**: How would you detect a brute force attack in SIEM?
**A**: Create rule: failed login count > 10 from same IP in 5 minutes. Alert when triggered.

**Q4**: What should you do if you see 1000+ alerts per day?
**A**: Tune rules to reduce false positives. Adjust thresholds. Add baselines.

**Q5**: How do you integrate threat intelligence with SIEM?
**A**: Subscribe to threat feeds (IP/domain reputation). Auto-update blocklists. Alert on matches.

---

## Tools Comparison

| Feature | Splunk | Elastic | Sentinel | QRadar |
|---------|--------|--------|----------|--------|
| Cost | Very High | Low | Medium | High |
| Ease of Use | Hard | Medium | Easy | Hard |
| Scalability | Excellent | Good | Excellent | Good |
| Learning Curve | Steep | Medium | Easy | Steep |
| Community | Large | Large | Growing | Small |
| Best For | Large enterprises | Cost-conscious | Azure shops | Compliance |

---

## Key Takeaways

1. **SIEM = Central log analysis platform**
2. **Detects threats through correlation rules**
3. **Multiple sources feed into SIEM**
4. **Raw logs normalized into standardized format**
5. **Alerts = suspicious patterns across logs**
6. **SOC L1 investigates alerts, not logs directly**
7. **Tuning rules = reduce false positives**
8. **Threat intel = enhance detection**
9. **Playbooks = standardized responses**
10. **Metrics = measure SOC effectiveness**

---

## Resources

- Splunk Tutorial: https://www.splunk.com/en_us/training.html
- Elastic Documentation: https://www.elastic.co/guide/
- Microsoft Sentinel: https://docs.microsoft.com/en-us/azure/sentinel/
- TryHackMe: SIEM rooms
- Blue Team Labs: SIEM challenges

---

