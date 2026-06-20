# Splunk Basics: Quick Revision Guide

## What is Splunk?

**Definition**: Platform that ingests logs, indexes them, and allows you to search and analyze them.

**For SOC**: Search millions of log entries, find patterns, detect threats.

---

## Splunk Architecture

```
Logs (Windows, firewall, apps, etc.)
         ↓
    Forwarder (agent that sends logs)
         ↓
    Indexer (processes and stores logs)
         ↓
    Search Head (user interface for searching)
         ↓
    SOC Analyst (you, writing queries)
```

---

## Basic Search Syntax

### Structure
```
index=indexname sourcetype=typename field=value
| command1
| command2
```

### Example
```
index=windows EventCode=4625 user=john.doe
| stats count by src_ip
| where count > 5
```

---

## Field Basics

### What is a Field?

**Field** = Key-value pair in log

**Raw Log**:
```
User: john.doe IP: 192.168.1.100 Action: Login Status: Failed
```

**Fields Extracted**:
- user = john.doe
- src_ip = 192.168.1.100
- action = Login
- status = Failed

### Common Field Names

```
user, src_ip, dest_ip, dest_port, host, source
status, action, event_code, sourcetype, index
timestamp, time, _time, result
```

---

## Search Operators

### Comparison Operators

```
=          Equals
!=         Not equals
>          Greater than
<          Less than
>=         Greater or equal
<=         Less or equal
IN()       Multiple values
LIKE       Pattern matching
```

### Examples

```
EventCode=4625                 (failed login)
EventCode!=1234                (not this event)
count>10                       (more than 10)
user IN (admin, administrator) (either user)
source LIKE "%Windows%"        (contains Windows)
```

### Boolean Operators

```
AND       Both conditions must be true
OR        Either condition can be true
NOT       Exclude results
```

**Examples**:
```
index=windows AND EventCode=4625
index=windows EventCode=4625 OR EventCode=4624
index=windows NOT user=SYSTEM
```

---

## Common Commands (Pipes)

### Pipe Symbol (|)

`|` = Pass results to next command

```
index=windows EventCode=4625 | stats count by user
                              ↑ Results piped to stats
```

### Most Used Commands

#### 1. STATS (Aggregation)

```
| stats count by user
| stats sum(bytes) by dest_ip
| stats count, avg(duration) by host
```

**Functions**:
- count = number of events
- sum = total value
- avg = average
- max = maximum
- min = minimum
- values = list unique values
- dc = distinct count (unique values)

#### 2. WHERE (Filter)

```
| stats count by user
| where count > 5
```

Filter results AFTER stats (not before).

#### 3. SEARCH (Find in Results)

```
index=windows EventCode=4625
| search user=john.doe
```

Can use before or after other commands.

#### 4. TABLE (Show Columns)

```
| table user, src_ip, EventCode, _time
```

Show only these columns.

#### 5. SORT (Arrange Results)

```
| sort - count          (descending, highest first)
| sort count            (ascending, lowest first)
| sort - _time          (newest first)
```

#### 6. DEDUP (Remove Duplicates)

```
| dedup user
```

Keep only first occurrence of each user.

#### 7. TOP (Top N Results)

```
| top 10 user
```

Show top 10 users (by count).

#### 8. RARE (Least Common)

```
| rare 5 user
```

Show 5 least common users.

#### 9. FIELDS (Select Columns)

```
| fields user, src_ip, EventCode
```

Similar to table but keeps original order.

#### 10. RENAME (Change Field Name)

```
| rename user as username
```

#### 11. EVAL (Calculate)

```
| eval bytes_MB = bytes/1024/1024
```

Create new field from calculation.

#### 12. IF (Conditional)

```
| eval threat_level = if(count>10, "High", "Low")
```

#### 13. TIMECHART (Time-based Stats)

```
| timechart count by user
```

Shows count over time, grouped by user.

#### 14. CHART (Grouping)

```
| chart count by user
```

#### 15. FILLNULL (Fill Missing Values)

```
| fillnull value=0
```

Replace empty values with 0.

---

## Time Functions

### Time Format: _time

Unix timestamp (seconds since Jan 1, 1970)

### Time Range Syntax

```
earliest=-24h          Last 24 hours
earliest=-7d           Last 7 days
earliest=-30m          Last 30 minutes
earliest=-1h           Last 1 hour
earliest=2024-01-01    Specific date

earliest=2024-01-01 latest=2024-01-31   Date range
```

### Use in Search

```
index=windows earliest=-24h
earliest=-24h EventCode=4625

index=windows earliest=-7d latest=-1d
```

### Date Functions

```
now()           Current time
relative_time(now(), "-24h")  24 hours ago
strftime(_time, "%H:%M:%S")   Format time as HH:MM:SS
strptime("Jan 01, 2024", "%b %d, %Y")  Parse date string
```

---

## Real SOC Queries

### Query 1: Brute Force Detection

```
index=windows EventCode=4625
| stats count as failed_logins by user, src_ip
| where failed_logins > 10
| sort - failed_logins
```

**Shows**: Users with >10 failed logins, grouped by IP

### Query 2: Multiple Failed Then Success

```
index=windows EventCode=4625 OR EventCode=4624
| stats count(eval(EventCode=4625)) as failed, 
        count(eval(EventCode=4624)) as success by user, src_ip
| where failed > 5 AND success > 0
| sort - failed
```

**Shows**: IPs with many failed logins but eventually succeeded (breach indicator)

### Query 3: Process Execution - PowerShell

```
index=windows EventCode=4688 CommandLine="*powershell*"
| search CommandLine="*IEX*" OR CommandLine="*DownloadString*"
| table _time, Computer, User, CommandLine
| sort - _time
```

**Shows**: PowerShell with suspicious commands (code execution)

### Query 4: Unusual Outbound Connection

```
index=proxy dest_ip NOT IN (8.8.8.8, 1.1.1.1, 209.244.0.3)
(assume whitelist above)
| stats count by src_ip, dest_ip, dest_port
| where count > 100
| sort - count
```

**Shows**: High-volume connections to non-whitelisted IPs

### Query 5: Failed Login By Hour

```
index=windows EventCode=4625
| timechart count by user span=1h
```

**Shows**: Failed login count per hour for each user

### Query 6: Service Creation (Persistence)

```
index=windows EventCode=7045
| search NOT ImagePath="C:\\Windows*"
| table _time, ServiceName, ImagePath, User
```

**Shows**: Services created outside System32 (suspicious persistence)

### Query 7: Registry Run Key Modification

```
index=sysmon EventCode=13
| search TargetObject="*\\Run*" OR TargetObject="*\\RunOnce*"
| table _time, User, TargetObject, Details
```

**Shows**: Registry Run key modifications (persistence mechanism)

### Query 8: Large File Download

```
index=proxy file_type=exe OR file_type=dll
| stats sum(bytes) as total_bytes by user, file_name
| eval total_MB = total_bytes/1024/1024
| where total_MB > 50
```

**Shows**: EXE/DLL downloads >50 MB (malware indicator)

### Query 9: Account Created By Non-Admin

```
index=windows EventCode=4720
| search NOT user="*admin*"
| table _time, TargetUserName, User, Computer
```

**Shows**: New accounts created (suspicious if by non-admin)

### Query 10: Failed Login + Admin

```
index=windows EventCode=4625 user=*admin*
| stats count by src_ip, user, _time
| where count > 5
| sort - count
```

**Shows**: Failed admin login attempts (high-priority)

---

## Search Best Practices

### 1. Always Use Index

```
✓ GOOD:   index=windows EventCode=4625
✗ BAD:    EventCode=4625 (searches all indexes)
```

Indexes limit search scope = faster results.

### 2. Filter Early

```
✓ GOOD:   index=windows EventCode=4625 user=john
✗ BAD:    index=windows | search user=john EventCode=4625
```

Filter before pipes = more efficient.

### 3. Specific Fields

```
✓ GOOD:   | fields user, src_ip, EventCode
✗ BAD:    | fields * (all fields, slower)
```

### 4. Limit Results

```
| head 10000    (only first 10k results)
```

For large searches, limit output.

### 5. Use NOT Instead of !=

```
✓ GOOD:   NOT user=SYSTEM
✗ BAD:    user!=SYSTEM
```

NOT is more efficient.

### 6. Avoid Wildcards

```
✓ GOOD:   sourcetype=windows
✗ BAD:    sourcetype=*windows*
```

Wildcard at start is very slow.

---

## Field Extraction

### Default Fields (Automatic)

```
_time        Event timestamp
_raw         Original log text
host         Source hostname
source       Source file path
sourcetype   Log type
index        Index name
```

### Custom Field Extraction

In Splunk UI:
1. Find event in search results
2. Click "Extract Fields" button
3. Highlight data
4. Name field
5. Save

**Now usable in searches**:
```
index=windows mycustomfield=value
```

---

## Regular Expressions (Regex)

### Basic Patterns

```
.      Any character
*      Previous char 0+ times
+      Previous char 1+ times
^      Start of line
$      End of line
[abc]  a OR b OR c
\d     Digit (0-9)
\w     Word character (a-z, A-Z, 0-9, _)
\s     Whitespace
```

### Examples

```
index=windows | search CommandLine=".*powershell.*"
index=proxy | search dest_ip="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
```

---

## Lookups (Reference Data)

### Purpose
Match data against external reference files.

**Example**: IP blocklist lookup

### Syntax
```
index=proxy | lookup threat_ips src_ip OUTPUT threat_level
| where threat_level="malicious"
```

**Shows**: Only connections from IPs in threat_ips file marked as malicious.

---

## Macros (Reusable Searches)

### Define Macro
```
In Settings → Advanced Search → Search Macros

Name: brute_force
Definition: EventCode=4625 | stats count by user, src_ip | where count > 10
```

### Use Macro
```
index=windows `brute_force`
```

Backticks = calls macro.

---

## Alerts (Automated Searches)

### Create Alert

1. Write search
2. Click "Save As" → "Alert"
3. Set schedule (every 5 min, hourly, etc.)
4. Set condition (when alert triggers)
5. Set action (email, webhook, etc.)

### Common Alert Conditions

```
Number of results > 0
Number of results > 10
Number of results < 5
```

### Example Alert

**Name**: Brute Force Detection

**Search**:
```
index=windows EventCode=4625 
| stats count by user, src_ip 
| where count > 10
```

**Schedule**: Every 5 minutes

**Condition**: Number of results > 0

**Action**: Send email to SOC team

---

## Dashboard Basics

### Create Dashboard

1. Search → Save As → Dashboard
2. Choose layout
3. Add panels (visualizations)
4. Arrange
5. Share

### Common Dashboard Types

- **Table**: Row/column display
- **Bar Chart**: Comparison
- **Line Chart**: Trends over time
- **Pie Chart**: Proportions
- **Single Value**: One metric

### Example Dashboard for SOC

**Panel 1**: Failed logins (24h)
```
index=windows EventCode=4625 earliest=-24h | stats count
```

**Panel 2**: Failed logins by user (24h)
```
index=windows EventCode=4625 earliest=-24h | top 10 user
```

**Panel 3**: Failed logins over time
```
index=windows EventCode=4625 earliest=-24h | timechart count
```

---

## Saved Searches

### Save for Later Use

1. Write search
2. Click "Save As" → "Search"
3. Name it
4. Save

### Run Saved Search

Click "Saved Searches" → select search → run

---

## Common Splunk Indexes

| Index | Contains |
|-------|----------|
| windows | Windows Event logs |
| linux | Linux logs |
| proxy | Web proxy logs |
| firewall | Firewall logs |
| mail | Email logs |
| app | Application logs |
| iis | IIS web server logs |
| sysmon | Endpoint monitoring |
| _internal | Splunk internal logs |

---

## Troubleshooting Searches

### Problem: No Results

```
Causes:
- Wrong index name
- Field name typo
- No matching data in time range
- Search syntax error

Solution:
- Check index exists: index=windows
- Check time range: earliest=-24h
- Review field names
- Check sourcetype
```

### Problem: Too Many Results (Slow)

```
Solutions:
- Add more filters (field=value)
- Use earliest/latest to limit time
- Use | head 10000
- Remove wildcards
```

### Problem: Wrong Field Values

```
Cause: Field not extracted properly
Solution:
- Manually extract field
- Check for typos in field name
- Verify sourcetype
- Use raw data (_raw field)
```

---

## Splunk Keyboard Shortcuts

```
Ctrl+A           Select all
Ctrl+C           Copy
Ctrl+V           Paste
Shift+Enter      New line in search
Ctrl+Enter       Run search
Ctrl+Shift+/     Comment line
```

---

## Quick Command Reference

```
| stats            Aggregate data
| where           Filter results
| sort            Sort results
| top             Show top N
| table           Show columns
| search          Find in results
| dedup           Remove duplicates
| eval            Calculate new field
| rename          Change field name
| timechart       Stats over time
| fields          Select fields
| head            Limit results
```

---

## Common Interview Questions

**Q1**: What's the difference between search and where?
**A**: `search` filters before processing (faster). `where` filters after (use for stats).

**Q2**: How do you find top 10 events?
**A**: `| top 10` or `| head 10`

**Q3**: How to count unique values?
**A**: `| stats dc(field)` (dc = distinct count)

**Q4**: How to combine multiple conditions?
**A**: `EventCode=4625 AND user=john` OR use `| where field1=value1 AND field2=value2`

**Q5**: How to search in time range?
**A**: `earliest=-24h latest=-1h` (last 24 to 1 hour ago)

---

## Quick Tips

1. **Use backticks for macros**: `macro_name`
2. **Use asterisk for wildcards**: source="*error*"
3. **Use NOT to exclude**: NOT user=SYSTEM
4. **Use IN for multiple values**: user IN (admin, root, john)
5. **Group results**: `| stats count by field`
6. **Show top results first**: `| sort - count`
7. **Format numbers**: `| numformat(bytes/1024/1024, "0.0") as MB`
8. **Fill empty values**: `| fillnull value=0`
9. **Remove empty lines**: `| search field!=""`
10. **Combine stats**: `| stats count, sum(bytes), avg(duration) by user`

---

## Real-World SOC Workflow

**1. Alert Received**: Malware detected on system

**2. Search for Malware**:
```
index=windows EventCode=4688 CommandLine="*malware.exe*"
| table _time, Computer, User, CommandLine
```

**3. Check File Hash**:
```
index=sysmon EventCode=1 Image="*malware.exe*"
| stats values(Hashes) by Computer
```

**4. Check Network Connections**:
```
index=proxy src_ip=192.168.1.100
| stats count by dest_ip, dest_port
| where count > 10
```

**5. Check Persistence**:
```
index=sysmon EventCode=13 Computer=SALES-01
| search TargetObject="*Run*"
| table _time, TargetObject, Details
```

**6. Check Lateral Movement**:
```
index=windows EventCode=4624 src_ip=192.168.1.100 Logon_Type=3
| stats count by User, Computer
```

---

## Splunk Pricing Model

```
Per-GB ingested per day:
$100-120 = 1 GB/day = ~30 million events/day
$300-400 = 10 GB/day = ~300 million events/day
```

**Large enterprises**: $1M+ annually

---

## Key Takeaways

1. **Splunk searches logs** = find patterns
2. **Use pipe (|)** = pass results to next command
3. **Always use index** = faster search
4. **Stats aggregates** = count, sum, avg
5. **Where filters** = after stats
6. **Timechart shows trends** = over time
7. **Regex finds patterns** = in text
8. **Alerts automate** = run searches on schedule
9. **Dashboards visualize** = show metrics
10. **Lookups match** = data against reference

---

## Quick Cheat Sheet

| Task | Query |
|------|-------|
| Count events | `\| stats count` |
| Count by field | `\| stats count by user` |
| Top 10 | `\| top 10 user` |
| Time trend | `\| timechart count by user` |
| Unique count | `\| stats dc(user)` |
| Sum bytes | `\| stats sum(bytes)` |
| Filter results | `\| where count > 10` |
| Show columns | `\| table user, src_ip` |
| Sort descending | `\| sort - count` |
| Remove duplicates | `\| dedup user` |

---

