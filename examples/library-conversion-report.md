# Batch conversion report (yaral → kql, spl, aql)

Source files: **237**

| Target | Converted | With warnings | Failed |
|---|---:|---:|---:|
| KQL (Microsoft Sentinel, ASIM) | 235 | 137 | 2 |
| SPL (Splunk, CIM) | 235 | 59 | 2 |
| AQL (IBM QRadar) | 235 | 187 | 2 |

## Not converted

| File | Stage | Reason |
|---|---|---|
| `identity/auth_bruteforce_then_success.yaral` | parse | multi-event rules ($fail, $success) cannot be expressed as a single query - convert each event variable separately |
| `identity/auth_spray_then_success.yaral` | parse | multi-event rules ($f, $s) cannot be expressed as a single query - convert each event variable separately |

## Most common warnings

| Warning | Count |
|---|---:|
| field <x> has no canonical mapping; kept verbatim | 189 |
| no event category; query runs over all tables (union *) - set the right table | 128 |
| AQL has no event-category filter for <x>; add a log source type filter | 107 |
| AQL LAST window is a single look-back, not a sliding window like YARA-L/KQL/SPL bins | 91 |
| field <x> from udm has no mapping to kql; kept verbatim - map it manually | 63 |
| field <x> from udm has no mapping to spl; kept verbatim - map it manually | 63 |
| field <x> from udm has no mapping to aql; kept verbatim - map it manually | 63 |
| function timestamp.get_hour() is not portable and that condition was dropped - add it manually | 6 |
| condition uses outcome variables (e.g. sums); only the event/distinct count was converted | 3 |
| reference list %pam_jump_hosts is not portable and was dropped | 3 |
