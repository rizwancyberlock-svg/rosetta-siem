# Batch conversion report (yaral → kql, spl, aql)

Source files: **312**

| Target | Converted | With warnings | Failed |
|---|---:|---:|---:|
| KQL (Microsoft Sentinel, ASIM) | 309 | 197 | 3 |
| SPL (Splunk, CIM) | 309 | 92 | 3 |
| AQL (IBM QRadar) | 309 | 242 | 3 |

## Not converted

| File | Stage | Reason |
|---|---|---|
| `identity/auth_bruteforce_then_success.yaral` | parse | multi-event rules ($fail, $success) cannot be expressed as a single query - convert each event variable separately |
| `identity/auth_spray_then_success.yaral` | parse | multi-event rules ($f, $s) cannot be expressed as a single query - convert each event variable separately |
| `windows/win_new_account_then_privileged_group.yaral` | parse | multi-event rules ($add, $create) cannot be expressed as a single query - convert each event variable separately |

## Most common warnings

| Warning | Count |
|---|---:|
| field <x> has no canonical mapping; kept verbatim | 312 |
| no event category; query runs over all tables (union *) - set the right table | 181 |
| AQL LAST window is a single look-back, not a sliding window like YARA-L/KQL/SPL bins | 130 |
| AQL has no event-category filter for <x>; add a log source type filter | 128 |
| field <x> from udm has no mapping to kql; kept verbatim - map it manually | 112 |
| field <x> from udm has no mapping to spl; kept verbatim - map it manually | 112 |
| field <x> from udm has no mapping to aql; kept verbatim - map it manually | 112 |
| condition uses outcome variables (e.g. sums); only the event/distinct count was converted | 9 |
| function timestamp.get_hour() is not portable and that condition was dropped - add it manually | 6 |
| reference list %pam_jump_hosts is not portable and was dropped | 3 |
