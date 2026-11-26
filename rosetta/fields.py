"""Canonical field taxonomy and per-language mappings.

Canonical names follow Elastic ECS style. Targets:
  udm  - Google SecOps Unified Data Model (YARA-L)
  spl  - Splunk Common Information Model (CIM)
  kql  - Microsoft Sentinel ASIM (Advanced Security Information Model)
  aql  - IBM QRadar event properties (custom properties vary per DSM)
"""
from __future__ import annotations

LANGS = ("udm", "spl", "kql", "aql")

#   canonical                (udm,                                 spl,                    kql (ASIM),          aql)
FIELDS: dict[str, tuple[str, str, str, str]] = {
    "process.command_line":   ("target.process.command_line",        "process",              "CommandLine",        "Process CommandLine"),
    "process.path":           ("target.process.file.full_path",      "process_path",         "TargetProcessName",  "Process Path"),
    "process.name":           ("",                                   "process_name",         "",                   "Process Name"),
    "process.parent.path":    ("principal.process.file.full_path",   "parent_process_path",  "ActingProcessName",  "Parent Process Path"),
    "process.parent.name":    ("",                                   "parent_process_name",  "",                   "Parent Process Name"),
    "user.name":              ("principal.user.userid",              "user",                 "ActorUsername",      "username"),
    "target.user.name":       ("target.user.userid",                 "user",                 "TargetUsername",     "username"),
    "host.name":              ("principal.hostname",                 "host",                 "DvcHostname",        "Hostname"),
    "source.ip":              ("principal.ip",                       "src",                  "SrcIpAddr",          "sourceip"),
    "destination.ip":         ("target.ip",                          "dest",                 "DstIpAddr",          "destinationip"),
    "source.port":            ("principal.port",                     "src_port",             "SrcPortNumber",      "sourceport"),
    "destination.port":       ("target.port",                        "dest_port",            "DstPortNumber",      "destinationport"),
    "destination.host":       ("target.hostname",                    "dest_host",            "DstHostname",        "Destination Hostname"),
    "event.code":             ("metadata.product_event_type",        "EventCode",            "EventOriginalType",  "EventID"),
    "event.outcome":          ("security_result.action",             "action",               "EventResult",        "Outcome"),
    "event.product":          ("metadata.product_name",              "product",              "EventProduct",       "LOGSOURCETYPENAME(devicetype)"),
    "event.vendor":           ("metadata.vendor_name",               "vendor",               "EventVendor",        "Vendor"),
    "event.severity":         ("security_result.severity",           "severity",             "EventSeverity",      "severity"),
    "rule.name":              ("security_result.rule_name",          "signature",            "RuleName",           "Rule Name"),
    "threat.name":            ("security_result.threat_name",        "signature",            "ThreatName",         "Threat Name"),
    "url.full":               ("target.url",                         "url",                  "Url",                "URL"),
    "http.user_agent":        ("network.http.user_agent",            "http_user_agent",      "HttpUserAgent",      "User Agent"),
    "http.status":            ("network.http.response_code",         "status",               "HttpStatusCode",     "HTTP Response Code"),
    "http.method":            ("network.http.method",                "http_method",          "HttpRequestMethod",  "HTTP Method"),
    "http.referrer":          ("network.http.referral_url",          "http_referrer",        "HttpReferrer",       "Referrer"),
    "dns.query":              ("network.dns.questions.name",         "query",                "DnsQuery",           "DNS Query"),
    "file.path":              ("target.file.full_path",              "file_path",            "TargetFilePath",     "Filename"),
    "registry.key":           ("target.registry.registry_key",       "registry_path",        "RegistryKey",        "Registry Key"),
    "network.bytes_out":      ("network.sent_bytes",                 "bytes_out",            "SrcBytes",           "BytesSent"),
    "network.protocol":       ("network.application_protocol",       "app",                  "NetworkApplicationProtocol", "Application"),
}

NUMERIC = {"source.port", "destination.port", "http.status", "network.bytes_out"}

# Extra names accepted when *parsing* (native schemas, Sysmon, Windows, CEF ...)
ALIASES: dict[str, dict[str, str]] = {
    "udm": {},
    "spl": {
        "CommandLine": "process.command_line", "Image": "process.path", "ParentImage": "process.parent.path",
        "ParentCommandLine": "process.parent.command_line", "User": "user.name", "Account_Name": "user.name",
        "ComputerName": "host.name", "Computer": "host.name", "dest_ip": "destination.ip", "src_ip": "source.ip",
        "dest_port": "destination.port", "src_port": "source.port", "EventID": "event.code",
        "http_user_agent": "http.user_agent", "uri": "url.full", "TargetFilename": "file.path",
        "TargetObject": "registry.key", "Process_Command_Line": "process.command_line",
        "New_Process_Name": "process.path", "dest_host": "destination.host",
    },
    "kql": {
        "ProcessCommandLine": "process.command_line", "FolderPath": "process.path", "FileName": "process.name",
        "InitiatingProcessFolderPath": "process.parent.path", "InitiatingProcessFileName": "process.parent.name",
        "InitiatingProcessCommandLine": "process.parent.command_line",
        "NewProcessName": "process.path", "ParentProcessName": "process.parent.path",
        "AccountName": "user.name", "SubjectUserName": "user.name", "TargetUserName": "target.user.name",
        "UserPrincipalName": "target.user.name", "DeviceName": "host.name", "Computer": "host.name",
        "EventID": "event.code", "IpAddress": "source.ip", "IPAddress": "source.ip",
        "SourceIP": "source.ip", "DestinationIP": "destination.ip", "RemoteIP": "destination.ip",
        "DestinationPort": "destination.port", "RemotePort": "destination.port", "SourcePort": "source.port",
        "RequestURL": "url.full", "RemoteUrl": "url.full", "RequestClientApplication": "http.user_agent",
        "DeviceVendor": "event.vendor", "DeviceProduct": "event.product", "SentBytes": "network.bytes_out",
        "Name": "dns.query", "QueryName": "dns.query", "RegistryValueName": "registry.value",
    },
    "aql": {
        "Command": "process.command_line", "Image": "process.path", "Process Name": "process.name",
        "ParentImage": "process.parent.path", "Username": "user.name", "sourceIP": "source.ip",
        "destinationIP": "destination.ip", "Event ID": "event.code", "url": "url.full",
        "devicetype": "event.product",
    },
}

# Same name means different things depending on the event category.
CONTEXTUAL: dict[str, dict[tuple[str, str], str]] = {
    # (lang, native name) per category -> canonical
    "authentication": {("spl", "user"): "target.user.name", ("aql", "username"): "target.user.name",
                       ("spl", "dest"): "destination.host"},
    "process": {("spl", "dest"): "host.name"},
}

OUTCOME_VALUES = {
    "udm": {"success": "ALLOW", "failure": "BLOCK"},
    "spl": {"success": "success", "failure": "failure"},
    "kql": {"success": "Success", "failure": "Failure"},
    "aql": {"success": "success", "failure": "failure"},
}
OUTCOME_PARSE = {
    "allow": "success", "allowed": "success", "success": "success", "succeeded": "success", "pass": "success",
    "block": "failure", "blocked": "failure", "deny": "failure", "denied": "failure", "drop": "failure",
    "failure": "failure", "failed": "failure", "fail": "failure",
}

# Event category per language
CATEGORY_UDM = {
    "process": "PROCESS_LAUNCH", "authentication": "USER_LOGIN", "network": "NETWORK_CONNECTION",
    "dns": "NETWORK_DNS", "http": "NETWORK_HTTP", "file": "FILE_CREATION", "registry": "REGISTRY_MODIFICATION",
}
UDM_CATEGORY = {v: k for k, v in CATEGORY_UDM.items()}
UDM_CATEGORY.update({"FILE_MODIFICATION": "file", "FILE_DELETION": "file", "FILE_MOVE": "file",
                     "REGISTRY_CREATION": "registry", "NETWORK_FLOW": "network", "USER_LOGOUT": "authentication"})

CATEGORY_ASIM = {
    "process": "_Im_ProcessCreate", "authentication": "_Im_Authentication", "network": "_Im_NetworkSession",
    "dns": "_Im_Dns", "http": "_Im_WebSession", "file": "_Im_FileEvent", "registry": "_Im_RegistryEvent",
}
KQL_TABLE_CATEGORY = {v.lower(): k for k, v in CATEGORY_ASIM.items()}
KQL_TABLE_CATEGORY.update({
    "improcesscreate": "process", "deviceprocessevents": "process",
    "imauthentication": "authentication", "signinlogs": "authentication", "deviceLogonEvents".lower(): "authentication",
    "imnetworksession": "network", "commonsecuritylog": "network", "devicenetworkevents": "network",
    "imdns": "dns", "dnsevents": "dns", "imwebsession": "http", "imfileevent": "file", "devicefileevents": "file",
    "imregistry": "registry", "deviceregistryevents": "registry",
})

CATEGORY_SPL_TAGS = {
    "process": "tag=process tag=report", "authentication": "tag=authentication",
    "network": "tag=network tag=communicate", "dns": "tag=network tag=resolution tag=dns",
    "http": "tag=web", "file": "tag=endpoint tag=filesystem", "registry": "tag=endpoint tag=registry",
}
SPL_TAG_CATEGORY = {"process": "process", "authentication": "authentication", "communicate": "network",
                    "dns": "dns", "web": "http", "filesystem": "file", "registry": "registry"}


def _index(lang: str) -> int:
    return LANGS.index(lang)


def to_native(lang: str, canonical: str, category: str = "generic") -> str | None:
    """Canonical -> native name. Returns None when the target has no equivalent."""
    if ":" in canonical and canonical.split(":", 1)[0] in LANGS:
        return canonical.split(":", 1)[1]
    entry = FIELDS.get(canonical)
    if not entry:
        return None
    if category == "process" and lang == "spl" and canonical == "host.name":
        return "dest"
    return entry[_index(lang)] or None


def to_canonical(lang: str, native: str, category: str = "generic") -> str:
    ctx = CONTEXTUAL.get(category, {})
    if (lang, native) in ctx:
        return ctx[(lang, native)]
    for canonical, entry in FIELDS.items():
        if entry[_index(lang)] and entry[_index(lang)].lower() == native.lower():
            return canonical
    alias = {k.lower(): v for k, v in ALIASES.get(lang, {}).items()}
    if native.lower() in alias:
        return alias[native.lower()]
    return f"{lang}:{native}"


def field_table() -> str:
    """Markdown table of all mappings (used by `rosetta fields` and the README)."""
    rows = ["| Canonical | Google SecOps UDM | Splunk CIM | Sentinel ASIM | QRadar |", "|---|---|---|---|---|"]
    for canonical, (udm, spl, kql, aql) in FIELDS.items():
        rows.append(f"| `{canonical}` | `{udm or '-'}` | `{spl or '-'}` | `{kql or '-'}` | `{aql or '-'}` |")
    return "\n".join(rows)
