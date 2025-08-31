import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime


def _to_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _utc_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat()
    except Exception:
        return s


# evidence normalization
process_fields = {
    "parentProcessId", "filePath", "registryKey", "userSid", "sha1", "sha256",
    "fileName", "aadUserId", "processId", "parentProcessFileName",
    "parentProcessFilePath", "registryHive", "registryValueType",
    "userPrincipalName", "processCommandLine", "parentProcessCreationTime",
    "registryValue", "detectionStatus", "accountName", "processCreationTime",
    "registryValueName"
}


def normalize_evidence(evidence_list):
    mapped = []
    merged_process = {}
    # start all from 1
    field_counters = {k: 1 for k in process_fields}
    # track unique values per field
    seen_values = {k: set() for k in process_fields}

    for ev in _to_list(evidence_list):
        if not isinstance(ev, dict):
            continue

        # General evidence fields
        obj = {
            "entityType": ev.get("entityType") or "Unknown",
            "timestamp": _utc_ts(ev.get("evidenceCreationTime") or ev.get("timestamp")),
            "host": ev.get("computerDnsName") or ev.get("deviceName") or ev.get("domainName"),
            "machineId": ev.get("MachineID") or ev.get("machineId") or ev.get("deviceId"),
            "user": ev.get("userPrincipalName") or ev.get("accountName") or ev.get("userName"),
            "userSid": ev.get("userSid"),
            "aadUserId": ev.get("aadUserId"),
        }

        clean = {k: v for k, v in obj.items() if v not in (None, "", [], {})}
        mapped.append(clean)

        # processes into a single dictionary with enumerated field names
        for k in process_fields:
            v = ev.get(k)
            if v not in (None, "", [], {}) and v not in seen_values[k]:
                merged_process[f"{k}{field_counters[k]}"] = v
                seen_values[k].add(v)
                field_counters[k] += 1

        # Add host, user, machineId once if missing
        for key in ["host", "user", "machineId"]:
            if key not in merged_process or merged_process[key] in (None, ""):
                merged_process[key] = obj.get(key)

    return mapped, [merged_process]  # Always single dict in list

# main function


def main():
    args = demisto.args()
    data = args.get("value", [])

    evidence_list = []
    if isinstance(data, dict):
        evidence_list = data.get("Evidence", []) or data.get("evidence", []) or data.get("entities", [])
    elif isinstance(data, list):
        evidence_list = data

    normalized, processes = normalize_evidence(evidence_list)

    return_results({
        "Contents": normalized,
        "ContentsFormat": "json",
        "ReadableContentsFormat": "markdown",
        "EntryContext": {
            "DefenderEvidence": normalized,
            "DefenderProcesses": processes
        }
    })


if __name__ in ("__main__", "builtin", "builtins"):
    main()
