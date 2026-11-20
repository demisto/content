Creates a Cortex XSOAR **Threat Intel Report** from a Group-IB record. Each collection maps to the out-of-the-box report type that fits it:

| Collection | Incident type | Report type | Read with |
| --- | --- | --- | --- |
| hi/threat, apt/threat | GIB Cybercriminal Threat, GIB Nation-State Cybercriminals Threat | Campaign | gibti-get-threat-info |
| hi/threat_actor, apt/threat_actor | GIB Cybercriminal Threat Actor, GIB Nation-State Cybercriminals Threat Actor | Threat Actor | gibti-get-threat-actor-info |
| malware/malware | GIB Malware | Malware | gibti-get-malware-malware-info |
| osi/vulnerability | GIB OSI Vulnerability | Vulnerability | gibti-get-osi-vulnerability-info |

Run inside one of these incidents, the script needs no arguments: the collection comes from the incident type and the record ID from the incident's GIB ID. Outside an incident pass `collection` and `gib_id`.

The report is written with the built-in `createThreatIntelReport` / `setThreatIntelReport` commands. The main fields Group-IB sent (attribution, evaluation, dates, regions, sectors, CVSS/EPSS, description, indicators, reports, forum accounts) are rendered into the report body, so nothing depends on tenant-specific custom fields; the `description`, `source` and (for Campaign / Threat Actor) `threatactor` fields are filled as well.

## How to switch it on

The pack ships the playbook **Group-IB TI - Create Threat Intel Report** attached to nothing: the default playbook of every Group-IB incident type is *Incident Postprocessing - Group-IB Threat Intelligence & Attribution*. Pick one:

1. Run it by hand inside one of the incidents above: `!GIBTICreateThreatIntelReport` (add `dry_run=true` to preview the payload).
2. Attach **Group-IB TI - Create Threat Intel Report** to the incident types above (Cortex XSOAR 8: **Settings & Info** > **Settings** > **Object Setup** > **Incidents**, then the incident type's playbook; 6.10: the incident type's settings) instead of the postprocessing playbook.
3. Call the playbook (or the script) from your own playbook.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | threat-intel |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* gibti-get-threat-info
* gibti-get-threat-actor-info
* gibti-get-malware-malware-info
* gibti-get-osi-vulnerability-info
* createThreatIntelReport (built-in)
* setThreatIntelReport (built-in)

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| gib_id | Group-IB record ID. Defaults to the GIB ID of the incident the script runs in. |
| collection | Group-IB collection the ID belongs to. Defaults to the collection behind the incident type the script runs in. |
| is_apt | Alternative to collection for threat reports (true = apt/threat, false = hi/threat); ignored when collection is given. |
| report_type | Threat Intel Report type to create. Defaults to the type that fits the collection (Campaign for threat reports, Threat Actor for actor profiles, Malware, Vulnerability). The body goes into the type's own body field; a tenant-defined type gets no body. |
| instance | Name of the Group-IB Threat Intelligence instance to read the record with. Defaults to the instance that fetched the incident, or to the only active instance; with several active instances and none of them the one that fetched the incident, the command runs on every instance. |
| dry_run | Build and return the report payload without creating anything. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GIBTI.ThreatIntelReport.id | ID of the created Threat Intel Report. | String |
| GIBTI.ThreatIntelReport.name | Name of the report. | String |
| GIBTI.ThreatIntelReport.type | Report type. | String |
| GIBTI.ThreatIntelReport.gibId | Group-IB record ID the report was built from. | String |
| GIBTI.ThreatIntelReport.collection | Group-IB collection the record came from. | String |
| GIBTI.ThreatIntelReport.created | Whether a report was created. | Boolean |
| GIBTI.ThreatIntelReport.dryRun | Whether the run was a dry run. | Boolean |
| GIBTI.ThreatIntelReport.payload | The report payload (name, type and fields) built in a dry run; absent otherwise. | Unknown |
