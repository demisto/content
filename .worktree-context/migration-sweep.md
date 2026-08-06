# XSUP-74179 - Repo-wide sweep: `xdr-get-incident-extra-data` -> `xdr-case-list`

Branch: `jl-migrate-incident-to-case`
Scope: entire `Packs/` tree + top-level `TestPlaybooks/`
Mode: read-only investigation. No files modified other than this report.

---

## 1. Direct answer

**Yes - exactly one item still needs migration in this MR.**

One **live breakage was introduced by the already-completed migration**:
[`playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml:841)
is invoked as a **shared-context** (`separatecontext: false`) sub-playbook by the now-migrated
[`Cortex_XDR_Alerts_Handling_v2.yml`](Packs/CortexXDR/Playbooks/Cortex_XDR_Alerts_Handling_v2.yml:1585),
but still reads `PaloAltoNetworksXDR.Incident.alerts.user_name` from the shared context that the
parent no longer populates.

Everything else found is either pre-existing tech debt, documentation, deprecated/superseded
content, or CTF training material.

---

## 2. The decisive technical rule used for classification

XSOAR sub-playbook context isolation determines whether a `PaloAltoNetworksXDR.Incident` read in a
child playbook is a **new** break or **pre-existing** debt:

| Parent task setting | Child reads `...Incident.*` from shared context | Verdict |
|---|---|---|
| `separatecontext: false` | Child sees parent context. Parent used to write `.Incident`, now writes `.Case`. | **BROKEN - newly introduced by this MR** |
| `separatecontext: true` | Child context starts isolated; parent's `.Incident` was **never** visible. Those reads already resolved empty before the migration. | **Pre-existing debt, not caused by this MR** |
| `separatecontext: true` + parent overrides every `inputs:` default | Child's `inputs:` defaults are dead code. | **BENIGN** |

Sub-playbook call audit of the migrated [`Cortex_XDR_Alerts_Handling_v2.yml`](Packs/CortexXDR/Playbooks/Cortex_XDR_Alerts_Handling_v2.yml:1):

| Line | Sub-playbook | `separatecontext` | Child reads `.Incident`? | Result |
|---|---|---|---|---|
| 357 | Cortex XDR - Port Scan - Adjusted | `true` (450) | only in `inputs:` defaults (2665-2781) | BENIGN - parent overrides all inputs with `.Case.Issues` |
| 486 | Cortex XDR - Malware Investigation | `false` (587) | only `outputs:` doc stub (661) | BENIGN |
| 617 | Cortex XDR - XCloud Cryptojacking | `true` (677) | n/a | OK |
| 714 | GenericPolling | `false` (738) | no | OK |
| 1150 | Possible External RDP Brute-Force | `true` (1261) | no | OK |
| 1302 | Cortex XDR - First SSO Access | `true` (1397) | no | OK |
| 1427 | Cloud IAM User Access Investigation | `true` (1462) | no | OK |
| 1520 | XCloud Token Theft Response | `true` (1557) | task-level (1104-1948) | pre-existing (isolated context) |
| **1586** | **Cloud Data Exfiltration Response** | **`false` (1608)** | **task-level (841, 914)** | **BROKEN - NEW** |
| 1638 | Remote PsExec with LOLBIN | `true` (1688) | task-level (525-538) | pre-existing |
| 1736 | Cortex XDR - Identity Analytics | `true` (1801) | task-level (112-1082) | pre-existing |
| 1831 | Cortex XDR - Large Upload | `true` (1872) | task-level (1847-4113) | pre-existing |
| 1980 | Malicious Pod Response - Agent | `false` (2022) | no | OK |

Sub-playbook call audit of the migrated [`Cortex_XDR_incident_handling_v3_6_5.yml`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:1):
all seven sub-playbook calls are either `separatecontext: true` (Calculate Severity, Entity
Enrichment, Hunting and Threat Detection, Device Control Violations, Block Indicators, Display
Risky Assets) or the already-migrated `Cortex XDR Alerts Handling v2` (1605, `separatecontext:
false`). **No breakage.**

**Reverse-direction check (highest priority):** is a migrated playbook called by a *non-migrated*
parent? `Cortex XDR Alerts Handling v2` has exactly one caller repo-wide -
`Cortex_XDR_incident_handling_v3_6_5.yml`, which is migrated. `Cortex XDR incident handling v3` has
no parent (it is a top-level incident-type playbook). **No breakage in that direction.**

---

## 3. MIGRATE-NOW - fold into this MR

| # | File + line | References | Impact | Justification |
|---|---|---|---|---|
| **M1** | [`playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml:841`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml:841) (task 83, `username` arg) | context path `PaloAltoNetworksXDR.Incident.alerts.user_name` x3 (root + 2 filters) | **BROKEN** | Shared-context child of the migrated parent. Parent now writes `.Case.Issues`; this read silently returns empty, so `username` is blank and the Cloud User Remediation branch no-ops. Rename to `PaloAltoNetworksXDR.Case.Issues.user_name`. |
| **M2** | [`playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml:914`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml:914) (task 84, `Username` arg to `Cloud User Investigation - Generic`) | same path x3 | **BROKEN** | Same root cause; the generic user-investigation sub-playbook receives an empty username. Rename to `PaloAltoNetworksXDR.Case.Issues.user_name`. |

Note the nested field stays `user_name` (not `issue_user_name`): per
[`normalize_case_data_record()`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.py:2830),
only top-level keys and the container names are re-keyed; fields inside nested issue records are
untouched.

Because `Packs/CloudIncidentResponse/` is a **different pack**, M1/M2 additionally require a
`Packs/CloudIncidentResponse/ReleaseNotes/<next>.md` entry and a `currentVersion` bump in
`Packs/CloudIncidentResponse/pack_metadata.json`.

---

## 4. Full classified findings

### 4a. Deprecated command invocations (`xdr-get-incident-extra-data`)

| File + line | Reference | Impact | Recommendation |
|---|---|---|---|
| [`playbook-Cortex_XDR_-_Cloud_Cryptomining.yml:551`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Cryptomining.yml:551) | command call | STILL-WORKS | FOLLOW-UP-TICKET - different pack, command still functions; no context consumer breaks today. |
| [`playbook-Cortex_XDR_-_XCloud_Token_Theft_-_Set_Verdict.yml:126`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_XCloud_Token_Theft_-_Set_Verdict.yml:126) | command call | STILL-WORKS | FOLLOW-UP-TICKET - same. |
| [`playbook-Cortex_XDR_-_AWS_IAM_user_access_investigation.yml:57`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_AWS_IAM_user_access_investigation.yml:57) | command call + `.Incident.alerts` reads (102-878) | STILL-WORKS | FOLLOW-UP-TICKET - self-consistent: it calls the deprecated command itself and reads its own output. Not reached via the migrated parent (the parent invokes `Cortex XDR - Cloud IAM User Access Investigation`, a different playbook). |
| [`playbook-Cortex_XDR_-_PrintNightmare_Detection_and_Response_6_5.yml:1127`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_PrintNightmare_Detection_and_Response_6_5.yml:1127) | command call + `.Incident.alerts/.users` (106-1361) | STILL-WORKS | FOLLOW-UP-TICKET - self-consistent, standalone playbook, no migrated parent. |
| [`playbook-Cortex_XDR_Lite_-_Incident_Handling.yml:1394`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Lite_-_Incident_Handling.yml:1394) | command call + ~40 `.Incident.*` reads (1420-2126) | STILL-WORKS | FOLLOW-UP-TICKET - XDR Lite is a self-contained top-level playbook; migrate as one unit later. |
| [`playbook-Cortex_XDR_Malware_-_Incident_Enrichment.yml:198`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Malware_-_Incident_Enrichment.yml:198) | command call + ~50 `.Incident.*` reads (13-802) | STILL-WORKS | FOLLOW-UP-TICKET - self-consistent, and its only parent (`Cortex XDR Malware - Investigation And Response`, line 1250) is also unmigrated. Migrating one without the other would create a new break - do them together in a follow-up. |
| [`Cortex_XDR_Alerts_Handling.yml:263`](Packs/CortexXDR/Playbooks/Cortex_XDR_Alerts_Handling.yml:263) and [`:594`](Packs/CortexXDR/Playbooks/Cortex_XDR_Alerts_Handling.yml:594) (**trailing-space** `'xdr-get-incident-extra-data '` in `PollingCommandName`) | command call + polling + ~120 `.Incident.*` refs | STILL-WORKS | LEAVE - v1, superseded by the migrated `Cortex XDR Alerts Handling v2`. |
| [`Cortex_XDR_Incident_Handling.yml:44`](Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml:44) | description text (via XDRSyncScript) | STALE-DOC | LEAVE - playbook is explicitly `Deprecated. Use 'Cortex XDR incident handling v3'`. |
| [`Cortex_XDR_incident_handling_v2.yml:155`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v2.yml:155) | description text + `.Incident.*` (1641-1706) | STALE-DOC | LEAVE - explicitly deprecated in favour of v3. |
| [`Cortex_XDR_-_Port_Scan.yml:1669`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Port_Scan.yml:1669) | description text (XDRSyncScript) | STALE-DOC | LEAVE - superseded by `Cortex XDR - Port Scan - Adjusted`. |
| [`XDRSyncScript.py:214`](Packs/CortexXDR/Scripts/XDRSyncScript/XDRSyncScript.py:214), [`:221`](Packs/CortexXDR/Scripts/XDRSyncScript/XDRSyncScript.py:221) | `demisto.executeCommand` | STILL-WORKS | LEAVE - script's own YAML says `Deprecated. No available replacement.` |
| [`XDRSyncScript.yml:87`](Packs/CortexXDR/Scripts/XDRSyncScript/XDRSyncScript.yml:87) + outputs 93-330 | comment + `.Incident.*` output docs | STALE-DOC | LEAVE - deprecated script. |
| [`CortexXDRIR.py:3443`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.py:3443) | command dispatch | STILL-WORKS | LEAVE - the deprecated command must keep working for backward compatibility. |
| [`CortexXDRIR.yml:348`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.yml:348) | `deprecated: true` + pointer to `xdr-case-list extra_data=true` | correct | LEAVE - already correct. |
| [`CortexXDRIR_test.py:1419`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR_test.py:1419), [`:206`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR_test.py:206) | unit test of the deprecated command | STILL-WORKS | LEAVE - tests must keep covering the still-shipped deprecated command. |
| [`command_examples.txt:2`](Packs/CortexXDR/Integrations/CortexXDRIR/command_examples.txt:2) | example invocation | STALE-DOC | FOLLOW-UP-TICKET - cosmetic; update alongside the integration doc refresh. |

### 4b. Test playbooks

| File + line | Reference | Impact | Recommendation |
|---|---|---|---|
| [`Test_XDR_Playbook.yml:174`](Packs/CortexXDR/TestPlaybooks/Test_XDR_Playbook.yml:174) + `.Incident.*` (132-1295) | command call, asserts deprecated outputs | STILL-WORKS | LEAVE - this is the regression test *for* the deprecated command. Removing it would drop coverage of shipped behaviour. |
| [`Test_XDR_Playbook_general_commands.yml:173`](Packs/CortexXDR/TestPlaybooks/Test_XDR_Playbook_general_commands.yml:173), 2993, 3082, 3175 + `.Incident.*` (131-3231) | command calls | STILL-WORKS | LEAVE - same rationale. |
| [`Test_Playbook_-_Cortex_XDR_Malware_-_Incident_Enrichment.yml`](Packs/CortexXDR/TestPlaybooks/Test_Playbook_-_Cortex_XDR_Malware_-_Incident_Enrichment.yml:170) (~30 refs) | tests the unmigrated `Cortex XDR Malware - Incident Enrichment` | STILL-WORKS | FOLLOW-UP-TICKET - must be migrated in lockstep with its playbook, not before. |
| [`Test_Playbook_-_Cortex_XDR_-_Endpoint_Investigation.yml`](Packs/CortexXDR/TestPlaybooks/Test_Playbook_-_Cortex_XDR_-_Endpoint_Investigation.yml:131) (~12 refs) | mostly inside human-readable failure `message:` strings | STALE-DOC | FOLLOW-UP-TICKET - only line 396 is a real context read; the rest are error-message prose. |
| [`Test_Playbook_-_Cortex_XDR_-_Get_File_Path_from_alerts_by_hash.yml:231`](Packs/CortexXDR/TestPlaybooks/Test_Playbook_-_Cortex_XDR_-_Get_File_Path_from_alerts_by_hash.yml:231), 245, 259, 299 | `.Incident.alerts` reads | STILL-WORKS | FOLLOW-UP-TICKET - pairs with the unmigrated `Cortex XDR - Get File Path from alerts by hash`. |
| Top-level `TestPlaybooks/` | - | - | **0 hits.** Clean. |

### 4c. Context-path-only consumers (no deprecated command call of their own)

| File + line | Reference | Impact | Recommendation |
|---|---|---|---|
| [`Cortex_XDR_-_Large_Upload.yml:1847`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Large_Upload.yml:1847), 2389, 2409, 2429, 3209, 3400, 3429, 3769, 4106 | `.Incident.alerts` at task level | BENIGN (pre-existing) | FOLLOW-UP-TICKET - called with `separatecontext: true`, so these reads already resolved empty before this MR. Real debt, but not a regression. |
| [`playbook-Cortex_XDR_-_Identity_Analytics.yml:112`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_Identity_Analytics.yml:112), 1080 | `.Incident.alerts` | BENIGN (pre-existing) | FOLLOW-UP-TICKET - isolated context. |
| [`playbook-Cortex_XDR_-_Remote_PsExec_with_LOLBIN_command_execution_alert.yml:526`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_Remote_PsExec_with_LOLBIN_command_execution_alert.yml:526), 537 | `.Incident.critical_severity_alert_count` / `.high_severity_alert_count` | BENIGN (pre-existing) | FOLLOW-UP-TICKET - isolated context. Note: these are *top-level* fields, so post-migration they map to `PaloAltoNetworksXDR.Case.*`. |
| [`playbook-Cortex_XDR_-_First_SSO_Access_-_Set_Verdict.yml:371`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_First_SSO_Access_-_Set_Verdict.yml:371) and 7 more | `.Incident.alerts.name` | BENIGN (pre-existing) | FOLLOW-UP-TICKET - isolated context, grandchild of the migrated parent. |
| [`playbook-Cortex_XDR_-_Get_File_Path_from_alerts_by_hash.yml:69`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_Get_File_Path_from_alerts_by_hash.yml:69) and 8 more | `.Incident.alerts` | BENIGN | FOLLOW-UP-TICKET - not invoked by either migrated playbook. |
| [`playbook-Cortex_XDR_Malware_-_Investigation_And_Response.yml:199`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Malware_-_Investigation_And_Response.yml:199) and 7 more | `.Incident.*` | STILL-WORKS | FOLLOW-UP-TICKET - migrate together with its child `Cortex XDR Malware - Incident Enrichment`. |
| [`Cortex_XDR_-_Port_Scan_-_Adjusted.yml:2668`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Port_Scan_-_Adjusted.yml:2668)-2777 | `.Incident.alerts` **inside `inputs:` defaults only** | **BENIGN** | FOLLOW-UP-TICKET - verified: every one of these inputs (`Username`, `SrcIPAddress`, `DstIPAddress`, `DstPort`, `SrcHostname`, `EndpointID`, `Initiator_CMD`, `Initiator_Process_SHA256`) is explicitly overridden with `.Case.Issues` by the migrated parent at lines 369-449. Dead defaults, cosmetic only. |
| [`playbook-Cortex_XDR_-_XCloud_Token_Theft_Response.yml:1104`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_XCloud_Token_Theft_Response.yml:1104), 1773, 1796, 1817, 1943 | `.Incident.alerts` | BENIGN (pre-existing) | FOLLOW-UP-TICKET - isolated context (`separatecontext: true` at parent line 1557). |
| [`playbook-Cortex_XDR_-_Cloud_Cryptomining_-_Set_Verdict.yml:155`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Cryptomining_-_Set_Verdict.yml:155) and 10 more | `.Incident.alerts` | STILL-WORKS | FOLLOW-UP-TICKET - reached only from `Cortex XDR - Cloud Cryptomining`, which calls the deprecated command itself. Self-consistent. |
| [`playbook-File_Reputation.yml:606`](Packs/CommonPlaybooks/Playbooks/playbook-File_Reputation.yml:606), 613, 619, 625 | `.Incident.alerts.*_signature_vendor` inside an `append` transformer chain | **BENIGN** | LEAVE - verified defensive: a generic cross-vendor playbook that appends several optional signature-vendor sources and de-dupes. A missing source degrades gracefully; it never fails. Adding a `.Case` variant is optional polish, not a fix. |
| [`Cortex_XDR_-_Malware_Investigation.yml:661`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Malware_Investigation.yml:661) | `outputs:` contextPath declaration only | STALE-DOC | FOLLOW-UP-TICKET - metadata stub, no runtime effect. |

### 4d. Documentation-only

`STALE-DOC` / `LEAVE` unless noted. All are output tables or command lists, no runtime effect.

| File | Notes |
|---|---|
| [`CortexXDRIR/README.md:256`](Packs/CortexXDR/Integrations/CortexXDRIR/README.md:256), 370, 397-479 | Integration README. Section 370 is already flagged `(Deprecated)`. The `xdr-get-incidents` table (256-277) documents a **different, non-deprecated** command that genuinely still outputs `.Incident` - **LEAVE, correct as-is.** |
| [`Cortex_XDR_Alerts_Handling_README.md`](Packs/CortexXDR/Playbooks/Cortex_XDR_Alerts_Handling_README.md:30) | v1 README - LEAVE (superseded). |
| [`Cortex_XDR_-_Port_Scan_-_Adjusted_README.md:55`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Port_Scan_-_Adjusted_README.md:55)-63 | documents the dead `inputs:` defaults - FOLLOW-UP with 4c row. |
| [`playbook-Cortex_XDR_Lite_-_Incident_Handling_README.md:44`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Lite_-_Incident_Handling_README.md:44) | FOLLOW-UP with XDR Lite. |
| [`Cortex_XDR_-_Large_Upload_README.md:61`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Large_Upload_README.md:61) | FOLLOW-UP. |
| [`Cortex_XDR_-_Malware_Investigation_README.md:70`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Malware_Investigation_README.md:70) | FOLLOW-UP. |
| [`playbook-Cortex_XDR_Malware_-_Incident_Enrichment_README.md:27`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Malware_-_Incident_Enrichment_README.md:27), 44 | FOLLOW-UP. |
| [`playbook-Cortex_XDR_-_AWS_IAM_user_access_investigation_README.md:33`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_AWS_IAM_user_access_investigation_README.md:33) | FOLLOW-UP. |
| [`playbook-Cortex_XDR_-_PrintNightmare_Detection_and_Response_6_5_README.md:37`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_-_PrintNightmare_Detection_and_Response_6_5_README.md:37) | FOLLOW-UP. |
| [`playbook-Cortex_XDR_-_Cloud_Cryptomining_README.md:40`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Cryptomining_README.md:40), [`...Set_Verdict_README.md:44`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_XCloud_Token_Theft_-_Set_Verdict_README.md:44) | FOLLOW-UP. |
| `Packs/CortexXDR/ReleaseNotes/` 2_3_0, 2_4_13, 2_6_0, 2_7_2, 3_0_3, 3_0_15, 4_10_29, 5_2_5, 6_1_25, 6_2_33.json, 6_3_9 | **LEAVE - immutable historical records. Never edit past release notes.** |

### 4e. CTF training pack - `Packs/ctf01/**`

**All LEAVE.** Verified as a deliberately forked training copy: the integration defines its own
`xdr-get-incident-extra-data-ctf` command
([`CortexXDRIRCTF.yml:116`](Packs/ctf01/Integrations/CortexXDRIRCTF/CortexXDRIRCTF.yml:116),
[`CortexXDRIRCTF.py:2177`](Packs/ctf01/Integrations/CortexXDRIRCTF/CortexXDRIRCTF.py:2177)) with its
own `.Incident` outputs (127-371). It is a closed loop - producer and consumers are both inside
`ctf01` - so nothing external can break it.

One nuance worth recording: [`playbook-Cortex_XDR_Alerts_Handling_CTF.yml:662`](Packs/ctf01/Playbooks/playbook-Cortex_XDR_Alerts_Handling_CTF.yml:662)
has `PollingCommandName: 'xdr-get-incident-extra-data '` - the **non**-`-ctf` name, with the trailing
space. This is a pre-existing copy-paste bug in the CTF pack (it should reference the `-ctf` fork),
unrelated to this migration. Still `LEAVE`; note it to the CTF owners if convenient.

### 4f. Non-playbook content types - all clean

| Content type | Result |
|---|---|
| `Layouts/` | **0 hits** |
| `IncidentFields/` | **0 hits** |
| `IncidentTypes/` | **0 hits** |
| `Classifiers/` (mappers) | **0 hits** |
| `Wizards/`, `Dashboards/`, `Widgets/`, `GenericDefinitions/` | **0 hits** |
| `Scripts/` | only `XDRSyncScript` (deprecated, see 4a) |

The only `.json` matches repo-wide are
[`ReleaseNotes/6_2_33.json`](Packs/CortexXDR/ReleaseNotes/6_2_33.json:3) (historical) and two
`Packs/CommonScripts/Scripts/ProvidesCommand/TestData/` fixtures, which are **captured API response
snapshots** used to test a generic command-discovery script - not content that executes. Both
`LEAVE`.

Layouts reference XDR data via **incident fields** (`incident.xdralerts`, `incident.xdrincidentid`),
never via the `PaloAltoNetworksXDR.*` context root, which is why they are unaffected.

---

## 5. `xdr-update-incident` -> `xdr-case-update` (deferred)

The command is marked `deprecated: true` at
[`CortexXDRIR.yml:693`](Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.yml:693) but is still
dispatched and fully functional.

Call sites:

| File + line | In a migrated file? |
|---|---|
| [`Cortex_XDR_incident_handling_v3_6_5.yml:190`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:190), [`:775`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:775), [`:985`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:985) | **Yes** - inside the migrated v3 playbook |
| [`playbook-Cortex_XDR_-_Cloud_Cryptomining.yml:587`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Cryptomining.yml:587), [`:695`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_Cloud_Cryptomining.yml:695) | No |
| [`playbook-Cortex_XDR_-_XCloud_Token_Theft_Response.yml:2020`](Packs/CloudIncidentResponse/Playbooks/playbook-Cortex_XDR_-_XCloud_Token_Theft_Response.yml:2020) | No |
| [`playbook-Cortex_XDR_Lite_-_Incident_Handling.yml:512`](Packs/CortexXDR/Playbooks/playbook-Cortex_XDR_Lite_-_Incident_Handling.yml:512) | No |
| [`Cortex_XDR_-_Port_Scan.yml:1757`](Packs/CortexXDR/Playbooks/Cortex_XDR_-_Port_Scan.yml:1757) | No (superseded v1) |
| [`Cortex_XDR_Incident_Handling.yml:101`](Packs/CortexXDR/Playbooks/Cortex_XDR_Incident_Handling.yml:101) | No (deprecated) |
| [`Cortex_XDR_incident_handling_v2.yml:328`](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v2.yml:328), 1036, 1299 | No (deprecated) |
| [`PaloAltoNetworks_Cortex_XDR_Incident_Sync.yml:164`](Packs/CortexXDR/Playbooks/PaloAltoNetworks_Cortex_XDR_Incident_Sync.yml:164) | No |
| [`Test_XDR_Playbook.yml:209`](Packs/CortexXDR/TestPlaybooks/Test_XDR_Playbook.yml:209), 1286; [`Test_XDR_Playbook_general_commands.yml:257`](Packs/CortexXDR/TestPlaybooks/Test_XDR_Playbook_general_commands.yml:257), 467, 2949 | No (tests) |

**Deferral is still safe. Confirmed.** The reasoning:

1. `xdr-update-incident` is a **write** command. Its only meaningful output is a success/failure
   entry - it does not populate a `PaloAltoNetworksXDR.Incident` tree that other tasks consume.
   The `.Incident` -> `.Case` rename therefore cannot orphan it.
2. Its input, `incident_id`, is sourced in the migrated v3 playbook from
   `PaloAltoNetworksXDR.Case.case_id`
   ([lines 784-786](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:784) and
   [994-996](Packs/CortexXDR/Playbooks/Cortex_XDR_incident_handling_v3_6_5.yml:994)) - already
   correctly repointed. The ID value itself is unchanged between the two shapes, so
   `xdr-update-incident` receives a valid ID and behaves identically.
3. The command is deprecated but not removed; the dispatcher still handles it.

**Recommendation:** `FOLLOW-UP-TICKET`. Track it as an explicit follow-up so the deprecated write
path does not linger indefinitely, but it does not need to block this MR.

---

## 6. `Packs/Core/` and `Packs/CortexPlatformCore/` - separate integration

Kept deliberately separate from the `PaloAltoNetworksXDR` findings.

- `Packs/CortexPlatformCore/`: **no analogous problem.** No `*-get-incident-extra-data` command and
  no `Incident`-rooted context paths.
- `Packs/Core/` (Cortex Core - IR): **no analogous deprecated-command problem.** There is no
  `core-get-incident-extra-data` command at all. The only `Core.Incident.*` context paths are the
  outputs of `core-get-incidents`
  ([`CortexCoreIR.yml:92`](Packs/Core/Integrations/CortexCoreIR/CortexCoreIR.yml:92)-153 and its
  [README](Packs/Core/Integrations/CortexCoreIR/README.md:2784)), which is a **live,
  non-deprecated** command. Note that `PaloAltoNetworksXDR.Incident` from `xdr-get-incidents` is
  likewise still valid and out of scope for this migration.

**Verdict: LEAVE.** No action required in either pack for XSUP-74179.

---

## 7. Totals

### By impact

| Classification | Distinct files | Notes |
|---|---|---|
| **BROKEN** | **1** | `playbook-Cortex_XDR_-_Cloud_Data_Exfiltration_Response.yml` (2 task sites) |
| STILL-WORKS | 14 | call the deprecated command themselves; tech debt, not breakage |
| BENIGN | 5 | isolated-context or defensive reads that degrade gracefully |
| STALE-DOC | 22 | 11 READMEs, 11 release notes / YAML doc stubs |

### By recommendation

| Recommendation | Distinct files | Notes |
|---|---|---|
| **MIGRATE-NOW** | **1 file / 2 edit sites** | plus a `CloudIncidentResponse` release note + version bump |
| FOLLOW-UP-TICKET | 24 | XDR Lite, Malware Enrichment (+ its parent and test), AWS IAM, PrintNightmare, Large Upload, Identity Analytics, PsExec, Cloud Cryptomining, XCloud Token Theft, Port Scan-Adjusted dead defaults, `xdr-update-incident`, assorted READMEs |
| LEAVE | 27 | v1/v2 superseded and deprecated playbooks, `XDRSyncScript`, deprecated-command dispatcher + its unit/integration tests, all historical release notes, all of `Packs/ctf01/**`, `playbook-File_Reputation.yml`, `Packs/Core` + `Packs/CortexPlatformCore`, `ProvidesCommand` test fixtures |

### Re-verification of the prior-analysis shortlist

Every item the prior analysis pre-labelled was independently re-checked, not assumed:

| Item | Prior label | Verified verdict |
|---|---|---|
| v1/v2 superseded XDR playbooks | LEAVE | **Confirmed LEAVE** - `description` fields state `Deprecated. Use 'Cortex XDR incident handling v3'`. |
| XDR Lite | FOLLOW-UP | **Confirmed FOLLOW-UP** - self-consistent (calls the command and reads its own output); no migrated parent. |
| Malware Enrichment | FOLLOW-UP | **Confirmed FOLLOW-UP**, with an added constraint: its parent `Malware - Investigation And Response` and its test playbook must move in the same change. |
| AWS IAM | FOLLOW-UP | **Confirmed FOLLOW-UP** - not reachable from the migrated parent (which calls the differently-named `Cloud IAM User Access Investigation`). |
| PrintNightmare | FOLLOW-UP | **Confirmed FOLLOW-UP** - standalone, self-consistent. |
| `Packs/CloudIncidentResponse/**` | LEAVE / FOLLOW-UP | **Partially corrected.** Most of the pack is FOLLOW-UP, but `Cloud Data Exfiltration Response` is **BROKEN / MIGRATE-NOW** - the shared-context (`separatecontext: false`) call from the migrated parent was missed by the earlier pass. |
| `Packs/ctf01/**` | LEAVE | **Confirmed LEAVE** - closed loop on forked `-ctf` commands. |
| `playbook-File_Reputation.yml` | LEAVE | **Confirmed LEAVE** - genuinely defensive `append`+`uniq` chain over optional sources. |
