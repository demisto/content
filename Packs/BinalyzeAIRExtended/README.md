# Binalyze AIR Extended for Cortex XSOAR 6.14

## Overview

**Binalyze AIR Extended** is a Cortex XSOAR integration designed to orchestrate Binalyze AIR incident response and forensic operations directly from XSOAR playbooks, automations, and the War Room.

The integration extends the baseline Binalyze AIR action set with operational commands for endpoint isolation, forensic acquisition, case management, triage rule lifecycle, task polling, asset lookup, acquisition profile discovery, repository visibility, and evidence artifact download.

This build is intended for SOC, DFIR, threat hunting, malware investigation, and detection engineering workflows where XSOAR acts as the orchestration layer and Binalyze AIR performs endpoint-level forensic and response actions.

## Main Capabilities

- Isolate or release endpoint isolation.
- Start forensic acquisition tasks using predefined or custom acquisition profiles.
- Create, get, list, close, and query Binalyze AIR cases.
- Look up assets/endpoints before taking response actions.
- Poll task status and task assignments for GenericPolling-compatible playbooks.
- Create, validate, update, list, get, delete, and assign triage rules.
- Run YARA, Sigma, and osquery-based triage tasks.
- List and inspect acquisition profiles.
- List and inspect repositories.
- Download files from the Binalyze AIR InterACT library into the XSOAR War Room.

## Supported Use Cases

### Incident Response

Use the integration to collect endpoint evidence, isolate compromised systems, and associate forensic tasks with a Binalyze AIR case linked to an XSOAR incident.

### Malware Investigation

Run memory, event log, browser artifact, quick, full, or compromise-assessment acquisitions from a playbook. Use YARA rules to hunt for malware indicators across selected endpoints.

### Threat Hunting

Create and validate temporary or persistent triage rules, assign them to endpoints or endpoint groups, and use task polling to track execution state.

### Detection Engineering

Push detection hypotheses from XSOAR into Binalyze AIR as Sigma, YARA, or osquery triage rules. Validate rule syntax before assignment and store results in XSOAR context.

### Containment

Use endpoint isolation for high-confidence incidents such as active command-and-control, ransomware behavior, credential dumping, or lateral movement. Production playbooks should apply approval gates before isolating critical assets.

## Integration Parameters

| Parameter | Required | Description |
|---|---:|---|
| Binalyze AIR Server URL | Yes | Base URL of the Binalyze AIR server, for example `https://air.example.com`. |
| API Key | Yes | Binalyze AIR API token. |
| Trust any certificate | No | Allows untrusted certificates. Not recommended for production. |
| Use system proxy settings | No | Uses the XSOAR system proxy configuration. |

## Installation

1. Import `Binalyze_AIR_Extended_XSOAR_6_14.yml` into Cortex XSOAR.
2. Create a new integration instance.
3. Set the Binalyze AIR Server URL.
4. Add the Binalyze AIR API key.
5. Keep certificate verification enabled in production unless your environment explicitly requires otherwise.
6. Click **Test** to verify connectivity.
7. Add commands to playbooks, automations, or run them from the War Room.

## API Token Requirements

The API token should follow the principle of least privilege. Grant only the permissions required for the commands you intend to use.

Recommended permission areas:

- Asset and endpoint read access.
- Case create/read/update/close access.
- Acquisition task create/read access.
- Triage rule create/read/update/delete/validate/assign access.
- Task read and polling access.
- Repository read access.
- InterACT library download access, if file download is required.
- Endpoint isolation permission, only for approved response playbooks.

## Command Reference

### Endpoint Isolation

#### `binalyze-air-isolate`

Isolates an endpoint or releases isolation.

Example:

```text
!binalyze-air-isolate hostname=HOST123 organization_id=0 isolation=enable
```

Example to release isolation:

```text
!binalyze-air-isolate hostname=HOST123 organization_id=0 isolation=disable
```

Important production guidance:

- Do not automatically isolate domain controllers, database servers, load balancers, core network servers, or critical business systems without approval.
- Use asset criticality, hostname allow/deny lists, and analyst approval gates.

### Forensic Acquisition

#### `binalyze-air-acquire`

Starts a forensic acquisition task for an endpoint.

Example:

```text
!binalyze-air-acquire hostname=HOST123 profile=compromise-assessment case_id=C-2026-0001 organization_id=0
```

Supported predefined profiles:

- `browsing-history`
- `compromise-assessment`
- `event-logs`
- `full`
- `memory-ram-pagefile`
- `quick`

Custom acquisition profiles can also be used by name if they exist in Binalyze AIR.

Recommended profile mapping:

| Scenario | Suggested Profile |
|---|---|
| First response validation | `quick` |
| General compromise investigation | `compromise-assessment` |
| Windows event-focused investigation | `event-logs` |
| Browser credential theft or phishing | `browsing-history` |
| Memory malware, injection, credential dumping | `memory-ram-pagefile` |
| Full forensic collection | `full` |

### Case Management

#### `binalyze-air-create-case`

Creates a Binalyze AIR case.

```text
!binalyze-air-create-case name="INC-2026-0001 - Suspicious PowerShell" organization_id=0 owner_user_id=<USER_ID> visibility="public-to-organization" assigned_user_ids=<USER_ID_1>,<USER_ID_2>
```

#### `binalyze-air-get-case`

Retrieves a case by ID.

```text
!binalyze-air-get-case case_id=<CASE_ID>
```

#### `binalyze-air-list-cases`

Lists cases using optional filters.

```text
!binalyze-air-list-cases organization_id=0 limit=50
```

#### `binalyze-air-close-case`

Closes a case.

```text
!binalyze-air-close-case case_id=<CASE_ID>
```

#### `binalyze-air-get-case-tasks`

Lists tasks associated with a case.

```text
!binalyze-air-get-case-tasks case_id=<CASE_ID>
```

#### `binalyze-air-get-case-endpoints`

Lists endpoints associated with a case.

```text
!binalyze-air-get-case-endpoints case_id=<CASE_ID>
```

#### `binalyze-air-get-case-activities`

Lists case activities.

```text
!binalyze-air-get-case-activities case_id=<CASE_ID>
```

### Asset and Endpoint Lookup

#### `binalyze-air-list-assets`

Lists assets/endpoints.

```text
!binalyze-air-list-assets organization_id=0 hostname=HOST123 limit=20
```

#### `binalyze-air-get-asset`

Gets a specific asset by ID.

```text
!binalyze-air-get-asset asset_id=<ASSET_ID>
```

#### `binalyze-air-get-asset-by-hostname`

Finds an asset by hostname.

```text
!binalyze-air-get-asset-by-hostname hostname=HOST123 organization_id=0
```

#### `binalyze-air-get-asset-tasks`

Lists tasks related to an asset.

```text
!binalyze-air-get-asset-tasks asset_id=<ASSET_ID>
```

Recommended practice:

- Run endpoint lookup before isolation or acquisition.
- Prefer unique asset or endpoint identifiers when possible.
- Detect duplicate hostnames before taking containment actions.

### Task Management and Polling

#### `binalyze-air-get-task`

Retrieves task status and exposes GenericPolling-friendly output fields.

```text
!binalyze-air-get-task task_id=<TASK_ID>
```

Important output fields:

- `BinalyzeAIR.Task.ID`
- `BinalyzeAIR.Task.Status`
- `BinalyzeAIR.Task.IsDone`
- `BinalyzeAIR.Task.IsSuccess`

#### `binalyze-air-list-tasks`

Lists tasks with optional filters.

```text
!binalyze-air-list-tasks case_id=<CASE_ID> organization_id=0 limit=50
```

#### `binalyze-air-get-task-assignments`

Lists task assignments.

```text
!binalyze-air-get-task-assignments task_id=<TASK_ID>
```

#### `binalyze-air-wait-task-completion`

Waits for task completion within the command execution window.

```text
!binalyze-air-wait-task-completion task_id=<TASK_ID> timeout_seconds=300 interval_seconds=15
```

Production guidance:

- For long-running acquisition jobs, prefer XSOAR GenericPolling instead of blocking waits.
- Use `binalyze-air-get-task` as the polling command.
- Treat failed, cancelled, and timeout states as analyst-review conditions.

### Triage Rules

#### `binalyze-air-create-triage-rule`

Creates a YARA, Sigma, or osquery triage rule.

```text
!binalyze-air-create-triage-rule engine=yara search_in=both organization_ids=0 description="Suspicious LSASS dump" rule="rule Suspicious_LSASS_Dump { strings: $a = \"lsass.dmp\" nocase condition: $a }"
```

Supported engines:

- `yara`
- `sigma`
- `osquery`

Supported search scopes:

- `system`
- `memory`
- `both`
- `event-records`

#### `binalyze-air-validate-triage-rule`

Validates rule syntax before creation or assignment.

```text
!binalyze-air-validate-triage-rule engine=yara rule="rule Test { strings: $a = \"mimikatz\" nocase condition: $a }"
```

#### `binalyze-air-update-triage-rule`

Updates an existing triage rule.

```text
!binalyze-air-update-triage-rule rule_id=<RULE_ID> engine=yara search_in=memory organization_ids=0 description="Updated rule" rule="..."
```

#### `binalyze-air-list-triage-rules`

Lists triage rules.

```text
!binalyze-air-list-triage-rules organization_id=0 engine=yara limit=50
```

#### `binalyze-air-get-triage-rule`

Retrieves a triage rule by ID.

```text
!binalyze-air-get-triage-rule rule_id=<RULE_ID>
```

#### `binalyze-air-delete-triage-rule`

Deletes a triage rule.

```text
!binalyze-air-delete-triage-rule rule_id=<RULE_ID>
```

#### `binalyze-air-assign-triage-task`

Assigns one or more triage rules to selected endpoints.

```text
!binalyze-air-assign-triage-task case_id=<CASE_ID> triage_rule_ids=<RULE_ID_1>,<RULE_ID_2> hostname=HOST123 organization_id=0 mitre_attack=True
```

Production guidance:

- Validate rules before assignment.
- Use endpoint include/exclude lists for controlled targeting.
- Apply CPU limits carefully on production servers.
- Use MITRE ATT&CK enrichment when useful for reporting and analyst interpretation.

### Acquisition Profiles

#### `binalyze-air-list-acquisition-profiles`

Lists acquisition profiles.

```text
!binalyze-air-list-acquisition-profiles organization_id=0 limit=50
```

#### `binalyze-air-get-acquisition-profile`

Gets an acquisition profile by ID.

```text
!binalyze-air-get-acquisition-profile profile_id=<PROFILE_ID>
```

### Repositories

#### `binalyze-air-list-repositories`

Lists evidence repositories.

```text
!binalyze-air-list-repositories organization_id=0 limit=50
```

#### `binalyze-air-get-repository`

Gets repository details.

```text
!binalyze-air-get-repository repository_id=<REPOSITORY_ID>
```

### File Download

#### `binalyze-air-download-file`

Downloads a file from the Binalyze AIR InterACT library to the XSOAR War Room.

```text
!binalyze-air-download-file file_name="report.zip"
```

## Suggested Playbook Flow

```text
1. Receive incident from SIEM, EDR, email security, or manual analyst input.
2. Normalize hostname, username, source IP, process, hash, and alert metadata.
3. Run binalyze-air-get-asset-by-hostname.
4. Validate asset uniqueness, organization ID, platform, and online status.
5. Create or map a Binalyze AIR case.
6. Decide whether isolation is required.
7. If containment is approved, run binalyze-air-isolate.
8. Start acquisition with the appropriate profile.
9. Poll acquisition task status using binalyze-air-get-task.
10. Create or select triage rules.
11. Validate triage rules.
12. Assign triage task to selected endpoint(s).
13. Poll triage task status.
14. Download available evidence artifacts.
15. Update incident severity and analyst verdict.
16. Decide whether to keep or release isolation.
17. Close or document the Binalyze AIR case.
```

## GenericPolling Example

Use `binalyze-air-get-task` as the polling command.

Recommended settings:

```text
Polling Command: binalyze-air-get-task
Polling ID Argument: task_id
Polling ID Value: BinalyzeAIR.Acquire.Result.ID or BinalyzeAIR.Triage.Task.ID
Completion Condition: BinalyzeAIR.Task.IsDone == true
Success Condition: BinalyzeAIR.Task.IsSuccess == true
```

## Context Outputs

Common context roots:

```text
BinalyzeAIR.Asset
BinalyzeAIR.Acquire
BinalyzeAIR.Case
BinalyzeAIR.Isolate
BinalyzeAIR.Task
BinalyzeAIR.TaskAssignment
BinalyzeAIR.TriageRule
BinalyzeAIR.AssignTriageTask
BinalyzeAIR.AcquisitionProfile
BinalyzeAIR.Repository
```

## Security Recommendations

- Use least-privilege API tokens.
- Do not use `Trust any certificate` in production unless explicitly required and risk-accepted.
- Restrict endpoint isolation permission to approved playbooks and roles.
- Add approval gates before isolating critical servers.
- Maintain allow/deny lists for sensitive assets.
- Log all isolation, acquisition, and triage actions.
- Record XSOAR incident ID, Binalyze case ID, task ID, analyst, timestamp, and action reason.
- Validate all generated YARA, Sigma, and osquery rules before assignment.
- Use endpoint include/exclude filters to prevent broad accidental execution.
- Apply CPU limits for triage tasks on production systems.

## Production Validation Checklist

Before production rollout, validate the following against your deployed Binalyze AIR version:

- API token permissions.
- Server URL and TLS settings.
- Endpoint lookup by hostname.
- Acquisition profile lookup by name and ID.
- Case creation and case close.
- Task status polling.
- Task assignments listing.
- Triage rule create, validate, update, list, get, delete, and assign.
- Repository list and get.
- File download from InterACT library.
- GenericPolling behavior in XSOAR 6.14.
- Isolation enable and disable on a non-critical test endpoint.

## Known Implementation Notes

- Some extended endpoint paths may vary by Binalyze AIR version. Validate exact path behavior in your own AIR environment before production rollout.
- For long-running tasks, prefer XSOAR GenericPolling over blocking command waits.
- Hostname-based targeting should be treated carefully in multi-organization or duplicate-hostname environments.
- Use asset IDs when possible.
- The integration normalizes common visibility values for case creation.
- The triage task command includes an explicit `organization_id` argument to avoid hardcoded organization targeting.

## Recommended Rollout Plan

### Phase 1: Lab Validation

- Import the integration.
- Configure a test API token.
- Test connectivity.
- Run asset lookup against test endpoints.
- Create a test case.
- Run a quick acquisition on a non-critical endpoint.
- Poll task status.

### Phase 2: Controlled SOC Use

- Add analyst approval gates.
- Test YARA/Sigma/osquery rule validation.
- Assign triage to a limited endpoint set.
- Download evidence artifacts to the War Room.
- Document task IDs and case IDs in the incident.

### Phase 3: Production Playbook Integration

- Integrate with SIEM and EDR incident types.
- Add asset criticality checks.
- Add automatic profile selection logic.
- Add containment approval workflows.
- Add reporting and evidence chain-of-custody fields.

## Troubleshooting

### Test connection fails with authorization error

Check the API key, token expiration, role permissions, and organization scope.

### Endpoint is not found

Verify hostname format, shortname versus FQDN, organization ID, and asset registration status in Binalyze AIR.

### Acquisition profile is not found

Confirm that the profile exists in Binalyze AIR and belongs to the selected organization.

### Task polling never completes

Check task status directly in Binalyze AIR. Increase polling interval or use GenericPolling for long-running tasks.

### Triage rule validation fails

Validate rule syntax, selected engine, and selected search scope. Confirm that the rule type is supported by your Binalyze AIR version.

### File download fails

Confirm the file name, library availability, token permission, and whether the acquisition/triage output has already been generated.
