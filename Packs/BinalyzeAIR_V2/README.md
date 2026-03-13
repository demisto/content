# Binalyze AIR Integration for Cortex XSOAR

This integration allows you to use **Binalyze AIR** isolation and evidence collection capabilities directly from **Cortex XSOAR**.

With this integration, you can:

* Isolate compromised endpoints
* Collect forensic evidence
* Assign triage tasks
* Automate incident response workflows

> Collect forensic data from endpoints in under 10 minutes.

This integration has been tested with **Binalyze AIR version v5.11.6

---

## Configuration

Configure the integration in Cortex XSOAR using the following parameters:

| Parameter                          | Description                                     | Required |
| ---------------------------------- | ----------------------------------------------- | -------- |
| Binalyze AIR Server URL            | Binalyze AIR server address                     | Yes      |
| API Key                            | Example: `api_1234567890abcdef1234567890abcdef` | Yes      |
| Trust any certificate (not secure) | Ignore SSL certificate validation               | No       |
| Use system proxy settings          | Use system proxy                                | No       |

---

## Available Commands

Commands can be executed:

* From the CLI
* Inside an automation
* As part of a playbook

After execution, a **DBot message** will appear in the War Room with the command details.

---

### 1. Isolate Endpoint

**Command:**

```
binalyze-air-isolate
```

**Description:**
Isolates or releases an endpoint from the network.

#### Arguments

| Argument        | Description                     | Required |
| --------------- | ------------------------------- | -------- |
| hostname        | Endpoint hostname               | Yes      |
| organization_id | Organization ID of the endpoint | Yes      |
| isolation       | `enable` or `disable`           | Yes      |

#### Context Output

| Path                                      | Type   | Description       |
| ----------------------------------------- | ------ | ----------------- |
| BinalyzeAIR.Isolate.result._id            | string | Isolation task ID |
| BinalyzeAIR.Isolate.result.name           | string | Task name         |
| BinalyzeAIR.Isolate.result.organizationId | number | Organization ID   |

---

### 2. Acquire Evidence

**Command:**

```
binalyze-air-acquire
```

**Description:**
Collects forensic evidence from an endpoint.

#### Arguments

| Argument        | Description                          | Required |
| --------------- | ------------------------------------ | -------- |
| hostname        | Endpoint hostname                    | Yes      |
| profile         | Acquisition profile                  | Yes      |
| case_id         | Case identifier (e.g. `C-2022-0001`) | Yes      |
| organization_id | Organization ID                      | Yes      |

#### Available Profiles

* `compromise-assessment`
* `browsing-history`
* `event-logs`
* `memory-ram-pagefile`
* `quick`
* `full`

---

## New Features

The following commands extend automation and proactive incident response capabilities:

| Command              | Description                                  |
| -------------------- | -------------------------------------------- |
| Assign Triage Task   | Assigns an existing triage task to endpoints |
| Create Case          | Creates a new case in Binalyze               |
| Create Triage Rule   | Creates a new triage rule                    |
| Download File        | Downloads files from endpoints for analysis  |
| Update Triage Rule   | Uploads a triage rule from XSOAR to Binalyze |
| Validate Triage Rule | Validates a triage rule before upload        |

---

## Automation Use Cases

With these features, you can build advanced XSOAR playbooks such as:

* Automatic endpoint isolation on high-severity alerts
* Rapid forensic evidence acquisition
* Automated triage task assignment
* Case creation and rule validation workflows

---

## Example Use Case Flow

1. Detection triggered in SIEM/EDR
2. XSOAR playbook starts
3. Endpoint is isolated via `binalyze-air-isolate`
4. Evidence is collected via `binalyze-air-acquire`
5. Triage task assigned automatically
6. Case created in Binalyze

---

## Requirements

* Cortex XSOAR
* Binalyze AIR Server
* Valid API key
* Network connectivity between XSOAR and Binalyze AIR

