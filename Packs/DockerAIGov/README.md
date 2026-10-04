# Docker AI Governance

<~XSIAM>

## Overview

AI coding agents run with real credentials and real network access. Docker's policy enforcement point sits in front of that activity and records every governed action it evaluates: which agent asked, which developer owned it, what was requested, and whether policy allowed it.

This pack brings that audit stream into Cortex XSIAM. It models the Docker SBX Policy Enforcement Point `AuditRecord` schema into XDM, detects the governance failures that matter, and provides an operations dashboard over the result.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling Docker AI Governance audit records that are ingested via the HTTP Event Collector into Cortex XSIAM.
  * The ingested logs can be queried in XQL Search using the *`docker_ai_gov_raw`* dataset.

Detection and monitoring content:

* Two correlation rules covering cloud credential access and sustained policy denial.
* A 15-widget dashboard covering governance decisions, activity by surface, denied resources, egress destinations, agent and user activity, and the issues these rules raise.

## Supported log categories

| Category | Category Display Name |
|:---------|:----------------------|
| `AUDIT_CATEGORY_MANAGEMENT` | Session lifecycle and policy synchronisation |
| `AUDIT_CATEGORY_EVALUATION` | Allow or deny policy decision |
| `AUDIT_CATEGORY_EXECUTION` | Outcome of a performed action |

Supported clients: Docker Sandbox (*`sbx`*) and MCP Enterprise Gateway (*`mcp`*).

### Supported timestamp formats

iso_8601 (*`2026-08-21T10:18:50.625005951+00:00`*)

***

## Data Collection

### Cortex XSIAM side - Custom - HTTP based Collector

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. If you have already configured a **Custom - HTTP based Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "http" and then select **Connect**.
3. Set the following values:

    | Parameter | Value |
    |:----------|:------|
    | `Name` | Docker AI Governance |
    | `Compression` | uncompressed |
    | `Log Format` | json |
    | `Vendor` | docker |
    | `Product` | ai_gov |

4. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
5. Click the 3 dots sign next to the newly created instance and copy the API URL, it will also be used later.

The `Vendor` and `Product` values must match exactly, as the parsing rule targets the resulting *`docker_ai_gov_raw`* dataset.

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-an-HTTP-Log-Collector-to-Receive-Logs).

### Docker side

Configure the Docker AI Governance audit exporter to forward `AuditRecord` events to the collector endpoint created above. Audit emission requires a supported Docker Sandbox version with organisation governance enabled. Refer to the Docker AI Governance documentation for the exporter configuration applicable to your deployment.

The collector accepts newline-delimited JSON, one `AuditRecord` per line. Send records to:

```
POST https://api-<tenant_name>.xdr.<tenant_region>.paloaltonetworks.com/logs/v1/event
Authorization: <your_http_collector_api_token>
Content-Type: application/json
```

Where no native exporter is available, any HTTP log shipper can forward the records. Using Fluent Bit as an example, edit the Fluent Bit configuration file and add the following output:

| Parameter | Value |
|:----------|:------|
| `Name` | http |
| `Match` | docker_ai_gov |
| `Host` | api-**<tenant_name>**.xdr.**<tenant_region>**.paloaltonetworks.com |
| `Port` | 443 |
| `URI` | /logs/v1/event |
| `Format` | json |
| `tls` | On |
| `tls.verify` | On |
| `Header` | Authorization **<your_http_collector_api_token>** |
| `Retry_Limit` | False |

Refer to the [Fluent Bit manual](https://docs.fluentbit.io/manual/data-pipeline/outputs/output_formats) for details on additional output plugins and configurations.

### Verifying ingestion

Confirm records are arriving:

```
dataset = docker_ai_gov_raw
| fields _time, action_type, category, decision, client_name, agent
| sort desc _time
| limit 20
```

Then confirm the modeling rule has compiled:

```
datamodel dataset = docker_ai_gov_raw
| fields _time, xdm.event.type, xdm.event.outcome, xdm.source.user.username
| limit 20
```

Note that `xdm.*` fields are addressable only through `datamodel`. Querying `dataset = docker_ai_gov_raw | fields xdm.event.type` returns an unknown field error even when the rule is working correctly, because the raw dataset exposes source columns only.

***

## Detections

| Rule | Severity | MITRE | Fires on |
|:-----|:---------|:------|:---------|
| Agent Reached Cloud Metadata Endpoint | High | T1552.005 | A governed agent connects to a cloud instance metadata service |
| Sustained Policy Denial Pressure | Medium | T1083, T1518 | A session exceeds both a denial count and a denial-ratio threshold |

Metadata services return instance identity documents and, under IMDSv1, temporary cloud credentials to anything that can reach them. The rule covers the link-local address shared by the major providers plus the GCP, Azure, Alibaba Cloud and Oracle variants, and fires regardless of the recorded decision because a broad allow rule would not have blocked the connection.

Denial pressure is gated on both an absolute count and a ratio, so a single denial or a low-volume session does not trigger it.

## Data model notes

Each record is one envelope plus exactly one action payload chosen from a `oneof`. **`action_type` names the populated payload**, so dispatch on that field alone rather than inferring it from `category` or `decision`.

A governed action usually produces an evaluation record followed by an execution record. No identifier joins the pair, they share only `audit_session_id`, and execution records can stand alone for ungoverned actions.

| Correlation key | Groups |
|:----------------|:-------|
| `audit_session_id` | All records from one governance daemon run |
| `sandbox_id` | Sessions of one sandbox VM across restarts |

The modeling rule adds `activity_class`, collapsing action types into a small set of governed surfaces, and `deny_enforced`, which separates a denial that blocked from one recorded while the policy was in audit mode. Execution outcome fields that share names across payload types are coalesced into `exec_*`.

## Limitations

* Audit emission depends on supported Sandbox versions and applicable licensing and governance conditions, so counts are a floor rather than a census.
* Records carry metadata only, with no prompt content, agent output or tool parameter values. Detections use governance decisions and resource identities, not content inspection.
* `deny_reason` is pending release upstream. Content references it but tolerates its absence.

## Tested against

Docker AI Gov Audit Data Model, 21 August 2026, schema_version 1.82.0, clients *`sbx`* and *`mcp`*.

</~XSIAM>
