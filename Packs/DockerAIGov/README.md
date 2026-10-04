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

| Rule | Severity | Fires on |
|:-----|:---------|:---------|
| Agent Reached Cloud Metadata Endpoint | High | A governed agent connects to a cloud instance metadata service |
| Sustained Policy Denial Pressure | Medium | A single session exceeds both a denial count and a denial-ratio threshold |

**Agent Reached Cloud Metadata Endpoint.** Instance metadata services return instance identity documents and, where IMDSv1 is still permitted, temporary cloud credentials to anything that can reach them. An AI agent has no legitimate reason to query one. The rule matches the link-local metadata address common to the major cloud providers, along with the provider-specific hostnames and alternative addresses used by GCP, Azure, Alibaba Cloud and Oracle. A broad "allow all hosts" policy rule would not have blocked the connection, so the rule fires regardless of the recorded decision.

**Sustained Policy Denial Pressure.** One denial is routine, an agent probing a boundary it does not know about. A sustained run of them within a single session means the agent is repeatedly attempting actions the policy forbids, which is either a badly scoped task or an agent being steered somewhere it should not go. The rule is gated on both an absolute count and a ratio so that low-volume sessions do not trigger it.

## Data model notes

Each record is one stable envelope plus exactly one action payload chosen from a `oneof`. **`action_type` names the populated payload**, so dispatch on that field alone. Docker's guidance is explicit that the payload must not be inferred from `category` or `decision`, and this pack follows it.

A governed action usually produces an evaluation record followed by an execution record. There is no cross-record identifier joining the pair, they share only `audit_session_id`. Execution records can also stand alone for ungoverned actions, so nothing here assumes an evaluation preceded one.

Correlation keys:

| Key | Groups |
|:----|:-------|
| `audit_session_id` | All records from one governance daemon run |
| `sandbox_id` | Sessions of one sandbox VM across restarts |

The modeling rule derives two fields the raw schema does not carry:

* `activity_class` collapses the action types into a small set of governed surfaces.
* `deny_enforced` distinguishes a denial that actually blocked from one recorded while the policy was in audit mode. Conflating the two overstates how much policy is really enforcing.

Execution outcome fields such as `success`, `duration_ms` and `error_class` share names across several payload types and are coalesced into `exec_*`, so they are queryable without branching on `action_type`.

## Limitations

**Coverage is a lower bound.** Docker's reference states that hosted audit emission depends on supported Sandbox versions and applicable sign-in, licensing and enforced organisation governance conditions. The absence of a record does not prove the absence of activity. Treat counts as a floor rather than a census, particularly for metrics describing active or governed users.

**Records are metadata only.** No prompt content, agent output or tool parameter values are carried. `matched_parameter_keys` holds parameter names only. Detections are therefore built on governance decisions and resource identities, not on content inspection.

**`deny_reason` is marked pending release** in the upstream schema. Content references it but tolerates its absence.

## Tested against

Docker AI Gov Audit Data Model, 21 August 2026, schema_version 1.82.0, clients *`sbx`* and *`mcp`*.

</~XSIAM>
