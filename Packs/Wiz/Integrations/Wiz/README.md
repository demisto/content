Agentless, context-aware and full-stack security and compliance across AWS, Azure, GCP, OCI, Kubernetes, and other supported cloud platforms.
This integration was integrated and tested with Wiz

## Configure Wiz in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| name | Integration Name. Default: `Wiz_instance_1` | True |
| said | Service Account ID | True |
| sasecret | Service Account Secret | True |
| auth_endpoint | Wiz Authentication Endpoint, e.g., `https://auth.app.wiz.io/oauth/token` | True |
| api_endpoint | Wiz API Endpoint. Default: `https://api.us1.app.wiz.io/graphql` <br /> To find your API endpoint URL: <br />1. Log in to Wiz, then open your <a href="https://app.wiz.io/user/profile">user profile</a> <br />2. Copy the **API Endpoint URL** to use here. | True
| first_fetch | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
| Fetch incidents | Issue Streaming type.<br />Either `Fetch incidents` (to constantly pull Issues) or `Do not fetch` (to push live Issues)| False |
| max_fetch | Max Issues to fetch | False |
| mirror_direction | Incident Mirror Direction. Choose the mirroring direction for Wiz issues: None, Incoming, Outgoing, or Incoming And Outgoing. Default is None (no mirroring). | False |
| mirror_limit | Page size for mirror API calls (1-500). Controls how many remote issues are fetched per `get-modified-remote-data` call. Default: 50. | False |
| comment_tag | Tag for comment mirroring. Add this tag to XSOAR war room entries to mirror them as Wiz issue notes. Default: `comments`. | False |

## Mirroring

The Wiz integration supports **bidirectional mirroring** between Wiz Issues and XSOAR incidents. Configure direction via the **Incident Mirror Direction** instance setting:

| Direction | Behavior |
| --- | --- |
| `None` | Mirroring disabled. No `dbotMirror*` metadata is attached to fetched incidents. |
| `Incoming` | Wiz → XSOAR only. Pulls remote status changes and notes into the XSOAR incident. |
| `Outgoing` | XSOAR → Wiz only. Pushes XSOAR status changes, due-date changes, and tagged war room entries to the Wiz Issue. |
| `Incoming And Outgoing` | Both directions active. |

### Mirrored fields

| Field | Direction | Notes |
| --- | --- | --- |
| Issue status | Both | XSOAR `closed`/`active` map to Wiz `RESOLVED`/`OPEN`. `in_progress` maps to `IN_PROGRESS`. Reopen restores `OPEN`. |
| Resolution reason | Outgoing | When closing in XSOAR, set `resolutionReason` (e.g. `ISSUE_FIXED`, `WONT_FIX`). When omitted, defaults to `WONT_FIX`. |
| Notes / comments | Both | Incoming: all Wiz issue notes are added as war room entries (formatted `**Author** (timestamp): text`). Service-account notes use `**[SA] <name>**`. Outgoing: only war room entries tagged with `comment_tag` (default `comments`) are pushed to Wiz. |
| Due date (`dueAt`) | Outgoing | Setting/clearing the XSOAR `wizissueduedate` field updates the Wiz Issue. |

### Loop prevention

Outgoing notes are prefixed with `Mirrored from Cortex XSOAR` and the Wiz integration filters them out on incoming sync, so mirrored notes are not echoed back into the war room.

### Note truncation

Notes longer than **1400 characters** are truncated and suffixed with `... [truncated]` before being sent to the Wiz API. This applies to all mirrored notes and to the `wiz-set-issue-note`, `wiz-resolve-issue`, `wiz-reject-issue`, and `wiz-defend-set-threat-comment` commands.

### Mirror engine commands

The following commands are invoked by the XSOAR mirroring engine and are **not intended for manual use**:

| Command | Purpose |
| --- | --- |
| `get-remote-data` | Fetches updates for a single incident from Wiz. |
| `get-modified-remote-data` | Returns the list of Wiz Issues modified since the last mirror cycle (paginated; page size = `mirror_limit`). |
| `update-remote-system` | Pushes local XSOAR changes (status, notes, due date) back to Wiz. |
| `get-mapping-fields` | Returns the schema of mappable fields. Used by the mapper UI. |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook or War Room.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### wiz-get-issue

***
Get the details for a Wiz Issue ID.

<h4> Base Command </h4>

`wiz-get-issue`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |

#### Command Example

```
!wiz-get-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-get-issues

***
Get the issues on cloud resources.
<h4> Base Command </h4>

`wiz-get-issues`

<h4> Input </h4>

| **Argument Name** | **Description**                                                                                                                                                  | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| issue_type        | The type of Issue to get<br />Expected input: `TOXIC_COMBINATION`, `THREAT_DETECTION`, `CLOUD_CONFIGURATION`.<br />The chosen type will be fetched  .            | Optional |
| entity_type       | The type of entity to get issues for.                                                                                                                            | Optional |
| resource_id       | Get Issues of a specific resource_id.<br />Expected input: `providerId`                                                                                          | Optional |
| severity          | Get Issues of a specific severuty.<br />Expected input: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFORMATIONAL`.<br />The chosen severity and above will be fetched | Optional |
*`entity_type` and `resource_id` are mutually exclusive.*

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issues | String | All Issues |

#### Command Example

```
!wiz-get-issues entity_type="VIRTUAL_MACHINE"
!wiz-get-issues issue_type="THREAT_DETECTION"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456" severity=HIGH
```

### wiz-get-resource

***
Get Details of a resource. You should pass exactly one of `resource_id`, `resource_name`.
When searching by name, results are limited to 500 records.

<h4> Base Command </h4>

`wiz-get-resource`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
|-------------------| --- |--------------|
| resource_id       | Resource provider id | optional     |
| resource_name     | search by name or external ID | optional     |

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Resource | String | Resource details |

#### Command Example

```
!wiz-get-resource resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
!wiz-get-resource resource_name="i-0g03j4h5gd123d456"
!wiz-get-resource resource_name="test_vm"
```

### wiz-get-resources

***
Get details of multiple resources based on various filters.

<h4> Base Command </h4>

`wiz-get-resources`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Filter by free text search on cloud resource name. | Optional |
| entity_type | Filter cloud resources by specific entity types. Possible values are: ACCESS_ROLE, ACCESS_ROLE_BINDING, ACCESS_ROLE_PERMISSION, API_GATEWAY, APPLICATION, AUTHENTICATION_CONFIGURATION, BACKUP_SERVICE, BUCKET, CDN, CERTIFICATE, CICD_SERVICE, CLOUD_LOG_CONFIGURATION, CLOUD_ORGANIZATION, COMPUTE_INSTANCE_GROUP, CONFIG_MAP, CONTAINER, CONTAINER_GROUP, CONTAINER_IMAGE, CONTAINER_REGISTRY, CONTAINER_SERVICE, DAEMON_SET, DATABASE, DATA_WORKLOAD, DB_SERVER, DEPLOYMENT, DNS_RECORD, DNS_ZONE, DOMAIN, EMAIL_SERVICE, ENCRYPTION_KEY, ENDPOINT, FILE_SYSTEM_SERVICE, FIREWALL, GATEWAY, GOVERNANCE_POLICY, GOVERNANCE_POLICY_GROUP, HOSTED_APPLICATION, IAM_BINDING, IP_RANGE, KUBERNETES_CLUSTER, KUBERNETES_CRON_JOB, KUBERNETES_INGRESS, KUBERNETES_INGRESS_CONTROLLER, KUBERNETES_JOB, KUBERNETES_NETWORK_POLICY, KUBERNETES_NODE, KUBERNETES_PERSISTENT_VOLUME, KUBERNETES_PERSISTENT_VOLUME_CLAIM, KUBERNETES_POD_SECURITY_POLICY, KUBERNETES_SERVICE, KUBERNETES_STORAGE_CLASS, KUBERNETES_VOLUME, LOAD_BALANCER, MANAGED_CERTIFICATE, MANAGEMENT_SERVICE, NETWORK_ADDRESS, NETWORK_INTERFACE, NETWORK_ROUTING_RULE, NETWORK_SECURITY_RULE, PEERING, POD, PORT_RANGE, PRIVATE_ENDPOINT, PROXY, PROXY_RULE, RAW_ACCESS_POLICY, REGISTERED_DOMAIN, REPLICA_SET, RESOURCE_GROUP, SEARCH_INDEX, SECRET, SECRET_CONTAINER, SERVERLESS, SERVERLESS_PACKAGE, SERVICE_ACCOUNT, STORAGE_ACCOUNT, SUBNET, SUBSCRIPTION, SWITCH, USER_ACCOUNT, VIRTUAL_DESKTOP, VIRTUAL_MACHINE, VIRTUAL_MACHINE_IMAGE, VIRTUAL_NETWORK, VOLUME, WEB_SERVICE, DATA_WORKFLOW. | Optional |
| subscription_external_ids | Filter cloud resources according to these external subscription IDs (AWS Account, Azure Subscription, GCP Project, and OCI Compartment). You can provide multiple IDs separated by commas. | Optional |
| provider_unique_ids | Filter cloud resources according to these cloud service provider unique IDs. You can provide multiple IDs separated by commas. | Optional |
| project_ids | Filter by Wiz project IDs (comma-separated). | Optional |
| native_types | Filter by cloud-native resource types (comma-separated, e.g. aws_ec2_instance). | Optional |
| updated_at_before | Filter resources updated before this date (ISO 8601, e.g. 2024-01-01T00:00:00Z). | Optional |
| updated_at_after | Filter resources updated after this date (ISO 8601, e.g. 2024-01-01T00:00:00Z). | Optional |

*At least one parameter must be provided.*

<h4> Context Output </h4>

This command returns the raw response data from the Wiz API. The response includes resource details in JSON format.

#### Command Example

```
!wiz-get-resources search="web-server"
!wiz-get-resources entity_type="VIRTUAL_MACHINE"
!wiz-get-resources subscription_external_ids="123456789,987654321"
!wiz-get-resources provider_unique_ids="i-0g03j4h5gd123d456"
!wiz-get-resources entity_type="BUCKET" search="backup"
```

### wiz-issue-in-progress

***
Set a Wiz Issue to in progress.

<h4> Base Command </h4>

`wiz-issue-in-progress`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details |

#### Command Example

```
!wiz-issue-in-progress issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-reopen-issue

***
Re-open an Issue.

<h4> Base Command </h4>

`wiz-reopen-issue`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |
| reopen_note | Note for re-opening Issue | Optional |

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details |

#### Command Example

```
!wiz-reopen-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b" reopen_note="still an issue"
```

### wiz-reject-issue

***
Reject a Wiz Issue. Not supported for THREAT_DETECTION issues.

<h4> Base Command </h4>

`wiz-reject-issue`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |
| reject_reason | Rejection reason. Possible values are: FALSE_POSITIVE, EXCEPTION, WONT_FIX. | Required |
| reject_note | Note for the rejection. Notes longer than 1400 characters are truncated and suffixed with `... [truncated]`. | Required |

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details |

#### Command Example

```
!wiz-reject-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b" reject_reason="WONT_FIX" reject_note="this is by design"
```

### wiz-resolve-issue

***
Resolve a Wiz Issue.

<h4> Base Command </h4>

`wiz-resolve-issue`

<h4> Input </h4>

| **Argument Name** | **Description**                                 | **Required** |
|-------------------|-------------------------------------------------| --- |
| issue_id          | Issue id                                        | Required |
| resolution_reason | Issue resolution reason. Possible values are: OBJECT_DELETED, ISSUE_FIXED, FALSE_POSITIVE, EXCEPTION, WONT_FIX. | Required |
| resolution_note   | Note to explain why the Issue has been resolved. Notes longer than 1400 characters are truncated and suffixed with `... [truncated]`. | Required |

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details |

#### Command Example

```
!wiz-resolve-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b" resolution_note="won't fix this issue as this is low priority" resolution_reason="WONT_FIX"
```

### wiz-set-issue-note

***
Set (append) a note to an Issue.

<h4> Base Command </h4>

`wiz-set-issue-note`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |
| note | Note for the Issue. Will be appended to existing notes. Notes longer than 1400 characters are truncated and suffixed with `... [truncated]`. | Required |

#### Command Example

```
!wiz-set-issue-note issue_id="12345678-1234-1234-1234-cc0a24716e0b" note="Checking with owner"
```

### wiz-clear-issue-note

***
Clears a note from an Issue.

<h4> Base Command </h4>

`wiz-clear-issue-note`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |

#### Command Example

```
!wiz-clear-issue-note issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-get-issue-evidence

***
Get the evidence from an Issue.

<h4> Base Command </h4>

`wiz-get-issue-evidence`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |

#### Command Example

```
!wiz-get-issue-evidence issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-rescan-machine-disk

***
Deprecated

### wiz-set-issue-due-date

***
Set a due date for an Issue.

<h4> Base Command </h4>

`wiz-set-issue-due-date`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |
| due_at | Due At Date. Format must be `YYYY-MM-DD` (e.g. `2026-12-31`). | Required |

#### Command Example

```
!wiz-set-issue-due-date issue_id="12345678-1234-1234-1234-cc0a24716e0b" due_at="2022-01-20"
```

### wiz-clear-issue-due-date

***
Clear a due date for an Issue.

<h4> Base Command </h4>

`wiz-clear-issue-due-date`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required |

#### Command Example

```
!wiz-clear-issue-due-date issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-get-project-team

***
Get the Project Owners and Security Champions details.

<h4> Base Command </h4>

`wiz-get-project-team`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Project Name | Required |

#### Command Example

```
!wiz-get-project-team project_name="project1"
```

### wiz-copy-to-forensics-account

***
Copy VM's Volumes to a Forensics Account

<h4> Base Command </h4>

`wiz-copy-to-forensics-account`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- |-----------------| --- |
| resource_id | Resource Id     | Required |

#### Command Example

```
!wiz-copy-to-forensics-account resource_id="12345678-1234-1234-1234-cc0a24716e0b"
!wiz-copy-to-forensics-account resource_id="arn:aws:ec2:us-east-1:123455563321:instance/i-05r662bfb9708a4e8"
```
