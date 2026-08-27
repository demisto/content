[Secureworks](https://secureworks.com) cloud-native solutions for extended detection and response are built on Taegis Cloud-Native Enterprise Security Platform. They leverage its AI-powered analytics and automation engines, curated threat intelligence, and comprehensive attack-vector coverage to help maximize the effectiveness and efficiency of your security program.

Taegis XDR is a cloud-native security solution that combines the power of human intellect with security analytics to unify detection and response across cloud, network, and endpoint environments for improved security operations and outcomes.

# What does this pack do?

- Ingest Taegis XDR cases as Cortex XSOAR incidents with full field mapping
- Mirror status, assignee, and comment changes bi-directionally between Cortex XSOAR and Taegis XDR
- View Taegis security event alerts
- View, create, and update Taegis Investigations
- View, create, and update CTP health and security tickets

## Integrations in this pack

| Integration | Status | Use |
|---|---|---|
| **Taegis XDR v3** | Current | Recommended integration for Taegis XDR. Adds case ingestion, bi-directional mirroring, assignee and status management, and an incident layout with action buttons. |
| **TaegisXDR v2** | Deprecated | Superseded by Taegis XDR v3. Retained for migration only. |
| **TaegisXDR** | Deprecated | Superseded by TaegisXDR v2, then Taegis XDR v3. |
| **Dell Secureworks** | Current | Secureworks CTP health and security tickets. |

> **Migrating from TaegisXDR v2 to Taegis XDR v3:** all 20 v2 command names are preserved verbatim in v3, so existing playbooks continue to work unchanged. Configure a Taegis XDR v3 instance, disable the v2 instance, and add `using-brand=TaegisXDRv3` only if you need to run both side by side during cutover.

## What's included for Taegis XDR v3

| Content Type | Name | Description |
|---|---|---|
| **Integration** | Taegis XDR v3 | Core integration for Taegis XDR case management, fetching, and bi-directional mirroring. |
| **Incident Type** | Taegis XDR - Case | Custom incident type for ingested Taegis XDR cases. |
| **Incident Fields** | 15 custom fields | Case status, assignee, detections, entities, key findings, close reason, and more. |
| **Classifiers** | Ingestion classifier + incoming/outgoing mappers | Routes Taegis cases to the correct incident type and maps fields in both directions. |
| **Layout** | Taegis XDR Case | Custom layout with tabs, close form (including archive-on-close), and action buttons. |
| **Scripts** | TaegisXDRAddCommentNote | Adds a War Room note that mirrors to Taegis XDR as a comment, attributed to the Cortex XSOAR user who added it. |
| | TaegisXDRAssigneeOptions | Populates assignee selection options from Taegis XDR users. |
| | TaegisXDRCaseCommentsDisplay | Dynamic section that renders case comments newest-first in the layout, with author, timestamp, and direction (to/from Taegis XDR). |
| | TaegisXDRCaseStatusOpenOptions | Populates available case status options. |
| | TaegisXDRPushAssigneeStatusForm | Pushes assignee and status changes back to Taegis XDR. |
| | TaegisXDRSetRequestedStatusFromRequestedAssignee | Sets the requested status based on assignee selection. |

## Prerequisites

- Cortex XSOAR 6.13.0 or later (8.x supported).
- A Secureworks Taegis XDR tenant with API access enabled.
- A Taegis XDR API client ID and client secret, assigned the **Tenant Analyst** role. Tenant Analyst is the least-privilege role that covers every command in this integration, including asset isolation and executing an existing Taegis XDR Automation. See the [Taegis XDR API documentation](https://docs.taegis.secureworks.com/apis/api_authenticate/) for credential generation and region-specific base URLs.
- Any Taegis XDR Automation you intend to run from Cortex XSOAR must already exist as a configured Playbook Instance. Tenant Analyst can execute one but cannot create one, so a Tenant Admin needs to set it up first.

## Key Capabilities

- **Case ingestion** - Fetches Taegis XDR cases as Cortex XSOAR incidents with full field mapping.
- **Bi-directional mirroring** - Status changes, assignee updates, and comments sync between Cortex XSOAR and Taegis XDR in both directions.
- **Assignee management** - Update case assignees directly from the Cortex XSOAR incident layout using a dynamic user picker populated from Taegis XDR.
- **Comment sync** - Add comments from the Cortex XSOAR War Room that automatically mirror to Taegis XDR case comments. Comments are attributed to their author and displayed newest-first in the case layout.
- **Investigation enrichment** - Retrieve detections, entities, and key findings associated with a case.
- **Archive on close** - Optionally archive Taegis XDR cases when closing the Cortex XSOAR incident.

## Triage Workflow

By design, ingested Taegis XDR cases are created in **Pending** status as a triage queue. An analyst **takes** a case by assigning it to themselves (Assign -> self), which sets them as the incident owner and moves it to **Active**. Ownership stays with whoever takes the case - a deliberate, single action that works identically on Cortex XSOAR v6 and v8.

The incident type ships with **no default playbook**, so triage is analyst-driven and mirroring keeps both systems in step. Attach your own playbook to the **Taegis XDR - Case** incident type if you want automated triage. If that playbook closes incidents, set **Taegis XDR Close Reason** to a `CLOSED_*` value as part of it - the integration uses that field to decide whether to close the corresponding Taegis case, so closing without it would close the Cortex XSOAR incident and leave the Taegis case open.

## Getting Started

1. Install this content pack.
2. Navigate to **Settings** -> **Integrations** and search for **Taegis XDR v3**.
3. Create a new instance and configure:
   - **Client ID** / **Client Secret** - your Taegis XDR API credential. Enter the Client ID as the username and the Client Secret as the password, or select a stored credential.
   - **API base URL** - the Taegis API endpoint for your environment.
   - **XDR base URL** - the Taegis XDR console URL for your environment.
   - **Mirroring** options as needed (incoming, outgoing, or both).
4. Click **Test** to verify connectivity, then enable the instance.
5. Confirm the ingestion classifier is assigned so incoming cases create "Taegis XDR - Case" incidents.

## Post-Install: Exclusion Lists

Optional, and not imported automatically with the content pack. The **Taegis XDR - Case** incident type extracts indicators only from **Taegis XDR Case Entities** and **Taegis XDR Key Findings**, so Taegis XDR's own console links are not extracted from the case link or the detections grid. These lists remain useful because Key Findings is free-form text, and an analyst who pastes a Taegis case link into it would otherwise create a URL or domain indicator for the Taegis console.

A single pasted console link produces both a URL indicator and a Domain indicator, so import both files from the `doc_files/ExclusionLists/` folder to suppress them:

- `TaegisXDRv3_urls.json` - Regex matching Secureworks Taegis XDR console URLs.
- `TaegisXDRv3_domains.json` - Regex matching Secureworks Taegis XDR domains.

**Cortex XSOAR v6:** Settings -> Advanced -> **Exclusion List** -> Import exclusion list (import icon) -> select each JSON file.

**Cortex XSOAR v8:** Settings & Info -> Settings -> Object Setup -> Indicators -> **Exclusion List** -> vertical ellipsis (...) -> **Upload** -> select each JSON file.
