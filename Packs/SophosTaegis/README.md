# Secureworks Taegis XDR

Integration with the Secureworks Taegis XDR platform for case ingestion, bi-directional mirroring, assignee and status management, and threat investigation.

## What's Included

| Content Type | Name | Description |
|---|---|---|
| **Integration** | Taegis XDR | Core integration for Taegis XDR case management, fetching, and bi-directional mirroring. |
| **Incident Type** | Taegis XDR - Case | Custom incident type for ingested Taegis XDR cases. |
| **Incident Fields** | 15 custom fields | Case status, assignee, detections, entities, key findings, close reason, and more. |
| **Classifiers** | Ingestion classifier + incoming/outgoing mappers | Routes Taegis cases to the correct incident type and maps fields in both directions. |
| **Layout** | Taegis XDR Case | Custom layout with tabs, close form (including archive-on-close), and action buttons. |
| **Playbook** | Taegis XDR Case Playbook | Abbreviated triage playbook - on case pickup, assigns the investigating analyst as owner, prompts review, and optionally closes the case. |
| **Scripts** | TaegisXDRAddCommentNote | Adds a War Room note that mirrors to Taegis XDR as a comment, attributed to the XSOAR user who added it. |
| | TaegisXDRAssigneeOptions | Populates assignee selection options from Taegis XDR users. |
| | TaegisXDRCaseCommentsDisplay | Dynamic section that renders case comments newest-first in the layout, with author, timestamp, and direction (to/from Taegis XDR). |
| | TaegisXDRCaseStatusOpenOptions | Populates available case status options. |
| | TaegisXDRPushAssigneeStatusForm | Pushes assignee and status changes back to Taegis XDR. |
| | TaegisXDRSetRequestedStatusFromRequestedAssignee | Sets the requested status based on assignee selection. |

## Prerequisites

- Cortex XSOAR 6.13.0 or later (8.x supported).
- A Secureworks Taegis XDR tenant with API access enabled.
- A Taegis XDR API client ID and client secret. See the [Taegis XDR API documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) for credential generation and region-specific base URLs.

## Key Capabilities

- **Case ingestion** - Fetches Taegis XDR cases as XSOAR incidents with full field mapping.
- **Bi-directional mirroring** - Status changes, assignee updates, and comments sync between XSOAR and Taegis XDR in both directions.
- **Assignee management** - Update case assignees directly from the XSOAR incident layout using a dynamic user picker populated from Taegis XDR.
- **Comment sync** - Add comments from the XSOAR War Room that automatically mirror to Taegis XDR case comments. Comments are attributed to their author and displayed newest-first in the case layout.
- **Investigation enrichment** - Retrieve detections, entities, and key findings associated with a case.
- **Archive on close** - Optionally archive Taegis XDR cases when closing the XSOAR incident.

## Triage Workflow

By design, ingested Taegis XDR cases are created in **Pending** status as a triage queue - the playbook does not run on ingestion. An analyst **takes** a case by assigning it to themselves (Assign -> self), which sets them as the incident owner and moves it to **Active**. The **Taegis XDR Case Playbook** then runs, prompting manual review and optional case closure. Ownership stays with whoever takes the case - a deliberate, single action that works identically on XSOAR v6 and v8.

## Getting Started

1. Install this content pack.
2. Navigate to **Settings** -> **Integrations** and search for **Taegis XDR**.
3. Create a new instance and configure:
   - **Client ID** and **Client Secret** - your Taegis XDR API credentials.
   - **API base URL** - the Taegis API endpoint for your environment.
   - **XDR base URL** - the Taegis XDR console URL for your environment.
   - **Mirroring** options as needed (incoming, outgoing, or both).
4. Click **Test** to verify connectivity, then enable the instance.
5. Confirm the ingestion classifier is assigned so incoming cases create "Taegis XDR - Case" incidents.

## Post-Install: Exclusion Lists

Exclusion lists are not automatically imported with the content pack. To prevent Taegis XDR URLs and domains from being flagged as indicators, import the two exclusion list files included in the `doc/ExclusionLists/` folder:

- `TaegisXDRv3_urls.json` - Regex pattern matching Secureworks Taegis XDR URLs.
- `TaegisXDRv3_domains.json` - Regex pattern matching Secureworks Taegis XDR domains.

**XSOAR v6:** Settings -> Advanced -> **Exclusion List** -> Import exclusion list (import icon) -> select each JSON file.

**XSOAR v8:** Settings & Info -> Settings -> Object Setup -> Indicators -> **Exclusion List** -> vertical ellipsis (...) -> **Upload** -> select each JSON file.
