Freshservice is a service management solution that allows customers to manage service requests, incidents, change requests tasks, and problem investigation.
This integration was integrated and tested with version 2 of FreshworksFreshservice

## Configure Freshworks Freshservice on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Freshworks Freshservice.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Freshservice URL \(make sure your URL includes your unique environment name\) | True |
    | API Token | Freshservice API access token. | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Fetch incidents | Enable fetch incidents. Only incidents created after the specified "First fetch timestamp" will be retrieved. | False |
    | First fetch timestamp | First alert created date to fetch. e.g., "1 min ago","2 weeks ago","3 months ago" | False |
    | Maximum incidents per fetch | Maximum number of incidents per fetch. Default is 100. | False |
    | Ticket type to fetch as incidents.  |  | False |
    | None | Incident priorities to fetch. The default is All. You can choose multiple priorities. | False |
    | Ticket Impact | Incident impacts to fetch. The default is All. You can choose multiple impacts. | False |
    | Ticket Status | The status of the tickets to fetch. Since each ticket type has its own unique set of statuses, select only statuses that match the selected ticket type\(s\). | False |
    | Ticket Risk | The risk of the tickets to fetch. Available only for the 'Change Request' ticket type. | False |
    | Ticket Urgency | The urgency of the tickets to fetch. Available only for the 'Incident/Service Request' ticket type. The default is All. You can choose multiple urgencies. | False |
    | Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Freshservice to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Freshservice\), or Incoming and Outgoing \(from/to Cortex XSOAR and Freshservice\). | False |
    | Close Mirrored XSOAR Incident | When selected, closing the Freshservice ticket is mirrored in Cortex XSOAR. | False |
    | Close Mirrored Freshservice Ticket | When selected, closing the Cortex XSOAR incident is mirrored in Freshservice. | False |
    | Fetch tickets tasks | Fetch tasks for each ticket type and consider them in the mirroring \(required an additional API request per each ticket\). | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### freshservice-ticket-list

***
Retrieve all existing tickets or a specific ticket by specifying the ticket ID. By default, only tickets that have been created within the past 30 days will be returned. For older tickets, use the updated_since filter. You can specify the 'query' argument, 'filter' argument or any filter arguments, but not all of them together. When providing multiple filter arguments the connection between them will be "AND".

#### Base Command

`freshservice-ticket-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. Only for fetching a list of tickets. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| ticket_id | The ticket ID. If not provided, return all existing tickets. | Optional |
| include | Extra ticket information to include. Just the 'stats', 'requester','requested_for' values are available for fetching a list of tickets. Use 'include' to embed additional details in the response. Each include will consume an additional 2 credits. For example, if you embed the stats information you will be charged a total of 3 API credits (1 credit for the API call, and 2 credits for the additional stats embedding). Possible values are: conversations, requester, requested_for, stats, department, tags. | Optional |
| filter | Ticket filter. You can specify the 'query' argument, 'filter' argument or any filter arguments, but not all of them together. Possible values are: open, watching, spam, deleted. | Optional |
| requester_id | Ticket requester ID (use freshservice-agent-list to get the agent ID). | Optional |
| email | Ticket requester email. | Optional |
| updated_since | Timestamp of when the ticket was last updated (for example "YYYY-MM-DDThh:mm", "1 min ago", "2 weeks ago"). | Optional |
| type | Ticket type. Possible values are: Incident, Service Request. | Optional |
| order_type | Tickets order type (order by ticket ID). Possible values are: asc, desc. | Optional |
| agent_id | Filter by agent ID. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Filter tickets by group ID. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| priority | Filter tickets by priority. Possible values are: Low, Medium, High, Urgent. | Optional |
| status | Filter tickets by status. Possible values are: Open, Pending, Resolved, Closed. | Optional |
| impact | Filter tickets by impact. Possible values are: Low, Medium, High. | Optional |
| urgency | Filter tickets by urgency. Possible values are: Low, Medium, High. | Optional |
| tag | Filter tickets by tag. | Optional |
| due_by | Filter Tickets by due by, (for example "YYYY-MM-DDThh:mm", "1 min ago", "2 weeks ago"). | Optional |
| fr_due_by | Filter Tickets by fr due by, (for example "YYYY-MM-DDThh:mm", "1 min ago", "2 weeks ago"). | Optional |
| created_at | Filter Tickets by created at, (for example "YYYY-MM-DDThh:mm", "1 min ago", "2 weeks ago"). | Optional |
| query | Query to fetch tickets. You can specify the 'query' argument, 'filter' argument or any filter arguments, but not all of them together. For example "priority:3 AND group_id:21000478054 AND status:2" (Logical operators AND, OR along with parentheses () can be used to group conditions). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.subject | String | Ticket subject. |
| Freshservice.Ticket.group_id | Number | Ticket group ID. |
| Freshservice.Ticket.department_id | Number | Ticket department ID. |
| Freshservice.Ticket.category | String | Ticket category. |
| Freshservice.Ticket.sub_category | String | Ticket subcategory. |
| Freshservice.Ticket.item_category | String | Ticket item category. |
| Freshservice.Ticket.requester_id | Number | Ticket requester ID. |
| Freshservice.Ticket.responder_id | Number | Ticket responder ID. |
| Freshservice.Ticket.due_by | Date | The timestamp that denotes when the ticket is due to be resolved.  |
| Freshservice.Ticket.fr_escalated | Boolean | Whether the ticket first request was escalated. |
| Freshservice.Ticket.deleted | Boolean | Ticket deleted. |
| Freshservice.Ticket.spam | Boolean | Ticket spam. |
| Freshservice.Ticket.email_config_id | Number | Ticket email config ID. |
| Freshservice.Ticket.is_escalated | Boolean | Whether the ticket is escalated. |
| Freshservice.Ticket.fr_due_by | Date | Indicates when the first response is due. |
| Freshservice.Ticket.id | Number | Ticket ID. |
| Freshservice.Ticket.priority | Number | Ticket priority. |
| Freshservice.Ticket.status | Number | Ticket status. |
| Freshservice.Ticket.source | Number | Ticket source. |
| Freshservice.Ticket.created_at | Date | Ticket creation time. |
| Freshservice.Ticket.updated_at | Date | Ticket updated at. |
| Freshservice.Ticket.requested_for_id | Number | Ticket requested for ID. |
| Freshservice.Ticket.to_emails | Number | Email addresses to which the ticket was originally sent. |
| Freshservice.Ticket.type | String | Ticket type. |
| Freshservice.Ticket.description | String | Ticket description. |
| Freshservice.Ticket.workspace_id | Number | Ticket workspace ID. |

#### Command example
```!freshservice-ticket-list```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": [
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-09T11:21:47Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "<div>s</div>",
                "description_text": "s",
                "due_by": "2023-04-12T18:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-10T20:00:00Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 244,
                "is_escalated": true,
                "item_category": null,
                "priority": "Medium",
                "reply_cc_emails": [],
                "requested_for_id": 21001792073,
                "requester_id": 21001792073,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "d",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-09T11:21:47Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-09T11:21:33Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "<div>s</div>",
                "description_text": "s",
                "due_by": "2023-04-19T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-12T18:00:00Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 243,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001792073,
                "requester_id": 21001792073,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "d",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-09T11:21:33Z",
                "workspace_id": 2
            },
            {
                "category": "Hardware",
                "cc_emails": [],
                "created_at": "2023-04-04T13:58:50Z",
                "custom_fields": {
                    "test_tal": "jgfhj"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "jhdgfjhgdj 17:00",
                "description_text": "jhdgfjhgdj 17:00",
                "due_by": "2023-04-05T17:40:16Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-04T18:40:16Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 242,
                "is_escalated": false,
                "item_category": "Mac",
                "priority": "High",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Computer",
                "subject": "hdgjnhgdj",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:41:16Z",
                "workspace_id": 2
            },
            {
                "category": "Hardware",
                "cc_emails": [],
                "created_at": "2023-04-04T12:47:23Z",
                "custom_fields": {
                    "test_tal": "gfsd"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "<div style=\"font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif; font-size: 14px; \"><div>gfsdgfdg</div></div>",
                "description_text": "gfsdgfdg",
                "due_by": "2023-04-06T18:50:12Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-04T20:50:12Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 241,
                "is_escalated": false,
                "item_category": "Mac",
                "priority": "Medium",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Computer",
                "subject": "vbfdgbdf",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T13:53:12Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-03T19:26:27Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "bfsbf 22:27 17:11",
                "description_text": "bfsbf 22:27 17:11",
                "due_by": "2023-04-04T14:36:07Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-03T20:26:27Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 240,
                "is_escalated": false,
                "item_category": null,
                "priority": "Urgent",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": null,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "bsadbfs",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:17:07Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-03T19:18:53Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "Mirroring IN From Postman 17:08 ***",
                "description_text": "Mirroring IN From Postman 17:08 ***",
                "due_by": "2024-04-13T19:18:53Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T16:18:53Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 239,
                "is_escalated": false,
                "item_category": null,
                "priority": "Medium",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": null,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "vgdsfa",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:10:36Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-03T18:57:53Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "fdbfg 21:59",
                "description_text": "fdbfg 21:59",
                "due_by": "2024-04-13T18:57:53Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T15:57:53Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 238,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": null,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "bgf",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-03T19:18:17Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-03T18:56:46Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "Mirroring IN From Postman 17:31 ***",
                "description_text": "Mirroring IN From Postman 17:31 ***",
                "due_by": "2023-04-05T12:57:13Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-04T13:56:46Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 237,
                "is_escalated": true,
                "item_category": null,
                "priority": "High",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": null,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "nene",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:30:56Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-03T18:47:25Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "bla 21:48 11:41 12:27",
                "description_text": "bla 21:48 11:41 12:27",
                "due_by": "2023-04-13T18:47:25Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T15:47:25Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 236,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": null,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "testtttttttt",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T09:28:24Z",
                "workspace_id": 2
            },
            {
                "category": "Hardware",
                "cc_emails": [],
                "created_at": "2023-04-03T15:50:59Z",
                "custom_fields": {
                    "test_tal": "gdfsgdf"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "update urgency? 19:50",
                "description_text": "update urgency? 19:50",
                "due_by": "2023-04-13T16:08:30Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T13:08:30Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 235,
                "is_escalated": false,
                "item_category": "Mac",
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Computer",
                "subject": "berbrebreb",
                "tags": [
                    "123"
                ],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-03T16:51:11Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-04-03T15:40:41Z",
                "custom_fields": {
                    "test_tal": "adgff"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "fdagfdg  19:49",
                "description_text": "fdagfdg  19:49",
                "due_by": "2023-04-13T15:40:48Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T12:40:48Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 234,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": "MS Office",
                "subject": "bfdds",
                "tags": [
                    "g"
                ],
                "to_emails": null,
                "type": "Service Request",
                "updated_at": "2023-04-03T16:49:11Z",
                "workspace_id": 2
            },
            {
                "category": "Hardware",
                "cc_emails": [],
                "created_at": "2023-04-03T15:25:02Z",
                "custom_fields": {
                    "test_tal": "rgre"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "<div style=\"font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif; font-size: 14px; \"><div>rgre</div></div>",
                "description_text": "rgre",
                "due_by": "2023-04-13T15:25:02Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T12:25:02Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 233,
                "is_escalated": false,
                "item_category": "PC",
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Yammer",
                "spam": false,
                "status": "Open",
                "sub_category": "Computer",
                "subject": "beb befrb",
                "tags": [
                    "gre"
                ],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-03T15:25:02Z",
                "workspace_id": 2
            },
            {
                "category": "Network",
                "cc_emails": [],
                "created_at": "2023-04-03T08:02:55Z",
                "custom_fields": {
                    "test_tal": "custom field test"
                },
                "deleted": false,
                "department_id": 21000263163,
                "description": "Mirroring IN From Postman 17:08 ***",
                "description_text": "Mirroring IN From Postman 17:08 ***",
                "due_by": "2023-04-14T14:14:10Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-06T20:14:10Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 230,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Access",
                "subject": "subject test",
                "tags": [
                    "gfg"
                ],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:14:10Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-04-02T14:34:38Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "16:58!",
                "description_text": "16:58!",
                "due_by": "2023-04-13T12:00:09Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-05T18:00:09Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 229,
                "is_escalated": true,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001523008,
                "requester_id": 21001523008,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "missing 'impact', 'urgency', 'attachments' fields",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T13:59:09Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-04-02T13:33:44Z",
                "custom_fields": {
                    "test_tal": "dsgdsg"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "Mirroring IN From Postman 16:52 ***",
                "description_text": "Mirroring IN From Postman 16:52 ***",
                "due_by": "2023-04-13T12:00:56Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-05T18:00:57Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 228,
                "is_escalated": true,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Open",
                "sub_category": "MS Office",
                "subject": "test ticket beni",
                "tags": [
                    "cccc"
                ],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T13:52:56Z",
                "workspace_id": 2
            },
            {
                "category": "Network",
                "cc_emails": [],
                "created_at": "2023-04-02T11:58:42Z",
                "custom_fields": {
                    "test_tal": "blablabla"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "Mirroring IN From Postman 15:27",
                "description_text": "Mirroring IN From Postman 15:27",
                "due_by": "2023-04-05T18:02:09Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-03T20:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 227,
                "is_escalated": false,
                "item_category": null,
                "priority": "Medium",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Connectivity",
                "subject": "blabla",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-04T14:23:09Z",
                "workspace_id": 2
            },
            {
                "category": "Network",
                "cc_emails": [],
                "created_at": "2023-03-29T14:35:35Z",
                "custom_fields": {
                    "test_tal": "bla bla"
                },
                "deleted": false,
                "department_id": 21000263162,
                "description": "Mirroring IN From Postman 15:51",
                "description_text": "Mirroring IN From Postman 15:51",
                "due_by": "2023-04-12T20:47:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-05T17:47:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": 21000478053,
                "id": 226,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001397559,
                "requester_id": 21001397559,
                "responder_id": 21001397559,
                "source": "Phone",
                "spam": false,
                "status": "Pending",
                "sub_category": "Connectivity",
                "subject": "subject fpidsfpidsfpisdfmdsfmdsp'fmdsmfpidsjmf idsoifhds udjfoidsjfidsj'",
                "tags": [
                    "aaa",
                    "cccc"
                ],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T12:52:12Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-03-27T13:39:13Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "Mirroring IN From Postman 18:56",
                "description_text": "Mirroring IN From Postman 18:56",
                "due_by": "2023-04-13T12:00:55Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-05T18:00:55Z",
                "fr_escalated": true,
                "fwd_emails": [],
                "group_id": null,
                "id": 223,
                "is_escalated": true,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001941102,
                "requester_id": 21001941102,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Open",
                "sub_category": null,
                "subject": "sa",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-03T15:56:07Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T12:17:29Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "OUT 15:28",
                "description_text": "OUT 15:28",
                "due_by": "2023-04-11T13:18:12Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-03T19:18:12Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 220,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T12:29:11Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T11:41:47Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "test!",
                "description_text": "test!",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 219,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Closed",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-27T09:02:18Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T10:22:28Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "<div>abc</div>",
                "description_text": "abc",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 218,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-26T10:22:29Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T09:56:17Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "Tal mirroring NOW",
                "description_text": "Tal mirroring NOW",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 217,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-30T12:19:21Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T09:44:52Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "TOLA 14:34",
                "description_text": "TOLA 14:34",
                "due_by": "2023-04-11T12:40:51Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 216,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T11:37:17Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-03-26T09:40:11Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "test! OUT to FS",
                "description_text": "test! OUT to FS",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 213,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Closed",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-30T13:25:07Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T09:36:39Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "14:10 *** NEW",
                "description_text": "14:10 *** NEW",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 212,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T11:19:09Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-03-26T09:32:31Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "mirroring OUT to FS from XSOAR 2023-04-04 13:06",
                "description_text": "mirroring OUT to FS from XSOAR 2023-04-04 13:06",
                "due_by": "2023-04-11T13:25:11Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-03T19:25:11Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 209,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T11:19:08Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-03-26T09:30:45Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "test-update from FS",
                "description_text": "test-update from FS",
                "due_by": "2023-04-11T12:45:27Z",
                "email_config_id": null,
                "fr_due_by": "2023-04-03T18:45:27Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 208,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-30T13:22:37Z",
                "workspace_id": 2
            },
            {
                "category": null,
                "cc_emails": [],
                "created_at": "2023-03-26T09:30:30Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "123456",
                "description_text": "123456",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 207,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-04-02T09:19:07Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T09:24:30Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "<div>abc</div>",
                "description_text": "abc",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 205,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-26T09:24:53Z",
                "workspace_id": 2
            },
            {
                "category": "Software",
                "cc_emails": [],
                "created_at": "2023-03-26T09:23:05Z",
                "custom_fields": {
                    "test_tal": null
                },
                "deleted": false,
                "department_id": null,
                "description": "Mirroring 204",
                "description_text": "Mirroring 204",
                "due_by": "2023-04-05T21:00:00Z",
                "email_config_id": null,
                "fr_due_by": "2023-03-29T18:00:00Z",
                "fr_escalated": false,
                "fwd_emails": [],
                "group_id": null,
                "id": 204,
                "is_escalated": false,
                "item_category": null,
                "priority": "Low",
                "reply_cc_emails": [],
                "requested_for_id": 21001932798,
                "requester_id": 21001932798,
                "responder_id": null,
                "source": "Portal",
                "spam": false,
                "status": "Pending",
                "sub_category": null,
                "subject": "abc",
                "tags": [],
                "to_emails": null,
                "type": "Incident",
                "updated_at": "2023-03-30T12:35:07Z",
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Ticket
>Showing page 1.
> Current page size: 50.
>|Id|Description Text|Requester Id|Type|Subject|Status|Source|Impact|Priority|Custom Fields|Category|Created At|Updated At|Due By|Fr Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 244 | s | 21001792073 | Incident | d | Open | Portal |  | Medium |  |  | 2023-04-09T11:21:47Z | 2023-04-09T11:21:47Z | 2023-04-12T18:00:00Z | 2023-04-10T20:00:00Z |
>| 243 | s | 21001792073 | Incident | d | Open | Portal |  | Low |  |  | 2023-04-09T11:21:33Z | 2023-04-09T11:21:33Z | 2023-04-19T21:00:00Z | 2023-04-12T18:00:00Z |
>| 242 | jhdgfjhgdj 17:00 | 21001397559 | Incident | hdgjnhgdj | Pending | Phone |  | High | test_tal: jgfhj | Hardware | 2023-04-04T13:58:50Z | 2023-04-04T14:41:16Z | 2023-04-05T17:40:16Z | 2023-04-04T18:40:16Z |
>| 241 | gfsdgfdg | 21001397559 | Incident | vbfdgbdf | Pending | Phone |  | Medium | test_tal: gfsd | Hardware | 2023-04-04T12:47:23Z | 2023-04-04T13:53:12Z | 2023-04-06T18:50:12Z | 2023-04-04T20:50:12Z |
>| 240 | bfsbf 22:27 17:11 | 21001397559 | Incident | bsadbfs | Pending | Phone |  | Urgent |  |  | 2023-04-03T19:26:27Z | 2023-04-04T14:17:07Z | 2023-04-04T14:36:07Z | 2023-04-03T20:26:27Z |
>| 239 | Mirroring IN From Postman 17:08 *** | 21001397559 | Incident | vgdsfa | Open | Phone |  | Medium |  |  | 2023-04-03T19:18:53Z | 2023-04-04T14:10:36Z | 2024-04-13T19:18:53Z | 2023-04-06T16:18:53Z |
>| 238 | fdbfg 21:59 | 21001397559 | Incident | bgf | Open | Phone |  | Low |  |  | 2023-04-03T18:57:53Z | 2023-04-03T19:18:17Z | 2024-04-13T18:57:53Z | 2023-04-06T15:57:53Z |
>| 237 | Mirroring IN From Postman 17:31 *** | 21001397559 | Incident | nene | Open | Phone |  | High |  |  | 2023-04-03T18:56:46Z | 2023-04-04T14:30:56Z | 2023-04-05T12:57:13Z | 2023-04-04T13:56:46Z |
>| 236 | bla 21:48 11:41 12:27 | 21001397559 | Incident | testtttttttt | Open | Phone |  | Low |  |  | 2023-04-03T18:47:25Z | 2023-04-04T09:28:24Z | 2023-04-13T18:47:25Z | 2023-04-06T15:47:25Z |
>| 235 | update urgency? 19:50 | 21001397559 | Incident | berbrebreb | Pending | Phone |  | Low | test_tal: gdfsgdf | Hardware | 2023-04-03T15:50:59Z | 2023-04-03T16:51:11Z | 2023-04-13T16:08:30Z | 2023-04-06T13:08:30Z |
>| 234 | fdagfdg  19:49 | 21001397559 | Service Request | bfdds | Open | Phone |  | Low | test_tal: adgff | Software | 2023-04-03T15:40:41Z | 2023-04-03T16:49:11Z | 2023-04-13T15:40:48Z | 2023-04-06T12:40:48Z |
>| 233 | rgre | 21001397559 | Incident | beb befrb | Open | Yammer |  | Low | test_tal: rgre | Hardware | 2023-04-03T15:25:02Z | 2023-04-03T15:25:02Z | 2023-04-13T15:25:02Z | 2023-04-06T12:25:02Z |
>| 230 | Mirroring IN From Postman 17:08 *** | 21001397559 | Incident | subject test | Pending | Phone |  | Low | test_tal: custom field test | Network | 2023-04-03T08:02:55Z | 2023-04-04T14:14:10Z | 2023-04-14T14:14:10Z | 2023-04-06T20:14:10Z |
>| 229 | 16:58! | 21001523008 | Incident | missing 'impact', 'urgency', 'attachments' fields | Open | Portal |  | Low |  |  | 2023-04-02T14:34:38Z | 2023-04-04T13:59:09Z | 2023-04-13T12:00:09Z | 2023-04-05T18:00:09Z |
>| 228 | Mirroring IN From Postman 16:52 *** | 21001397559 | Incident | test ticket beni | Open | Phone |  | Low | test_tal: dsgdsg | Software | 2023-04-02T13:33:44Z | 2023-04-04T13:52:56Z | 2023-04-13T12:00:56Z | 2023-04-05T18:00:57Z |
>| 227 | Mirroring IN From Postman 15:27 | 21001397559 | Incident | blabla | Pending | Phone |  | Medium | test_tal: blablabla | Network | 2023-04-02T11:58:42Z | 2023-04-04T14:23:09Z | 2023-04-05T18:02:09Z | 2023-04-03T20:00:00Z |
>| 226 | Mirroring IN From Postman 15:51 | 21001397559 | Incident | subject fpidsfpidsfpisdfmdsfmdsp'fmdsmfpidsjmf idsoifhds udjfoidsjfidsj' | Pending | Phone |  | Low | test_tal: bla bla | Network | 2023-03-29T14:35:35Z | 2023-04-02T12:52:12Z | 2023-04-12T20:47:00Z | 2023-04-05T17:47:00Z |
>| 223 | Mirroring IN From Postman 18:56 | 21001941102 | Incident | sa | Open | Portal |  | Low |  |  | 2023-03-27T13:39:13Z | 2023-04-03T15:56:07Z | 2023-04-13T12:00:55Z | 2023-04-05T18:00:55Z |
>| 220 | OUT 15:28 | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T12:17:29Z | 2023-04-02T12:29:11Z | 2023-04-11T13:18:12Z | 2023-04-03T19:18:12Z |
>| 219 | test! | 21001932798 | Incident | abc | Closed | Portal |  | Low |  | Software | 2023-03-26T11:41:47Z | 2023-03-27T09:02:18Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 218 | abc | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T10:22:28Z | 2023-03-26T10:22:29Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 217 | Tal mirroring NOW | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T09:56:17Z | 2023-03-30T12:19:21Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 216 | TOLA 14:34 | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T09:44:52Z | 2023-04-02T11:37:17Z | 2023-04-11T12:40:51Z | 2023-03-29T18:00:00Z |
>| 213 | test! OUT to FS | 21001932798 | Incident | abc | Closed | Portal |  | Low |  |  | 2023-03-26T09:40:11Z | 2023-03-30T13:25:07Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 212 | 14:10 *** NEW | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T09:36:39Z | 2023-04-02T11:19:09Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 209 | mirroring OUT to FS from XSOAR 2023-04-04 13:06 | 21001932798 | Incident | abc | Pending | Portal |  | Low |  |  | 2023-03-26T09:32:31Z | 2023-04-02T11:19:08Z | 2023-04-11T13:25:11Z | 2023-04-03T19:25:11Z |
>| 208 | test-update from FS | 21001932798 | Incident | abc | Pending | Portal |  | Low |  |  | 2023-03-26T09:30:45Z | 2023-03-30T13:22:37Z | 2023-04-11T12:45:27Z | 2023-04-03T18:45:27Z |
>| 207 | 123456 | 21001932798 | Incident | abc | Pending | Portal |  | Low |  |  | 2023-03-26T09:30:30Z | 2023-04-02T09:19:07Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 205 | abc | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T09:24:30Z | 2023-03-26T09:24:53Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |
>| 204 | Mirroring 204 | 21001932798 | Incident | abc | Pending | Portal |  | Low |  | Software | 2023-03-26T09:23:05Z | 2023-03-30T12:35:07Z | 2023-04-05T21:00:00Z | 2023-03-29T18:00:00Z |


### freshservice-ticket-create

***
Create a new Ticket at the service desk. The default Ticket type
is incident. Create ticket required one of the following: requester_id, phone, email. Ticket type helps categorize the ticket according to the different
kinds of issues your support team deals with. As of now, API v2 supports only
type 'incident'.

#### Base Command

`freshservice-ticket-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | HTML content of the ticket. | Required |
| name | Name of the requester. | Optional |
| requester_id | User ID of the requester. For existing contacts, the 'requester_id' can be passed instead of the requester's email. In case both 'email' and 'requester ID' are specified, the requester ID will override the 'email' field. If 'requester_id' is not provided, 'email' must be specified. | Optional |
| email | Email address of the requester. If 'email' is not provided, 'requester_id' must be specified. In case both 'email' and 'requester ID' are specified, the requester ID will override the 'email' field. If no contact exists with this email address in Freshservice, it will be added as a new contact. | Optional |
| phone | Phone number of the requester. The 'phone' can be passed instead of the requester's email. If no contact exists with this phone number in Freshservice, it will be added as a new contact. The name attribute is mandatory if the phone number is set and the email address is not. | Optional |
| status | Status of the ticket. Possible values are: Open, Pending, Resolved, Closed. | Required |
| priority | Priority of the ticket. Possible values are: Low, Medium, High, Urgent. | Required |
| subject | The subject of the ticket. | Required |
| source | The channel through which the ticket was created. The default value is 'Portal'. (Email=1, Portal=2, Phone=3, Chat=4, Feedback widget=5, Yammer=6, AWS Cloudwatch=7, Pagerduty=8, Walkup=9, Slack=10). Possible values are: Email, Portal, Phone, Chat, Feedback widget, Yammer, AWS Cloudwatch, Pagerduty, Walkup, Slack. | Optional |
| tags | Tags that have been associated with the ticket. | Optional |
| department_id | Department ID of the requester. Use freshservice-department-list to get the department ID. | Optional |
| category | Ticket category. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | Ticket subcategory. Note that each category has a different predefined subcategory. | Optional |
| assets | Assets that have to be associated with the ticket (the asset display_id). | Optional |
| urgency | Ticket urgency. Possible values are: Low, Medium, High. | Optional |
| impact | Ticket impact. Possible values are: Low, Medium, High. | Optional |
| problem | The problem that needs to be associated with the ticket (use freshservice-problem-list to get the problem ID). | Optional |
| change_initiating_ticket | Change causing the Ticket that needs to be associated with the Ticket (use freshservice-change-list to get the change ID). | Optional |
| change_initiated_by_ticket | Change needed for the Ticket to be fixed that needs to be associated with the Ticket (use freshservice-change-list to get the change ID). | Optional |
| responder_id | The ID of the agent to whom the ticket has been assigned (use freshservice-agent-list to get the agent ID). | Optional |
| attachments | Ticket attachments. The total size of these attachments cannot exceed 15MB. Upload the file to Cortex XSOAR and provide the file ID for attaching the file to Freshservice tickets. | Optional |
| cc_emails | Email address added in the 'cc' field of the incoming ticket email. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. For example 'key1=value1, key2=value2'. | Optional |
| due_by | The timestamp that denotes when the ticket is due to be resolved. The value must be greater than the ticket creation time. | Optional |
| email_config_id | The ID of the email config which is used for this ticket. (i.e., support@yourcompany.com/sales@yourcompany.com). | Optional |
| fr_due_by | The timestamp that denotes when the first response is due. Has to be greater than ticket creation time. It should not be blank if due_by is given. (for example YYYY-MM-DDThh:mm). | Optional |
| group_id | The ID of the group to which the Ticket has been assigned. The default value is the ID of the group that is associated with the given email config ID. Use freshservice-agent-group-list to get the agent group ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.fr_escalated | Boolean | Whether the ticket first request was escalated. |
| Freshservice.Ticket.spam | Boolean | Ticket spam. |
| Freshservice.Ticket.email_config_id | Number | Ticket email config ID. |
| Freshservice.Ticket.group_id | Number | Ticket group ID. |
| Freshservice.Ticket.priority | Number | Ticket priority. |
| Freshservice.Ticket.requester_id | Date | Ticket requester ID. |
| Freshservice.Ticket.requested_for_id | Date | Ticket requested for ID. |
| Freshservice.Ticket.responder_id | Number | Ticket responder ID. |
| Freshservice.Ticket.source | Number | Ticket source. |
| Freshservice.Ticket.status | Number | Ticket status. |
| Freshservice.Ticket.subject | String | Ticket subject. |
| Freshservice.Ticket.to_emails | String | Email addresses to which the ticket was originally sent. |
| Freshservice.Ticket.department_id | Number | Ticket department ID. |
| Freshservice.Ticket.id | Number | Ticket ID. |
| Freshservice.Ticket.type | String | Ticket type. |
| Freshservice.Ticket.due_by | Date | The timestamp that denotes when the ticket is due to be resolved.  |
| Freshservice.Ticket.fr_due_by | Date | Indicates when the first response is due. |
| Freshservice.Ticket.is_escalated | Boolean | Whether the ticket is escalated. |
| Freshservice.Ticket.description | String | Ticket description. |
| Freshservice.Ticket.category | String | Ticket category. |
| Freshservice.Ticket.sub_category | String | Ticket subcategory. |
| Freshservice.Ticket.item_category | String | Ticket item category. |
| Freshservice.Ticket.created_at | Date | Ticket creation time. |
| Freshservice.Ticket.updated_at | Date | Ticket updated at. |

#### Command example
```!freshservice-ticket-create description=description email=liors@qmasters.co status=Open priority=Low subject=subject```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "attachments": [],
            "category": null,
            "cc_emails": [],
            "created_at": "2023-04-13T14:15:15Z",
            "custom_fields": {
                "test_tal": null
            },
            "department_id": null,
            "description": "<div>description</div>",
            "description_text": "description",
            "due_by": "2023-04-25T14:15:15Z",
            "email_config_id": null,
            "fr_due_by": "2023-04-17T20:15:15Z",
            "fr_escalated": false,
            "fwd_emails": [],
            "group_id": null,
            "id": 247,
            "is_escalated": false,
            "item_category": null,
            "priority": "Low",
            "reply_cc_emails": [],
            "requested_for_id": 21001792073,
            "requester_id": 21001792073,
            "responder_id": null,
            "source": "Portal",
            "spam": false,
            "status": "Open",
            "sub_category": null,
            "subject": "subject",
            "tags": [],
            "to_emails": null,
            "type": "Incident",
            "updated_at": "2023-04-13T14:15:15Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Ticket
>Ticket created successfully
>|Id|Description Text|Requester Id|Type|Subject|Status|Source|Impact|Priority|Custom Fields|Category|Created At|Updated At|Due By|Fr Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 247 | description | 21001792073 | Incident | subject | Open | Portal |  | Low |  |  | 2023-04-13T14:15:15Z | 2023-04-13T14:15:15Z | 2023-04-25T14:15:15Z | 2023-04-17T20:15:15Z |


### freshservice-ticket-update

***
Update an existing Ticket in Freshservice.

#### Base Command

`freshservice-ticket-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The Ticket ID to update (use freshservice-ticket-list to get ticket ID). | Required |
| description | HTML content of the ticket. | Optional |
| name | Name of the requester. | Optional |
| requester_id | User ID of the requester (use freshservice-agent-list to get the agent ID). For existing contacts, the requester_id can be passed instead of the requester's email. | Optional |
| email | Email address of the requester. If no contact exists with this email address in Freshservice, it will be added as a new contact. | Optional |
| phone | Phone number of the requester. If no contact exists with this phone number in Freshservice, it will be added as a new contact. The name attribute is mandatory if the phone number is set and the email address is not. | Optional |
| status | Status of the ticket. Possible values are: Open, Pending, Resolved, Closed. | Optional |
| priority | Priority of the ticket. Possible values are: Low, Medium, High, Urgent. | Optional |
| subject | The subject of the ticket. | Optional |
| source | The channel through which the Ticket was created. The default value is 2. (Email=1, Portal=2, Phone=3, Chat=4, Feedback widget=5, Yammer=6, AWS Cloudwatch=7, Pagerduty=8, Walkup=9, Slack=10). Possible values are: Email, Portal, Phone, Chat, Feedback widget, Yammer, AWS Cloudwatch, Pagerduty, Walkup, Slack. | Optional |
| tags | Tags that have been associated with the ticket (replace the exist value). | Optional |
| department_id | Department ID of the requester. Use freshservice-department-list to get the department ID. | Optional |
| category | Ticket category. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | Ticket subcategory.  Note that each category has a different predefined subcategory. | Optional |
| assets | Assets that have to be associated with the ticket (the asset display_id. Replace the exist value). | Optional |
| urgency | Ticket urgency. Possible values are: Low, Medium, High. | Optional |
| impact | Ticket impact. Possible values are: Low, Medium, High. | Optional |
| problem | The problem that needs to be associated with the ticket (use freshservice-problem-list to get the problem ID). | Optional |
| change_initiating_ticket | Change causing the Ticket that needs to be associated with the Ticket (use freshservice-change-list to get the change ID). | Optional |
| change_initiated_by_ticket | Change needed for the Ticket to be fixed that needs to be associated with the Ticket (use freshservice-change-list to get the change ID). | Optional |
| responder_id | The ID of the agent to whom the ticket has been assigned (use freshservice-agent-list to get the agent ID). | Optional |
| attachments | Ticket attachments. The total size of these attachments cannot exceed 15MB. Upload the file to Cortex XSOAR and provide the file ID for attaching the file to Freshservice tickets. | Optional |
| cc_emails | Email address added in the 'cc' field of the incoming ticket email. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. Read more here. | Optional |
| due_by | Timestamp that denotes when the Ticket is due to be resolved (for example YYYY-MM-DDThh:mm). | Optional |
| email_config_id | The ID of the email config which is used for this ticket. (i.e., support@yourcompany.com/sales@yourcompany.com). | Optional |
| fr_due_by | Timestamp that denotes when the first response is due (for example YYYY-MM-DDThh:mm). | Optional |
| group_id | The ID of the group to which the Ticket has been assigned. The default value is the ID of the group that is associated with the given email_config_id. Use freshservice-agent-group-list to get the agent group ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.spam | Boolean | Ticket spam. |
| Freshservice.Ticket.email_config_id | Number | Ticket email config ID. |
| Freshservice.Ticket.fr_escalated | Boolean | Whether the ticket first request was escalated. |
| Freshservice.Ticket.group_id | Number | Ticket group ID. |
| Freshservice.Ticket.priority | Number | Ticket priority. |
| Freshservice.Ticket.requester_id | Date | Ticket requester ID. |
| Freshservice.Ticket.requested_for_id | Date | Ticket requested for ID. |
| Freshservice.Ticket.responder_id | Number | Ticket responder ID. |
| Freshservice.Ticket.source | Number | Ticket source. |
| Freshservice.Ticket.status | Number | Ticket status. |
| Freshservice.Ticket.subject | String | Ticket subject. |
| Freshservice.Ticket.description | String | Ticket description. |
| Freshservice.Ticket.category | String | Ticket category. |
| Freshservice.Ticket.sub_category | String | Ticket sub-category. |
| Freshservice.Ticket.item_category | String | Ticket item category. |
| Freshservice.Ticket.id | Number | Ticket ID. |
| Freshservice.Ticket.type | String | Ticket type. |
| Freshservice.Ticket.to_emails | String | Email addresses to which the ticket was originally sent. |
| Freshservice.Ticket.department_id | Number | Ticket department ID. |
| Freshservice.Ticket.is_escalated | Boolean | Whether the ticket is escalated. |
| Freshservice.Ticket.due_by | Date | The timestamp that denotes when the ticket is due to be resolved.  |
| Freshservice.Ticket.fr_due_by | Date | Indicates when the first response is due. |
| Freshservice.Ticket.created_at | Date | Ticket creation time. |
| Freshservice.Ticket.updated_at | Date | Ticket updated at. |

#### Command example
```!freshservice-ticket-update ticket_id=245 description=description```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "attachments": [],
            "category": null,
            "cc_emails": [],
            "created_at": "2023-04-13T13:06:39Z",
            "custom_fields": {
                "test_tal": "sd"
            },
            "department_id": null,
            "description": "description",
            "description_text": "description",
            "due_by": "2023-04-25T13:06:39Z",
            "email_config_id": null,
            "fr_due_by": "2023-04-17T19:06:40Z",
            "fr_escalated": false,
            "fwd_emails": [],
            "group_id": null,
            "id": 245,
            "is_escalated": false,
            "item_category": null,
            "priority": "Low",
            "reply_cc_emails": [],
            "requested_for_id": 21001523121,
            "requester_id": 21001523121,
            "responder_id": null,
            "source": "Portal",
            "spam": false,
            "status": "Open",
            "sub_category": null,
            "subject": "Support Needed...",
            "tags": [
                "sss"
            ],
            "to_emails": null,
            "type": "Request",
            "updated_at": "2023-04-13T14:15:21Z",
            "workspace_id": 3
        }
    }
}
```

#### Human Readable Output

>### Ticket
>Ticket updated successfully
>|Id|Description Text|Requester Id|Type|Subject|Status|Source|Impact|Priority|Custom Fields|Category|Created At|Updated At|Due By|Fr Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 245 | description | 21001523121 | Request | Support Needed... | Open | Portal |  | Low | test_tal: sd |  | 2023-04-13T13:06:39Z | 2023-04-13T14:15:21Z | 2023-04-25T13:06:39Z | 2023-04-17T19:06:40Z |


### freshservice-ticket-delete

***
Delete an existing Ticket in Freshservice.

#### Base Command

`freshservice-ticket-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The Ticket ID to delete (use freshservice-ticket-list to get ticket ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-ticket-delete ticket_id=246```
#### Human Readable Output

>Ticket deleted successfully

### freshservice-ticket-task-list

***
Retrieve tasks list (or a specific task) on a Ticket with the given ID from Freshservice.

#### Base Command

`freshservice-ticket-task-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| ticket_id | The Ticket ID (use freshservice-ticket-list to get ticket ID). | Required |
| task_id | The Ticket task ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Task.id | Number | Task ID. |
| Freshservice.Ticket.Task.agent_id | Number | Task agent ID. |
| Freshservice.Ticket.Task.status | Number | Task status. |
| Freshservice.Ticket.Task.due_date | Date | Task due date. |
| Freshservice.Ticket.Task.notify_before | Number | Task notify before. |
| Freshservice.Ticket.Task.title | String | Task title. |
| Freshservice.Ticket.Task.description | String | Task description. |
| Freshservice.Ticket.Task.created_at | Date | Task creation time. |
| Freshservice.Ticket.Task.updated_at | Date | Task updated at. |
| Freshservice.Ticket.Task.closed_at | Date | Task closed at. |
| Freshservice.Ticket.Task.group_id | Number | Task group ID. |
| Freshservice.Ticket.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-ticket-task-list ticket_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-03-26T10:13:03Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-03-29T18:00:00Z",
                    "group_id": null,
                    "id": 107,
                    "notify_before": 7200,
                    "status": "Open",
                    "title": "test",
                    "updated_at": "2023-03-26T10:13:03Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Ticket
>Showing page 1.
> Current page size: 50.
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 107 | description | test | 7200 | Open | false |  | 2023-03-26T10:13:03Z | 2023-03-26T10:13:03Z | 2023-03-29T18:00:00Z |


### freshservice-ticket-task-create

***
Create a new task on a Ticket request in Freshservice.

#### Base Command

`freshservice-ticket-task-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Required |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Required |
| title | Task title. | Required |
| description | Task description. | Required |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| ticket_id | The Ticket ID to add a task for (use freshservice-ticket-list to get ticket ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Task.id | Number | Task ID. |
| Freshservice.Ticket.Task.agent_id | Number | Task agent ID. |
| Freshservice.Ticket.Task.status | Number | Task status. |
| Freshservice.Ticket.Task.due_date | Date | Task due date. |
| Freshservice.Ticket.Task.notify_before | Number | Task notify before. |
| Freshservice.Ticket.Task.title | String | Task title. |
| Freshservice.Ticket.Task.description | String | Task description. |
| Freshservice.Ticket.Task.created_at | Date | Task creation time. |
| Freshservice.Ticket.Task.updated_at | Date | Task updated at. |
| Freshservice.Ticket.Task.closed_at | Date | Task closed at. |
| Freshservice.Ticket.Task.group_id | Number | Task group ID. |
| Freshservice.Ticket.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-ticket-task-create due_date="2020-04-03T10:26:13.067Z" notify_before="2020-05-03T10:26:13.067Z" title=title description=description status=Open ticket_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:15:38Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:15:38Z",
                    "group_id": null,
                    "id": 192,
                    "notify_before": 7200,
                    "status": "Open",
                    "title": "title",
                    "updated_at": "2023-04-13T14:15:38Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Ticket
>Ticket Task created successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 192 | description | title | 7200 | Open | false |  | 2023-04-13T14:15:38Z | 2023-04-13T14:15:38Z | 2023-04-17T20:15:38Z |


### freshservice-ticket-task-update

***
Update an existing task on an existing Ticket in Freshservice.

#### Base Command

`freshservice-ticket-task-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Optional |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Optional |
| title | Task title. | Optional |
| description | Task description. | Optional |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| ticket_id | The Ticket ID to update a task for (use freshservice-ticket-list to get ticket ID). | Required |
| task_id | The Task ID for an update (use freshservice-ticket-task-list to get the task ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Task.id | Number | Task ID. |
| Freshservice.Ticket.Task.agent_id | Number | Task agent ID. |
| Freshservice.Ticket.Task.status | Number | Task status. |
| Freshservice.Ticket.Task.due_date | Date | Task due date. |
| Freshservice.Ticket.Task.notify_before | Number | Task notify before. |
| Freshservice.Ticket.Task.title | String | Task title. |
| Freshservice.Ticket.Task.description | String | Task description. |
| Freshservice.Ticket.Task.created_at | Date | Task creation time. |
| Freshservice.Ticket.Task.updated_at | Date | Task updated at. |
| Freshservice.Ticket.Task.closed_at | Date | Task closed at. |
| Freshservice.Ticket.Task.group_id | Number | Task group ID. |
| Freshservice.Ticket.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-ticket-task-update description=updated ticket_id=220 task_id=183```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T13:48:07Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "updated",
                    "due_date": "2023-04-17T19:48:07Z",
                    "group_id": null,
                    "id": 183,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis-tese",
                    "updated_at": "2023-04-13T14:15:44Z",
                    "workspace_id": 2
                }
            ],
            "id": "220"
        }
    }
}
```

#### Human Readable Output

>### Ticket
>Ticket Task updated successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 183 | updated | Supply lightsabers to all the Jedis-tese | 0 | Open | false |  | 2023-04-13T13:48:07Z | 2023-04-13T14:15:44Z | 2023-04-17T19:48:07Z |


### freshservice-ticket-task-delete

***
Delete the task on a Ticket with the given ID from Freshservice.

#### Base Command

`freshservice-ticket-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID (use freshservice-ticket-list to get ticket ID). | Required |
| task_id | Task ID to delete (use freshservice-ticket-task-list to get the task ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-ticket-task-delete ticket_id=220 task_id=184```
#### Human Readable Output

>Ticket Task deleted successfully

### freshservice-ticket-conversation-list

***
Retrieve all Conversations of a Ticket. Conversations consist of replies as well as public and private notes added to a ticket. Notes are non-invasive ways of sharing updates about a ticket amongst agents and requesters. Private notes are for collaboration between agents and are not visible to the requester. Public notes are visible to and can be created by, both requesters and agents.

#### Base Command

`freshservice-ticket-conversation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| ticket_id | The Ticket ID (use freshservice-ticket-list to get ticket ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Conversation.id | Date | Conversation ID. |
| Freshservice.Ticket.Conversation.user_id | Date | Conversation user ID. |
| Freshservice.Ticket.Conversation.to_emails | String | Conversation to emails. |
| Freshservice.Ticket.Conversation.body | String | Conversation body. |
| Freshservice.Ticket.Conversation.body_text | String | Conversation body text. |
| Freshservice.Ticket.Conversation.ticket_id | Number | Conversation ticket ID. |
| Freshservice.Ticket.Conversation.created_at | Date | Conversation creation time. |
| Freshservice.Ticket.Conversation.updated_at | Date | Conversation updated at. |
| Freshservice.Ticket.Conversation.incoming | Boolean | Conversation incoming. |
| Freshservice.Ticket.Conversation.private | Boolean | Conversation private. |
| Freshservice.Ticket.Conversation.support_email | String | Conversation support email. |
| Freshservice.Ticket.Conversation.source | Number | Conversation source. |
| Freshservice.Ticket.Conversation.from_email | String | Conversation from email. |
| Freshservice.Ticket.Conversation.meta.count | Number | Conversation meta count. |

#### Command example
```!freshservice-ticket-conversation-list ticket_id=6```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Conversation": [
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>Can you provide some screenshots?</div>",
                    "body_text": "Can you provide some screenshots?",
                    "cc_emails": [],
                    "created_at": "2023-04-13T13:55:40Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21010429932,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-04-13T13:55:40Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hi tom, Still Angry</div>",
                    "body_text": "Hi tom, Still Angry",
                    "cc_emails": [],
                    "created_at": "2023-04-13T13:54:15Z",
                    "from_email": null,
                    "id": 21010429825,
                    "incoming": false,
                    "private": false,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-04-13T13:54:15Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>Can you provide some screenshots?</div>",
                    "body_text": "Can you provide some screenshots?",
                    "cc_emails": [],
                    "created_at": "2023-04-13T13:53:38Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21010429779,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-04-13T13:53:38Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T12:17:39Z",
                    "from_email": null,
                    "id": 21009603625,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-26T12:17:39Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T12:17:38Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21009603624,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-26T12:17:38Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "Can you provide some screenshots?",
                    "body_text": "Can you provide some screenshots?",
                    "cc_emails": [],
                    "created_at": "2023-03-26T11:42:56Z",
                    "from_email": null,
                    "id": 21009603527,
                    "incoming": false,
                    "private": false,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-04-13T13:55:18Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T11:41:56Z",
                    "from_email": null,
                    "id": 21009603526,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-26T11:41:56Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T11:41:54Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21009603524,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-26T11:41:54Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T10:24:07Z",
                    "from_email": null,
                    "id": 21009603185,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-26T10:24:07Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T10:22:35Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21009603181,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-26T10:22:35Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T10:09:15Z",
                    "from_email": null,
                    "id": 21009603141,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-26T10:09:15Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T10:09:08Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21009603140,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-26T10:09:08Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T09:57:19Z",
                    "from_email": null,
                    "id": 21009603114,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-26T09:57:19Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>body</div>",
                    "body_text": "body",
                    "cc_emails": [],
                    "created_at": "2023-03-26T09:57:11Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21009603113,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-26T09:57:11Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hey</div>",
                    "body_text": "Hey",
                    "cc_emails": [],
                    "created_at": "2023-03-05T12:36:36Z",
                    "from_email": null,
                    "id": 21008417267,
                    "incoming": true,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-05T12:36:36Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hi tom, Still Angry</div>",
                    "body_text": "Hi tom, Still Angry",
                    "cc_emails": [],
                    "created_at": "2023-03-05T12:35:43Z",
                    "from_email": null,
                    "id": 21008417266,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-05T12:35:43Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hi tom, Still Angry</div>",
                    "body_text": "Hi tom, Still Angry",
                    "cc_emails": [],
                    "created_at": "2023-03-05T12:34:55Z",
                    "from_email": null,
                    "id": 21008417264,
                    "incoming": false,
                    "private": false,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-05T12:34:55Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hey</div>",
                    "body_text": "Hey",
                    "cc_emails": [],
                    "created_at": "2023-03-05T12:18:54Z",
                    "from_email": null,
                    "id": 21008417220,
                    "incoming": false,
                    "private": true,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-05T12:18:54Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "<div>Hi tom, Still Angry</div>",
                    "body_text": "Hi tom, Still Angry",
                    "cc_emails": [],
                    "created_at": "2023-03-05T12:08:14Z",
                    "from_email": null,
                    "id": 21008417196,
                    "incoming": false,
                    "private": false,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-03-05T12:08:14Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T11:03:51Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008417060,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T11:03:51Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:57:06Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008417031,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:57:06Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:56:55Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008417030,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:56:55Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:52:25Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008417020,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:52:25Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [
                        {
                            "attachment_url": "https://qmasters.attachments.freshservice.com/data/helpdesk/attachments/production/21009126499/original/test.py?response-content-type=application/octet-stream&Expires=1681481755&Signature=ZmGXg~qrBrH-LHHWWvfnXgEDmIqgVNVkaAU1BGUwjGvG9mUVTqucIj120QknLsYNoQdBwDKY4~6mW-ZKr5xUpzcZe3Ng02SaaRJOOHwcGm88bMiY9cmEBeWRlZiV-ECCyyGy6fRn6XFYDhrjVjITPYMEFujZDpFC-pMxSn6jig5JVS7zLD9loKM04u9fQheEZDW-kBeFE0L~gjv1zpuAO-Cqc7MPlOA7ik6vgToITcvQeHLxslA1FjidIqTS5jJZ1K7YfNYzpJdmuczuxTJXrPZlOw39XoCIDoFUbsMgRVp0Q20Q-Cidv5V1IpFjdJSn5sY48iUcMQgwKyyJMeGvtQ__&Key-Pair-Id=APKAIPHBXWY2KT5RCMPQ",
                            "canonical_url": "https://qmasters.freshservice.com/helpdesk/attachments/21009126499",
                            "content_type": "application/octet-stream",
                            "created_at": "2023-03-05T10:47:34Z",
                            "id": 21009126499,
                            "name": "test.py",
                            "size": 2510,
                            "updated_at": "2023-03-05T10:47:34Z"
                        }
                    ],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:47:34Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416993,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:47:34Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:45:57Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416988,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:45:57Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [
                        {
                            "attachment_url": "https://qmasters.attachments.freshservice.com/data/helpdesk/attachments/production/21009126496/original/test.py?response-content-type=application/octet-stream&Expires=1681481755&Signature=Sc5Uw2yTCH9x9q7XuqFH2wxIs8~tCft4fwpfBkvCBKMrTAc9vyRy6JXTR7FvzbBV81s5saGiM5uBRbIti29~WM4ca3Ixx~qlLnwpd5rnWR690VQvZ9d66VEin9AJ3XsDElPOyAfuvB1OhXmQ9bCRV4J5nS~OfMfMMM9f~4T4dTaV3mIEICI~gD6MfB06AeFSNnHRyEKR1tZhs3I8RCgzdxkRUt2bLiMliAh9lyuWUzWUEBZdTii5CgnTY-ude-hRz7-~1boZov9AHTGy5tXCIIkrJEAyBYL-MRfj8ahqeHS7VOKPynghc5AMyGlGv7h3kfDrhb09LJ5AbX0aONr8ag__&Key-Pair-Id=APKAIPHBXWY2KT5RCMPQ",
                            "canonical_url": "https://qmasters.freshservice.com/helpdesk/attachments/21009126496",
                            "content_type": "application/octet-stream",
                            "created_at": "2023-03-05T10:45:22Z",
                            "id": 21009126496,
                            "name": "test.py",
                            "size": 2510,
                            "updated_at": "2023-03-05T10:45:22Z"
                        }
                    ],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:45:22Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416983,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:45:22Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [
                        {
                            "attachment_url": "https://qmasters.attachments.freshservice.com/data/helpdesk/attachments/production/21009126491/original/test.py?response-content-type=application/octet-stream&Expires=1681481755&Signature=gMLp~Z8Fr6-dSC6JBDx-eW~x4GR44t2Hgo0w4ue6eZCMtlYHzAQ0F27ycM1Q0UefPemvtVIp80~xgPZinIuCcceBJ5qn7zHuf9uQ-QHoBBe2L8wmUjl5Xb4-B55oRbPVwTgL~ziI8DmeW0pLxP3qfIl447FPMTHCVIByFurizORc5k0wzhrxGfbWIVxGOBrhWZTKXNICxwOwg7fNjb1CkjrmeDMzB2C-7Y7VbAhfCJH-QsuMqFo5W7zw29HD92-FuMFtgY8loHeYF7aWSflYmO9lzHpgWUK1hJ77Trm9an4cX~QtrQEIDtslZXR1jinfj4d9VEMgJLPvek9RHH~8pQ__&Key-Pair-Id=APKAIPHBXWY2KT5RCMPQ",
                            "canonical_url": "https://qmasters.freshservice.com/helpdesk/attachments/21009126491",
                            "content_type": "application/octet-stream",
                            "created_at": "2023-03-05T10:43:39Z",
                            "id": 21009126491,
                            "name": "test.py",
                            "size": 2510,
                            "updated_at": "2023-03-05T10:43:39Z"
                        }
                    ],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:43:39Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416981,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:43:39Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:15:02Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416893,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:15:02Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [
                        {
                            "attachment_url": "https://qmasters.attachments.freshservice.com/data/helpdesk/attachments/production/21009126357/original/Specification_Document_MaintControl_%28Eng%29.docx?response-content-type=application/octet-stream&Expires=1681481755&Signature=eXeXr2YuW4FS9~xffgb7JwqeZMGw0Ce911NYY14zkGxoEnf9g9rPtCXrO9sUM3AMNCrATjNu1gWErU8VKL1feoo9tp8ttyxjQTuHYHVSDu~9-wiuaWwEJ8L3TVfuoiiUkgL~duRYeWGWXHKj9Y3tXAGGHX41Obp6WdgROna9tEoMo~56hGsVZJFEiYYTCtVKVuVy2MH-nxlOuSSN0c2y6iVxwOV2sxTkFB-PHtPgDkXQ9zt7eJpj9J8Mle6YBAvkU7DB3X6SkQKDJyr2xrk24DASwfuNItjgIXRAzac9MjMfvunSJmWf9HdzMA2H47xpDp37yiVrVk9NhEwBRbj-cA__&Key-Pair-Id=APKAIPHBXWY2KT5RCMPQ",
                            "canonical_url": "https://qmasters.freshservice.com/helpdesk/attachments/21009126357",
                            "content_type": "application/octet-stream",
                            "created_at": "2023-03-05T10:14:57Z",
                            "id": 21009126357,
                            "name": "Specification_Document_MaintControl_(Eng).docx",
                            "size": 584470,
                            "updated_at": "2023-03-05T10:14:57Z"
                        }
                    ],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:14:57Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416892,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:14:57Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:13:48Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416890,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:13:48Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:09:29Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416872,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:09:29Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [
                        "liors@qmasters.co"
                    ],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:04:25Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416852,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:04:25Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T10:00:45Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416838,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T10:00:45Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [
                        {
                            "attachment_url": "https://qmasters.attachments.freshservice.com/data/helpdesk/attachments/production/21009126206/original/Specification_Document_MaintControl_%28Eng%29.docx?response-content-type=application/octet-stream&Expires=1681481755&Signature=RIPkBJ2B3HzZ0IM4RiRmgx9XXQRWWFpZYf5tVHuuaPvS3dwjVX6L~8xB1VPZYDGff3uz1l1qPz3yc4kndOSuiGXY0kHSod6xqLIN5SuRvdpwiZ8U681oswz-sJvIj1ky~WuWGhPXU4EyT5I64J-GbOY4w-VzTMPwVGOgHwXTOmKG3lptg~F2t~xx90BikMZkp3rfa9dQMveoH-hQ3KHGhN-NvOl4pABWYaFTFcGjjFXIglsPZNt35Pd-4~1JaL1l0P--Huctl0GTmPEjK7dXpuZHhWyubCLel5nMkWenAM2Wm~69UWLbXAPTudPr5zRPWp32RPXSIjGfujpOu4N5-Q__&Key-Pair-Id=APKAIPHBXWY2KT5RCMPQ",
                            "canonical_url": "https://qmasters.freshservice.com/helpdesk/attachments/21009126206",
                            "content_type": "application/octet-stream",
                            "created_at": "2023-03-05T09:46:43Z",
                            "id": 21009126206,
                            "name": "Specification_Document_MaintControl_(Eng).docx",
                            "size": 584470,
                            "updated_at": "2023-03-05T09:46:43Z"
                        }
                    ],
                    "bcc_emails": [],
                    "body": "<div>try to upload file</div>",
                    "body_text": "try to upload file",
                    "cc_emails": [],
                    "created_at": "2023-03-05T09:46:43Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21008416788,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-03-05T09:46:43Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": null,
                    "body": "Can you provide some screenshots?",
                    "body_text": "Can you provide some screenshots?",
                    "cc_emails": [],
                    "created_at": "2023-02-01T15:41:22Z",
                    "from_email": null,
                    "id": 21006798574,
                    "incoming": false,
                    "private": false,
                    "source": 2,
                    "support_email": null,
                    "ticket_id": 6,
                    "to_emails": [],
                    "updated_at": "2023-02-01T15:41:33Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>Can you provide some screenshots?</div>",
                    "body_text": "Can you provide some screenshots?",
                    "cc_emails": [],
                    "created_at": "2023-01-15T14:15:14Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21006225815,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-01-15T14:15:14Z",
                    "user_id": 21001397559
                },
                {
                    "attachments": [],
                    "bcc_emails": [],
                    "body": "<div>We are working on this issue. Will keep you posted.</div>",
                    "body_text": "We are working on this issue. Will keep you posted.",
                    "cc_emails": [],
                    "created_at": "2023-01-15T13:11:25Z",
                    "from_email": "QDEV@qmasters.freshservice.com",
                    "id": 21006225647,
                    "incoming": false,
                    "private": false,
                    "source": 0,
                    "support_email": "QDEV@qmasters.freshservice.com",
                    "ticket_id": 6,
                    "to_emails": [
                        "jack@freshservice.com"
                    ],
                    "updated_at": "2023-01-15T13:11:25Z",
                    "user_id": 21001397559
                }
            ],
            "id": "6"
        }
    }
}
```

#### Human Readable Output

>### Ticket conversations
>Showing page 1.
> Current page size: 50.
>|Id|User Id|Body Text|To Emails|Incoming|Private|Source|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 21010429932 | 21001397559 | Can you provide some screenshots? | jack@freshservice.com | false | false | 0 | 2023-04-13T13:55:40Z | 2023-04-13T13:55:40Z |
>| 21010429825 | 21001397559 | Hi tom, Still Angry |  | false | false | 2 | 2023-04-13T13:54:15Z | 2023-04-13T13:54:15Z |
>| 21010429779 | 21001397559 | Can you provide some screenshots? | jack@freshservice.com | false | false | 0 | 2023-04-13T13:53:38Z | 2023-04-13T13:53:38Z |
>| 21009603625 | 21001397559 | body |  | false | true | 2 | 2023-03-26T12:17:39Z | 2023-03-26T12:17:39Z |
>| 21009603624 | 21001397559 | body | jack@freshservice.com | false | false | 0 | 2023-03-26T12:17:38Z | 2023-03-26T12:17:38Z |
>| 21009603527 | 21001397559 | Can you provide some screenshots? |  | false | false | 2 | 2023-03-26T11:42:56Z | 2023-04-13T13:55:18Z |
>| 21009603526 | 21001397559 | body |  | false | true | 2 | 2023-03-26T11:41:56Z | 2023-03-26T11:41:56Z |
>| 21009603524 | 21001397559 | body | jack@freshservice.com | false | false | 0 | 2023-03-26T11:41:54Z | 2023-03-26T11:41:54Z |
>| 21009603185 | 21001397559 | body |  | false | true | 2 | 2023-03-26T10:24:07Z | 2023-03-26T10:24:07Z |
>| 21009603181 | 21001397559 | body | jack@freshservice.com | false | false | 0 | 2023-03-26T10:22:35Z | 2023-03-26T10:22:35Z |
>| 21009603141 | 21001397559 | body |  | false | true | 2 | 2023-03-26T10:09:15Z | 2023-03-26T10:09:15Z |
>| 21009603140 | 21001397559 | body | jack@freshservice.com | false | false | 0 | 2023-03-26T10:09:08Z | 2023-03-26T10:09:08Z |
>| 21009603114 | 21001397559 | body |  | false | true | 2 | 2023-03-26T09:57:19Z | 2023-03-26T09:57:19Z |
>| 21009603113 | 21001397559 | body | jack@freshservice.com | false | false | 0 | 2023-03-26T09:57:11Z | 2023-03-26T09:57:11Z |
>| 21008417267 | 21001397559 | Hey |  | true | true | 2 | 2023-03-05T12:36:36Z | 2023-03-05T12:36:36Z |
>| 21008417266 | 21001397559 | Hi tom, Still Angry |  | false | true | 2 | 2023-03-05T12:35:43Z | 2023-03-05T12:35:43Z |
>| 21008417264 | 21001397559 | Hi tom, Still Angry |  | false | false | 2 | 2023-03-05T12:34:55Z | 2023-03-05T12:34:55Z |
>| 21008417220 | 21001397559 | Hey |  | false | true | 2 | 2023-03-05T12:18:54Z | 2023-03-05T12:18:54Z |
>| 21008417196 | 21001397559 | Hi tom, Still Angry |  | false | false | 2 | 2023-03-05T12:08:14Z | 2023-03-05T12:08:14Z |
>| 21008417060 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T11:03:51Z | 2023-03-05T11:03:51Z |
>| 21008417031 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:57:06Z | 2023-03-05T10:57:06Z |
>| 21008417030 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:56:55Z | 2023-03-05T10:56:55Z |
>| 21008417020 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:52:25Z | 2023-03-05T10:52:25Z |
>| 21008416993 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:47:34Z | 2023-03-05T10:47:34Z |
>| 21008416988 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:45:57Z | 2023-03-05T10:45:57Z |
>| 21008416983 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:45:22Z | 2023-03-05T10:45:22Z |
>| 21008416981 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:43:39Z | 2023-03-05T10:43:39Z |
>| 21008416893 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:15:02Z | 2023-03-05T10:15:02Z |
>| 21008416892 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:14:57Z | 2023-03-05T10:14:57Z |
>| 21008416890 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:13:48Z | 2023-03-05T10:13:48Z |
>| 21008416872 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:09:29Z | 2023-03-05T10:09:29Z |
>| 21008416852 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:04:25Z | 2023-03-05T10:04:25Z |
>| 21008416838 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T10:00:45Z | 2023-03-05T10:00:45Z |
>| 21008416788 | 21001397559 | try to upload file | jack@freshservice.com | false | false | 0 | 2023-03-05T09:46:43Z | 2023-03-05T09:46:43Z |
>| 21006798574 | 21001397559 | Can you provide some screenshots? |  | false | false | 2 | 2023-02-01T15:41:22Z | 2023-02-01T15:41:33Z |
>| 21006225815 | 21001397559 | Can you provide some screenshots? | jack@freshservice.com | false | false | 0 | 2023-01-15T14:15:14Z | 2023-01-15T14:15:14Z |
>| 21006225647 | 21001397559 | We are working on this issue. Will keep you posted. | jack@freshservice.com | false | false | 0 | 2023-01-15T13:11:25Z | 2023-01-15T13:11:25Z |


### freshservice-ticket-conversation-reply-create

***
Create a new reply for an existing Ticket Conversation.

#### Base Command

`freshservice-ticket-conversation-reply-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| body | Content of the note. | Required |
| attachments | Attachments. The total size of all the Ticket attachments (not just this note) cannot exceed 15MB. Please upload the file to XSOAR and provide the file ID for attaching the file to Freshservice tickets. | Optional |
| from_email | The email address from which the reply is sent. By default, the global support email will be used. | Optional |
| user_id | The ID of the agent/user who is adding the note (use freshservice-agent-list to get the agent ID). | Optional |
| cc_emails | Email address added in the 'cc' field of the outgoing Ticket email. | Optional |
| bcc_emails | Email address added in the 'bcc' field of the outgoing Ticket email. | Optional |
| ticket_id | Ticket ID (use freshservice-ticket-list to get ticket ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Conversation.Reply.id | Number | Ticket Conversation Reply ID. |
| Freshservice.Ticket.Conversation.Reply.user_id | Number | Ticket Conversation Reply user ID. |
| Freshservice.Ticket.Conversation.Reply.to_emails | String | Ticket Conversation Reply to emails. |
| Freshservice.Ticket.Conversation.Reply.body | String | Ticket Conversation Reply body. |
| Freshservice.Ticket.Conversation.Reply.body_text | String | Ticket Conversation Reply body text. |
| Freshservice.Ticket.Conversation.Reply.ticket_id | Number | Ticket Conversation Reply ticket ID. |
| Freshservice.Ticket.Conversation.Reply.created_at | Date | Ticket conversation reply creation time. |
| Freshservice.Ticket.Conversation.Reply.updated_at | Date | Ticket Conversation Reply updated at. |
| Freshservice.Ticket.Conversation.Reply.from_email | String | Ticket Conversation Reply from email. |

#### Command example
```!freshservice-ticket-conversation-reply-create body=body ticket_id=6```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Conversation": {
                "attachments": [],
                "bcc_emails": [],
                "body": "<div>body</div>",
                "body_text": "body",
                "cc_emails": [],
                "created_at": "2023-04-13T14:16:01Z",
                "from_email": "QDEV@qmasters.freshservice.com",
                "id": 21010431439,
                "ticket_id": 6,
                "to_emails": [
                    "jack@freshservice.com"
                ],
                "updated_at": "2023-04-13T14:16:01Z",
                "user_id": 21001397559
            },
            "id": "6"
        }
    }
}
```

#### Human Readable Output

>### Ticket conversation reply created successfully
>|Id|User Id|Body Text|To Emails|From Email|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 21010431439 | 21001397559 | body | jack@freshservice.com | QDEV@qmasters.freshservice.com | 2023-04-13T14:16:01Z | 2023-04-13T14:16:01Z |


### freshservice-ticket-conversation-note-create

***
Create a new note for an existing Ticket Conversation.

#### Base Command

`freshservice-ticket-conversation-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachments | Attachments. The total size of all the Ticket attachments (not just this note) cannot exceed 15MB. Please upload the file to XSOAR and provide the file ID for attaching the file to Freshservice tickets. | Optional |
| body | Content of the note. | Required |
| incoming | Set to true if a particular note should appear as being created from the outside (i.e., not through the web portal). The default value is false. Possible values are: true, false. | Optional |
| notify_emails | Email addresses of agents/users who need to be notified about this note. | Optional |
| private | Set to false if the note is not private. The default value is true. Possible values are: true, false. | Optional |
| user_id | The ID of the agent/user who is adding the note (use freshservice-agent-list to get the agent ID). | Optional |
| ticket_id | Ticket ID (use freshservice-ticket-list to get ticket ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Conversation.Note.id | Date | Ticket Conversation Note ID. |
| Freshservice.Ticket.Conversation.Note.user_id | Date | Ticket Conversation Note user ID. |
| Freshservice.Ticket.Conversation.Note.body | String | Ticket Conversation Note body. |
| Freshservice.Ticket.Conversation.Note.body_text | String | Ticket Conversation Note body text. |
| Freshservice.Ticket.Conversation.Note.ticket_id | Number | Ticket Conversation Note ticket ID. |
| Freshservice.Ticket.Conversation.NoteCreate.Created_at | Date | Ticket conversation note creation time. |
| Freshservice.Ticket.Conversation.Note.updated_at | Date | Ticket Conversation Note updated at. |
| Freshservice.Ticket.Conversation.Note.incoming | Boolean | Ticket Conversation Note incoming. |
| Freshservice.Ticket.Conversation.Note.private | Boolean | Ticket Conversation Note private. |
| Freshservice.Ticket.Conversation.Note.support_email | String | Ticket Conversation Note support email. |

#### Command example
```!freshservice-ticket-conversation-note-create body=body ticket_id=6```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Note": {
                "attachments": [],
                "body": "<div>body</div>",
                "body_text": "body",
                "created_at": "2023-04-13T14:16:06Z",
                "id": 21010431444,
                "incoming": false,
                "private": true,
                "support_email": null,
                "ticket_id": 6,
                "to_emails": [],
                "updated_at": "2023-04-13T14:16:06Z",
                "user_id": 21001397559
            },
            "id": "6"
        }
    }
}
```

#### Human Readable Output

>### Ticket conversation note created successfully
>|Id|User Id|Body Text|To Emails|Incoming|Private|Source|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 21010431444 | 21001397559 | body |  | false | true |  | 2023-04-13T14:16:06Z | 2023-04-13T14:16:06Z |


### freshservice-ticket-conversation-update

***
Update an existing Conversation on an existing Ticket in Freshservice.

#### Base Command

`freshservice-ticket-conversation-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| body | Conversation content to update. | Required |
| conversation_id | The Conversation ID (use freshservice-ticket-conversation-list to get the conversation ID). | Required |
| name | Conversation name. | Optional |
| attachment | Conversation attachment. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Ticket.Conversation.id | Date | Conversation ID. |
| Freshservice.Ticket.Conversation.user_id | Date | Conversation user ID. |
| Freshservice.Ticket.Conversation.body | String | Conversation body. |
| Freshservice.Ticket.Conversation.body_text | String | Conversation body text. |
| Freshservice.Ticket.Conversation.ticket_id | Number | Conversation ticket ID. |
| Freshservice.Ticket.Conversation.created_at | Date | Conversation creation time. |
| Freshservice.Ticket.Conversation.updated_at | Date | Conversation updated at. |
| Freshservice.Ticket.Conversation.incoming | Boolean | Conversation incoming. |
| Freshservice.Ticket.Conversation.private | Boolean | Conversation private. |
| Freshservice.Ticket.Conversation.support_email | String | Conversation support email. |

#### Command example
```!freshservice-ticket-conversation-update body=body conversation_id=21009603527```
#### Context Example
```json
{
    "Freshservice": {
        "Ticket": {
            "Conversation": {
                "attachments": [],
                "body": "body",
                "body_text": "body",
                "created_at": "2023-03-26T11:42:56Z",
                "id": 21009603527,
                "incoming": false,
                "private": false,
                "support_email": null,
                "ticket_id": 6,
                "to_emails": [],
                "updated_at": "2023-04-13T14:16:12Z",
                "user_id": 21001397559
            },
            "id": 6
        }
    }
}
```

#### Human Readable Output

>### Ticket conversation updated successfully
>|Id|User Id|Body Text|To Emails|Incoming|Private|Source|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 21009603527 | 21001397559 | body |  | false | false |  | 2023-03-26T11:42:56Z | 2023-04-13T14:16:12Z |


### freshservice-ticket-conversation-delete

***
Delete the Conversation on a Ticket with the given ID from Freshservice.

#### Base Command

`freshservice-ticket-conversation-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| conversation_id | The conversation ID to delete (use freshservice-ticket-conversation-list to get the conversation ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-ticket-conversation-delete conversation_id=21010429932```
#### Human Readable Output

>Conversation deleted successfully

### freshservice-problem-list

***
Retrieve a list of all Problems or a specific problem with the given ID from Freshservice.

#### Base Command

`freshservice-problem-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| problem_id | The Problem request ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.id | Number | Problem ID. |
| Freshservice.Problem.agent_id | Number | Problem agent ID. |
| Freshservice.Problem.description | String | Problem description. |
| Freshservice.Problem.requester_id | Date | Problem requester ID. |
| Freshservice.Problem.subject | String | Problem subject. |
| Freshservice.Problem.group_id | Date | Problem group ID. |
| Freshservice.Problem.priority | Number | Problem priority. |
| Freshservice.Problem.impact | Number | Problem impact. |
| Freshservice.Problem.status | Number | Problem status. |
| Freshservice.Problem.due_by | Date | The timestamp that denotes when the problem is due to be resolved.  |
| Freshservice.Problem.known_error | Boolean | Problem known error. |
| Freshservice.Problem.department_id | Number | Problem department ID. |
| Freshservice.Problem.category | String | Problem category. |
| Freshservice.Problem.sub_category | String | Problem sub-category. |
| Freshservice.Problem.item_category | String | Problem item category. |
| Freshservice.Problem.created_at | Date | Problem creation time |
| Freshservice.Problem.updated_at | Date | Problem updated at. |

#### Command example
```!freshservice-problem-list```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": [
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-04-13T14:02:45Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 39,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-04-13T14:02:45Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-04-13T14:00:51Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 38,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-04-13T14:00:51Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-04-13T13:59:58Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 37,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-04-13T13:59:58Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-04-13T13:56:10Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 35,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-04-13T13:56:10Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Hardware",
                "created_at": "2023-04-03T18:33:49Z",
                "department_id": 21000263162,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div>test description</div>\n</div>",
                "description_text": "test description",
                "due_by": "2023-04-05T18:32:00Z",
                "group_id": 21000478053,
                "id": 34,
                "impact": "Low",
                "item_category": "Mac",
                "known_error": true,
                "priority": "Low",
                "requester_id": 21001397559,
                "status": "Open",
                "sub_category": "Computer",
                "subject": "problem test",
                "updated_at": "2023-04-04T08:46:17Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Network",
                "created_at": "2023-04-03T15:20:36Z",
                "department_id": 21000263162,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'><div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div>dfagfdsgsfg</div>\n</div>\n</div>",
                "description_text": "dfagfdsgsfg",
                "due_by": "2023-04-05T15:20:00Z",
                "group_id": 21000478053,
                "id": 33,
                "impact": "Low",
                "item_category": null,
                "known_error": true,
                "priority": "Low",
                "requester_id": 21001397559,
                "status": "Open",
                "sub_category": "Access",
                "subject": "bhsgtrdfsg",
                "updated_at": "2023-04-03T15:22:44Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Network",
                "created_at": "2023-04-03T15:20:35Z",
                "department_id": 21000263162,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'><div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div>dfagfdsgsfg 18:28</div>\n</div>\n</div>",
                "description_text": "dfagfdsgsfg 18:28",
                "due_by": "2023-04-05T15:20:00Z",
                "group_id": 21000478053,
                "id": 32,
                "impact": "Low",
                "item_category": null,
                "known_error": true,
                "priority": "Medium",
                "requester_id": 21001397559,
                "status": "Open",
                "sub_category": "Access",
                "subject": "bhsgtrdfsg",
                "updated_at": "2023-04-03T15:26:08Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Software",
                "created_at": "2023-04-03T08:21:21Z",
                "department_id": 21000263162,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div>bfdabhgfdbgd</div>\n</div>",
                "description_text": "bfdabhgfdbgd",
                "due_by": "2023-04-05T08:20:00Z",
                "group_id": 21000478053,
                "id": 31,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001397559,
                "status": "Open",
                "sub_category": "Windows",
                "subject": "problem test beni",
                "updated_at": "2023-04-03T08:21:21Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-26T12:20:07Z",
                "department_id": null,
                "description": "<div>description</div>",
                "description_text": "description",
                "due_by": "2023-05-04T22:00:00Z",
                "group_id": null,
                "id": 30,
                "impact": "Medium",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001932798,
                "status": "Open",
                "sub_category": null,
                "subject": "subject",
                "updated_at": "2023-03-26T12:20:07Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-26T11:43:50Z",
                "department_id": null,
                "description": "<div>description</div>",
                "description_text": "description",
                "due_by": "2023-04-04T22:00:00Z",
                "group_id": null,
                "id": 29,
                "impact": "Medium",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001932798,
                "status": "Open",
                "sub_category": null,
                "subject": "subject",
                "updated_at": "2023-03-26T11:43:50Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Customer Payment",
                "created_at": "2023-03-22T11:23:59Z",
                "department_id": 21000263160,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": 21000478052,
                "id": 26,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": "Refund",
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:23:59Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Customer Payment",
                "created_at": "2023-03-22T11:23:21Z",
                "department_id": 21000263160,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": 21000478052,
                "id": 25,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:23:21Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Customer Payment",
                "created_at": "2023-03-22T11:22:48Z",
                "department_id": 21000263160,
                "description": "19:12",
                "description_text": "19:12",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": null,
                "id": 24,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:22:48Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": "Customer Payment",
                "created_at": "2023-03-22T11:22:14Z",
                "department_id": null,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": null,
                "id": 23,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:22:14Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": null,
                "created_at": "2023-03-22T11:21:46Z",
                "department_id": null,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": null,
                "id": 22,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:21:46Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": null,
                "created_at": "2023-03-22T11:20:55Z",
                "department_id": null,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": null,
                "id": 21,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:20:55Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-22T11:20:36Z",
                "department_id": null,
                "description": "<div>testbyben</div>",
                "description_text": "testbyben",
                "due_by": "2023-03-28T00:00:00Z",
                "group_id": null,
                "id": 20,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001924647,
                "status": "Open",
                "sub_category": null,
                "subject": "testbyben",
                "updated_at": "2023-03-22T11:20:36Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-21T08:21:31Z",
                "department_id": null,
                "description": "<div>dsf</div>",
                "description_text": "dsf",
                "due_by": "2023-05-01T00:00:00Z",
                "group_id": null,
                "id": 18,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001792073,
                "status": "Open",
                "sub_category": null,
                "subject": "dasdsa",
                "updated_at": "2023-03-21T08:21:31Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": null,
                "created_at": "2023-03-19T13:09:52Z",
                "department_id": null,
                "description": "<div>fds</div>",
                "description_text": "fds",
                "due_by": "2023-05-05T00:00:00Z",
                "group_id": null,
                "id": 17,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001792073,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "dsa",
                "updated_at": "2023-03-19T13:09:52Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-19T13:09:26Z",
                "department_id": null,
                "description": "<div>fds</div>",
                "description_text": "fds",
                "due_by": "2023-05-05T00:00:00Z",
                "group_id": null,
                "id": 16,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001792073,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "dsa",
                "updated_at": "2023-03-19T13:09:26Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": null,
                "created_at": "2023-03-19T12:36:47Z",
                "department_id": null,
                "description": "<div>test description</div>",
                "description_text": "test description",
                "due_by": "2023-05-11T00:00:00Z",
                "group_id": null,
                "id": 15,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001894392,
                "status": "Open",
                "sub_category": null,
                "subject": "New test by ben",
                "updated_at": "2023-03-19T12:36:47Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": "Customer Payment",
                "created_at": "2023-03-15T19:46:46Z",
                "department_id": null,
                "description": "<div>testededed</div>",
                "description_text": "testededed",
                "due_by": "2023-10-01T10:00:00Z",
                "group_id": null,
                "id": 14,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001895008,
                "status": "Open",
                "sub_category": null,
                "subject": "test",
                "updated_at": "2023-03-15T19:46:46Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-03-12T14:13:43Z",
                "department_id": null,
                "description": "<div>sd</div>",
                "description_text": "sd",
                "due_by": "2024-03-31T10:35:47Z",
                "group_id": null,
                "id": 12,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001792073,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "ds",
                "updated_at": "2023-03-12T14:13:43Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": "Employee Onboarding/Offboarding",
                "created_at": "2023-03-06T13:40:38Z",
                "department_id": null,
                "description": "<div>d</div>",
                "description_text": "d",
                "due_by": "2024-02-10T12:46:00Z",
                "group_id": null,
                "id": 9,
                "impact": "High",
                "item_category": null,
                "known_error": false,
                "priority": "High",
                "requester_id": 21001792073,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "s",
                "updated_at": "2023-03-06T13:49:54Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-02-08T12:46:41Z",
                "department_id": null,
                "description": "test",
                "description_text": "test",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 8,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Urgent",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-03-26T12:22:03Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [],
                "category": null,
                "created_at": "2023-02-07T11:18:48Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 7,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-02-07T11:18:48Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "category": null,
                "created_at": "2023-02-02T11:42:01Z",
                "department_id": null,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div>problem</div>\n</div>",
                "description_text": "problem",
                "due_by": "2023-02-04T11:41:00Z",
                "group_id": null,
                "id": 6,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Low",
                "requester_id": 21001397559,
                "status": "Open",
                "sub_category": null,
                "subject": "problem",
                "updated_at": "2023-02-02T11:42:01Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-02-02T11:32:21Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 5,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-02-02T11:32:21Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-02-02T11:32:07Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 4,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-02-02T11:32:07Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": null,
                "created_at": "2023-02-01T15:49:11Z",
                "department_id": null,
                "description": "<div>Hi guys, <br><br>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel",
                "due_by": "2023-07-20T16:18:46Z",
                "group_id": null,
                "id": 3,
                "impact": "Low",
                "item_category": null,
                "known_error": false,
                "priority": "Medium",
                "requester_id": 21001523090,
                "status": "Change Requested",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-02-01T15:49:11Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "category": "Hardware",
                "created_at": "2022-12-25T08:38:06Z",
                "department_id": 21000263162,
                "description": "<div>Hi guys, <br/><br/>We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.<br/><br/>Regards<br/> Rachel<br/> </div> ",
                "description_text": null,
                "due_by": "2023-01-08T08:38:00Z",
                "group_id": 21000478053,
                "id": 1,
                "impact": "High",
                "item_category": null,
                "known_error": true,
                "priority": "High",
                "requester_id": 21001397561,
                "status": "Open",
                "sub_category": null,
                "subject": "Unable to reach email server",
                "updated_at": "2023-03-26T11:49:59Z",
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Problem
>Showing page 1.
> Current page size: 50.
>|Id|Description Text|Requester Id|Subject|Impact|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 39 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-04-13T14:02:45Z | 2023-04-13T14:02:45Z | 2023-07-20T16:18:46Z |
>| 38 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-04-13T14:00:51Z | 2023-04-13T14:00:51Z | 2023-07-20T16:18:46Z |
>| 37 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-04-13T13:59:58Z | 2023-04-13T13:59:58Z | 2023-07-20T16:18:46Z |
>| 35 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-04-13T13:56:10Z | 2023-04-13T13:56:10Z | 2023-07-20T16:18:46Z |
>| 34 | test description | 21001397559 | problem test | Low | Open | Low | 21000478053 | true | Hardware | 2023-04-03T18:33:49Z | 2023-04-04T08:46:17Z | 2023-04-05T18:32:00Z |
>| 33 | dfagfdsgsfg | 21001397559 | bhsgtrdfsg | Low | Open | Low | 21000478053 | true | Network | 2023-04-03T15:20:36Z | 2023-04-03T15:22:44Z | 2023-04-05T15:20:00Z |
>| 32 | dfagfdsgsfg 18:28 | 21001397559 | bhsgtrdfsg | Low | Open | Medium | 21000478053 | true | Network | 2023-04-03T15:20:35Z | 2023-04-03T15:26:08Z | 2023-04-05T15:20:00Z |
>| 31 | bfdabhgfdbgd | 21001397559 | problem test beni | Low | Open | Low | 21000478053 | false | Software | 2023-04-03T08:21:21Z | 2023-04-03T08:21:21Z | 2023-04-05T08:20:00Z |
>| 30 | description | 21001932798 | subject | Medium | Open | Medium |  | false |  | 2023-03-26T12:20:07Z | 2023-03-26T12:20:07Z | 2023-05-04T22:00:00Z |
>| 29 | description | 21001932798 | subject | Medium | Open | Medium |  | false |  | 2023-03-26T11:43:50Z | 2023-03-26T11:43:50Z | 2023-04-04T22:00:00Z |
>| 26 | testbyben | 21001924647 | testbyben | Low | Open | Low | 21000478052 | false | Customer Payment | 2023-03-22T11:23:59Z | 2023-03-22T11:23:59Z | 2023-03-28T00:00:00Z |
>| 25 | testbyben | 21001924647 | testbyben | Low | Open | Low | 21000478052 | false | Customer Payment | 2023-03-22T11:23:21Z | 2023-03-22T11:23:21Z | 2023-03-28T00:00:00Z |
>| 24 | 19:12 | 21001924647 | testbyben | Low | Open | Low |  | false | Customer Payment | 2023-03-22T11:22:48Z | 2023-03-22T11:22:48Z | 2023-03-28T00:00:00Z |
>| 23 | testbyben | 21001924647 | testbyben | Low | Open | Low |  | false | Customer Payment | 2023-03-22T11:22:14Z | 2023-03-22T11:22:14Z | 2023-03-28T00:00:00Z |
>| 22 | testbyben | 21001924647 | testbyben | Low | Open | Low |  | false |  | 2023-03-22T11:21:46Z | 2023-03-22T11:21:46Z | 2023-03-28T00:00:00Z |
>| 21 | testbyben | 21001924647 | testbyben | Low | Open | Low |  | false |  | 2023-03-22T11:20:55Z | 2023-03-22T11:20:55Z | 2023-03-28T00:00:00Z |
>| 20 | testbyben | 21001924647 | testbyben | Low | Open | Low |  | false |  | 2023-03-22T11:20:36Z | 2023-03-22T11:20:36Z | 2023-03-28T00:00:00Z |
>| 18 | dsf | 21001792073 | dasdsa | Low | Open | High |  | false |  | 2023-03-21T08:21:31Z | 2023-03-21T08:21:31Z | 2023-05-01T00:00:00Z |
>| 17 | fds | 21001792073 | dsa | High | Change Requested | High |  | false |  | 2023-03-19T13:09:52Z | 2023-03-19T13:09:52Z | 2023-05-05T00:00:00Z |
>| 16 | fds | 21001792073 | dsa | High | Change Requested | High |  | false |  | 2023-03-19T13:09:26Z | 2023-03-19T13:09:26Z | 2023-05-05T00:00:00Z |
>| 15 | test description | 21001894392 | New test by ben | High | Open | High |  | false |  | 2023-03-19T12:36:47Z | 2023-03-19T12:36:47Z | 2023-05-11T00:00:00Z |
>| 14 | testededed | 21001895008 | test | High | Open | Low |  | false | Customer Payment | 2023-03-15T19:46:46Z | 2023-03-15T19:46:46Z | 2023-10-01T10:00:00Z |
>| 12 | sd | 21001792073 | ds | High | Change Requested | High |  | false |  | 2023-03-12T14:13:43Z | 2023-03-12T14:13:43Z | 2024-03-31T10:35:47Z |
>| 9 | d | 21001792073 | s | High | Change Requested | High |  | false | Employee Onboarding/Offboarding | 2023-03-06T13:40:38Z | 2023-03-06T13:49:54Z | 2024-02-10T12:46:00Z |
>| 8 | test | 21001523090 | Unable to reach email server | Low | Change Requested | Urgent |  | false |  | 2023-02-08T12:46:41Z | 2023-03-26T12:22:03Z | 2023-07-20T16:18:46Z |
>| 7 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-02-07T11:18:48Z | 2023-02-07T11:18:48Z | 2023-07-20T16:18:46Z |
>| 6 | problem | 21001397559 | problem | Low | Open | Low |  | false |  | 2023-02-02T11:42:01Z | 2023-02-02T11:42:01Z | 2023-02-04T11:41:00Z |
>| 5 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-02-02T11:32:21Z | 2023-02-02T11:32:21Z | 2023-07-20T16:18:46Z |
>| 4 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-02-02T11:32:07Z | 2023-02-02T11:32:07Z | 2023-07-20T16:18:46Z |
>| 3 | Hi guys,   We have been facing issues when we try to reach Email Server 3. Looks like there is something wrong here.  Regards  Rachel | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-02-01T15:49:11Z | 2023-02-01T15:49:11Z | 2023-07-20T16:18:46Z |
>| 1 |  | 21001397561 | Unable to reach email server | High | Open | High | 21000478053 | true | Hardware | 2022-12-25T08:38:06Z | 2023-03-26T11:49:59Z | 2023-01-08T08:38:00Z |


### freshservice-problem-create

***
Create a new problem request in Freshservice. Creating a problem required one of the following- requester_id or email.

#### Base Command

`freshservice-problem-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Problem request description. | Required |
| subject | Problem request subject. | Required |
| email | Requester email. If not specified - must provide 'requester_id'. | Optional |
| requester_id | Requester ID (use freshservice-agent-list to get the agent ID). If not specified - must provide 'email'. | Optional |
| priority | Priority of the Problem. Possible values are: Low, Medium, High, Urgent. | Required |
| status | Status identifier of the Problem. Possible values are: Open, Change Requested, Closed. | Required |
| due_by | Timestamp at which Problem due ends (for example YYYY-MM-DDThh:mm). | Required |
| impact | Impact of the Problem. Possible values are: Low, Medium, High. | Required |
| department_id | Unique ID of the department initiating the Problem. Use freshservice-department-list to get the department ID. | Optional |
| category | Category of the Problem. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | The sub-category of the Problem. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. | Optional |
| analysis_fields | Key value pairs containing the names and values of the Problem Cause, Problem Symptom, and Problem Impact. | Optional |
| assets | List of assets associated with the problem (the asset display_id). | Optional |
| agent_id | Unique identifier of the agent to whom the Problem is assigned. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Unique identifier of the agent group to which the Problem is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.id | Number | Problem ID. |
| Freshservice.Problem.agent_id | Unknown | Problem agent ID. |
| Freshservice.Problem.description | String | Problem description. |
| Freshservice.Problem.requester_id | Date | Problem requester ID. |
| Freshservice.Problem.subject | String | Problem subject. |
| Freshservice.Problem.group_id | Date | Problem group ID. |
| Freshservice.Problem.priority | Number | Problem priority. |
| Freshservice.Problem.impact | Number | Problem impact. |
| Freshservice.Problem.status | Number | Problem status. |
| Freshservice.Problem.due_by | Date | The timestamp that denotes when the problem is due to be resolved.  |
| Freshservice.Problem.known_error | Boolean | Problem known error. |
| Freshservice.Problem.department_id | Date | Problem department ID. |
| Freshservice.Problem.category | String | Problem category. |
| Freshservice.Problem.sub_category | String | Problem sub-category. |
| Freshservice.Problem.item_category | String | Problem item category. |
| Freshservice.Problem.created_at | Date | Problem creation time |
| Freshservice.Problem.updated_at | Date | Problem updated at. |

#### Command example
```!freshservice-problem-create description=description subject=subject email=sample@freshservice.com priority=Low status=Open due_by="2023-07-20T16:18:46Z" impact=Low```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": {
            "agent_id": null,
            "analysis_fields": {},
            "assets": [],
            "associated_change": null,
            "category": null,
            "created_at": "2023-04-13T14:16:29Z",
            "custom_fields": {},
            "department_id": null,
            "description": "<div>description</div>",
            "description_text": "description",
            "due_by": "2023-07-20T16:18:46Z",
            "group_id": null,
            "id": 40,
            "impact": "Low",
            "item_category": null,
            "known_error": false,
            "priority": "Low",
            "requester_id": 21001523090,
            "status": "Open",
            "sub_category": null,
            "subject": "subject",
            "updated_at": "2023-04-13T14:16:29Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Problem
>Problem created successfully
>|Id|Description Text|Requester Id|Subject|Impact|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 40 | description | 21001523090 | subject | Low | Open | Low |  | false |  | 2023-04-13T14:16:29Z | 2023-04-13T14:16:29Z | 2023-07-20T16:18:46Z |


### freshservice-problem-update

***
Update an existing Problem in Freshservice.

#### Base Command

`freshservice-problem-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| problem_id | The problem ID for an update (use freshservice-problem-list to get the problem request ID). | Required |
| description | Problem request description. | Optional |
| subject | Problem request subject. | Optional |
| email | Requester email. | Optional |
| priority | Priority of the Problem. Possible values are: Low, Medium, High, Urgent. | Optional |
| status | Status identifier of the Problem. Possible values are: Open, Change Requested, Closed. | Optional |
| due_by | Timestamp at which Problem due ends (for example YYYY-MM-DDThh:mm). | Optional |
| impact | Impact of the Problem. Possible values are: Low, Medium, High. | Optional |
| department_id | Unique ID of the department initiating the Problem. Use freshservice-department-list to get the department ID. | Optional |
| category | Category of the Problem. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | The sub-category of the Problem. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. | Optional |
| analysis_fields | Key value pairs containing the names and values of the Problem Cause, Problem Symptom, and Problem Impact. | Optional |
| assets | List of assets associated with the problem (replace the exist value). | Optional |
| group_id | Unique identifier of the agent group to which the Problem is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| agent_id | Unique identifier of the agent to whom the Problem is assigned. Use freshservice-agent-list to get the agent ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.id | Number | Problem ID. |
| Freshservice.Problem.agent_id | Unknown | Problem agent ID. |
| Freshservice.Problem.description | String | Problem description. |
| Freshservice.Problem.requester_id | Date | Problem requester ID. |
| Freshservice.Problem.subject | String | Problem subject. |
| Freshservice.Problem.group_id | Date | Problem group ID. |
| Freshservice.Problem.priority | Number | Problem priority. |
| Freshservice.Problem.impact | Number | Problem impact. |
| Freshservice.Problem.status | Number | Problem status. |
| Freshservice.Problem.due_by | Date | The timestamp that denotes when the problem is due to be resolved.  |
| Freshservice.Problem.known_error | Boolean | Problem known error. |
| Freshservice.Problem.department_id | Date | Problem department ID. |
| Freshservice.Problem.category | String | Problem category. |
| Freshservice.Problem.sub_category | Unknown | Problem sub-category. |
| Freshservice.Problem.item_category | Unknown | Problem item category. |
| Freshservice.Problem.created_at | Date | Problem creation time |
| Freshservice.Problem.updated_at | Date | Problem updated at. |

#### Command example
```!freshservice-problem-update problem_id=38 description=description```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": {
            "agent_id": null,
            "analysis_fields": {},
            "assets": [],
            "associated_change": null,
            "category": null,
            "created_at": "2023-04-13T14:00:51Z",
            "custom_fields": {},
            "department_id": null,
            "description": "description",
            "description_text": "description",
            "due_by": "2023-07-20T16:18:46Z",
            "group_id": null,
            "id": 38,
            "impact": "Low",
            "item_category": null,
            "known_error": false,
            "priority": "Medium",
            "requester_id": 21001523090,
            "status": "Change Requested",
            "sub_category": null,
            "subject": "Unable to reach email server",
            "updated_at": "2023-04-13T14:00:51Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Problem
>Problem updated successfully
>|Id|Description Text|Requester Id|Subject|Impact|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Due By|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 38 | description | 21001523090 | Unable to reach email server | Low | Change Requested | Medium |  | false |  | 2023-04-13T14:00:51Z | 2023-04-13T14:00:51Z | 2023-07-20T16:18:46Z |


### freshservice-problem-delete

***
Delete the Problem with the given ID from Freshservice.

#### Base Command

`freshservice-problem-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| problem_id | The problem ID to delete (use freshservice-problem-list to get the problem request ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-problem-delete problem_id=37```
#### Human Readable Output

>Problem deleted successfully

### freshservice-problem-task-list

***
Retrieve the tasks on a Problem with the given ID from Freshservice.

#### Base Command

`freshservice-problem-task-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| problem_id | Problem ID. | Required |
| task_id | The change request task ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.Task.id | Number | Task ID. |
| Freshservice.Problem.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Problem.Task.status | Number | Task status. |
| Freshservice.Problem.Task.due_date | Date | Task due date. |
| Freshservice.Problem.Task.notify_before | Number | Task notify before. |
| Freshservice.Problem.Task.title | String | Task title. |
| Freshservice.Problem.Task.description | String | Task description. |
| Freshservice.Problem.Task.created_at | Date | Task creation time. |
| Freshservice.Problem.Task.updated_at | Date | Task updated at. |
| Freshservice.Problem.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Problem.Task.group_id | Unknown | Task group ID. |
| Freshservice.Problem.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-problem-task-list problem_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T12:22:36Z",
                    "created_at": "2023-01-15T16:03:37Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "test",
                    "due_date": "2023-01-19T19:00:00Z",
                    "group_id": null,
                    "id": 6,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-03-26T12:22:36Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-22T15:00:59Z",
                    "created_at": "2023-01-19T10:27:15Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-01-23T19:00:00Z",
                    "group_id": null,
                    "id": 12,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-03-22T15:00:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-22T15:00:59Z",
                    "created_at": "2023-02-07T11:28:33Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2020-04-27T13:23:20Z",
                    "group_id": null,
                    "id": 14,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-03-22T15:00:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-22T15:01:00Z",
                    "created_at": "2023-03-08T10:52:46Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "d",
                    "due_date": "2023-03-10T19:00:00Z",
                    "group_id": null,
                    "id": 24,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "d",
                    "updated_at": "2023-03-22T15:01:00Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:01:04Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-04-17T20:01:04Z",
                    "group_id": null,
                    "id": 185,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:01:04Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:03:02Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-04-17T20:03:02Z",
                    "group_id": null,
                    "id": 186,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:03:02Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Problem
>Showing page 1.
> Current page size: 50.
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 6 | test | Supply lightsabers to all the Jedis | 0 | Completed | false | 2023-03-26T12:22:36Z | 2023-01-15T16:03:37Z | 2023-03-26T12:22:36Z | 2023-01-19T19:00:00Z |
>| 12 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Completed | false | 2023-03-22T15:00:59Z | 2023-01-19T10:27:15Z | 2023-03-22T15:00:59Z | 2023-01-23T19:00:00Z |
>| 14 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Completed | false | 2023-03-22T15:00:59Z | 2023-02-07T11:28:33Z | 2023-03-22T15:00:59Z | 2020-04-27T13:23:20Z |
>| 24 | d | d | 0 | Completed | false | 2023-03-22T15:01:00Z | 2023-03-08T10:52:46Z | 2023-03-22T15:01:00Z | 2023-03-10T19:00:00Z |
>| 185 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:01:04Z | 2023-04-13T14:01:04Z | 2023-04-17T20:01:04Z |
>| 186 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:03:02Z | 2023-04-13T14:03:02Z | 2023-04-17T20:03:02Z |


### freshservice-problem-task-create

***
Create a new task on a problem in Freshservice.

#### Base Command

`freshservice-problem-task-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Required |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Required |
| title | Task title. | Required |
| description | Task description. | Required |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| problem_id | The problem ID to add a task for (use freshservice-problem-list to get the problem request ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.Task.id | Number | Task ID. |
| Freshservice.Problem.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Problem.Task.status | Number | Task status. |
| Freshservice.Problem.Task.due_date | Date | Task due date. |
| Freshservice.Problem.Task.notify_before | Number | Task notify before. |
| Freshservice.Problem.Task.title | String | Task title. |
| Freshservice.Problem.Task.description | String | Task description. |
| Freshservice.Problem.Task.created_at | Date | Task creation time. |
| Freshservice.Problem.Task.updated_at | Date | Task updated at. |
| Freshservice.Problem.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Problem.Task.group_id | Unknown | Task group ID. |
| Freshservice.Problem.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-problem-task-create due_date="2020-04-03T10:26:13.067Z" notify_before="2020-05-03T10:26:13.067Z" title=title description=description status=Open problem_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:16:52Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:16:52Z",
                    "group_id": null,
                    "id": 193,
                    "notify_before": 7200,
                    "status": "Open",
                    "title": "title",
                    "updated_at": "2023-04-13T14:16:52Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Problem
>Problem Task created successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 193 | description | title | 7200 | Open | false |  | 2023-04-13T14:16:52Z | 2023-04-13T14:16:52Z | 2023-04-17T20:16:52Z |


### freshservice-problem-task-update

***
Update an existing task on an existing Problem in Freshservice.

#### Base Command

`freshservice-problem-task-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Optional |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Optional |
| title | Task title. | Optional |
| description | Task description. | Optional |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| problem_id | The problem ID to update a task for (use freshservice-problem-list to get the problem request ID). | Required |
| task_id | The Task ID for an update (use freshservice-problem-task-list to get the task ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Problem.Task.id | Number | Task ID. |
| Freshservice.Problem.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Problem.Task.status | Number | Task status. |
| Freshservice.Problem.Task.due_date | Date | Task due date. |
| Freshservice.Problem.Task.notify_before | Number | Task notify before. |
| Freshservice.Problem.Task.title | String | Task title. |
| Freshservice.Problem.Task.description | String | Task description. |
| Freshservice.Problem.Task.created_at | Date | Task creation time. |
| Freshservice.Problem.Task.updated_at | Date | Task updated at. |
| Freshservice.Problem.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Problem.Task.group_id | Unknown | Task group ID. |
| Freshservice.Problem.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-problem-task-update description=description problem_id=2 task_id=185```
#### Context Example
```json
{
    "Freshservice": {
        "Problem": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:01:04Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:01:04Z",
                    "group_id": null,
                    "id": 185,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:16:58Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Problem
>Problem Task updated successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 185 | description | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:01:04Z | 2023-04-13T14:16:58Z | 2023-04-17T20:01:04Z |


### freshservice-problem-task-delete

***
Delete the task on a Problem with the given ID from Freshservice.

#### Base Command

`freshservice-problem-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| problem_id | The problem ID (use freshservice-problem-list to get problem request ID). | Required |
| task_id | The task ID for delete (use freshservice-problem-task-list to get the task ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-problem-task-delete problem_id=2 task_id=186```
#### Human Readable Output

>Problem Task deleted successfully

### freshservice-change-list

***
Retrieve a list of all Change requests or the Change request with the given ID from Freshservice.

#### Base Command

`freshservice-change-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| change_id | Change request ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.agent_id | Unknown | Change agent ID. |
| Freshservice.Change.group_id | Unknown | Change group ID. |
| Freshservice.Change.priority | Number | Change priority. |
| Freshservice.Change.impact | Number | Change impact. |
| Freshservice.Change.status | Number | Change status. |
| Freshservice.Change.risk | Number | Change risk. |
| Freshservice.Change.change_type | Number | Change type. |
| Freshservice.Change.planned_start_date | Date | Change planned start date. |
| Freshservice.Change.planned_end_date | Date | Change planned end date. |
| Freshservice.Change.subject | String | Change subject. |
| Freshservice.Change.department_id | Unknown | Change department ID. |
| Freshservice.Change.category | Unknown | Change category. |
| Freshservice.Change.sub_category | Unknown | Change sub-category. |
| Freshservice.Change.item_category | Unknown | Change item category. |
| Freshservice.Change.description | String | Change description. |
| Freshservice.Change.id | Number | Change ID. |
| Freshservice.Change.requester_id | Date | Change requester ID. |
| Freshservice.Change.approval_status | Number | Change approval status. |
| Freshservice.Change.change_window_id | Unknown | Change window ID. |
| Freshservice.Change.created_at | Date | Change creation time |
| Freshservice.Change.updated_at | Date | Change updated at. |

#### Command example
```!freshservice-change-list```
#### Context Example
```json
{
    "Freshservice": {
        "Change": [
            {
                "agent_id": null,
                "approval_status": 4,
                "assets": [],
                "blackout_window": {},
                "category": null,
                "change_type": "Minor",
                "change_window_id": null,
                "created_at": "2023-04-13T14:06:10Z",
                "department_id": null,
                "description": "<div>Hi Team, <br><br> One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn\u2019t help. We need to get it replaced ASAP. <br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi Team,    One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn\u2019t help. We need to get it replaced ASAP.   Regards  Rachel",
                "group_id": null,
                "id": 29,
                "impact": "Low",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2019-03-23T16:18:46Z",
                "planned_start_date": "2019-03-20T16:18:46Z",
                "priority": "Low",
                "requester_id": 21001523121,
                "risk": "Low",
                "status": "Open",
                "sub_category": null,
                "subject": "Getting ES3 back up to speed",
                "updated_at": "2023-04-13T14:06:10Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "approval_status": 4,
                "assets": [],
                "blackout_window": {},
                "category": null,
                "change_type": "Minor",
                "change_window_id": null,
                "created_at": "2023-04-13T14:03:42Z",
                "department_id": null,
                "description": "<div>Hi Team, <br><br> One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn\u2019t help. We need to get it replaced ASAP. <br><br>Regards<br> Rachel<br> </div>",
                "description_text": "Hi Team,    One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn\u2019t help. We need to get it replaced ASAP.   Regards  Rachel",
                "group_id": null,
                "id": 28,
                "impact": "Low",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2019-03-23T16:18:46Z",
                "planned_start_date": "2019-03-20T16:18:46Z",
                "priority": "Low",
                "requester_id": 21001523121,
                "risk": "Low",
                "status": "Open",
                "sub_category": null,
                "subject": "Getting ES3 back up to speed",
                "updated_at": "2023-04-13T14:03:42Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "approval_status": 4,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "blackout_window": {},
                "category": "Software",
                "change_type": "Major",
                "change_window_id": null,
                "created_at": "2023-03-29T15:10:11Z",
                "department_id": 21000263162,
                "description": "<div style='font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;'>\n<div></div>\n<div style=\"margin-bottom:15px;\">\n<strong style='color: rgb(0, 0, 0); font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; font-size: 14px; text-align: justify;'>Lorem Ipsum</strong><span style=\"color: rgb(0, 0, 0); text-align: justify;\">\u00a0is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.</span>\n</div>\n</div>",
                "description_text": "Lorem Ipsum\u00a0is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
                "group_id": 21000478053,
                "id": 27,
                "impact": "Medium",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2023-03-28T22:30:00Z",
                "planned_start_date": "2023-03-28T21:45:00Z",
                "priority": "Medium",
                "requester_id": 21001397559,
                "risk": "Medium",
                "status": "Open",
                "sub_category": "MS Office",
                "subject": "bsfbfsb",
                "updated_at": "2023-03-29T15:10:11Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "approval_status": 4,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "blackout_window": {},
                "category": "Travel",
                "change_type": "Standard",
                "change_window_id": null,
                "created_at": "2023-03-23T17:01:01Z",
                "department_id": 21000263162,
                "description": "mirroring OUT 16:49",
                "description_text": "mirroring OUT 16:49",
                "group_id": 21000478053,
                "id": 19,
                "impact": "Medium",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2023-03-29T22:00:00Z",
                "planned_start_date": "2023-03-27T21:30:00Z",
                "priority": "High",
                "requester_id": 21001397559,
                "risk": "Medium",
                "status": "Open",
                "sub_category": "Access",
                "subject": "oj[oko'",
                "updated_at": "2023-04-04T13:50:11Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "approval_status": 4,
                "assets": [],
                "blackout_window": {},
                "category": null,
                "change_type": "Emergency",
                "change_window_id": null,
                "created_at": "2023-03-19T12:49:52Z",
                "department_id": null,
                "description": "14:08",
                "description_text": "14:08",
                "group_id": 21000478054,
                "id": 11,
                "impact": "High",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2023-11-01T00:00:00Z",
                "planned_start_date": "2023-10-02T00:00:00Z",
                "priority": "Low",
                "requester_id": 21001894392,
                "risk": "High",
                "status": "Open",
                "sub_category": null,
                "subject": "New test by ben",
                "updated_at": "2023-04-02T11:07:57Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "approval_status": 4,
                "assets": [],
                "blackout_window": {},
                "category": null,
                "change_type": "Emergency",
                "change_window_id": null,
                "created_at": "2023-03-19T12:38:33Z",
                "department_id": null,
                "description": "<div>test description</div>",
                "description_text": "test description",
                "group_id": null,
                "id": 10,
                "impact": "High",
                "impacted_services": [],
                "item_category": null,
                "maintenance_window": {},
                "planned_end_date": "2023-11-01T00:00:00Z",
                "planned_start_date": "2023-10-02T00:00:00Z",
                "priority": "High",
                "requester_id": 21001894392,
                "risk": "High",
                "status": "Open",
                "sub_category": null,
                "subject": "New test by ben",
                "updated_at": "2023-03-19T12:38:33Z",
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Change
>Showing page 1.
> Current page size: 50.
>|Id|Description Text|Requester Id|Subject|Risk|Impact|Status|Priority|Change Type|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 29 | Hi Team,    One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn’t help. We need to get it replaced ASAP.   Regards  Rachel | 21001523121 | Getting ES3 back up to speed | Low | Low | Open | Low | Minor |  | 2023-04-13T14:06:10Z | 2023-04-13T14:06:10Z | 2019-03-20T16:18:46Z | 2019-03-23T16:18:46Z |
>| 28 | Hi Team,    One of our email servers, Exchange Server (ES3) has been acting up. We tried rebooting it, but that didn’t help. We need to get it replaced ASAP.   Regards  Rachel | 21001523121 | Getting ES3 back up to speed | Low | Low | Open | Low | Minor |  | 2023-04-13T14:03:42Z | 2023-04-13T14:03:42Z | 2019-03-20T16:18:46Z | 2019-03-23T16:18:46Z |
>| 27 | Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. | 21001397559 | bsfbfsb | Medium | Medium | Open | Medium | Major | Software | 2023-03-29T15:10:11Z | 2023-03-29T15:10:11Z | 2023-03-28T21:45:00Z | 2023-03-28T22:30:00Z |
>| 19 | mirroring OUT 16:49 | 21001397559 | oj[oko' | Medium | Medium | Open | High | Standard | Travel | 2023-03-23T17:01:01Z | 2023-04-04T13:50:11Z | 2023-03-27T21:30:00Z | 2023-03-29T22:00:00Z |
>| 11 | 14:08 | 21001894392 | New test by ben | High | High | Open | Low | Emergency |  | 2023-03-19T12:49:52Z | 2023-04-02T11:07:57Z | 2023-10-02T00:00:00Z | 2023-11-01T00:00:00Z |
>| 10 | test description | 21001894392 | New test by ben | High | High | Open | High | Emergency |  | 2023-03-19T12:38:33Z | 2023-03-19T12:38:33Z | 2023-10-02T00:00:00Z | 2023-11-01T00:00:00Z |


### freshservice-change-create

***
Create a new Change request in Freshservice. Creating a ticket required one of the following- requester_id or email.

#### Base Command

`freshservice-change-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The content of the change. | Required |
| priority | Priority of the change. Possible values are: Low, Medium, High, Urgent. | Required |
| impact | Impact of the change (Low-1, Medium-2, High-3). Possible values are: Low, Medium, High. | Required |
| status | Status of the change (Open-1,Planning-2,Approval-3,Pending Release-4,Pending Review-5,closed-6). Possible values are: Open, Planning, Approval, Pending Release, Pending Review, closed. | Required |
| risk | Risk of the change (Low-1, Medium-2, High-3, Very High-4). Possible values are: Low, Medium, High, Very High. | Required |
| change_type | Type of the change. Possible values are: Minor, Standard, Major, Emergency. | Required |
| planned_start_date | Timestamp at which change is starting (for example YYYY-MM-DDThh:mm). | Required |
| planned_end_date | Timestamp at which change is ending (for example YYYY-MM-DDThh:mm). | Required |
| subject | The subject of the change. | Required |
| email | Requester email. If not specified - must provide 'requester_id'. | Optional |
| requester_id | Requester ID (use freshservice-agent-list to get the agent ID). If not specified - must provide 'email'. | Optional |
| agent_id | Unique identifier of the agent to whom the change is assigned. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Unique identifier of the agent group to which the change is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| department_id | Unique ID of the department initiating the change. Use freshservice-department-list to get the department ID. | Optional |
| category | Category of the Problem. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | The sub-category of the Problem. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.agent_id | Unknown | Change agent ID. |
| Freshservice.Change.group_id | Unknown | Change group ID. |
| Freshservice.Change.priority | Number | Change priority. |
| Freshservice.Change.impact | Number | Change impact. |
| Freshservice.Change.status | Number | Change status. |
| Freshservice.Change.risk | Number | Change risk. |
| Freshservice.Change.change_type | Number | Change change_type. |
| Freshservice.Change.planned_start_date | Date | Change planned start date. |
| Freshservice.Change.planned_end_date | Date | Change planned end date. |
| Freshservice.Change.subject | String | Change subject. |
| Freshservice.Change.department_id | Unknown | Change department ID. |
| Freshservice.Change.category | Unknown | Change category. |
| Freshservice.Change.sub_category | Unknown | Change sub-category. |
| Freshservice.Change.item_category | Unknown | Change item category. |
| Freshservice.Change.description | String | Change description. |
| Freshservice.Change.id | Number | Change ID. |
| Freshservice.Change.requester_id | Date | Change requester ID. |
| Freshservice.Change.approval_status | Number | Change approval status. |
| Freshservice.Change.change_window_id | Unknown | Change window ID. |
| Freshservice.Change.created_at | Date | Change creation time |
| Freshservice.Change.updated_at | Date | Change updated at. |

#### Command example
```!freshservice-change-create description=description priority=Low impact=Low status=Open risk=Low change_type=Minor planned_start_date="2019-03-20T16:18:46Z" planned_end_date="2019-03-23T16:18:46Z" subject=subject email=sample@freshservice.com```
#### Context Example
```json
{
    "Freshservice": {
        "Change": {
            "agent_id": null,
            "approval_status": 4,
            "assets": [],
            "blackout_window": {},
            "category": null,
            "change_type": "Minor",
            "change_window_id": null,
            "created_at": "2023-04-13T14:17:14Z",
            "custom_fields": {},
            "department_id": null,
            "description": "<div>description</div>",
            "description_text": "description",
            "group_id": null,
            "id": 30,
            "impact": "Low",
            "impacted_services": [],
            "item_category": null,
            "maintenance_window": {},
            "planned_end_date": "2019-03-23T16:18:46Z",
            "planned_start_date": "2019-03-20T16:18:46Z",
            "planning_fields": {
                "custom_fields": {}
            },
            "priority": "Low",
            "requester_id": 21001523090,
            "risk": "Low",
            "status": "Open",
            "sub_category": null,
            "subject": "subject",
            "updated_at": "2023-04-13T14:17:14Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Change
>Change created successfully
>|Id|Description Text|Requester Id|Subject|Risk|Impact|Status|Priority|Change Type|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 30 | description | 21001523090 | subject | Low | Low | Open | Low | Minor |  | 2023-04-13T14:17:14Z | 2023-04-13T14:17:14Z | 2019-03-20T16:18:46Z | 2019-03-23T16:18:46Z |


### freshservice-change-update

***
Update an existing Change request in Freshservice.

#### Base Command

`freshservice-change-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The content of the change. | Optional |
| change_id | The change ID (use freshservice-change-list to get the change request ID). | Required |
| priority | Priority of the change. Possible values are: Low, Medium, High, Urgent. | Optional |
| impact | Impact of the change (Low-1, Medium-2, High-3). Possible values are: Low, Medium, High. | Optional |
| status | Status of the change (Open-1,Planning-2,Approval-3,Pending Release-4,Pending Review-5,closed-6). Possible values are: Open, Planning, Approval, Pending Release, Pending Review, closed. | Optional |
| risk | Risk of the change (Low-1, Medium-2, High-3, Very High-4). Possible values are: Low, Medium, High, Very High. | Optional |
| change_type | Type of the change. Possible values are: Minor, Standard, Major, Emergency. | Optional |
| planned_start_date | Timestamp at which change is starting (for example YYYY-MM-DDThh:mm). | Optional |
| planned_end_date | Timestamp at which change is ending (for example YYYY-MM-DDThh:mm). | Optional |
| subject | The subject of the change. | Optional |
| email | requester email. | Optional |
| agent_id | Unique identifier of the agent to whom the change is assigned. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Unique identifier of the agent group to which the change is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| department_id | Unique ID of the department initiating the change. Use freshservice-department-list to get the department ID. | Optional |
| category | Category of the Problem. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| sub_category | The sub-category of the Problem. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.agent_id | Unknown | Change agent ID. |
| Freshservice.Change.group_id | Unknown | Change group ID. |
| Freshservice.Change.priority | Number | Change priority. |
| Freshservice.Change.impact | Number | Change impact. |
| Freshservice.Change.status | Number | Change status. |
| Freshservice.Change.risk | Number | Change risk. |
| Freshservice.Change.change_type | Number | Change change_type. |
| Freshservice.Change.planned_start_date | Date | Change planned start date. |
| Freshservice.Change.planned_end_date | Date | Change planned end date. |
| Freshservice.Change.subject | String | Change subject. |
| Freshservice.Change.department_id | Unknown | Change department ID. |
| Freshservice.Change.category | Unknown | Change category. |
| Freshservice.Change.sub_category | Unknown | Change sub-category. |
| Freshservice.Change.item_category | Unknown | Change item category. |
| Freshservice.Change.description | String | Change description. |
| Freshservice.Change.id | Number | Change ID. |
| Freshservice.Change.requester_id | Date | Change requester ID. |
| Freshservice.Change.approval_status | Number | Change approval status. |
| Freshservice.Change.change_window_id | Unknown | Change window ID. |
| Freshservice.Change.created_at | Date | Change creation time |
| Freshservice.Change.updated_at | Date | Change updated at. |

#### Command example
```!freshservice-change-update description=description change_id=28 subject=subject```
#### Context Example
```json
{
    "Freshservice": {
        "Change": {
            "agent_id": null,
            "approval_status": 4,
            "assets": [],
            "blackout_window": {},
            "category": null,
            "change_type": "Minor",
            "change_window_id": null,
            "created_at": "2023-04-13T14:03:42Z",
            "custom_fields": {},
            "department_id": null,
            "description": "description",
            "description_text": "description",
            "group_id": null,
            "id": 28,
            "impact": "Low",
            "impacted_services": [],
            "item_category": null,
            "maintenance_window": {},
            "planned_end_date": "2019-03-23T16:18:46Z",
            "planned_start_date": "2019-03-20T16:18:46Z",
            "planning_fields": {
                "custom_fields": {}
            },
            "priority": "Low",
            "requester_id": 21001523121,
            "risk": "Low",
            "status": "Open",
            "sub_category": null,
            "subject": "subject",
            "updated_at": "2023-04-13T14:17:20Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Change
>Change updated successfully
>|Id|Description Text|Requester Id|Subject|Risk|Impact|Status|Priority|Change Type|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 28 | description | 21001523121 | subject | Low | Low | Open | Low | Minor |  | 2023-04-13T14:03:42Z | 2023-04-13T14:17:20Z | 2019-03-20T16:18:46Z | 2019-03-23T16:18:46Z |


### freshservice-change-delete

***
Delete the Change request with the given ID from Freshservice.

#### Base Command

`freshservice-change-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_id | The change ID to delete (use freshservice-change-list to get the change request ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-change-delete change_id=29```
#### Human Readable Output

>Change deleted successfully

### freshservice-change-task-list

***
Retrieve the tasks on a Change request with the given ID from Freshservice.

#### Base Command

`freshservice-change-task-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| change_id | Change request ID (use freshservice-change-list to get the change request ID). | Required |
| task_id | The change request task ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.Task.id | Number | Task ID. |
| Freshservice.Change.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Change.Task.status | Number | Task status. |
| Freshservice.Change.Task.due_date | Date | Task due date. |
| Freshservice.Change.Task.notify_before | Number | Task notify before. |
| Freshservice.Change.Task.title | String | Task title. |
| Freshservice.Change.Task.description | String | Task description. |
| Freshservice.Change.Task.created_at | Date | Task creation time. |
| Freshservice.Change.Task.updated_at | Date | Task updated at. |
| Freshservice.Change.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Change.Task.group_id | Unknown | Task group ID. |
| Freshservice.Change.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-change-task-list change_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Change": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:58Z",
                    "created_at": "2023-01-15T16:05:20Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2020-04-27T13:23:20Z",
                    "group_id": null,
                    "id": 8,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:59Z",
                    "created_at": "2023-01-19T10:27:07Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-01-23T19:00:00Z",
                    "group_id": null,
                    "id": 11,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:59Z",
                    "created_at": "2023-03-08T10:52:17Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "updated",
                    "due_date": "2023-03-10T19:00:00Z",
                    "group_id": null,
                    "id": 23,
                    "notify_before": 0,
                    "status": "Completed",
                    "title": "d",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:59Z",
                    "created_at": "2023-03-08T13:56:19Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "ddd",
                    "due_date": "2023-03-10T19:56:19Z",
                    "group_id": null,
                    "id": 26,
                    "notify_before": 1800,
                    "status": "Completed",
                    "title": "ttt",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:59Z",
                    "created_at": "2023-03-19T12:47:11Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "dsa",
                    "due_date": "2023-03-22T18:00:00Z",
                    "group_id": null,
                    "id": 36,
                    "notify_before": 7200,
                    "status": "Completed",
                    "title": "sd",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": "2023-03-26T09:58:59Z",
                    "created_at": "2023-03-19T12:47:29Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "dsa",
                    "due_date": "2023-03-22T18:00:00Z",
                    "group_id": null,
                    "id": 37,
                    "notify_before": 7200,
                    "status": "Completed",
                    "title": "sd",
                    "updated_at": "2023-03-26T09:58:59Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:08:05Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-04-17T20:08:05Z",
                    "group_id": null,
                    "id": 187,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:08:05Z",
                    "workspace_id": 2
                },
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:08:32Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "We need to re-supply to win the war!",
                    "due_date": "2023-04-17T20:08:32Z",
                    "group_id": null,
                    "id": 188,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:08:32Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Change
>Showing page 1.
> Current page size: 50.
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 8 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Completed | false | 2023-03-26T09:58:58Z | 2023-01-15T16:05:20Z | 2023-03-26T09:58:59Z | 2020-04-27T13:23:20Z |
>| 11 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Completed | false | 2023-03-26T09:58:59Z | 2023-01-19T10:27:07Z | 2023-03-26T09:58:59Z | 2023-01-23T19:00:00Z |
>| 23 | updated | d | 0 | Completed | false | 2023-03-26T09:58:59Z | 2023-03-08T10:52:17Z | 2023-03-26T09:58:59Z | 2023-03-10T19:00:00Z |
>| 26 | ddd | ttt | 1800 | Completed | false | 2023-03-26T09:58:59Z | 2023-03-08T13:56:19Z | 2023-03-26T09:58:59Z | 2023-03-10T19:56:19Z |
>| 36 | dsa | sd | 7200 | Completed | false | 2023-03-26T09:58:59Z | 2023-03-19T12:47:11Z | 2023-03-26T09:58:59Z | 2023-03-22T18:00:00Z |
>| 37 | dsa | sd | 7200 | Completed | false | 2023-03-26T09:58:59Z | 2023-03-19T12:47:29Z | 2023-03-26T09:58:59Z | 2023-03-22T18:00:00Z |
>| 187 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:08:05Z | 2023-04-13T14:08:05Z | 2023-04-17T20:08:05Z |
>| 188 | We need to re-supply to win the war! | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:08:32Z | 2023-04-13T14:08:32Z | 2023-04-17T20:08:32Z |


### freshservice-change-task-create

***
Create a new task on a change request in Freshservice.

#### Base Command

`freshservice-change-task-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Required |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Required |
| title | Task title. | Required |
| description | Task description. | Required |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| change_id | The change ID to add a task for (use freshservice-change-list to get the change request ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.Task.id | Number | Task ID. |
| Freshservice.Change.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Change.Task.status | Number | Task status. |
| Freshservice.Change.Task.due_date | Date | Task due date. |
| Freshservice.Change.Task.notify_before | Number | Task notify before. |
| Freshservice.Change.Task.title | String | Task title. |
| Freshservice.Change.Task.description | String | Task description. |
| Freshservice.Change.Task.created_at | Date | Task creation time. |
| Freshservice.Change.Task.updated_at | Date | Task updated at. |
| Freshservice.Change.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Change.Task.group_id | Unknown | Task group ID. |
| Freshservice.Change.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-change-task-create due_date="2020-04-03T10:26:13.067Z" notify_before="2020-05-03T10:26:13.067Z" title=title description=description status=Open change_id=2```
#### Context Example
```json
{
    "Freshservice": {
        "Change": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:17:37Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:17:37Z",
                    "group_id": null,
                    "id": 194,
                    "notify_before": 7200,
                    "status": "Open",
                    "title": "title",
                    "updated_at": "2023-04-13T14:17:37Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Change
>Change Task created successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 194 | description | title | 7200 | Open | false |  | 2023-04-13T14:17:37Z | 2023-04-13T14:17:37Z | 2023-04-17T20:17:37Z |


### freshservice-change-task-update

***
Update an existing task on an existing Change request in Freshservice.

#### Base Command

`freshservice-change-task-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Optional |
| notify_before | Task notify before (For example 30 minutes, 7 hours and etc). | Optional |
| title | Task title. | Optional |
| description | Task description. | Optional |
| status | Task status, default is 'Open'. Possible values are: Open, In Progress, Completed. | Optional |
| change_id | The change ID to update a task (use freshservice-change-list to get the change request ID). | Required |
| task_id | The Task ID for an update (use freshservice-change-task-list to get the task ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Change.Task.id | Number | Task ID. |
| Freshservice.Change.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Change.Task.status | Number | Task status. |
| Freshservice.Change.Task.due_date | Date | Task due date. |
| Freshservice.Change.Task.notify_before | Number | Task notify before. |
| Freshservice.Change.Task.title | String | Task title. |
| Freshservice.Change.Task.description | String | Task description. |
| Freshservice.Change.Task.created_at | Date | Task creation time. |
| Freshservice.Change.Task.updated_at | Date | Task updated at. |
| Freshservice.Change.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Change.Task.group_id | Unknown | Task group ID. |
| Freshservice.Change.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-change-task-update description=description change_id=2 task_id=188```
#### Context Example
```json
{
    "Freshservice": {
        "Change": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:08:32Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:08:32Z",
                    "group_id": null,
                    "id": 188,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:17:43Z",
                    "workspace_id": 2
                }
            ],
            "id": "2"
        }
    }
}
```

#### Human Readable Output

>### Change
>Change Task updated successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 188 | description | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:08:32Z | 2023-04-13T14:17:43Z | 2023-04-17T20:08:32Z |


### freshservice-change-task-delete

***
Delete the task on a Change request with the given ID from Freshservice.

#### Base Command

`freshservice-change-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_id | Change ID (use freshservice-change-list to get the change request ID). | Required |
| task_id | Task ID (use freshservice-change-task-list to get the task ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-change-task-delete change_id=187 task_id=2```
#### Human Readable Output

>Task 2 does not exist

### freshservice-release-list

***
Retrieve a list of all Releases (or specific by ID) in Freshservice.

#### Base Command

`freshservice-release-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| release_id | The release ID. | Optional |
| filter_name | Filters to view only specific releases (which match only the criteria you choose). Possible values are: all, my_open, unassigned, completed, incompleted, deleted. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.id | Number | release ID. |
| Freshservice.Release.agent_id | Unknown | release agent ID. |
| Freshservice.Release.description | String | release description. |
| Freshservice.Release.group_id | Unknown | release group ID. |
| Freshservice.Release.department_id | Unknown | release department ID. |
| Freshservice.Release.subject | String | release subject. |
| Freshservice.Release.category | Unknown | release category. |
| Freshservice.Release.sub_category | Unknown | release sub-category. |
| Freshservice.Release.item_category | Unknown | release item category. |
| Freshservice.Release.planned_start_date | Date | release planned start date. |
| Freshservice.Release.planned_end_date | Date | release planned end date. |
| Freshservice.Release.status | Number | release status. |
| Freshservice.Release.priority | Number | release priority. |
| Freshservice.Release.release_type | Number | release release_type. |
| Freshservice.Release.work_start_date | Date | release work start date. |
| Freshservice.Release.work_end_date | Date | release work end date. |
| Freshservice.Release.created_at | Date | release creation time. |
| Freshservice.Release.updated_at | Date | release updated at. |
| Freshservice.Release.associated_change_ids | Number | release associated change IDs. |

#### Command example
```!freshservice-release-list```
#### Context Example
```json
{
    "Freshservice": {
        "Release": [
            {
                "agent_id": null,
                "assets": [],
                "associated_change_ids": [],
                "category": "Hardware",
                "created_at": "2023-04-13T14:11:15Z",
                "department_id": null,
                "description": "<div>Not given.</div>",
                "description_text": "Not given.",
                "group_id": null,
                "id": 41,
                "item_category": null,
                "planned_end_date": "2023-03-31T10:35:47Z",
                "planned_start_date": "2020-03-31T10:35:47Z",
                "priority": "Low",
                "release_type": "Minor",
                "status": "In Progress",
                "sub_category": null,
                "subject": "string",
                "updated_at": "2023-04-13T14:11:15Z",
                "work_end_date": "2023-03-31T10:35:47Z",
                "work_start_date": "2020-03-31T10:35:47Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "associated_change_ids": [],
                "category": "Hardware",
                "created_at": "2023-04-13T14:09:07Z",
                "department_id": null,
                "description": "<div>Not given.</div>",
                "description_text": "Not given.",
                "group_id": null,
                "id": 40,
                "item_category": null,
                "planned_end_date": "2023-03-31T10:35:47Z",
                "planned_start_date": "2020-03-31T10:35:47Z",
                "priority": "Low",
                "release_type": "Minor",
                "status": "In Progress",
                "sub_category": null,
                "subject": "string",
                "updated_at": "2023-04-13T14:09:07Z",
                "work_end_date": "2023-03-31T10:35:47Z",
                "work_start_date": "2020-03-31T10:35:47Z",
                "workspace_id": 2
            },
            {
                "agent_id": 21001397559,
                "assets": [
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-1",
                        "department_id": null,
                        "description": null,
                        "display_id": 1,
                        "group_id": null,
                        "impact": 2,
                        "name": "Andrea's Laptop"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-2",
                        "department_id": null,
                        "description": null,
                        "display_id": 2,
                        "group_id": null,
                        "impact": 1,
                        "name": "Dell Monitor"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-3",
                        "department_id": null,
                        "description": null,
                        "display_id": 3,
                        "group_id": null,
                        "impact": 1,
                        "name": "Logitech Mouse"
                    },
                    {
                        "agent_id": null,
                        "asset_tag": "ASSET-4",
                        "department_id": null,
                        "description": null,
                        "display_id": 4,
                        "group_id": null,
                        "impact": 1,
                        "name": "monitor"
                    }
                ],
                "associated_change_ids": [],
                "category": "Network",
                "created_at": "2023-04-03T15:13:12Z",
                "department_id": 21000263162,
                "description": "fdbfdsghdfsgh 19:05",
                "description_text": "fdbfdsghdfsgh 19:05",
                "group_id": 21000478053,
                "id": 39,
                "item_category": null,
                "planned_end_date": "2023-04-02T22:15:00Z",
                "planned_start_date": "2023-04-02T21:15:00Z",
                "priority": "Medium",
                "release_type": "Standard",
                "status": "In Progress",
                "sub_category": "Access",
                "subject": "test test test",
                "updated_at": "2023-04-03T16:06:18Z",
                "work_end_date": "2023-04-02T22:15:00Z",
                "work_start_date": "2023-04-02T21:15:00Z",
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "assets": [],
                "associated_change_ids": [],
                "category": "Hardware",
                "created_at": "2023-03-28T10:13:28Z",
                "department_id": null,
                "description": "<div>Not given.</div>",
                "description_text": "Not given.",
                "group_id": null,
                "id": 38,
                "item_category": null,
                "planned_end_date": "2023-03-31T10:35:47Z",
                "planned_start_date": "2020-03-31T10:35:47Z",
                "priority": "Low",
                "release_type": "Minor",
                "status": "In Progress",
                "sub_category": null,
                "subject": "string",
                "updated_at": "2023-03-28T10:13:28Z",
                "work_end_date": "2023-03-31T10:35:47Z",
                "work_start_date": "2020-03-31T10:35:47Z",
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Release
>Showing page 1.
> Current page size: 50.
>|Id|Description Text|Subject|Release Type|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 41 | Not given. | string | Minor | In Progress | Low |  |  | Hardware | 2023-04-13T14:11:15Z | 2023-04-13T14:11:15Z | 2020-03-31T10:35:47Z | 2023-03-31T10:35:47Z |
>| 40 | Not given. | string | Minor | In Progress | Low |  |  | Hardware | 2023-04-13T14:09:07Z | 2023-04-13T14:09:07Z | 2020-03-31T10:35:47Z | 2023-03-31T10:35:47Z |
>| 39 | fdbfdsghdfsgh 19:05 | test test test | Standard | In Progress | Medium | 21000478053 |  | Network | 2023-04-03T15:13:12Z | 2023-04-03T16:06:18Z | 2023-04-02T21:15:00Z | 2023-04-02T22:15:00Z |
>| 38 | Not given. | string | Minor | In Progress | Low |  |  | Hardware | 2023-03-28T10:13:28Z | 2023-03-28T10:13:28Z | 2020-03-31T10:35:47Z | 2023-03-31T10:35:47Z |


### freshservice-release-create

***
Create a new Release request in Freshservice.

#### Base Command

`freshservice-release-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| priority | Priority of the Release. Possible values are: Low, Medium, High, Urgent. | Required |
| status | Status identifier of the Release. (1-Open, 2-On hold, 3-In Progress, 4-Incomplete, 5-Completed). Possible values are: Open, On hold, In Progress, Incomplete, Completed. | Required |
| release_type | Type of the Release (1-minor, 2-standard, 3-major, 4-emergency). Possible values are: Minor, Standard, Major, Emergency. | Required |
| subject | The subject of the Release. | Required |
| description | Description of the release. | Required |
| planned_start_date | Timestamp at which the release is starting (for example YYYY-MM-DDThh:mm). | Required |
| planned_end_date | Timestamp at which release is ending (for example YYYY-MM-DDThh:mm). | Required |
| category | Category of the Release. Possible values are: Hardware, Software, Network, Office Applications, Talent Management, Travel, Employee Records and Documents, Office Furniture, Office Equipment, Employee Benefits, Employee Onboarding/Offboarding, Employee Relations, Workplace Access and Security, Building and Grounds Maintenance, Vendor Document Review, Payroll, Vendor Payment, Customer Payment, Reimbursements and Advances, Legal Document Creation, Legal Review - Vendor Documents, Legal Review - Customer Documents, Other. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. | Optional |
| agent_id | Unique identifier of the agent to whom the Release is assigned. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Unique identifier of the agent group to which the Release is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| department_id | Unique ID of the department initiating the Release. Use freshservice-department-list to get the department ID. | Optional |
| sub_category | The sub-category of the Release. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.id | Number | Release ID. |
| Freshservice.Release.agent_id | Unknown | Release agent ID. |
| Freshservice.Release.description | String | Release description. |
| Freshservice.Release.group_id | Unknown | Release group ID. |
| Freshservice.Release.department_id | Unknown | Release department ID. |
| Freshservice.Release.subject | String | Release subject. |
| Freshservice.Release.category | String | Release category. |
| Freshservice.Release.sub_category | Unknown | Release sub-category. |
| Freshservice.Release.item_category | Unknown | Release item category. |
| Freshservice.Release.planned_start_date | Date | Release planned start date. |
| Freshservice.Release.planned_end_date | Date | Release planned end date. |
| Freshservice.Release.status | Number | Release status. |
| Freshservice.Release.priority | Number | Release priority. |
| Freshservice.Release.release_type | Number | Release type. |
| Freshservice.Release.work_start_date | Date | Release work start date. |
| Freshservice.Release.work_end_date | Date | Release work end date. |
| Freshservice.Release.created_at | Date | release creation time. |
| Freshservice.Release.updated_at | Date | Release updated at. |

#### Command example
```!freshservice-release-create priority=Low status=Open release_type=Minor subject=subject description=description planned_start_date="2019-03-20T16:18:46Z" planned_end_date="2019-03-23T16:18:46Z"```
#### Context Example
```json
{
    "Freshservice": {
        "Release": {
            "agent_id": null,
            "assets": [],
            "associated_change_ids": [],
            "category": null,
            "created_at": "2023-04-13T14:18:00Z",
            "custom_fields": {},
            "department_id": null,
            "description": "<div>description</div>",
            "description_text": "description",
            "group_id": null,
            "id": 42,
            "item_category": null,
            "planned_end_date": "2019-03-23T16:18:46Z",
            "planned_start_date": "2019-03-20T16:18:46Z",
            "planning_fields": {},
            "priority": "Low",
            "release_type": "Minor",
            "status": "Open",
            "sub_category": null,
            "subject": "subject",
            "updated_at": "2023-04-13T14:18:00Z",
            "work_end_date": "2019-03-23T16:18:46Z",
            "work_start_date": "2019-03-20T16:18:46Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Release
>Release created successfully
>|Id|Description Text|Subject|Release Type|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 42 | description | subject | Minor | Open | Low |  |  |  | 2023-04-13T14:18:00Z | 2023-04-13T14:18:00Z | 2019-03-20T16:18:46Z | 2019-03-23T16:18:46Z |


### freshservice-release-update

***
Update an existing Release in Freshservice.

#### Base Command

`freshservice-release-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| priority | Priority of the Release. Possible values are: Low, Medium, High, Urgent. | Optional |
| status | Status identifier of the Release. (1-Open, 2-On hold, 3-In Progress, 4-Incomplete, 5-Completed). Possible values are: Open, On hold, In Progress, Incomplete, Completed. | Optional |
| release_type | Type of the Release (1-minor, 2-standard, 3-major, 4-emergency). Possible values are: Minor, Standard, Major, Emergency. | Optional |
| subject | The subject of the Release. | Optional |
| description | Description of the release. | Optional |
| planned_start_date | Timestamp at which release is starting (for example YYYY-MM-DDThh:mm). | Optional |
| planned_end_date | Timestamp at which release is ending (for example YYYY-MM-DDThh:mm). | Optional |
| release_id | The release ID (use freshservice-release-list to get the release request ID). | Required |
| sub_category | Sub-category of the Release. | Optional |
| department_id | Unique ID of the department initiating the Release. Use freshservice-department-list to get the department ID. | Optional |
| agent_id | Unique identifier of the agent to whom the Release is assigned. Use freshservice-agent-list to get the agent ID. | Optional |
| group_id | Unique identifier of the agent group to which the Release is assigned. Use freshservice-agent-group-list to get the agent group ID. | Optional |
| custom_fields | Key value pairs containing the names and values of custom fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.id | Number | Release ID. |
| Freshservice.Release.agent_id | Unknown | Release agent ID. |
| Freshservice.Release.description | String | Release description. |
| Freshservice.Release.group_id | Unknown | Release group ID. |
| Freshservice.Release.department_id | Unknown | Release department ID. |
| Freshservice.Release.subject | String | Release subject. |
| Freshservice.Release.category | String | Release category. |
| Freshservice.Release.sub_category | Unknown | Release sub-category. |
| Freshservice.Release.item_category | Unknown | Release item category. |
| Freshservice.Release.planned_start_date | Date | Release planned start date. |
| Freshservice.Release.planned_end_date | Date | Release planned end date. |
| Freshservice.Release.status | Number | Release status. |
| Freshservice.Release.priority | Number | Release priority. |
| Freshservice.Release.release_type | Number | Release release_type. |
| Freshservice.Release.work_start_date | Date | Release work start date. |
| Freshservice.Release.work_end_date | Date | Release work end date. |
| Freshservice.Release.created_at | Date | release creation time. |
| Freshservice.Release.updated_at | Date | Release updated at. |

#### Command example
```!freshservice-release-update description=description release_id=40```
#### Context Example
```json
{
    "Freshservice": {
        "Release": {
            "agent_id": null,
            "assets": [],
            "associated_change_ids": [],
            "category": "Hardware",
            "created_at": "2023-04-13T14:09:07Z",
            "custom_fields": {},
            "department_id": null,
            "description": "description",
            "description_text": "description",
            "group_id": null,
            "id": 40,
            "item_category": null,
            "planned_end_date": "2023-03-31T10:35:47Z",
            "planned_start_date": "2020-03-31T10:35:47Z",
            "planning_fields": {},
            "priority": "Low",
            "release_type": "Minor",
            "status": "In Progress",
            "sub_category": null,
            "subject": "string",
            "updated_at": "2023-04-13T14:09:07Z",
            "work_end_date": "2023-03-31T10:35:47Z",
            "work_start_date": "2020-03-31T10:35:47Z",
            "workspace_id": 2
        }
    }
}
```

#### Human Readable Output

>### Release
>Release updated successfully
>|Id|Description Text|Subject|Release Type|Status|Priority|Group Id|Known Error|Category|Created At|Updated At|Planned Start Date|Planned End Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 40 | description | string | Minor | In Progress | Low |  |  | Hardware | 2023-04-13T14:09:07Z | 2023-04-13T14:09:07Z | 2020-03-31T10:35:47Z | 2023-03-31T10:35:47Z |


### freshservice-release-delete

***
Delete a Release with the given ID from Freshservice.

#### Base Command

`freshservice-release-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| release_id | The release ID (use freshservice-release-list to get the release request ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-release-delete release_id=41```
#### Human Readable Output

>Release deleted successfully

### freshservice-release-task-list

***
Retrieve the tasks on a Release with the given ID from Freshservice.

#### Base Command

`freshservice-release-task-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| release_id | The release ID (use freshservice-release-list to get the release request ID). | Required |
| task_id | The release request task ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.Task.id | Number | Task ID. |
| Freshservice.Release.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Release.Task.status | Number | Task status. |
| Freshservice.Release.Task.due_date | Date | Task due date. |
| Freshservice.Release.Task.notify_before | Number | Task notify before. |
| Freshservice.Release.Task.title | String | Task title. |
| Freshservice.Release.Task.description | String | Task description. |
| Freshservice.Release.Task.created_at | Date | Task creation time. |
| Freshservice.Release.Task.updated_at | Date | Task updated at. |
| Freshservice.Release.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Release.Task.group_id | Number | Task group ID. |
| Freshservice.Release.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-release-task-list release_id=40```
#### Context Example
```json
{
    "Freshservice": {
        "Release": {
            "Task": [],
            "id": "40"
        }
    }
}
```

#### Human Readable Output

>### Release
>Showing page 1.
> Current page size: 50.
>**No entries.**


### freshservice-release-task-create

***
Create a new task on a Release in Freshservice.

#### Base Command

`freshservice-release-task-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Required |
| notify_before | Time in seconds before which notification is sent prior to due date (For example 30 minutes, 7 hours and etc). | Required |
| title | Task title. | Required |
| description | Task description. | Required |
| status | Status of the task,. Possible values are: Open, In Progress, Completed. | Optional |
| release_id | The release ID to add a task for (use freshservice-release-list to get the release request ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.Task.id | Number | Task ID. |
| Freshservice.Release.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Release.Task.status | Number | Task status. |
| Freshservice.Release.Task.due_date | Date | Task due date. |
| Freshservice.Release.Task.notify_before | Number | Task notify before. |
| Freshservice.Release.Task.title | String | Task title. |
| Freshservice.Release.Task.description | String | Task description. |
| Freshservice.Release.Task.created_at | Date | Task creation time. |
| Freshservice.Release.Task.updated_at | Date | Task updated at. |
| Freshservice.Release.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Release.Task.group_id | Unknown | Task group ID. |
| Freshservice.Release.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-release-task-create due_date="2020-04-03T10:26:13.067Z" notify_before="2020-05-03T10:26:13.067Z" title=title description=description status=Open release_id=34```
#### Context Example
```json
{
    "Freshservice": {
        "Release": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:18:22Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:18:22Z",
                    "group_id": null,
                    "id": 195,
                    "notify_before": 7200,
                    "status": "Open",
                    "title": "title",
                    "updated_at": "2023-04-13T14:18:22Z",
                    "workspace_id": 2
                }
            ],
            "id": "34"
        }
    }
}
```

#### Human Readable Output

>### Release
>Release Task created successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 195 | description | title | 7200 | Open | false |  | 2023-04-13T14:18:22Z | 2023-04-13T14:18:22Z | 2023-04-17T20:18:22Z |


### freshservice-release-task-update

***
Update an existing task on an existing Release in Freshservice.

#### Base Command

`freshservice-release-task-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| due_date | Task due date (for example YYYY-MM-DDThh:mm). | Optional |
| notify_before | Task notify before (For example 30 minutes, 7 hours and etc). | Optional |
| title | Task title. | Optional |
| description | Task description. | Optional |
| status | Status of the task,. Possible values are: Open, In Progress, Completed. | Optional |
| release_id | The Release ID to update a task for (use freshservice-release-list to get the release request ID). | Required |
| task_id | The Task ID for an update (use freshservice-release-task-list to get the task ID). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Release.Task.id | Number | Task ID. |
| Freshservice.Release.Task.agent_id | Unknown | Task agent ID. |
| Freshservice.Release.Task.status | Number | Task status. |
| Freshservice.Release.Task.due_date | Date | Task due date. |
| Freshservice.Release.Task.notify_before | Number | Task notify before. |
| Freshservice.Release.Task.title | String | Task title. |
| Freshservice.Release.Task.description | String | Task description. |
| Freshservice.Release.Task.created_at | Date | Task creation time. |
| Freshservice.Release.Task.updated_at | Date | Task updated at. |
| Freshservice.Release.Task.closed_at | Unknown | Task closed at. |
| Freshservice.Release.Task.group_id | Unknown | Task group ID. |
| Freshservice.Release.Task.deleted | Boolean | Task deleted. |

#### Command example
```!freshservice-release-task-update description=description status=Open release_id=34 task_id=190```
#### Context Example
```json
{
    "Freshservice": {
        "Release": {
            "Task": [
                {
                    "agent_id": null,
                    "closed_at": null,
                    "created_at": "2023-04-13T14:12:11Z",
                    "custom_fields": {},
                    "deleted": false,
                    "description": "description",
                    "due_date": "2023-04-17T20:12:11Z",
                    "group_id": null,
                    "id": 190,
                    "notify_before": 0,
                    "status": "Open",
                    "title": "Supply lightsabers to all the Jedis",
                    "updated_at": "2023-04-13T14:18:28Z",
                    "workspace_id": 2
                }
            ],
            "id": "34"
        }
    }
}
```

#### Human Readable Output

>### Release
>Release Task updated successfully
>|Id|Description|Title|Notify Before|Status|Deleted|Closed At|Created At|Updated At|Due Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 190 | description | Supply lightsabers to all the Jedis | 0 | Open | false |  | 2023-04-13T14:12:11Z | 2023-04-13T14:18:28Z | 2023-04-17T20:12:11Z |


### freshservice-release-task-delete

***
Delete the task on a Release with the given ID from Freshservice.

#### Base Command

`freshservice-release-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| release_id | The Release ID (use freshservice-release-list to get the release request ID). | Required |
| task_id | The task ID to delete (use freshservice-release-task-list to get the task ID). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!freshservice-release-task-delete release_id=34 task_id=191```
#### Human Readable Output

>Release Task deleted successfully

### freshservice-requester-list

***
Lists all the requesters (information about a user) in a Freshservice account. You can specify 'query' argument or any filter arguments, not both. When providing multiple filter arguments the connection between them will be "AND".

#### Base Command

`freshservice-requester-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| requester_id | The requester ID (use freshservice-agent-list to get the requester ID). | Optional |
| first_name | First name of the requester. | Optional |
| last_name | Last name of the requester. | Optional |
| name | Concatenation of first_name and last_name with single space in-between fields. | Optional |
| job_title | Title of the requester. | Optional |
| primary_email | Email address of the requester. | Optional |
| work_phone_number | Work phone of the requester. | Optional |
| mobile_phone_number | Mobile phone of the requester. | Optional |
| department_id | ID of the department(s) assigned to the requester (use freshservice-department-list to get the department ID). | Optional |
| reporting_manager_id | User ID of the agent's reporting manager (you can use freshservice-agent-list to extract the reporting_manager_id). | Optional |
| time_zone | Requester time zone. | Optional |
| language | Language code(Eg. en, ja-JP). | Optional |
| location_id | ID of the location. | Optional |
| created_at | Date (YYYY-MM-DDThh:mm) when the requester is created. | Optional |
| updated_at | Date (YYYY-MM-DDThh:mm) when the requester is updated. | Optional |
| query | Query to fetch requesters. Use query or other filter arguments, not both. For example "time_zone:'Eastern Time (US &amp; Canada)' AND language:'en'" (Logical operators AND, OR along with parentheses () can be used to group conditions). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Requester.active | Boolean | Requester active. |
| Freshservice.Requester.address | Unknown | Requester address. |
| Freshservice.Requester.background_information | Unknown | Requester background information. |
| Freshservice.Requester.can_see_all_changes_from_associated_departments | Boolean | Requester can see all changes from associated departments. |
| Freshservice.Requester.can_see_all_tickets_from_associated_departments | Boolean | Requester can see all tickets from associated departments. |
| Freshservice.Requester.created_at | Date | Requester creation time. |
| Freshservice.Requester.department_names | Unknown | Requester department names. |
| Freshservice.Requester.external_id | Unknown | Requester external ID. |
| Freshservice.Requester.first_name | String | Requester first name. |
| Freshservice.Requester.has_logged_in | Boolean | Requester has logged in. |
| Freshservice.Requester.id | Date | Requester ID. |
| Freshservice.Requester.is_agent | Boolean | Requester is agent. |
| Freshservice.Requester.job_title | Unknown | Requester job title. |
| Freshservice.Requester.language | String | Requester language. |
| Freshservice.Requester.last_name | Unknown | Requester last name. |
| Freshservice.Requester.location_id | Unknown | Requester location ID. |
| Freshservice.Requester.location_name | Unknown | Requester location name. |
| Freshservice.Requester.mobile_phone_number | Unknown | Requester mobile phone number. |
| Freshservice.Requester.primary_email | String | Requester primary email. |
| Freshservice.Requester.reporting_manager_id | Unknown | Requester reporting manager ID. |
| Freshservice.Requester.time_format | String | Requester time format. |
| Freshservice.Requester.time_zone | String | Requester time zone. |
| Freshservice.Requester.updated_at | Date | Requester updated at. |
| Freshservice.Requester.vip_user | Boolean | Requester vip user. |
| Freshservice.Requester.work_phone_number | Unknown | Requester work phone number. |

#### Command example
```!freshservice-requester-list```
#### Context Example
```json
{
    "Freshservice": {
        "Requester": [
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-15T18:52:53Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "asdasdas",
                "has_logged_in": false,
                "id": 21001894858,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": null,
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-15T18:52:53Z",
                "vip_user": false,
                "work_phone_number": "+975454545"
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-15T17:01:37Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "benasdas",
                "has_logged_in": false,
                "id": 21001894482,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": null,
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-15T17:01:37Z",
                "vip_user": false,
                "work_phone_number": "+972542059588"
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-23T15:44:39Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Email",
                "has_logged_in": false,
                "id": 21001932798,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "email@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-23T15:44:39Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2022-12-25T08:38:05Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Greg",
                "has_logged_in": false,
                "id": 21001397563,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": "Nazarovsky",
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "gregorin@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-01-03T14:17:32Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2022-12-25T08:37:28Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Jack",
                "has_logged_in": false,
                "id": 21001397562,
                "is_agent": false,
                "job_title": "CIO",
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "jack@freshservice.com",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2022-12-25T08:37:28Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-27T13:39:13Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Liorq",
                "has_logged_in": false,
                "id": 21001941102,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "liorq@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-27T13:39:13Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-02T11:48:32Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Liors",
                "has_logged_in": false,
                "id": 21001792073,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "liors@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-02T11:48:32Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": "test data",
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-01T11:51:14Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Ronh",
                "has_logged_in": false,
                "id": 21001789289,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": "hadad",
                "location_id": 21000437322,
                "location_name": "Canada",
                "mobile_phone_number": null,
                "primary_email": "ronh@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-02T14:27:26Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-01-15T14:20:54Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sample",
                "has_logged_in": false,
                "id": 21001523090,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sample@freshservice.com",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-01-15T14:20:54Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-22T11:50:56Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb+change",
                "has_logged_in": false,
                "id": 21001924673,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb+change@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-22T11:50:56Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-22T11:26:44Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb+prblemupdate",
                "has_logged_in": false,
                "id": 21001924652,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb+prblemupdate@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-22T11:26:44Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-22T11:20:36Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb+problem",
                "has_logged_in": false,
                "id": 21001924647,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb+problem@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-22T11:20:36Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-15T16:44:37Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb+t",
                "has_logged_in": false,
                "id": 21001894392,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb+t@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-15T16:44:37Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-14T13:59:02Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb+test",
                "has_logged_in": false,
                "id": 21001853633,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb+test@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-14T13:59:02Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-15T19:46:28Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Sarb21312",
                "has_logged_in": false,
                "id": 21001895008,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "sarb21312@qmasters.co",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-15T19:46:28Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-03-02T16:02:38Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Tal",
                "has_logged_in": false,
                "id": 21001793038,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "tal@gamil.com",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-03-02T16:02:38Z",
                "vip_user": false,
                "work_phone_number": null
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-02-26T16:01:32Z",
                "custom_fields": {},
                "department_ids": [
                    21000263166
                ],
                "department_names": [
                    "IT"
                ],
                "external_id": null,
                "first_name": "Tal",
                "has_logged_in": false,
                "id": 21001776393,
                "is_agent": false,
                "job_title": "CTO",
                "language": "en",
                "last_name": "Gumi",
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "tal@gmail.com",
                "reporting_manager_id": 21001789289,
                "secondary_emails": [
                    "talg+local@qmasters.co"
                ],
                "time_format": "12h",
                "time_zone": "Monterrey",
                "updated_at": "2023-03-02T14:30:27Z",
                "vip_user": false,
                "work_phone_number": "+9725412545488"
            },
            {
                "active": true,
                "address": null,
                "background_information": null,
                "can_see_all_changes_from_associated_departments": false,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-01-15T15:52:00Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "external_id": null,
                "first_name": "Tom",
                "has_logged_in": false,
                "id": 21001523121,
                "is_agent": false,
                "job_title": null,
                "language": "en",
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "mobile_phone_number": null,
                "primary_email": "tom@outerspace.com",
                "reporting_manager_id": null,
                "secondary_emails": [],
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-01-15T15:52:00Z",
                "vip_user": false,
                "work_phone_number": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Requester
>Showing page 1.
> Current page size: 50.
>|Id|First Name|Last Name|Primary Email|Active|Created At|Updated At|Time Zone|Department Id|Department Name|Can See All Tickets From Associated Departments|Can See All Changes From Associated Departments|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 21001894858 | asdasdas |  |  | true | 2023-03-15T18:52:53Z | 2023-03-15T18:52:53Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001894482 | benasdas |  |  | true | 2023-03-15T17:01:37Z | 2023-03-15T17:01:37Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001932798 | Email |  | email@qmasters.co | true | 2023-03-23T15:44:39Z | 2023-03-23T15:44:39Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001397563 | Greg | Nazarovsky | gregorin@qmasters.co | true | 2022-12-25T08:38:05Z | 2023-01-03T14:17:32Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001397562 | Jack |  | jack@freshservice.com | true | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001941102 | Liorq |  | liorq@qmasters.co | true | 2023-03-27T13:39:13Z | 2023-03-27T13:39:13Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001792073 | Liors |  | liors@qmasters.co | true | 2023-03-02T11:48:32Z | 2023-03-02T11:48:32Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001789289 | Ronh | hadad | ronh@qmasters.co | true | 2023-03-01T11:51:14Z | 2023-03-02T14:27:26Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001523090 | Sample |  | sample@freshservice.com | true | 2023-01-15T14:20:54Z | 2023-01-15T14:20:54Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001924673 | Sarb+change |  | sarb+change@qmasters.co | true | 2023-03-22T11:50:56Z | 2023-03-22T11:50:56Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001924652 | Sarb+prblemupdate |  | sarb+prblemupdate@qmasters.co | true | 2023-03-22T11:26:44Z | 2023-03-22T11:26:44Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001924647 | Sarb+problem |  | sarb+problem@qmasters.co | true | 2023-03-22T11:20:36Z | 2023-03-22T11:20:36Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001894392 | Sarb+t |  | sarb+t@qmasters.co | true | 2023-03-15T16:44:37Z | 2023-03-15T16:44:37Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001853633 | Sarb+test |  | sarb+test@qmasters.co | true | 2023-03-14T13:59:02Z | 2023-03-14T13:59:02Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001895008 | Sarb21312 |  | sarb21312@qmasters.co | true | 2023-03-15T19:46:28Z | 2023-03-15T19:46:28Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001793038 | Tal |  | tal@gamil.com | true | 2023-03-02T16:02:38Z | 2023-03-02T16:02:38Z | Eastern Time (US & Canada) |  |  | false | false |
>| 21001776393 | Tal | Gumi | tal@gmail.com | true | 2023-02-26T16:01:32Z | 2023-03-02T14:30:27Z | Monterrey |  |  | false | false |
>| 21001523121 | Tom |  | tom@outerspace.com | true | 2023-01-15T15:52:00Z | 2023-01-15T15:52:00Z | Eastern Time (US & Canada) |  |  | false | false |


### freshservice-agent-list

***
Retrieve a list of all Agents (or specific by ID) in Freshservice. You can specify 'query' argument or any filter arguments, not both. When providing multiple filter arguments the connection between them will be "AND".

#### Base Command

`freshservice-agent-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| agent_id | Agent ID. | Optional |
| first_name | First name of the agent. | Optional |
| last_name | Last name of the agent. | Optional |
| name | Concatenation of first_name and last_name with single space in-between fields. | Optional |
| job_title | Title of the agent. | Optional |
| email | Email address of the agent. | Optional |
| work_phone_number | Work phone of the agent. | Optional |
| mobile_phone_number | Mobile phone of the agent. | Optional |
| department_id | ID of the department(s) assigned to the agent. Use freshservice-department-list to get the agent ID. | Optional |
| reporting_manager_id | User ID of the agent's reporting manager. | Optional |
| time_zone | Agent time zone. | Optional |
| language | Language code(Eg. en, ja-JP). | Optional |
| location_id | ID of the location. | Optional |
| created_at | Date when the agent is created (for example YYYY-MM-DDThh:mm). | Optional |
| updated_at | Date when the agent is updated (for example YYYY-MM-DDThh:mm). | Optional |
| query | Query to fetch agents. Use query or other filter arguments, not both. For example "(department_id:4001 OR department_id:5001) AND (location_id:200 OR location_id:300)". | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Agent.active | Boolean | Agent active. |
| Freshservice.Agent.address | Unknown | Agent address. |
| Freshservice.Agent.auto_assign_status_changed_at | Unknown | Agent auto_assign_status_changed_at. |
| Freshservice.Agent.auto_assign_tickets | Boolean | Agent auto assign tickets. |
| Freshservice.Agent.background_information | Unknown | Agent background information. |
| Freshservice.Agent.can_see_all_tickets_from_associated_departments | Boolean | Agent can see all tickets from associated departments. |
| Freshservice.Agent.created_at | Date | Agent creation time. |
| Freshservice.Agent.department_names | Unknown | Agent department names. |
| Freshservice.Agent.email | String | Agent email. |
| Freshservice.Agent.external_id | Unknown | Agent external ID. |
| Freshservice.Agent.first_name | String | Agent first name. |
| Freshservice.Agent.has_logged_in | Boolean | Agent has logged in. |
| Freshservice.Agent.id | Date | Agent ID. |
| Freshservice.Agent.job_title | Unknown | Agent job title. |
| Freshservice.Agent.language | String | Agent language. |
| Freshservice.Agent.last_active_at | Date | Agent last active at. |
| Freshservice.Agent.last_login_at | Unknown | Agent last login at. |
| Freshservice.Agent.last_name | String | Agent last name. |
| Freshservice.Agent.location_id | Unknown | Agent location ID. |
| Freshservice.Agent.location_name | Unknown | Agent location name. |
| Freshservice.Agent.mobile_phone_number | Unknown | Agent mobile phone number. |
| Freshservice.Agent.occasional | Boolean | Agent occasional. |
| Freshservice.Agent.reporting_manager_id | Unknown | Agent reporting manager ID. |
| Freshservice.Agent.role_ids | Date | Agent role IDs. |
| Freshservice.Agent.role_id | Date | Agent role ID. |
| Freshservice.Agent.assignment_scope | String | Agent roles assignment scope. |
| Freshservice.Agent.workspace_id | Number | Agent roles workspace ID. |
| Freshservice.Agent.signature | String | Agent signature. |
| Freshservice.Agent.time_format | String | Agent time format. |
| Freshservice.Agent.time_zone | String | Agent time zone. |
| Freshservice.Agent.updated_at | Date | Agent updated at. |
| Freshservice.Agent.vip_user | Boolean | Agent vip user. |
| Freshservice.Agent.work_phone_number | Unknown | Agent work phone number. |
| Freshservice.Agent.workspace_ids | Number | Agent workspace IDs. |

#### Command example
```!freshservice-agent-list```
#### Context Example
```json
{
    "Freshservice": {
        "Agent": [
            {
                "active": true,
                "address": null,
                "auto_assign_status_changed_at": "2023-03-13T11:27:46Z",
                "auto_assign_tickets": true,
                "background_information": null,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2022-12-25T08:37:27Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "email": "benim@qmasters.co",
                "external_id": null,
                "first_name": "Beni",
                "group_ids": [
                    21000478053
                ],
                "has_logged_in": true,
                "id": 21001397559,
                "job_title": null,
                "language": "en",
                "last_active_at": "2023-04-04T11:45:58Z",
                "last_login_at": "2023-04-02T14:14:26Z",
                "last_name": "Manela",
                "location_id": null,
                "location_name": null,
                "member_of": [
                    21000478053
                ],
                "mobile_phone_number": null,
                "observer_of": [],
                "occasional": false,
                "reporting_manager_id": null,
                "role_ids": [
                    21000388918,
                    21000388920,
                    21000388932,
                    21000388931
                ],
                "roles": [
                    {
                        "assignment_scope": "entire_helpdesk",
                        "groups": [],
                        "role_id": 21000388918,
                        "workspace_id": 1
                    },
                    {
                        "assignment_scope": "entire_helpdesk",
                        "groups": [],
                        "role_id": 21000388920,
                        "workspace_id": 2
                    },
                    {
                        "assignment_scope": "entire_helpdesk",
                        "groups": [],
                        "role_id": 21000388931,
                        "workspace_id": 3
                    },
                    {
                        "assignment_scope": "entire_helpdesk",
                        "groups": [],
                        "role_id": 21000388932,
                        "workspace_id": 3
                    }
                ],
                "scopes": {},
                "signature": "<p><br></p>\n",
                "time_format": "12h",
                "time_zone": "Athens",
                "updated_at": "2022-12-25T09:53:00Z",
                "vip_user": false,
                "work_phone_number": null,
                "workspace_ids": [
                    2,
                    3
                ]
            },
            {
                "active": false,
                "address": null,
                "auto_assign_status_changed_at": null,
                "auto_assign_tickets": true,
                "background_information": null,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2022-12-25T08:37:28Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "email": "rachel@freshservice.com",
                "external_id": null,
                "first_name": "Rachel",
                "group_ids": [],
                "has_logged_in": false,
                "id": 21001397561,
                "job_title": null,
                "language": "en",
                "last_active_at": null,
                "last_login_at": null,
                "last_name": null,
                "location_id": null,
                "location_name": null,
                "member_of": [],
                "mobile_phone_number": null,
                "observer_of": [],
                "occasional": false,
                "reporting_manager_id": null,
                "role_ids": [],
                "roles": [],
                "scopes": {},
                "signature": null,
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2022-12-25T08:37:28Z",
                "vip_user": false,
                "work_phone_number": null,
                "workspace_ids": []
            },
            {
                "active": true,
                "address": null,
                "auto_assign_status_changed_at": "2023-01-24T09:11:28Z",
                "auto_assign_tickets": true,
                "background_information": null,
                "can_see_all_tickets_from_associated_departments": false,
                "created_at": "2023-01-15T10:06:40Z",
                "custom_fields": {},
                "department_ids": [],
                "department_names": null,
                "email": "talg@qmasters.co",
                "external_id": null,
                "first_name": "Tal",
                "group_ids": [],
                "has_logged_in": true,
                "id": 21001523008,
                "job_title": null,
                "language": "en",
                "last_active_at": "2023-01-24T09:10:50Z",
                "last_login_at": "2023-01-19T11:02:22Z",
                "last_name": "Gumi",
                "location_id": null,
                "location_name": null,
                "member_of": [],
                "mobile_phone_number": null,
                "observer_of": [],
                "occasional": true,
                "reporting_manager_id": null,
                "role_ids": [
                    21000388918
                ],
                "roles": [
                    {
                        "assignment_scope": "entire_helpdesk",
                        "groups": [],
                        "role_id": 21000388918,
                        "workspace_id": 2
                    }
                ],
                "scopes": {},
                "signature": "",
                "time_format": "12h",
                "time_zone": "Eastern Time (US & Canada)",
                "updated_at": "2023-01-15T10:06:40Z",
                "vip_user": false,
                "work_phone_number": null,
                "workspace_ids": [
                    2
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Agent
>Showing page 1.
> Current page size: 50.
>|Id|First Name|Last Name|Email|Active|Created At|Updated At|Time Zone|Language|Can See All Tickets From Associated Departments|Auto Assign Status Changed At|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 21001397559 | Beni | Manela | benim@qmasters.co | true | 2022-12-25T08:37:27Z | 2022-12-25T09:53:00Z | Athens | en | false | 2023-03-13T11:27:46Z |
>| 21001397561 | Rachel |  | rachel@freshservice.com | false | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z | Eastern Time (US & Canada) | en | false |  |
>| 21001523008 | Tal | Gumi | talg@qmasters.co | true | 2023-01-15T10:06:40Z | 2023-01-15T10:06:40Z | Eastern Time (US & Canada) | en | false | 2023-01-24T09:11:28Z |


### freshservice-role-list

***
Lists all the roles in a Freshservice account. Roles allow you to manage access permissions for agents.

#### Base Command

`freshservice-role-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| role_id | The role ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Role.description | String | Role description. |
| Freshservice.Role.id | Date | Role ID. |
| Freshservice.Role.name | String | Role name. |
| Freshservice.Role.created_at | Date | Role creation time. |
| Freshservice.Role.updated_at | Date | Role updated at. |
| Freshservice.Role.default | Boolean | Role default. |
| Freshservice.Role.role_type | Number | Role type. |

#### Command example
```!freshservice-role-list```
#### Context Example
```json
{
    "Freshservice": {
        "Role": [
            {
                "created_at": "2022-12-25T08:37:26Z",
                "default": true,
                "description": "Has complete admin control over the service desk including access to account or billing related information",
                "id": 21000388918,
                "name": "Account Admin",
                "role_type": 1,
                "updated_at": "2022-12-25T08:37:26Z"
            },
            {
                "created_at": "2022-12-25T08:37:26Z",
                "default": true,
                "description": "Can perform all non-admin actions except reporting",
                "id": 21000388919,
                "name": "IT Agent",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:26Z"
            },
            {
                "created_at": "2022-12-25T08:37:26Z",
                "default": true,
                "description": "Can perform all non-admin actions",
                "id": 21000388920,
                "name": "IT Supervisor",
                "role_type": 2,
                "updated_at": "2023-03-15T05:02:39Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, view and create change and have full access for problem module",
                "id": 21000388921,
                "name": "Problem Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, view and create problem release and have full access for change module",
                "id": 21000388922,
                "name": "Change Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, view and create change and have full access for release module",
                "id": 21000388923,
                "name": "Release Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, view problem, change, release and have full access for CMDB module",
                "id": 21000388924,
                "name": "Configuration Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, view problem, change and have full access for Contract module",
                "id": 21000388925,
                "name": "Contract Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities, can view and manage alerts",
                "id": 21000388926,
                "name": "IT Ops Agent",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can view, create and manage projects",
                "id": 21000388927,
                "name": "Project Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can view and work on projects",
                "id": 21000388928,
                "name": "Project Member",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can perform all agent related activities and perform all activities on Purchase Order",
                "id": 21000388929,
                "name": "Procurement Manager",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can work on Tickets, Projects, Solutions, and Announcements. Cannot view reports",
                "id": 21000388930,
                "name": "Business Agent",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:37:57Z",
                "default": true,
                "description": "Can work on Tickets, Projects, Solutions, and Announcements. Can view and manage reports",
                "id": 21000388931,
                "name": "Business Team Supervisor",
                "role_type": 2,
                "updated_at": "2022-12-25T08:37:57Z"
            },
            {
                "created_at": "2022-12-25T08:43:45Z",
                "default": true,
                "description": "Workspace Admin",
                "id": 21000388932,
                "name": "Workspace Admin",
                "role_type": 1,
                "updated_at": "2022-12-25T08:43:45Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Role
>Showing page 1.
> Current page size: 50.
>|Id|Name|Description|Role Type|Default|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 21000388918 | Account Admin | Has complete admin control over the service desk including access to account or billing related information | 1 | true | 2022-12-25T08:37:26Z | 2022-12-25T08:37:26Z |
>| 21000388919 | IT Agent | Can perform all non-admin actions except reporting | 2 | true | 2022-12-25T08:37:26Z | 2022-12-25T08:37:26Z |
>| 21000388920 | IT Supervisor | Can perform all non-admin actions | 2 | true | 2022-12-25T08:37:26Z | 2023-03-15T05:02:39Z |
>| 21000388921 | Problem Manager | Can perform all agent related activities, view and create change and have full access for problem module | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388922 | Change Manager | Can perform all agent related activities, view and create problem release and have full access for change module | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388923 | Release Manager | Can perform all agent related activities, view and create change and have full access for release module | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388924 | Configuration Manager | Can perform all agent related activities, view problem, change, release and have full access for CMDB module | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388925 | Contract Manager | Can perform all agent related activities, view problem, change and have full access for Contract module | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388926 | IT Ops Agent | Can perform all agent related activities, can view and manage alerts | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388927 | Project Manager | Can view, create and manage projects | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388928 | Project Member | Can view and work on projects | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388929 | Procurement Manager | Can perform all agent related activities and perform all activities on Purchase Order | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388930 | Business Agent | Can work on Tickets, Projects, Solutions, and Announcements. Cannot view reports | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388931 | Business Team Supervisor | Can work on Tickets, Projects, Solutions, and Announcements. Can view and manage reports | 2 | true | 2022-12-25T08:37:57Z | 2022-12-25T08:37:57Z |
>| 21000388932 | Workspace Admin | Workspace Admin | 1 | true | 2022-12-25T08:43:45Z | 2022-12-25T08:43:45Z |


### freshservice-vendor-list

***
Lists all the vendors (or specific by ID) in the Freshservice account.

#### Base Command

`freshservice-vendor-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| vendor_id | Vendor ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Vendor.address.line1 | Unknown | Vendor address line1. |
| Freshservice.Vendor.address.city | Unknown | Vendor address city. |
| Freshservice.Vendor.address.state | Unknown | Vendor address state. |
| Freshservice.Vendor.address.country | Unknown | Vendor address country. |
| Freshservice.Vendor.address.zipcode | Unknown | Vendor address zip code. |
| Freshservice.Vendor.id | Date | Vendor ID. |
| Freshservice.Vendor.name | String | Vendor name. |
| Freshservice.Vendor.description | String | Vendor description. |
| Freshservice.Vendor.contact_name | Unknown | Vendor contact name. |
| Freshservice.Vendor.email | Unknown | Vendor email. |
| Freshservice.Vendor.mobile | Unknown | Vendor mobile. |
| Freshservice.Vendor.phone | Unknown | Vendor phone. |
| Freshservice.Vendor.primary_contact_id | Unknown | Vendor primary contact ID. |
| Freshservice.Vendor.created_at | Date | Vendor creation time. |
| Freshservice.Vendor.updated_at | Date | Vendor updated at. |

#### Command example
```!freshservice-vendor-list```
#### Context Example
```json
{
    "Freshservice": {
        "Vendor": [
            {
                "address": {
                    "city": "Cupertino",
                    "country": "United States",
                    "line1": "1 Infinite Loop",
                    "state": "California",
                    "zipcode": "95014"
                },
                "contact_name": null,
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "",
                "email": null,
                "id": 21000275400,
                "mobile": null,
                "name": "Apple",
                "phone": null,
                "primary_contact_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "address": {
                    "city": "Round Rock",
                    "country": "United States",
                    "line1": "1 Dell Way",
                    "state": "Texas",
                    "zipcode": "78664"
                },
                "contact_name": null,
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "",
                "email": null,
                "id": 21000275401,
                "mobile": null,
                "name": "Dell",
                "phone": null,
                "primary_contact_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "address": {
                    "city": "San Mateo",
                    "country": "United States",
                    "line1": "2950 S Delaware St Suite 201",
                    "state": "California",
                    "zipcode": "94401"
                },
                "contact_name": null,
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "",
                "email": null,
                "id": 21000275403,
                "mobile": null,
                "name": "Freshworks",
                "phone": null,
                "primary_contact_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "address": {
                    "city": "Newark",
                    "country": "United States",
                    "line1": "7700 Gateway Blvd",
                    "state": "California",
                    "zipcode": "94560"
                },
                "contact_name": null,
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "",
                "email": null,
                "id": 21000275402,
                "mobile": null,
                "name": "Logitech",
                "phone": null,
                "primary_contact_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "address": {
                    "city": null,
                    "country": null,
                    "line1": null,
                    "state": null,
                    "zipcode": null
                },
                "contact_name": null,
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "",
                "email": null,
                "id": 21000275404,
                "mobile": null,
                "name": "Microsoft",
                "phone": null,
                "primary_contact_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Vendor
>Showing page 1.
> Current page size: 50.
>|Id|Name|Contact Name|Description|Email|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 21000275400 | Apple |  |  |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000275401 | Dell |  |  |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000275403 | Freshworks |  |  |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000275402 | Logitech |  |  |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000275404 | Microsoft |  |  |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |


### freshservice-software-list

***
Lists all the softwares (or specific by ID) in the Freshservice account.

#### Base Command

`freshservice-software-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| software_id | Software ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Software.overview | Unknown | Software application overview. |
| Freshservice.Software.graph_data | Unknown | Software application graph data. |
| Freshservice.Software.last_sync_date | Unknown | Software application last sync date. |
| Freshservice.Software.user_count | Number | Software application user count. |
| Freshservice.Software.installation_count | Number | Software application installation count. |
| Freshservice.Software.id | Date | Software application ID. |
| Freshservice.Software.name | String | Software application name. |
| Freshservice.Software.description | Unknown | Software application description. |
| Freshservice.Software.notes | Unknown | Software application notes. |
| Freshservice.Software.publisher_id | Date | Software application publisher ID. |
| Freshservice.Software.created_at | Date | Software application creation time. |
| Freshservice.Software.updated_at | Date | Software application updated at. |
| Freshservice.Software.workspace_id | Number | Software application workspace ID. |
| Freshservice.Software.application_type | String | Software application application type. |
| Freshservice.Software.status | String | Software application status. |
| Freshservice.Software.managed_by_id | Date | Software application managed by ID. |
| Freshservice.Software.category | Unknown | Software application category. |

#### Command example
```!freshservice-software-list```
#### Context Example
```json
{
    "Freshservice": {
        "Software": [
            {
                "additional_data": {
                    "graph_data": null,
                    "last_sync_date": null,
                    "overview": null
                },
                "application_type": "saas",
                "category": null,
                "created_at": "2022-12-25T08:38:12Z",
                "description": null,
                "id": 21000992114,
                "installation_count": 0,
                "managed_by_id": 21001397563,
                "name": "Freshservice",
                "notes": null,
                "publisher_id": 21000275403,
                "sources": [],
                "status": "managed",
                "updated_at": "2022-12-25T08:38:12Z",
                "user_count": 1,
                "workspace_id": 2
            },
            {
                "additional_data": {
                    "graph_data": null,
                    "last_sync_date": null,
                    "overview": null
                },
                "application_type": "desktop",
                "category": null,
                "created_at": "2022-12-25T08:38:12Z",
                "description": null,
                "id": 21000992115,
                "installation_count": 1,
                "managed_by_id": 21001397563,
                "name": "Microsoft Office 365",
                "notes": null,
                "publisher_id": 21000275404,
                "sources": [],
                "status": "managed",
                "updated_at": "2022-12-25T08:38:12Z",
                "user_count": 1,
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Software
>Showing page 1.
> Current page size: 50.
>|Id|Name|Description|Application Type|Status|Created At|Updated At|Managed By Id|Publisher Id|Workspace Id|User Count|Category|Installation Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 21000992114 | Freshservice |  | saas | managed | 2022-12-25T08:38:12Z | 2022-12-25T08:38:12Z | 21001397563 | 21000275403 | 2 | 1 |  | 0 |
>| 21000992115 | Microsoft Office 365 |  | desktop | managed | 2022-12-25T08:38:12Z | 2022-12-25T08:38:12Z | 21001397563 | 21000275404 | 2 | 1 |  | 1 |


### freshservice-asset-list

***
Lists all the assets (or specific by ID) in the Freshservice account. You can specify 'query' argument or any filter arguments, not both. When providing multiple filter arguments the connection between them will be "AND".

#### Base Command

`freshservice-asset-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| asset_id | Asset ID. | Optional |
| asset_type_id | ID of the asset type. | Optional |
| department_id | ID of the department to which the asset belongs. Use freshservice-department-list to get the agent ID. | Optional |
| location_id | ID of the location. | Optional |
| asset_state | Status of the asset. Possible values are: IN USE, IN STOCK. | Optional |
| user_id | ID of the user to whom the asset is assigned (use freshservice-agent-list to get the agent ID). | Optional |
| agent_id | ID of the agent by whom the asset is managed. Use freshservice-agent-list to get the agent ID. | Optional |
| name | Display name of the asset. | Optional |
| asset_tag | Tag that is assigned to the asset. | Optional |
| created_at | Date when the asset is created (for example YYYY-MM-DDThh:mm). | Optional |
| updated_at | Date when the asset is updated (for example YYYY-MM-DDThh:mm). | Optional |
| serial_number | Serial number of the asset. | Optional |
| query | Query to fetch assets. Use query or other filter arguments, not both. For example "asset_state:'IN STOCK' AND created_at:&gt;'2018-08-10'" (Logical operators AND, OR along with parentheses () can be used to group conditions). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Asset.id | Date | Asset ID. |
| Freshservice.Asset.display_id | Number | Asset display ID. |
| Freshservice.Asset.name | String | Asset name. |
| Freshservice.Asset.description | Unknown | Asset description. |
| Freshservice.Asset.asset_type_id | Date | Asset type ID. |
| Freshservice.Asset.impact | String | Asset impact. |
| Freshservice.Asset.author_type | String | Asset author type. |
| Freshservice.Asset.usage_type | String | Asset usage type. |
| Freshservice.Asset.asset_tag | String | Asset tag. |
| Freshservice.Asset.user_id | Date | Asset user ID. |
| Freshservice.Asset.department_id | Unknown | Asset department ID. |
| Freshservice.Asset.location_id | Unknown | Asset location ID. |
| Freshservice.Asset.agent_id | Unknown | Asset agent ID. |
| Freshservice.Asset.group_id | Unknown | Asset group ID. |
| Freshservice.Asset.assigned_on | Unknown | Asset assigned_on. |
| Freshservice.Asset.created_at | Date | Asset creation time. |
| Freshservice.Asset.updated_at | Date | Asset updated at. |
| Freshservice.Asset.end_of_life | Date | Asset end of life. |
| Freshservice.Asset.workspace_id | Number | Asset workspace ID. |

#### Command example
```!freshservice-asset-list```
#### Context Example
```json
{
    "Freshservice": {
        "Asset": [
            {
                "agent_id": null,
                "asset_tag": "ASSET-4",
                "asset_type_id": 21002421495,
                "assigned_on": "2023-01-19T11:08:00Z",
                "author_type": "User",
                "created_at": "2023-01-19T11:08:57Z",
                "department_id": null,
                "description": null,
                "discovery_enabled": true,
                "display_id": 4,
                "end_of_life": null,
                "group_id": null,
                "id": 21001187595,
                "impact": "low",
                "location_id": null,
                "name": "monitor",
                "updated_at": "2023-01-19T11:08:57Z",
                "usage_type": "permanent",
                "user_id": 21001397559,
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "asset_tag": "ASSET-3",
                "asset_type_id": 21002421487,
                "assigned_on": null,
                "author_type": "User",
                "created_at": "2022-12-25T08:38:11Z",
                "department_id": null,
                "description": null,
                "discovery_enabled": true,
                "display_id": 3,
                "end_of_life": "2026-12-25",
                "group_id": null,
                "id": 21001118375,
                "impact": "low",
                "location_id": null,
                "name": "Logitech Mouse",
                "updated_at": "2022-12-25T08:38:11Z",
                "usage_type": "permanent",
                "user_id": null,
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "asset_tag": "ASSET-2",
                "asset_type_id": 21002421495,
                "assigned_on": null,
                "author_type": "User",
                "created_at": "2022-12-25T08:38:11Z",
                "department_id": null,
                "description": null,
                "discovery_enabled": true,
                "display_id": 2,
                "end_of_life": "2027-12-25",
                "group_id": null,
                "id": 21001118374,
                "impact": "low",
                "location_id": null,
                "name": "Dell Monitor",
                "updated_at": "2022-12-25T08:38:11Z",
                "usage_type": "permanent",
                "user_id": null,
                "workspace_id": 2
            },
            {
                "agent_id": null,
                "asset_tag": "ASSET-1",
                "asset_type_id": 21002421523,
                "assigned_on": null,
                "author_type": "User",
                "created_at": "2022-12-25T08:38:11Z",
                "department_id": null,
                "description": null,
                "discovery_enabled": true,
                "display_id": 1,
                "end_of_life": "2025-12-25",
                "group_id": null,
                "id": 21001118373,
                "impact": "medium",
                "location_id": null,
                "name": "Andrea's Laptop",
                "updated_at": "2022-12-25T08:38:11Z",
                "usage_type": "permanent",
                "user_id": 21001397563,
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset
>Showing page 1.
> Current page size: 50.
>|Display Id|Name|Description|Asset Type Id|Impact|Author Type|Usage Type|Created At|Updated At|End Of Life|
>|---|---|---|---|---|---|---|---|---|---|
>| 4 | monitor |  | 21002421495 | low | User | permanent | 2023-01-19T11:08:57Z | 2023-01-19T11:08:57Z |  |
>| 3 | Logitech Mouse |  | 21002421487 | low | User | permanent | 2022-12-25T08:38:11Z | 2022-12-25T08:38:11Z | 2026-12-25 |
>| 2 | Dell Monitor |  | 21002421495 | low | User | permanent | 2022-12-25T08:38:11Z | 2022-12-25T08:38:11Z | 2027-12-25 |
>| 1 | Andrea's Laptop |  | 21002421523 | medium | User | permanent | 2022-12-25T08:38:11Z | 2022-12-25T08:38:11Z | 2025-12-25 |


### freshservice-purchase-order-list

***
Lists all the purchase orders (or specific by ID) in a Freshservice account.

#### Base Command

`freshservice-purchase-order-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| purchase_order_id | Purchase order ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.PurchaseOrder.id | Number | Purchase order ID. |
| Freshservice.PurchaseOrder.name | String | Purchase order name. |
| Freshservice.PurchaseOrder.po_number | String | Purchase order number. |
| Freshservice.PurchaseOrder.total_cost | Number | Purchase order total cost. |
| Freshservice.PurchaseOrder.expected_delivery_date | Date | Purchase order expected delivery date. |
| Freshservice.PurchaseOrder.created_at | Date | Purchase order creation time. |
| Freshservice.PurchaseOrder.updated_at | Date | Purchase order updated at. |
| Freshservice.PurchaseOrder.vendor_id | Date | Purchase order vendor ID. |
| Freshservice.PurchaseOrder.department_id | Unknown | Purchase order department ID. |
| Freshservice.PurchaseOrder.created_by | Date | Purchase order created by. |
| Freshservice.PurchaseOrder.status | Number | Purchase order status. |
| Freshservice.PurchaseOrder.workspace_id | Number | Purchase order workspace ID. |

#### Command example
```!freshservice-purchase-order-list```
#### Context Example
```json
{
    "Freshservice": {
        "PurchaseOrder": [
            {
                "created_at": "2023-03-02T14:12:39Z",
                "created_by": 21001397559,
                "department_id": null,
                "expected_delivery_date": null,
                "id": 3,
                "name": "TeetForBen",
                "po_number": "PO-2",
                "status": "Open",
                "total_cost": 500,
                "updated_at": "2023-03-02T14:12:39Z",
                "vendor_id": 21000275404,
                "workspace_id": 2
            },
            {
                "created_at": "2022-12-25T08:38:11Z",
                "created_by": 21001397559,
                "department_id": null,
                "expected_delivery_date": "2022-12-27T05:00:00Z",
                "id": 1,
                "name": "Purchase Order for Dell laptops",
                "po_number": "PO-1",
                "status": "Cancelled",
                "total_cost": 11030,
                "updated_at": "2023-03-02T14:34:48Z",
                "vendor_id": 21000275401,
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### PurchaseOrder
>Showing page 1.
> Current page size: 50.
>|Id|Name|Vendor Id|Po Number|Total Cost|Status|Created At|Updated At|Expected Delivery Date|
>|---|---|---|---|---|---|---|---|---|
>| 3 | TeetForBen | 21000275404 | PO-2 | 500.0 | Open | 2023-03-02T14:12:39Z | 2023-03-02T14:12:39Z |  |
>| 1 | Purchase Order for Dell laptops | 21000275401 | PO-1 | 11030.0 | Cancelled | 2022-12-25T08:38:11Z | 2023-03-02T14:34:48Z | 2022-12-27T05:00:00Z |


### freshservice-agent-group-list

***
Lists all the agent groups (or specific by ID) in a Freshservice account.

#### Base Command

`freshservice-agent-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| agent_group_id | Agent group ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.AgentGroup.id | Number | Agent groupr ID. |
| Freshservice.AgentGroup.name | String | Agent group name. |
| Freshservice.AgentGroup.description | String | Agent group description. |
| Freshservice.AgentGroup.auto_ticket_assign | String | Agent group auto ticket assign. |
| Freshservice.AgentGroup.workspace_id | Number | Agent group workspace ID. |
| Freshservice.AgentGroup.created_at | Date | Agent group creation time. |
| Freshservice.AgentGroup.updated_at | Date | Agent group updated at. |
| Freshservice.AgentGroup.agent_ids | String | Agent group agent IDs. |
| Freshservice.AgentGroup.members | String | Agent group members. |
| Freshservice.AgentGroup.observers | String | Agent group observers. |
| Freshservice.AgentGroup.unassigned_for | String | Agent group unassigned for. |

#### Command example
```!freshservice-agent-group-list```
#### Context Example
```json
{
    "Freshservice": {
        "AgentGroup": [
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:43:46Z",
                "description": "Applications Management Team",
                "escalate_to": null,
                "id": 21000478062,
                "members": [],
                "name": "General - Applications Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:43:46Z",
                "workspace_id": 3
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:43:46Z",
                "description": "Equipment Management Team",
                "escalate_to": null,
                "id": 21000478061,
                "members": [],
                "name": "General - Equipment Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:43:46Z",
                "workspace_id": 3
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:43:46Z",
                "description": "Request Management Team",
                "escalate_to": null,
                "id": 21000478063,
                "members": [],
                "name": "General - Request Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:43:46Z",
                "workspace_id": 3
            },
            {
                "agent_ids": [
                    21001397559
                ],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Capacity Management Team",
                "escalate_to": null,
                "id": 21000478053,
                "members": [
                    21001397559
                ],
                "name": "IT - Capacity Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": "15m",
                "updated_at": "2023-02-26T15:40:54Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Change Management Team",
                "escalate_to": null,
                "id": 21000478049,
                "members": [],
                "name": "IT - Change Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Database Management Team",
                "escalate_to": null,
                "id": 21000478051,
                "members": [],
                "name": "IT - Database Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Hardware Management Team",
                "escalate_to": null,
                "id": 21000478052,
                "members": [],
                "name": "IT - Hardware Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Helpdesk Monitoring Team",
                "escalate_to": null,
                "id": 21000478058,
                "members": [],
                "name": "IT - Helpdesk Monitoring Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Incident Management Team",
                "escalate_to": null,
                "id": 21000478045,
                "members": [],
                "name": "IT - Incident Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Major Incident Management Team",
                "escalate_to": null,
                "id": 21000478046,
                "members": [],
                "name": "IT - Major Incident Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Network Team",
                "escalate_to": null,
                "id": 21000478057,
                "members": [],
                "name": "IT - Network Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Problem Management Team",
                "escalate_to": null,
                "id": 21000478048,
                "members": [],
                "name": "IT - Problem Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Release Management Team",
                "escalate_to": null,
                "id": 21000478050,
                "members": [],
                "name": "IT - Release Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Service Design Team",
                "escalate_to": null,
                "id": 21000478055,
                "members": [],
                "name": "IT - Service Design Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Service Request Fulfillment Team",
                "escalate_to": null,
                "id": 21000478047,
                "members": [],
                "name": "IT - Service Request Fulfillment Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Software Team",
                "escalate_to": null,
                "id": 21000478056,
                "members": [],
                "name": "IT - Software Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            },
            {
                "agent_ids": [],
                "auto_ticket_assign": false,
                "business_hours_id": null,
                "created_at": "2022-12-25T08:37:30Z",
                "description": "Supplier Management Team",
                "escalate_to": null,
                "id": 21000478054,
                "members": [],
                "name": "IT - Supplier Management Team",
                "observers": [],
                "ocs_schedule_id": null,
                "unassigned_for": null,
                "updated_at": "2022-12-25T08:37:30Z",
                "workspace_id": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### AgentGroup
>Showing page 1.
> Current page size: 50.
>|Id|Name|Description|Members|Observers|Agent Ids|Created At|Updated At|Auto Ticket Assign|
>|---|---|---|---|---|---|---|---|---|
>| 21000478062 | General - Applications Management Team | Applications Management Team |  |  |  | 2022-12-25T08:43:46Z | 2022-12-25T08:43:46Z | false |
>| 21000478061 | General - Equipment Management Team | Equipment Management Team |  |  |  | 2022-12-25T08:43:46Z | 2022-12-25T08:43:46Z | false |
>| 21000478063 | General - Request Management Team | Request Management Team |  |  |  | 2022-12-25T08:43:46Z | 2022-12-25T08:43:46Z | false |
>| 21000478053 | IT - Capacity Management Team | Capacity Management Team | 21001397559 |  | 21001397559 | 2022-12-25T08:37:30Z | 2023-02-26T15:40:54Z | false |
>| 21000478049 | IT - Change Team | Change Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478051 | IT - Database Team | Database Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478052 | IT - Hardware Team | Hardware Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478058 | IT - Helpdesk Monitoring Team | Helpdesk Monitoring Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478045 | IT - Incident Team | Incident Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478046 | IT - Major Incident Team | Major Incident Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478057 | IT - Network Team | Network Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478048 | IT - Problem Management Team | Problem Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478050 | IT - Release Team | Release Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478055 | IT - Service Design Team | Service Design Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478047 | IT - Service Request Fulfillment Team | Service Request Fulfillment Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478056 | IT - Software Team | Software Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |
>| 21000478054 | IT - Supplier Management Team | Supplier Management Team |  |  |  | 2022-12-25T08:37:30Z | 2022-12-25T08:37:30Z | false |


### freshservice-department-list

***
Lists all the departments (or specific by ID) in a Freshservice account.

#### Base Command

`freshservice-department-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| department_id | Department ID. | Optional |
| name | Name of the department. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.Department.id | Number | Department ID. |
| Freshservice.Department.name | String | Department name. |
| Freshservice.Department.description | String | Department description. |
| Freshservice.Department.custom_fields | String | Department custom fields. |
| Freshservice.Department.domains | String | Department domains. |
| Freshservice.Department.created_at | Date | Department creation time. |
| Freshservice.Department.updated_at | Date | Department updated at. |
| Freshservice.Department.prime_user_id | Number | Department prime user ID. |
| Freshservice.Department.head_user_id | Number | Department head user ID. |

#### Command example
```!freshservice-department-list```
#### Context Example
```json
{
    "Freshservice": {
        "Department": [
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "Support Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263162,
                "name": "Customer Support",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2023-02-08T09:59:16Z",
                "custom_fields": {},
                "description": "Beast, Being and Spirit Divisions, and Pest Advisory Bureau.",
                "domains": [
                    "creatures.ministryofmagic.gov"
                ],
                "head_user_id": null,
                "id": 21000315199,
                "name": "Department for the Regulation and Control of Magical Creatures",
                "prime_user_id": null,
                "updated_at": "2023-02-08T09:59:16Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "Development Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263160,
                "name": "Development",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "Finance Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263163,
                "name": "Finance",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "HR Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263164,
                "name": "HR",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "IT Service Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263166,
                "name": "IT",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "Operations Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263165,
                "name": "Operations",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            },
            {
                "created_at": "2022-12-25T08:37:58Z",
                "custom_fields": {},
                "description": "Sales Team",
                "domains": [],
                "head_user_id": null,
                "id": 21000263161,
                "name": "Sales",
                "prime_user_id": null,
                "updated_at": "2022-12-25T08:37:58Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Department
>Showing page 1.
> Current page size: 50.
>|Id|Name|Description|Domains|Created At|Updated At|
>|---|---|---|---|---|---|
>| 21000263162 | Customer Support | Support Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000315199 | Department for the Regulation and Control of Magical Creatures | Beast, Being and Spirit Divisions, and Pest Advisory Bureau. | creatures.ministryofmagic.gov | 2023-02-08T09:59:16Z | 2023-02-08T09:59:16Z |
>| 21000263160 | Development | Development Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000263163 | Finance | Finance Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000263164 | HR | HR Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000263166 | IT | IT Service Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000263165 | Operations | Operations Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |
>| 21000263161 | Sales | Sales Team |  | 2022-12-25T08:37:58Z | 2022-12-25T08:37:58Z |


### freshservice-requester-field-list

***
Lists all the Requester fields in a Freshservice account.

#### Base Command

`freshservice-requester-field-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Freshservice.RequesterField.id | Number | Requester fields ID. |
| Freshservice.RequesterField.name | String | Requester fields name. |
| Freshservice.RequesterField.label | String | Requester fields label. |
| Freshservice.RequesterField.position | Number | Requester fields position. |
| Freshservice.RequesterField.type | String | Requester fields type. |
| Freshservice.RequesterField.created_at | Date | Requester fields creation time. |
| Freshservice.RequesterField.updated_at | Date | Requester fields updated at. |
| Freshservice.RequesterField.label_for_requesters | String | Requester field label for. |
| Freshservice.RequesterField.choices | String | Requester fields choices. |

#### Command example
```!freshservice-requester-field-list```
#### Context Example
```json
{
    "Freshservice": {
        "RequesterField": [
            {
                "created_at": "2022-12-25T08:37:27Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": true,
                "id": 21000497683,
                "label": "First Name",
                "label_for_requesters": "First Name",
                "name": "first_name",
                "position": 1,
                "requesters_can_edit": true,
                "required_for_agents": true,
                "required_for_requesters": true,
                "type": "default_first_name",
                "updated_at": "2022-12-25T08:37:27Z"
            },
            {
                "created_at": "2022-12-25T08:37:27Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": true,
                "id": 21000497684,
                "label": "Last Name",
                "label_for_requesters": "Last Name",
                "name": "last_name",
                "position": 2,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_last_name",
                "updated_at": "2022-12-25T08:37:27Z"
            },
            {
                "created_at": "2022-12-25T08:37:27Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497685,
                "label": "Title",
                "label_for_requesters": "Title",
                "name": "job_title",
                "position": 3,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_job_title",
                "updated_at": "2022-12-25T08:37:27Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": true,
                "id": 21000497686,
                "label": "Email",
                "label_for_requesters": "Email",
                "name": "email",
                "position": 4,
                "requesters_can_edit": false,
                "required_for_agents": true,
                "required_for_requesters": true,
                "type": "default_email",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497687,
                "label": "Work Phone",
                "label_for_requesters": "Work Phone",
                "name": "phone",
                "position": 5,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_phone",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497688,
                "label": "Mobile Phone",
                "label_for_requesters": "Mobile Phone",
                "name": "mobile",
                "position": 6,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_mobile",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497689,
                "label": "Department",
                "label_for_requesters": "Department",
                "name": "department",
                "position": 7,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_department",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497690,
                "label": "Can see all tickets from this department",
                "label_for_requesters": "Can see all tickets from this department",
                "name": "department_head",
                "position": 8,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_department_head",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497691,
                "label": "Reporting Manager",
                "label_for_requesters": "Reporting Manager",
                "name": "reporting_manager",
                "position": 9,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_reporting_manager",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497692,
                "label": "Address",
                "label_for_requesters": "Address",
                "name": "address",
                "position": 10,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_address",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "choices": {
                    "Abu Dhabi": "(GMT+04:00) Abu Dhabi",
                    "Adelaide": "(GMT+09:30) Adelaide",
                    "Alaska": "(GMT-09:00) Alaska",
                    "Almaty": "(GMT+06:00) Almaty",
                    "American Samoa": "(GMT-11:00) American Samoa",
                    "Amsterdam": "(GMT+01:00) Amsterdam",
                    "Arizona": "(GMT-07:00) Arizona",
                    "Astana": "(GMT+06:00) Astana",
                    "Athens": "(GMT+02:00) Athens",
                    "Atlantic Time (Canada)": "(GMT-04:00) Atlantic Time (Canada)",
                    "Auckland": "(GMT+12:00) Auckland",
                    "Azores": "(GMT-01:00) Azores",
                    "Baghdad": "(GMT+03:00) Baghdad",
                    "Baku": "(GMT+04:00) Baku",
                    "Bangkok": "(GMT+07:00) Bangkok",
                    "Beijing": "(GMT+08:00) Beijing",
                    "Belgrade": "(GMT+01:00) Belgrade",
                    "Berlin": "(GMT+01:00) Berlin",
                    "Bern": "(GMT+01:00) Bern",
                    "Bogota": "(GMT-05:00) Bogota",
                    "Brasilia": "(GMT-03:00) Brasilia",
                    "Bratislava": "(GMT+01:00) Bratislava",
                    "Brisbane": "(GMT+10:00) Brisbane",
                    "Brussels": "(GMT+01:00) Brussels",
                    "Bucharest": "(GMT+02:00) Bucharest",
                    "Budapest": "(GMT+01:00) Budapest",
                    "Buenos Aires": "(GMT-03:00) Buenos Aires",
                    "Cairo": "(GMT+02:00) Cairo",
                    "Canberra": "(GMT+10:00) Canberra",
                    "Cape Verde Is.": "(GMT-01:00) Cape Verde Is.",
                    "Caracas": "(GMT-04:00) Caracas",
                    "Casablanca": "(GMT+00:00) Casablanca",
                    "Central America": "(GMT-06:00) Central America",
                    "Central Time (US & Canada)": "(GMT-06:00) Central Time (US & Canada)",
                    "Chatham Is.": "(GMT+12:45) Chatham Is.",
                    "Chennai": "(GMT+05:30) Chennai",
                    "Chihuahua": "(GMT-06:00) Chihuahua",
                    "Chongqing": "(GMT+08:00) Chongqing",
                    "Copenhagen": "(GMT+01:00) Copenhagen",
                    "Darwin": "(GMT+09:30) Darwin",
                    "Dhaka": "(GMT+06:00) Dhaka",
                    "Dublin": "(GMT+00:00) Dublin",
                    "Eastern Time (US & Canada)": "(GMT-05:00) Eastern Time (US & Canada)",
                    "Edinburgh": "(GMT+00:00) Edinburgh",
                    "Ekaterinburg": "(GMT+05:00) Ekaterinburg",
                    "Fiji": "(GMT+12:00) Fiji",
                    "Georgetown": "(GMT-04:00) Georgetown",
                    "Greenland": "(GMT-02:00) Greenland",
                    "Guadalajara": "(GMT-06:00) Guadalajara",
                    "Guam": "(GMT+10:00) Guam",
                    "Hanoi": "(GMT+07:00) Hanoi",
                    "Harare": "(GMT+02:00) Harare",
                    "Hawaii": "(GMT-10:00) Hawaii",
                    "Helsinki": "(GMT+02:00) Helsinki",
                    "Hobart": "(GMT+10:00) Hobart",
                    "Hong Kong": "(GMT+08:00) Hong Kong",
                    "Indiana (East)": "(GMT-05:00) Indiana (East)",
                    "International Date Line West": "(GMT-12:00) International Date Line West",
                    "Irkutsk": "(GMT+08:00) Irkutsk",
                    "Islamabad": "(GMT+05:00) Islamabad",
                    "Istanbul": "(GMT+03:00) Istanbul",
                    "Jakarta": "(GMT+07:00) Jakarta",
                    "Jerusalem": "(GMT+02:00) Jerusalem",
                    "Kabul": "(GMT+04:30) Kabul",
                    "Kaliningrad": "(GMT+02:00) Kaliningrad",
                    "Kamchatka": "(GMT+12:00) Kamchatka",
                    "Karachi": "(GMT+05:00) Karachi",
                    "Kathmandu": "(GMT+05:45) Kathmandu",
                    "Kolkata": "(GMT+05:30) Kolkata",
                    "Krasnoyarsk": "(GMT+07:00) Krasnoyarsk",
                    "Kuala Lumpur": "(GMT+08:00) Kuala Lumpur",
                    "Kuwait": "(GMT+03:00) Kuwait",
                    "Kyiv": "(GMT+02:00) Kyiv",
                    "La Paz": "(GMT-04:00) La Paz",
                    "Lima": "(GMT-05:00) Lima",
                    "Lisbon": "(GMT+00:00) Lisbon",
                    "Ljubljana": "(GMT+01:00) Ljubljana",
                    "London": "(GMT+00:00) London",
                    "Madrid": "(GMT+01:00) Madrid",
                    "Magadan": "(GMT+11:00) Magadan",
                    "Marshall Is.": "(GMT+12:00) Marshall Is.",
                    "Mazatlan": "(GMT-07:00) Mazatlan",
                    "Melbourne": "(GMT+10:00) Melbourne",
                    "Mexico City": "(GMT-06:00) Mexico City",
                    "Mid-Atlantic": "(GMT-02:00) Mid-Atlantic",
                    "Midway Island": "(GMT-11:00) Midway Island",
                    "Minsk": "(GMT+03:00) Minsk",
                    "Monrovia": "(GMT+00:00) Monrovia",
                    "Monterrey": "(GMT-06:00) Monterrey",
                    "Montevideo": "(GMT-03:00) Montevideo",
                    "Moscow": "(GMT+03:00) Moscow",
                    "Mountain Time (US & Canada)": "(GMT-07:00) Mountain Time (US & Canada)",
                    "Mumbai": "(GMT+05:30) Mumbai",
                    "Muscat": "(GMT+04:00) Muscat",
                    "Nairobi": "(GMT+03:00) Nairobi",
                    "New Caledonia": "(GMT+11:00) New Caledonia",
                    "New Delhi": "(GMT+05:30) New Delhi",
                    "Newfoundland": "(GMT-03:30) Newfoundland",
                    "Novosibirsk": "(GMT+07:00) Novosibirsk",
                    "Nuku'alofa": "(GMT+13:00) Nuku'alofa",
                    "Osaka": "(GMT+09:00) Osaka",
                    "Pacific Time (US & Canada)": "(GMT-08:00) Pacific Time (US & Canada)",
                    "Paris": "(GMT+01:00) Paris",
                    "Perth": "(GMT+08:00) Perth",
                    "Port Moresby": "(GMT+10:00) Port Moresby",
                    "Prague": "(GMT+01:00) Prague",
                    "Pretoria": "(GMT+02:00) Pretoria",
                    "Puerto Rico": "(GMT-04:00) Puerto Rico",
                    "Quito": "(GMT-05:00) Quito",
                    "Rangoon": "(GMT+06:30) Rangoon",
                    "Riga": "(GMT+02:00) Riga",
                    "Riyadh": "(GMT+03:00) Riyadh",
                    "Rome": "(GMT+01:00) Rome",
                    "Samara": "(GMT+04:00) Samara",
                    "Samoa": "(GMT+13:00) Samoa",
                    "Santiago": "(GMT-04:00) Santiago",
                    "Sapporo": "(GMT+09:00) Sapporo",
                    "Sarajevo": "(GMT+01:00) Sarajevo",
                    "Saskatchewan": "(GMT-06:00) Saskatchewan",
                    "Seoul": "(GMT+09:00) Seoul",
                    "Singapore": "(GMT+08:00) Singapore",
                    "Skopje": "(GMT+01:00) Skopje",
                    "Sofia": "(GMT+02:00) Sofia",
                    "Solomon Is.": "(GMT+11:00) Solomon Is.",
                    "Srednekolymsk": "(GMT+11:00) Srednekolymsk",
                    "Sri Jayawardenepura": "(GMT+05:30) Sri Jayawardenepura",
                    "St. Petersburg": "(GMT+03:00) St. Petersburg",
                    "Stockholm": "(GMT+01:00) Stockholm",
                    "Sydney": "(GMT+10:00) Sydney",
                    "Taipei": "(GMT+08:00) Taipei",
                    "Tallinn": "(GMT+02:00) Tallinn",
                    "Tashkent": "(GMT+05:00) Tashkent",
                    "Tbilisi": "(GMT+04:00) Tbilisi",
                    "Tehran": "(GMT+03:30) Tehran",
                    "Tijuana": "(GMT-08:00) Tijuana",
                    "Tokelau Is.": "(GMT+13:00) Tokelau Is.",
                    "Tokyo": "(GMT+09:00) Tokyo",
                    "UTC": "(GMT+00:00) UTC",
                    "Ulaanbaatar": "(GMT+08:00) Ulaanbaatar",
                    "Urumqi": "(GMT+06:00) Urumqi",
                    "Vienna": "(GMT+01:00) Vienna",
                    "Vilnius": "(GMT+02:00) Vilnius",
                    "Vladivostok": "(GMT+10:00) Vladivostok",
                    "Volgograd": "(GMT+03:00) Volgograd",
                    "Warsaw": "(GMT+01:00) Warsaw",
                    "Wellington": "(GMT+12:00) Wellington",
                    "West Central Africa": "(GMT+01:00) West Central Africa",
                    "Yakutsk": "(GMT+09:00) Yakutsk",
                    "Yerevan": "(GMT+04:00) Yerevan",
                    "Zagreb": "(GMT+01:00) Zagreb",
                    "Zurich": "(GMT+01:00) Zurich"
                },
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497693,
                "label": "Time Zone",
                "label_for_requesters": "Time Zone",
                "name": "time_zone",
                "position": 11,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_time_zone",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "choices": [],
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497694,
                "label": "Time Format",
                "label_for_requesters": "Time Format",
                "name": "time_format",
                "position": 12,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_time_format",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "choices": {
                    "ar": "Arabic",
                    "ca": "Catalan",
                    "cs": "Czech",
                    "cy-GB": "Welsh",
                    "da": "Danish",
                    "de": "German",
                    "en": "English",
                    "es": "Spanish",
                    "es-LA": "Spanish (Latin America)",
                    "et": "Estonian",
                    "fi": "Finnish",
                    "fr": "French",
                    "he": "Hebrew",
                    "hr": "Croatian",
                    "hu": "Hungarian",
                    "id": "Indonesian",
                    "it": "Italian",
                    "ja-JP": "Japanese",
                    "ko": "Korean",
                    "lv-LV": "Latvian",
                    "nb-NO": "Norwegian",
                    "nl": "Dutch",
                    "pl": "Polish",
                    "pt-BR": "Portuguese (BR)",
                    "pt-PT": "Portuguese/Portugal",
                    "ro": "Romanian",
                    "ru-RU": "Russian",
                    "sk": "Slovak",
                    "sl": "Slovenian",
                    "sv-SE": "Swedish",
                    "th": "Thai",
                    "tr": "Turkish",
                    "uk": "Ukrainian",
                    "vi": "Vietnamese",
                    "zh-CN": "Chinese",
                    "zh-TW": "Traditional Chinese"
                },
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497695,
                "label": "Language",
                "label_for_requesters": "Language",
                "name": "language",
                "position": 13,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_language",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497696,
                "label": "Mark as VIP",
                "label_for_requesters": "Mark as VIP",
                "name": "vip_user",
                "position": 14,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_vip_user",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "choices": [],
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": true,
                "editable_in_signup": false,
                "id": 21000497697,
                "label": "Location",
                "label_for_requesters": "Location",
                "name": "location_id",
                "position": 15,
                "requesters_can_edit": true,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_location_id",
                "updated_at": "2022-12-25T08:37:28Z"
            },
            {
                "created_at": "2022-12-25T08:37:28Z",
                "default": true,
                "displayed_for_requesters": false,
                "editable_in_signup": false,
                "id": 21000497698,
                "label": "Background Information",
                "label_for_requesters": "Background Information",
                "name": "description",
                "position": 16,
                "requesters_can_edit": false,
                "required_for_agents": false,
                "required_for_requesters": false,
                "type": "default_description",
                "updated_at": "2022-12-25T08:37:28Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### RequesterField
>Showing page 1.
> Current page size: None.
>|Id|Name|Label|Position|Type|Label For Requesters|Choices|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 21000497683 | first_name | First Name | 1 | default_first_name | First Name |  | 2022-12-25T08:37:27Z | 2022-12-25T08:37:27Z |
>| 21000497684 | last_name | Last Name | 2 | default_last_name | Last Name |  | 2022-12-25T08:37:27Z | 2022-12-25T08:37:27Z |
>| 21000497685 | job_title | Title | 3 | default_job_title | Title |  | 2022-12-25T08:37:27Z | 2022-12-25T08:37:27Z |
>| 21000497686 | email | Email | 4 | default_email | Email |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497687 | phone | Work Phone | 5 | default_phone | Work Phone |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497688 | mobile | Mobile Phone | 6 | default_mobile | Mobile Phone |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497689 | department | Department | 7 | default_department | Department |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497690 | department_head | Can see all tickets from this department | 8 | default_department_head | Can see all tickets from this department |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497691 | reporting_manager | Reporting Manager | 9 | default_reporting_manager | Reporting Manager |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497692 | address | Address | 10 | default_address | Address |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497693 | time_zone | Time Zone | 11 | default_time_zone | Time Zone | International Date Line West: (GMT-12:00) International Date Line West<br/>American Samoa: (GMT-11:00) American Samoa<br/>Midway Island: (GMT-11:00) Midway Island<br/>Hawaii: (GMT-10:00) Hawaii<br/>Alaska: (GMT-09:00) Alaska<br/>Pacific Time (US & Canada): (GMT-08:00) Pacific Time (US & Canada)<br/>Tijuana: (GMT-08:00) Tijuana<br/>Arizona: (GMT-07:00) Arizona<br/>Mazatlan: (GMT-07:00) Mazatlan<br/>Mountain Time (US & Canada): (GMT-07:00) Mountain Time (US & Canada)<br/>Central America: (GMT-06:00) Central America<br/>Central Time (US & Canada): (GMT-06:00) Central Time (US & Canada)<br/>Chihuahua: (GMT-06:00) Chihuahua<br/>Guadalajara: (GMT-06:00) Guadalajara<br/>Mexico City: (GMT-06:00) Mexico City<br/>Monterrey: (GMT-06:00) Monterrey<br/>Saskatchewan: (GMT-06:00) Saskatchewan<br/>Bogota: (GMT-05:00) Bogota<br/>Eastern Time (US & Canada): (GMT-05:00) Eastern Time (US & Canada)<br/>Indiana (East): (GMT-05:00) Indiana (East)<br/>Lima: (GMT-05:00) Lima<br/>Quito: (GMT-05:00) Quito<br/>Atlantic Time (Canada): (GMT-04:00) Atlantic Time (Canada)<br/>Caracas: (GMT-04:00) Caracas<br/>Georgetown: (GMT-04:00) Georgetown<br/>La Paz: (GMT-04:00) La Paz<br/>Puerto Rico: (GMT-04:00) Puerto Rico<br/>Santiago: (GMT-04:00) Santiago<br/>Newfoundland: (GMT-03:30) Newfoundland<br/>Brasilia: (GMT-03:00) Brasilia<br/>Buenos Aires: (GMT-03:00) Buenos Aires<br/>Montevideo: (GMT-03:00) Montevideo<br/>Greenland: (GMT-02:00) Greenland<br/>Mid-Atlantic: (GMT-02:00) Mid-Atlantic<br/>Azores: (GMT-01:00) Azores<br/>Cape Verde Is.: (GMT-01:00) Cape Verde Is.<br/>Casablanca: (GMT+00:00) Casablanca<br/>Dublin: (GMT+00:00) Dublin<br/>Edinburgh: (GMT+00:00) Edinburgh<br/>Lisbon: (GMT+00:00) Lisbon<br/>London: (GMT+00:00) London<br/>Monrovia: (GMT+00:00) Monrovia<br/>UTC: (GMT+00:00) UTC<br/>Amsterdam: (GMT+01:00) Amsterdam<br/>Belgrade: (GMT+01:00) Belgrade<br/>Berlin: (GMT+01:00) Berlin<br/>Bern: (GMT+01:00) Bern<br/>Bratislava: (GMT+01:00) Bratislava<br/>Brussels: (GMT+01:00) Brussels<br/>Budapest: (GMT+01:00) Budapest<br/>Copenhagen: (GMT+01:00) Copenhagen<br/>Ljubljana: (GMT+01:00) Ljubljana<br/>Madrid: (GMT+01:00) Madrid<br/>Paris: (GMT+01:00) Paris<br/>Prague: (GMT+01:00) Prague<br/>Rome: (GMT+01:00) Rome<br/>Sarajevo: (GMT+01:00) Sarajevo<br/>Skopje: (GMT+01:00) Skopje<br/>Stockholm: (GMT+01:00) Stockholm<br/>Vienna: (GMT+01:00) Vienna<br/>Warsaw: (GMT+01:00) Warsaw<br/>West Central Africa: (GMT+01:00) West Central Africa<br/>Zagreb: (GMT+01:00) Zagreb<br/>Zurich: (GMT+01:00) Zurich<br/>Athens: (GMT+02:00) Athens<br/>Bucharest: (GMT+02:00) Bucharest<br/>Cairo: (GMT+02:00) Cairo<br/>Harare: (GMT+02:00) Harare<br/>Helsinki: (GMT+02:00) Helsinki<br/>Jerusalem: (GMT+02:00) Jerusalem<br/>Kaliningrad: (GMT+02:00) Kaliningrad<br/>Kyiv: (GMT+02:00) Kyiv<br/>Pretoria: (GMT+02:00) Pretoria<br/>Riga: (GMT+02:00) Riga<br/>Sofia: (GMT+02:00) Sofia<br/>Tallinn: (GMT+02:00) Tallinn<br/>Vilnius: (GMT+02:00) Vilnius<br/>Baghdad: (GMT+03:00) Baghdad<br/>Istanbul: (GMT+03:00) Istanbul<br/>Kuwait: (GMT+03:00) Kuwait<br/>Minsk: (GMT+03:00) Minsk<br/>Moscow: (GMT+03:00) Moscow<br/>Nairobi: (GMT+03:00) Nairobi<br/>Riyadh: (GMT+03:00) Riyadh<br/>St. Petersburg: (GMT+03:00) St. Petersburg<br/>Volgograd: (GMT+03:00) Volgograd<br/>Tehran: (GMT+03:30) Tehran<br/>Abu Dhabi: (GMT+04:00) Abu Dhabi<br/>Baku: (GMT+04:00) Baku<br/>Muscat: (GMT+04:00) Muscat<br/>Samara: (GMT+04:00) Samara<br/>Tbilisi: (GMT+04:00) Tbilisi<br/>Yerevan: (GMT+04:00) Yerevan<br/>Kabul: (GMT+04:30) Kabul<br/>Ekaterinburg: (GMT+05:00) Ekaterinburg<br/>Islamabad: (GMT+05:00) Islamabad<br/>Karachi: (GMT+05:00) Karachi<br/>Tashkent: (GMT+05:00) Tashkent<br/>Chennai: (GMT+05:30) Chennai<br/>Kolkata: (GMT+05:30) Kolkata<br/>Mumbai: (GMT+05:30) Mumbai<br/>New Delhi: (GMT+05:30) New Delhi<br/>Sri Jayawardenepura: (GMT+05:30) Sri Jayawardenepura<br/>Kathmandu: (GMT+05:45) Kathmandu<br/>Almaty: (GMT+06:00) Almaty<br/>Astana: (GMT+06:00) Astana<br/>Dhaka: (GMT+06:00) Dhaka<br/>Urumqi: (GMT+06:00) Urumqi<br/>Rangoon: (GMT+06:30) Rangoon<br/>Bangkok: (GMT+07:00) Bangkok<br/>Hanoi: (GMT+07:00) Hanoi<br/>Jakarta: (GMT+07:00) Jakarta<br/>Krasnoyarsk: (GMT+07:00) Krasnoyarsk<br/>Novosibirsk: (GMT+07:00) Novosibirsk<br/>Beijing: (GMT+08:00) Beijing<br/>Chongqing: (GMT+08:00) Chongqing<br/>Hong Kong: (GMT+08:00) Hong Kong<br/>Irkutsk: (GMT+08:00) Irkutsk<br/>Kuala Lumpur: (GMT+08:00) Kuala Lumpur<br/>Perth: (GMT+08:00) Perth<br/>Singapore: (GMT+08:00) Singapore<br/>Taipei: (GMT+08:00) Taipei<br/>Ulaanbaatar: (GMT+08:00) Ulaanbaatar<br/>Osaka: (GMT+09:00) Osaka<br/>Sapporo: (GMT+09:00) Sapporo<br/>Seoul: (GMT+09:00) Seoul<br/>Tokyo: (GMT+09:00) Tokyo<br/>Yakutsk: (GMT+09:00) Yakutsk<br/>Adelaide: (GMT+09:30) Adelaide<br/>Darwin: (GMT+09:30) Darwin<br/>Brisbane: (GMT+10:00) Brisbane<br/>Canberra: (GMT+10:00) Canberra<br/>Guam: (GMT+10:00) Guam<br/>Hobart: (GMT+10:00) Hobart<br/>Melbourne: (GMT+10:00) Melbourne<br/>Port Moresby: (GMT+10:00) Port Moresby<br/>Sydney: (GMT+10:00) Sydney<br/>Vladivostok: (GMT+10:00) Vladivostok<br/>Magadan: (GMT+11:00) Magadan<br/>New Caledonia: (GMT+11:00) New Caledonia<br/>Solomon Is.: (GMT+11:00) Solomon Is.<br/>Srednekolymsk: (GMT+11:00) Srednekolymsk<br/>Auckland: (GMT+12:00) Auckland<br/>Fiji: (GMT+12:00) Fiji<br/>Kamchatka: (GMT+12:00) Kamchatka<br/>Marshall Is.: (GMT+12:00) Marshall Is.<br/>Wellington: (GMT+12:00) Wellington<br/>Chatham Is.: (GMT+12:45) Chatham Is.<br/>Nuku'alofa: (GMT+13:00) Nuku'alofa<br/>Samoa: (GMT+13:00) Samoa<br/>Tokelau Is.: (GMT+13:00) Tokelau Is. | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497694 | time_format | Time Format | 12 | default_time_format | Time Format |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497695 | language | Language | 13 | default_language | Language | ar: Arabic<br/>ca: Catalan<br/>zh-CN: Chinese<br/>hr: Croatian<br/>cs: Czech<br/>da: Danish<br/>nl: Dutch<br/>en: English<br/>et: Estonian<br/>fi: Finnish<br/>fr: French<br/>de: German<br/>he: Hebrew<br/>hu: Hungarian<br/>id: Indonesian<br/>it: Italian<br/>ja-JP: Japanese<br/>ko: Korean<br/>lv-LV: Latvian<br/>nb-NO: Norwegian<br/>pl: Polish<br/>pt-BR: Portuguese (BR)<br/>pt-PT: Portuguese/Portugal<br/>ro: Romanian<br/>ru-RU: Russian<br/>sk: Slovak<br/>sl: Slovenian<br/>es: Spanish<br/>es-LA: Spanish (Latin America)<br/>sv-SE: Swedish<br/>th: Thai<br/>zh-TW: Traditional Chinese<br/>tr: Turkish<br/>uk: Ukrainian<br/>vi: Vietnamese<br/>cy-GB: Welsh | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497696 | vip_user | Mark as VIP | 14 | default_vip_user | Mark as VIP |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497697 | location_id | Location | 15 | default_location_id | Location |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |
>| 21000497698 | description | Background Information | 16 | default_description | Background Information |  | 2022-12-25T08:37:28Z | 2022-12-25T08:37:28Z |


### get-mapping-fields

***
Returns the list of fields for an incident type.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required |
| lastUpdate | Retrieves entries that were created after lastUpdate. | Required |

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available in Cortex XSOAR from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | A date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Optional |

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Freshworks Freshservice corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Freshworks Freshservice events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Freshworks Freshservice events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Freshworks Freshservice events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Freshworks Freshservice.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Freshworks Freshservice.
