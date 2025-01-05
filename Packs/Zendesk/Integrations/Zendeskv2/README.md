Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-zendesk-v2).

## Configure Zendesk v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://demisto.zendesk.com) |  | True |
| Username (or '&lt;username&gt;/token' when using API key). | example 'admin@org.com' when using the password, or 'admin@org.com/token' when using an API key. | True |
| Password/API key |  | True |
| Fetch incidents |  | False |
| Incident Mirroring Direction | Selects which direction you want the incidents mirrored. You can mirror \*\*Incoming\*\* only \(from Zendesk to Cortex XSOAR\), \*\*Outgoing\*\* only \(from Cortex XSOAR to Zendesk\), or both \*\*Incoming And Outgoing\*\*. | False |
| Close mirrored incidents | If true, XSOAR will mirror also the ticket closeing. | False |
| Mirror tags | Comment and files that will be marked with this tag will be pushed into Zendesk. | False |
| Ticket Field to Fetch by | Duplications might accrue when choosing 'updated-at' | True |
| Ticket types to fetch |  | False |
| Fetch tickets status filter |  | False |
| Fetch tickets priority filter |  | False |
| Fetch tickets query filter |  | False |
| Maximum number of incidents per fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

    (The test does not ensure sufficient permissions for all integration commands.)
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

## Required permissions
This integration enables executing commands with different permission levels. See the commands' descriptions for more information on the required permission. 
To learn more on Zendesk roles refer to:
[Understanding Zendesk Support user roles](https://support.zendesk.com/hc/en-us/articles/4408883763866-Understanding-Zendesk-Support-user-roles#topic_ibd_fdq_cc)
[About team member product roles and access](https://support.zendesk.com/hc/en-us/articles/4408832171034)

### zendesk-user-list
***
Gets the specified user's data. 
Required permissions: Admins, Agents and Light Agents.


#### Base Command

`zendesk-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's ID to retrieve. | Optional | 
| user_name | The user's name. <br/>Required permissions to use this argument: Agents . | Optional | 
| external_id | The user's unique identifier from another system. | Optional | 
| role | The user's role. Possible values are: end_user, agent, admin. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.User.active | boolean | False if the user has been deleted. | 
| Zendesk.User.alias | string | An alias displayed to end users. | 
| Zendesk.User.chat_only | boolean | Whether the user is a chat-only agent. | 
| Zendesk.User.created_at | date | The time the user was created. | 
| Zendesk.User.custom_role_id | number | A custom role if the user is an agent on the Enterprise plan or above. | 
| Zendesk.User.default_group_id | number | The ID of the user's default group. | 
| Zendesk.User.details | string | Any details you want to store about the user, such as an address. | 
| Zendesk.User.external_id | string | A unique identifier from another system. | 
| Zendesk.User.email | string | The user's primary email address. | 
| Zendesk.User.iana_time_zone | string | The time zone for the user. | 
| Zendesk.User.id | number | The user's ID. | 
| Zendesk.User.last_login_at | string | The last time the user signed in to Zendesk Support. | 
| Zendesk.User.locale | string | The user's locale. | 
| Zendesk.User.moderator | boolean | Whether the user has forum moderation capabilities. | 
| Zendesk.User.name | string | The user's name. | 
| Zendesk.User.notes | string | Any notes you want to store about the user. | 
| Zendesk.User.only_private_comments | boolean | True if the user can only create private comments. | 
| Zendesk.User.organization_id | number | The ID of the user's organization. | 
| Zendesk.User.organization | string | The name of the user's organization. | 
| Zendesk.User.phone | string | The user's primary phone number. | 
| Zendesk.User.remote_photo_url | string | A URL pointing to the user's profile picture. | 
| Zendesk.User.report_csv | boolean | Whether the user can access the CSV report on the Search tab of the Reporting page in the Support admin interface. | 
| Zendesk.User.restricted_agent | boolean | Whether the agent has any restrictions; false for admins and unrestricted agents, true for other agents. | 
| Zendesk.User.role | string | The user's role. Possible values are "end-user", "agent", or "admin". | 
| Zendesk.User.role_type | string | The user's role type. | 
| Zendesk.User.shared | boolean | Whether the user is shared from a different Zendesk Support instance. | 
| Zendesk.User.shared_agent | boolean | Whether the user is a shared agent from a different Zendesk Support instance. | 
| Zendesk.User.shared_phone_number | boolean | Whether the phone number is shared. | 
| Zendesk.User.signature | string | The user's signature. | 
| Zendesk.User.suspended | boolean | Whether the agent is suspended. Tickets from suspended users are also suspended, and these users cannot sign in to the end user portal. | 
| Zendesk.User.tags | string | The user's tags. Only present if your account has user tagging enabled. | 
| Zendesk.User.ticket_restriction | string | Specifies which tickets the user has access to. Possible values are: "organization", "groups", "assigned", "requested", null. | 
| Zendesk.User.time_zone | string | The user's time zone. | 
| Zendesk.User.two_factor_auth_enabled | boolean | Whether two factor authentication is enabled. | 
| Zendesk.User.updated_at | string | The time the user was last updated. | 
| Zendesk.User.verified | boolean | Whether any of the user's identities is verified. | 

### zendesk-user-create
***
Creates a new Zendesk user. 
Required permissions: Agents, with restrictions on certain actions.


#### Base Command

`zendesk-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The user's name. | Required | 
| email | The user's primary email address. | Required | 
| role | The user's role. Possible values are "end-user", "agent", or "admin". Possible values are: end_user, agent, admin. | Required | 
| role_type | The user's role type. Possible values are: custom_agent, light_agent, chat_agent, chat_agent_contributor, admin, billing_admin. | Optional | 
| verified | Whether to mark the user's email as verified. Possible values are: true, false. Default is false. | Optional | 
| tags | A comma-separated list of users' tags. | Optional | 
| phone | The user's primary phone number. | Optional | 
| organization_name | The name of the user's organization. | Optional | 
| organization_id | The ID of the user's organization. | Optional | 
| notes | Any notes you want to store about the user. | Optional | 
| details | Any details you want to store about the user, such as an address. | Optional | 
| external_id | A unique identifier from another system. | Optional | 
| locale | The user's locale. | Optional | 
| alias | An alias displayed to end users. | Optional | 
| default_group_id | The ID of the user's default group. | Optional | 
| custom_role_id | A custom role if the user is an agent on the Enterprise plan or above. | Optional | 
| identities | Users external identities (JSON-formatted argument) e.g., [{"type": "email", "value": "test@user.com"}, {"type": "twitter", "value": "tester84"}]. | Optional | 
| user_fields | Values of custom fields in the user's profile (json formated field). | Optional | 
| check_if_user_exists | Check if the user already exists (Will fail if the user exists already or will update a user's existing data). Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.User.active | boolean | false if the user has been deleted. | 
| Zendesk.User.alias | string | An alias displayed to end users. | 
| Zendesk.User.chat_only | boolean | Whether or not the user is a chat-only agent. | 
| Zendesk.User.created_at | date | The time the user was created. | 
| Zendesk.User.custom_role_id | number | A custom role if the user is an agent on the Enterprise plan or above. | 
| Zendesk.User.default_group_id | number | The ID of the user's default group. | 
| Zendesk.User.details | string | Any details you want to store about the user, such as an address. | 
| Zendesk.User.external_id | string | A unique identifier from another system. | 
| Zendesk.User.email | string | The user's primary email address. | 
| Zendesk.User.iana_time_zone | string | The time zone for the user. | 
| Zendesk.User.id | number | The user's ID. | 
| Zendesk.User.last_login_at | string | The last time the user signed in to Zendesk Support. | 
| Zendesk.User.locale | string | The user's locale. | 
| Zendesk.User.moderator | boolean | Whether the user has forum moderation capabilities. | 
| Zendesk.User.name | string | The user's name. | 
| Zendesk.User.notes | string | Any notes you want to store about the user. | 
| Zendesk.User.only_private_comments | boolean | True if the user can only create private comments. | 
| Zendesk.User.organization_id | number | The ID of the user's organization. | 
| Zendesk.User.organization | string | The name of the user's organization. | 
| Zendesk.User.phone | string | The user's primary phone number. | 
| Zendesk.User.remote_photo_url | string | A URL pointing to the user's profile picture. | 
| Zendesk.User.report_csv | boolean | Whether the user can access the CSV report on the Search tab of the Reporting page in the Support admin interface. | 
| Zendesk.User.restricted_agent | boolean | Whether the agent has any restrictions; false for admins and unrestricted agents, true for other agents. | 
| Zendesk.User.role | string | The user's role. Possible values are "end-user", "agent", or "admin". | 
| Zendesk.User.role_type | string | The user's role type. | 
| Zendesk.User.shared | boolean | Whether the user is shared from a different Zendesk Support instance. | 
| Zendesk.User.shared_agent | boolean | Whether the user is a shared agent from a different Zendesk Support instance. | 
| Zendesk.User.shared_phone_number | boolean | Whether the phone number is shared. | 
| Zendesk.User.signature | string | The user's signature. | 
| Zendesk.User.suspended | boolean | Whether the agent is suspended. Tickets from suspended users are also suspended, and these users cannot sign in to the end user portal. | 
| Zendesk.User.tags | string | The user's tags. Only present if your account has user tagging enabled. | 
| Zendesk.User.ticket_restriction | string | Specifies which tickets the user has access to. Possible values are: "organization", "groups", "assigned", "requested", null. | 
| Zendesk.User.time_zone | string | The user's time zone. | 
| Zendesk.User.two_factor_auth_enabled | boolean | Whether two factor authentication is enabled. | 
| Zendesk.User.updated_at | string | The time the user was last updated. | 
| Zendesk.User.verified | boolean | Whether any of the user's identities is verified. | 

### zendesk-user-update
***
Update user data. 
Required permissions: Agents, with restrictions on certain actions.


#### Base Command

`zendesk-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID to update. | Required | 
| name | The user's name. | Optional | 
| role | The user's role. Possible values are "end-user", "agent", or "admin". Possible values are: end_user, agent, admin. | Optional | 
| role_type | The user's role type. Possible values are: custom_agent, light_agent, chat_agent, chat_agent_contributor, admin, billing_admin. | Optional | 
| verified | Whether to mark the user email as verified (the added email). Possible values are: true, false. | Optional | 
| suspended | Whether the user is suspended. Possible values are: true, false. | Optional | 
| tags | The user's tags. | Optional | 
| email | Secondary email to add. | Optional | 
| phone | The user's primary phone number. | Optional | 
| organization_name | The name of the user's organization. | Optional | 
| organization_id | The ID of the user's organization. | Optional | 
| notes | Any notes you want to store about the user. | Optional | 
| details | Any details you want to store about the user, such as an address. | Optional | 
| external_id | A unique identifier from another system. | Optional | 
| locale | The user's locale. | Optional | 
| alias | An alias displayed to end users. | Optional | 
| default_group_id | The ID of the user's default group. | Optional | 
| custom_role_id | A custom role if the user is an agent on the Enterprise plan or above. | Optional | 
| identities | Users external identities (JSON-formatted argument) e.g., [{"type": "email", "value": "test@user.com"}, {"type": "twitter", "value": "tester84"}]. | Optional | 
| user_fields | Values of custom fields in the user's profile (JSON-formatted field). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.User.active | boolean | False if the user has been deleted. | 
| Zendesk.User.alias | string | An alias displayed to end users. | 
| Zendesk.User.chat_only | boolean | Whether the user is a chat-only agent. | 
| Zendesk.User.created_at | date | The time the user was created. | 
| Zendesk.User.custom_role_id | number | A custom role if the user is an agent on the Enterprise plan or above. | 
| Zendesk.User.default_group_id | number | The ID of the user's default group. | 
| Zendesk.User.details | string | Any details you want to store about the user, such as an address. | 
| Zendesk.User.external_id | string | A unique identifier from another system. | 
| Zendesk.User.email | string | The user's primary email address. | 
| Zendesk.User.iana_time_zone | string | The time zone for the user. | 
| Zendesk.User.id | number | The user's ID. | 
| Zendesk.User.last_login_at | string | The last time the user signed in to Zendesk Support. | 
| Zendesk.User.locale | string | The user's locale. | 
| Zendesk.User.moderator | boolean | Whether the user has forum moderation capabilities. | 
| Zendesk.User.name | string | The user's name. | 
| Zendesk.User.notes | string | Any notes you want to store about the user. | 
| Zendesk.User.only_private_comments | boolean | True if the user can only create private comments. | 
| Zendesk.User.organization_id | number | The ID of the user's organization. | 
| Zendesk.User.organization | string | The name of the user's organization. | 
| Zendesk.User.phone | string | The user's primary phone number. | 
| Zendesk.User.remote_photo_url | string | A URL pointing to the user's profile picture. | 
| Zendesk.User.report_csv | boolean | Whether the user can access the CSV report on the Search tab of the Reporting page in the Support admin interface. | 
| Zendesk.User.restricted_agent | boolean | If the agent has any restrictions; false for admins and unrestricted agents, true for other agents. | 
| Zendesk.User.role | string | The user's role. Possible values are "end-user", "agent", or "admin". | 
| Zendesk.User.role_type | string | The user's role type. | 
| Zendesk.User.shared | boolean | Whether the user is shared from a different Zendesk Support instance. | 
| Zendesk.User.shared_agent | boolean | Whether the user is a shared agent from a different Zendesk Support instance. | 
| Zendesk.User.shared_phone_number | boolean | Whether the phone number is shared. | 
| Zendesk.User.signature | string | The user's signature. | 
| Zendesk.User.suspended | boolean | Whether the agent is suspended. Tickets from suspended users are also suspended, and these users cannot sign in to the end user portal. | 
| Zendesk.User.tags | string | The user's tags. Only present if your account has user tagging enabled. | 
| Zendesk.User.ticket_restriction | string | Specifies which tickets the user has access to. Possible values are: "organization", "groups", "assigned", "requested", null | 
| Zendesk.User.time_zone | string | The user's time zone. | 
| Zendesk.User.two_factor_auth_enabled | boolean | Whether two factor authentication is enabled. | 
| Zendesk.User.updated_at | string | The time the user was last updated. | 
| Zendesk.User.verified | boolean | Whether any of the user's identities is verified. | 

### zendesk-user-delete
***
Delete a user. 
Required permissions: Admins.


#### Base Command

`zendesk-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to delete. | Required | 


#### Context Output

There is no context output for this command.
### zendesk-organization-list
***
Get organization's data. 
Required permissions: Agents, with certain restrictions. 
If the agent has a custom agent role that restricts the agent's access to only users in their own organization,
a 403 Forbidden error is returned. See Creating custom agent roles in Zendesk help.


#### Base Command

`zendesk-organization-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | The ID of a specific organization. <br/>Required permissions: Admins, Agents.  | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Organization.created_at | date | The time the organization was created. | 
| Zendesk.Organization.details | string | Any details about the organization, such as the address. | 
| Zendesk.Organization.domain_names | string | Domain names associated with this organization. | 
| Zendesk.Organization.external_id | string | A unique external ID to associate organizations to an external record. | 
| Zendesk.Organization.group_id | number | New tickets from users in this organization are automatically put in this group. | 
| Zendesk.Organization.id | number | The organization ID. | 
| Zendesk.Organization.name | string | The name of the organization. | 
| Zendesk.Organization.notes | string | Any notes you have about the organization. | 
| Zendesk.Organization.shared_comments | boolean | End users in this organization are able to see each other's comments on tickets. | 
| Zendesk.Organization.shared_tickets | boolean | End users in this organization are able to see each other's tickets. | 
| Zendesk.Organization.tags | string | The tags of the organization. | 
| Zendesk.Organization.updated_at | date | The time of the last update of the organization. | 
| Zendesk.Organization.url | string | The API URL of this organization. | 

### zendesk-ticket-list
***
List Zendesk tickets. 
Required permissions: Agents. 


#### Base Command

`zendesk-ticket-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query to search for tickets. For more information about the search syntax, see https://developer.zendesk.com/rest_api/docs/core/search. . | Optional | 
| ticket_id | The ID of a specific ticket. | Optional | 
| filter | Filter tickets for which the specified user is relevant. Possible values are: assigned, requested, ccd, followed, recent. | Optional | 
| user_id | The agent ID associated with tickets filtered. | Optional | 
| sort | The order of the retrieved tickets. Possible values are: id_asc, status_asc, updated_at_asc, id_desc, status_desc, updated_at_desc. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Ticket.allow_attachments | boolean | Whether the agents have permission to attachments to a comment. | 
| Zendesk.Ticket.allow_channelback | boolean | False if channelback is disabled, true otherwise. Only applicable for channels framework ticket. | 
| Zendesk.Ticket.assignee | string | The agent currently assigned to the ticket. | 
| Zendesk.Ticket.assignee_id | number | The ID of the agent currently assigned to the ticket. | 
| Zendesk.Ticket.collaborators | string | The users currently CC'ed on the ticket. | 
| Zendesk.Ticket.collaborator_ids | number | The ID of the users currently CC'ed on the ticket. | 
| Zendesk.Ticket.created_at | date | The ticket creation time. | 
| Zendesk.Ticket.description | string | The ticket description. | 
| Zendesk.Ticket.due_at | date | If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format. | 
| Zendesk.Ticket.email_ccs | string | The agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.email_cc_ids | number | The ID of the agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.external_id | string | An ID you can use to link Zendesk Support tickets to local records. | 
| Zendesk.Ticket.followers | string | The agents currently following the ticket. | 
| Zendesk.Ticket.follower_ids | number | The ID of the user who is currently following the ticket. | 
| Zendesk.Ticket.followup_ids | number | The IDs of the followups created from this ticket. IDs are only visible once the ticket is closed. | 
| Zendesk.Ticket.forum_topic_id | number | The topic in the Zendesk Web portal this ticket originated from, if any. | 
| Zendesk.Ticket.group_id | number | The ID of the group this ticket is assigned to. | 
| Zendesk.Ticket.has_incidents | boolean | True if a ticket is a problem type and has one or more incidents linked to it. Otherwise, the value is false. | 
| Zendesk.Ticket.id | number | The ticket ID. | 
| Zendesk.Ticket.is_public | boolean | True if any comments are public, false otherwise. | 
| Zendesk.Ticket.organization | string | The organization of the requester. | 
| Zendesk.Ticket.organization_id | number | The ID of the organization of the requester. | 
| Zendesk.Ticket.priority | string | The urgency with which the ticket should be addressed. | 
| Zendesk.Ticket.problem_id | number | For tickets of type "incident", the ID of the problem the incident is linked to. | 
| Zendesk.Ticket.raw_subject | string | The dynamic content placeholder, if present, or the "subject" value, if not. | 
| Zendesk.Ticket.recipient | string | The original recipient email address of the ticket. | 
| Zendesk.Ticket.requester | string | The user who requested this ticket. | 
| Zendesk.Ticket.requester_id | number | The ID of the user who requested this ticket. | 
| Zendesk.Ticket.satisfaction_rating | unknown | The satisfaction rating of the ticket, if it exists, or the state of satisfaction, "offered" or "unoffered". | 
| Zendesk.Ticket.sharing_agreement_ids | number | The IDs of the sharing agreements used for this ticket. | 
| Zendesk.Ticket.status | string | The state of the ticket. | 
| Zendesk.Ticket.subject | string | The value of the subject field for this ticket. | 
| Zendesk.Ticket.submitter | string | The user who submitted the ticket. | 
| Zendesk.Ticket.submitter_id | number | The ID of the user who submitted the ticket. | 
| Zendesk.Ticket.tags | string | The array of tags applied to this ticket. | 
| Zendesk.Ticket.type | string | The type of this ticket. | 
| Zendesk.Ticket.updated_at | date | When this ticket was last updated. | 
| Zendesk.Ticket.url | string | The API URL of this ticket. | 

### zendesk-ticket-create
***
Create a new zendesk ticket.
Required permissions: Agents.


#### Base Command

`zendesk-ticket-create`
#### Input

| **Argument Name**      | **Description** | **Required** |
|------------------------| --- | --- |
| subject                | The subject of this ticket. | Required | 
| type                   | The type of this ticket. Possible values are: problem, incident, question, task. | Required | 
| requester              | The user who requested this ticket. | Required | 
| assignee_email         | The email address of the agent to assign the ticket to. | Optional | 
| collaborators          | Users to add as CC's when creating a ticket. | Optional | 
| description            | The ticket description. | Required | 
| recipient              | The original recipient email address of the ticket. | Optional | 
| status                 | The state of the ticket. Possible values are: new, open, pending, hold, solved, closed. | Optional | 
| priority               | The urgency with which the ticket should be addressed. Possible values are: urgent, high, normal, low. Default is normal. | Optional | 
| due_at                 | If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format. | Optional | 
| email_ccs              | An array of agents or end users email CCs to add or delete from the ticket. Default is add.\nThe format is '562624,562625:put,example@example.com:delete'. | Optional | 
| external_id            | An ID you can use to link Zendesk Support tickets to local records. | Optional | 
| forum_topic_id         | The topic in the Zendesk Web portal this ticket originated from, if any. | Optional | 
| followers              | An array of agent followers to add or delete from the ticket. Default is add.\nThe format is '562624,562625:put,example@example.com:delete'. | Optional | 
| group_id               | The group this ticket is assigned to. | Optional | 
| organization_id        | The organization of the requester. | Optional | 
| problem_id             | For tickets of type "incident", the ID of the problem the incident is linked to. | Optional | 
| tags                   | The tags applied to this ticket. | Optional | 
| via_followup_source_id | The ID of a closed ticket when creating a follow-up ticket. | Optional | 
| custom_fields          | Custom fields for the ticket (this is a JSON-formatted argument, see: https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets#setting-custom-field-values). | Optional | 
| brand_id               | Enterprise only. The ID of the brand this ticket is associated with. | Optional | 
| comment                | A comment to add to the ticket. | Optional | 
| html_comment           | An HTML comment to add to the ticket. | Optional | 
| public | true if a public comment; false if an internal note. The initial value set on ticket creation persists for any additional comment unless you change it. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Ticket.allow_attachments | boolean | Whether the agents have permission to add attachments to a comment. | 
| Zendesk.Ticket.allow_channelback | boolean | False if channelback is disabled, true otherwise. Only applicable for channels framework ticket. | 
| Zendesk.Ticket.assignee | string | The agent currently assigned to the ticket. | 
| Zendesk.Ticket.assignee_id | number | The ID of the agent currently assigned to the ticket. | 
| Zendesk.Ticket.collaborators | string | The users currently CC'ed on the ticket. | 
| Zendesk.Ticket.collaborator_ids | number | The ID of the users currently CC'ed on the ticket. | 
| Zendesk.Ticket.created_at | date | The ticket creation time. | 
| Zendesk.Ticket.description | string | The ticket description. | 
| Zendesk.Ticket.due_at | date | If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format. | 
| Zendesk.Ticket.email_ccs | string | The agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.email_cc_ids | number | The ID of the agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.external_id | string | An ID you can use to link Zendesk Support tickets to local records. | 
| Zendesk.Ticket.followers | string | The agents currently following the ticket. | 
| Zendesk.Ticket.follower_ids | number | The ID of the user who is currently following the ticket. | 
| Zendesk.Ticket.followup_ids | number | The IDs of the followups created from this ticket. IDs are only visible once the ticket is closed. | 
| Zendesk.Ticket.forum_topic_id | number | The topic in the Zendesk Web portal this ticket originated from, if any. | 
| Zendesk.Ticket.group_id | number | The ID of the group this ticket is assigned to. | 
| Zendesk.Ticket.has_incidents | boolean | True if a ticket is a problem type and has one or more incidents linked to it. Otherwise, the value is false. | 
| Zendesk.Ticket.id | number | The ticket ID. | 
| Zendesk.Ticket.is_public | boolean | True if any comments are public, false otherwise. | 
| Zendesk.Ticket.organization | string | The organization of the requester. | 
| Zendesk.Ticket.organization_id | number | The ID of the organization of the requester. | 
| Zendesk.Ticket.priority | string | The urgency with which the ticket should be addressed. | 
| Zendesk.Ticket.problem_id | number | For tickets of type "incident", the ID of the problem the incident is linked to. | 
| Zendesk.Ticket.raw_subject | string | The dynamic content placeholder, if present, or the "subject" value, if not. | 
| Zendesk.Ticket.recipient | string | The original recipient email address of the ticket. | 
| Zendesk.Ticket.requester | string | The user who requested this ticket. | 
| Zendesk.Ticket.requester_id | number | The ID of the user who requested this ticket. | 
| Zendesk.Ticket.satisfaction_rating | unknown | The satisfaction rating of the ticket, if it exists, or the state of satisfaction, "offered" or "unoffered". | 
| Zendesk.Ticket.sharing_agreement_ids | number | The IDs of the sharing agreements used for this ticket. | 
| Zendesk.Ticket.status | string | The state of the ticket. | 
| Zendesk.Ticket.subject | string | The value of the subject field for this ticket. | 
| Zendesk.Ticket.submitter | string | The user who submitted the ticket. | 
| Zendesk.Ticket.submitter_id | number | The ID of the user who submitted the ticket. | 
| Zendesk.Ticket.tags | string | The array of tags applied to this ticket. | 
| Zendesk.Ticket.type | string | The type of this ticket. | 
| Zendesk.Ticket.updated_at | date | When this ticket was last updated. | 
| Zendesk.Ticket.url | string | The API URL of this ticket. | 

### zendesk-ticket-update
***
Updates a Zendesk ticket.
Required permissions: Agents.


#### Base Command

`zendesk-ticket-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to update. | Required | 
| subject | The subject of this ticket. | Optional | 
| type | The type of this ticket. Possible values are: problem, incident, question, task. | Optional | 
| requester | The user who requested this ticket. | Optional | 
| assignee_email | The email address of the agent to assign the ticket to. | Optional | 
| collaborators | Users to add as CCs when creating a ticket. | Optional | 
| comment | A comment to add to the ticket. | Optional | 
| html_comment | An HTML comment to add to the ticket. | Optional | 
| public | true if a public comment; false if an internal note. The initial value set on ticket creation persists for any additional comment unless you change it. Possible values are: true, false. Default is true. | Optional | 
| recipient | The original recipient email address of the ticket. | Optional | 
| status | The state of the ticket. Possible values are: open, pending, hold, solved, closed. | Optional | 
| priority | The urgency with which the ticket should be addressed. Possible values are: urgent, high, normal, low. | Optional | 
| due_at | If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format. | Optional | 
| email_ccs | An array of agents or end users email CC's to add or delete from the ticket. Default is add.\nThe format is '562624,562625:put,example@example.com:delete'. | Optional | 
| external_id | An ID you can use to link Zendesk Support tickets to local records. | Optional | 
| followers | An array of agent followers to add or delete from the ticket. Default is add.\nThe format is '562624,562625:put,example@example.com:delete'. | Optional | 
| group_id | The ID of the group this ticket is assigned to. | Optional | 
| organization | The ID of the organization of the requester. | Optional | 
| problem_id | For tickets of type "incident", the ID of the problem the incident is linked to. | Optional | 
| tags | The tags applied to this ticket. | Optional | 
| custom_fields | Custom fields for the ticket (this is a JSON-formatted argument see: https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets#setting-custom-field-values). | Optional | 
| brand_id | Enterprise only. The ID of the brand this ticket is associated with. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Ticket.allow_attachments | boolean | Whether the agents have permission to attachments to a comment. | 
| Zendesk.Ticket.allow_channelback | boolean | False if channelback is disabled, true otherwise. Only applicable for channels framework ticket. | 
| Zendesk.Ticket.assignee | string | The agent currently assigned to the ticket. | 
| Zendesk.Ticket.collaborators | string | The users currently CC'ed on the ticket. | 
| Zendesk.Ticket.collaborator_ids | number | The ID of the users currently CC'ed on the ticket. | 
| Zendesk.Ticket.created_at | date | The ticket creation time. | 
| Zendesk.Ticket.description | string | The ticket description. | 
| Zendesk.Ticket.due_at | date | If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format. | 
| Zendesk.Ticket.email_ccs | string | The agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.email_cc_ids | number | The ID of the agents or end users currently CC'ed on the ticket. | 
| Zendesk.Ticket.external_id | string | An ID you can use to link Zendesk Support tickets to local records. | 
| Zendesk.Ticket.followers | string | The agents currently following the ticket. | 
| Zendesk.Ticket.follower_ids | number | The ID of the user who is currently following the ticket. | 
| Zendesk.Ticket.followup_ids | number | The IDs of the followups created from this ticket. Ids are only visible once the ticket is closed. | 
| Zendesk.Ticket.forum_topic_id | number | The topic in the Zendesk Web portal this ticket originated from, if any. | 
| Zendesk.Ticket.group_id | number | The group this ticket is assigned to. | 
| Zendesk.Ticket.has_incidents | boolean | True if a ticket is a problem type and has one or more incidents linked to it. Otherwise, the value is false. | 
| Zendesk.Ticket.id | number | The ticket ID. | 
| Zendesk.Ticket.is_public | boolean | True if any comments are public, false otherwise. | 
| Zendesk.Ticket.organization | string | The organization of the requester. | 
| Zendesk.Ticket.priority | string | The urgency with which the ticket should be addressed. | 
| Zendesk.Ticket.problem_id | number | For tickets of type "incident", the ID of the problem the incident is linked to. | 
| Zendesk.Ticket.raw_subject | string | The dynamic content placeholder, if present, or the "subject" value, if not. | 
| Zendesk.Ticket.recipient | string | The original recipient email address of the ticket. | 
| Zendesk.Ticket.requester | string | The user who requested this ticket. | 
| Zendesk.Ticket.satisfaction_rating | unknown | The satisfaction rating of the ticket, if it exists, or the state of satisfaction, "offered" or "unoffered". | 
| Zendesk.Ticket.sharing_agreement_ids | number | The IDs of the sharing agreements used for this ticket. | 
| Zendesk.Ticket.status | string | The state of the ticket. | 
| Zendesk.Ticket.subject | string | The value of the subject field for this ticket. | 
| Zendesk.Ticket.submitter | string | The user who submitted the ticket. | 
| Zendesk.Ticket.tags | string | The array of tags applied to this ticket. | 
| Zendesk.Ticket.type | string | The type of this ticket. | 
| Zendesk.Ticket.updated_at | date | When this ticket was last updated. | 
| Zendesk.Ticket.url | string | The API URL of this ticket. | 

### zendesk-ticket-delete
***
Delete ticket. 
Required permissions: Admins, Agents with permission to delete tickets.
Agent delete permissions are set in Support.
See Deleting tickets in the Zendesk Support Help Center.


#### Base Command

`zendesk-ticket-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to delete. | Required | 


#### Context Output

There is no context output for this command.
### zendesk-ticket-comment-list
***
List comments for a given ticket.
Required permissions: Agents.


#### Base Command

`zendesk-ticket-comment-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to list comments. | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Ticket.Comment.attachments.content_type | string | The content type of the image. Example value: "image/png". | 
| Zendesk.Ticket.Comment.attachments.content_url | string | A full URL where the attached image file can be downloaded. | 
| Zendesk.Ticket.Comment.attachments.deleted | boolean | If true, the attachment has been deleted. | 
| Zendesk.Ticket.Comment.attachments.file_name | string | The name of the file. | 
| Zendesk.Ticket.Comment.attachments.height | string | The height of the image file in pixels. | 
| Zendesk.Ticket.Comment.attachments.id | number | The ID of the attachment. | 
| Zendesk.Ticket.Comment.attachments.inline | boolean | If true, the attachment is excluded from the attachment list and the attachment's URL can be referenced within the comment of a ticket. | 
| Zendesk.Ticket.Comment.attachments.mapped_content_url | string | The URL the attachment image file has been mapped to. | 
| Zendesk.Ticket.Comment.attachments.size | number | The size of the image file in bytes. | 
| Zendesk.Ticket.Comment.attachments.url | string | A URL to access the attachment details. | 
| Zendesk.Ticket.Comment.attachments.width | string | The width of the image file in pixels. | 
| Zendesk.Ticket.Comment.audit_id | number | The ID of the ticket audit record. | 
| Zendesk.Ticket.Comment.author | string | The comment author. | 
| Zendesk.Ticket.Comment.body | string | The comment string. | 
| Zendesk.Ticket.Comment.created_at | date | The time the comment was created. | 
| Zendesk.Ticket.Comment.html_body | string | The comment formatted as HTML. | 
| Zendesk.Ticket.Comment.id | number | The comment ID. | 
| Zendesk.Ticket.Comment.metadata | unknown | System information \(web client, IP address, etc.\) and comment flags, if any. | 
| Zendesk.Ticket.Comment.plain_body | string | The comment as plain text. | 
| Zendesk.Ticket.Comment.public | boolean | True if a public comment, false if an internal note. | 
| Zendesk.Ticket.Comment.type | string | Comment or VoiceComment. | 

### zendesk-ticket-attachment-add
***
Attach file to ticket.
Required permissions: End users.


#### Base Command

`zendesk-ticket-attachment-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket where the file should be uploaded. | Required | 
| file_id | The file entry ID. | Required | 
| comment | The comment body for the attached file. | Required | 
| filename | The filename to upload. Default is the original filename. | Optional | 


#### Context Output

There is no context output for this command.
### zendesk-attachment-get
***
Get attachment.
Required permissions: Admins.


#### Base Command

`zendesk-attachment-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | The ID of attachment to retrieve. | Required | 


#### Context Output

There is no context output for this command.
### zendesk-search
***
Search in Zendesk.


#### Base Command

`zendesk-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for the search. | Required | 
| page_number | The page number (used for pagination). | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Search | unknown | The search results. | 

### zendesk-article-list
***
List all available articles.
Required permissions: Agents, End users, Anonymous users.


#### Base Command

`zendesk-article-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| article_id | The ID of a specific article to retrieve. | Optional | 
| locale | The locale that the article is displayed in. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 


#### Context Output

There is no context output for this command.
### zendesk-clear-cache
***
Clears the Zendesk integration cache.


#### Base Command

`zendesk-clear-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### get-remote-data
***
Get remote data from a remote incident. Note that this method will not update the current incident. It's used for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***
Returns the list of fields for an incident type.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-modified-remote-data
***
Get the list of incidents that were modified since the last update. Note that this method is used for debugging purposes. get-modified-remote-data is used as part of a Mirroring feature, which is available since version 6.1.


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time. The incident is only returned if it was modified after the last update time. | Optional | 


#### Context Output

There is no context output for this command.
### update-remote-system
***
Updates local incident changes in the remote incident. This method is only used for debugging purposes and will not update the current incident.


#### Base Command

`update-remote-system`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.


### zendesk-group-user-list

***
Get group's users. 
Allowed for: Admins, Agents and Light Agents.

*Note*: In case the group_id does not exist, the command will return all users.

#### Base Command

`zendesk-group-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of a specific group. | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.UserGroup.active | Boolean | False if the user has been deleted. | 
| Zendesk.UserGroup.alias | String | An alias displayed to end users. | 
| Zendesk.UserGroup.created_at | Date | The time the user was created. | 
| Zendesk.UserGroup.custom_role_id | Number | A custom role if the user is an agent on the Enterprise plan or above. | 
| Zendesk.UserGroup.default_group_id | Number | The ID of the user's default group. | 
| Zendesk.UserGroup.details | String | Any details you want to store about the user, such as an address. | 
| Zendesk.UserGroup.email | String | The user's primary email address. | 
| Zendesk.UserGroup.external_id | String | A unique identifier from another system. | 
| Zendesk.UserGroup.iana_time_zone | String | The time zone for the user. | 
| Zendesk.UserGroup.id | Number | The user's ID. | 
| Zendesk.UserGroup.last_login_at | Date | The last time the user signed in to Zendesk Support. | 
| Zendesk.UserGroup.locale | String | The user's locale. | 
| Zendesk.UserGroup.locale_id | Number | The user's locale ID. | 
| Zendesk.UserGroup.moderator | Boolean | Whether the user has forum moderation capabilities. | 
| Zendesk.UserGroup.name | String | The user's name. | 
| Zendesk.UserGroup.notes | String | Any notes you want to store about the user. | 
| Zendesk.UserGroup.only_private_comments | Boolean | True if the user can only create private comments. | 
| Zendesk.UserGroup.organization_id | Number | The ID of the user's organization. | 
| Zendesk.UserGroup.phone | String | The user's primary phone number. | 
| Zendesk.UserGroup.photo | String | A URL pointing to the user's profile picture. | 
| Zendesk.UserGroup.report_csv | Boolean | Whether the user can access the CSV report on the Search tab of the Reporting page in the Support admin interface. | 
| Zendesk.UserGroup.restricted_agent | Boolean | Whether the agent has any restrictions; false for admins and unrestricted agents, true for other agents. | 
| Zendesk.UserGroup.role | String | The user's role. Possible values are "end-user", "agent", or "admin". | 
| Zendesk.UserGroup.role_type | Number | The user's role type. | 
| Zendesk.UserGroup.shared | Boolean | Whether the user is shared from a different Zendesk Support instance. | 
| Zendesk.UserGroup.shared_agent | Boolean | Whether the user is a shared agent from a different Zendesk Support instance. | 
| Zendesk.UserGroup.shared_phone_number | Boolean | Whether the phone number is shared. | 
| Zendesk.UserGroup.signature | String | The user's signature. | 
| Zendesk.UserGroup.suspended | Boolean | Whether the agent is suspended. Tickets from suspended users are also suspended, and these users cannot sign in to the end user portal. | 
| Zendesk.UserGroup.tags | Unknown | The user's tags. Only present if your account has user tagging enabled. | 
| Zendesk.UserGroup.ticket_restriction | Unknown | Specifies which tickets the user has access to. Possible values are: "organization", "groups", "assigned", "requested", null. | 
| Zendesk.UserGroup.time_zone | String | The user's time zone. | 
| Zendesk.UserGroup.two_factor_auth_enabled | Unknown | Whether two factor authentication is enabled. | 
| Zendesk.UserGroup.updated_at | Date | The time the user was last updated. | 
| Zendesk.UserGroup.url | String | The URL that points to the user's API record. | 
| Zendesk.UserGroup.user_fields | Unknown | The user fields as shown in the Zendesk user interface. | 
| Zendesk.UserGroup.verified | Boolean | Whether any of the user's identities is verified. | 

#### Command example
```!zendesk-group-user-list group_id=12345 limit=1```
#### Context Example
```json
{
    "Zendesk": {
        "UserGroup": [
            {
                "active": true,
                "alias": "",
                "created_at": "2022-03-27T08:42:06Z",
                "custom_role_id": 4678497517981,
                "default_group_id": 4678483739805,
                "details": "",
                "email": "test@user.com",
                "external_id": null,
                "iana_time_zone": "Asia/Jerusalem",
                "id": 1908275070333,
                "last_login_at": "2023-05-31T11:13:41Z",
                "locale": "en-US",
                "locale_id": 1,
                "moderator": true,
                "name": "Admin",
                "notes": "",
                "only_private_comments": false,
                "organization_id": 4678483740317,
                "phone": null,
                "photo": null,
                "report_csv": true,
                "restricted_agent": false,
                "role": "admin",
                "role_type": 4,
                "shared": false,
                "shared_agent": false,
                "shared_phone_number": null,
                "signature": "",
                "suspended": false,
                "tags": [],
                "ticket_restriction": null,
                "time_zone": "Asia/Jerusalem",
                "two_factor_auth_enabled": null,
                "updated_at": "2023-05-31T11:13:41Z",
                "url": "https://some-url/api/v2/users/1908275070333.json",
                "user_fields": {},
                "verified": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Zendesk Group Users:
>|Id|Name|Email|Role|CreatedAt|
>|---|---|---|---|---|
>| 1908275070333 | Admin | test@user.com | admin | 2022-03-27T08:42:06Z |

### zendesk-group-list

***
Get Zendesk groups. 
Allowed for: Admins, Agents.

#### Base Command

`zendesk-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page_size | The page size (used for pagination). | Optional | 
| page_number | The page number (used for pagination). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zendesk.Group.created_at | Date | The time the group was created. | 
| Zendesk.Group.default | Boolean | If the group is the default one for the account. | 
| Zendesk.Group.deleted | Boolean | `true` if the group is deleted `false` otherwise. | 
| Zendesk.Group.description | String | The description of the group. | 
| Zendesk.Group.id | Number | The group ID. | 
| Zendesk.Group.is_public | Boolean | If true, the group is public. If false, the group is private. You can't change a private group to a public group. | 
| Zendesk.Group.name | String | The name of the group. | 
| Zendesk.Group.updated_at | Date | The time of the last update of the group. | 
| Zendesk.Group.url | String | The API URL of the group. | 

#### Command example
```!zendesk-group-list limit=1```
#### Context Example
```json
{
    "Zendesk": {
        "Group": [
            {
                "created_at": "2023-06-06T07:44:20Z",
                "default": false,
                "deleted": false,
                "description": "This is a group for testing",
                "id": 11395818128925,
                "is_public": true,
                "name": "Test Group",
                "updated_at": "2023-06-06T07:44:20Z",
                "url": "https://some-url/api/v2/groups/11395818128925.json"
            }
        ]
    }
}
```

#### Human Readable Output

>### Zendesk groups:
>|Id| Name |IsPublic|CreatedAt|UpdatedAt|
>|------|---|---|---|---|
>| 11395818128925 | Test Group | true | 2023-06-06T07:44:20Z | 2023-06-06T07:44:20Z |


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Zendesk v2 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Zendesk v2 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Zendesk v2 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Zendesk v2 events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Zendesk v2.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.


**Important Notes:** 
- To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Zendesk v2.
- Required permissions: Admins
