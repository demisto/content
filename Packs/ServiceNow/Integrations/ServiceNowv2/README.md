IT service management. Demisto interfaces with ServiceNow to help streamline security-related service management and IT operations. For example, you can use the ‘ServiceNow’ integration in order to:

- View, create, update or delete a ServiceNow ticket directly from the Demisto CLI and enrich it with Demisto data.
- View, create, update and delete records from any ServiceNow table.
- Query ServiceNow data with the ServiceNow query syntax.

Please refer to ServiceNow documentation for additional information. We especially recommend the Operators available for filters and queries page: https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html

This integration was integrated and tested with the Orlando version of ServiceNow.

## Use cases
1. Get, update, create, and delete ServiceNow tickets, as well as add links and comments, or upload files to the tickets.
2. Fetch newly created incidents.
3. Get, update, create, delete records from any ServiceNow table.
## Wrapper Scripts
There are 3 scripts that serve as examples for wrapping the following generic commands:
servicenow-query-table - ServiceNowQueryIncident
servicenow-create-record - ServiceNowCreateIncident
servicenow-update-record - ServiceNowUpdateIncident

You can use these scripts if you want to wrap these commands around a ServiceNow table of your choice.
These scripts are wrapped around the incident table, so to wrap them around another table simply copy the scripts and edit the code, arguments and outputs accordingly.
## Configure ServiceNow v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceNow v2.
3. Click **Add instance** to create and configure a new integration instance.
4. To ensure that mirroring works:
   1. Select the **Fetches incidents** radio button.
   2. Under **Classifier**, select ServiceNow Classifier.
   3. Under **Incident type**, select ServiceNowTicket.
   4. Under **Mapper (incoming)**, select ServiceNow - Incoming Mapper.
   5. Under **Mapper (outgoing)**, select ServiceNow - Outgoing Mapper.
   6. To enable mirroring when closing an incident or ticket in Cortex XSOAR and ServiceNow, select the **Close Mirrored XSOAR Incident** and **Close Mirrored ServiceNow Ticket** checkboxes, respectively.

        ![image](https://raw.githubusercontent.com/demisto/content/8038ce7e02dfd47b75adc9bedf1f7e9747dd77d5/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/closing-params.png)
        
## Instance Creation Flow
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization follow the next steps:
1. Login to your ServiceNow instance and create an endpoint for XSOAR to access your instance (please see [Snow OAuth](https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/security/task/t_CreateEndpointforExternalClients.html) for more information). 
2. Copy the `Client Id` and `Client Secret` (press the lock next to the client secret to reveal it) that were automatically generated when creating the endpoint into the `Username` and `Password` fields of the instance configuration.
3. Select the `Use OAuth Login` checkbox and click the `Done` button.
4. Run the command `!servicenow-oauth-login` from the XSOAR CLI and fill in the username and password of the ServiceNow instance. This step generates an access token to the ServiceNow instance and is required only in the first time after configuring a new instance in the XSOAR platform.
5. (Optional) Test the created instance by running the `!servicenow-oauth-test` command.

**Notes:**
1. When running the `!servicenow-oauth-login` command, a refresh token is generated and will be used to produce new access tokens after the current access token has expired.
2. Every time the refresh token expires you will have to run the `servicenow-oauth-login` command again. Hence, we recommend to set the `Refresh Token Lifespan` field in the endpoint created in step 1 to a long period (can be set to several years). 


### Using Multi Factor Authentication (MFA)
MFA can be used both when using basic authorization and when using OAuth 2.0 authorization, however we strongly recommend using OAuth 2.0 when using MFA.
If MFA is enabled for your user, follow the next steps:
1. Open the Google Authenticator application on your mobile device and make note of the number. The number refreshes every 30 seconds.
2. Enter your username and password, and append the One Time Password (OTP) that you currently see on your mobile device to your password without any extra spaces. For example, if your password is `12345` and the current OTP code is `424 058`, enter `12345424058`.

**Notes:**
1. When using basic authorization, you will have to update your password with the current OTP every time the current code expires (30 seconds), hence we recommend using OAuth 2.0 authorization.
2. For using OAuth 2.0 see the above instructions. The OTP code should be appended to the password parameter in the `!servicenow-oauth-login` command.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ServiceNow URL, in the format `https://company.service-now.com/` | True |
| credentials | Username | False |
| use_oauth | Use OAuth | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| ticket_type | Default ticket type on which to run ticket commands and fetch incidents | False |
| api_version | ServiceNow API Version \(e.g. 'v1'\) | False |
| isFetch | Fetch incidents | False |
| sysparm_query | The query to use when fetching incidents | False |
| fetch_limit | How many incidents to fetch each time | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| timestamp_field | Timestamp field to filter by \(e.g., \`opened\_at\`\) This is how the filter is applied to the query: "ORDERBYopened\_at^opened\_at&gt;\[Last Run\]". To prevent duplicate incidents, this field is mandatory for fetching incidents. | False |
| incidentType | Incident type | False |
| get_attachments | Get incident attachments | False |
| mirror_direction | Chose whenever to mirror the incident. You can mirror only In (from ServiceNow to XSOAR), only out(from XSOAR to ServiceNow) or both direction. | None |
| comment_tag | Choose the tag to add to an entry to mirror it as a comment in ServiceNow. | comments |
| work_notes_tag | Choose the tag to add to an entry to mirror it as a work note in ServiceNow. | work_notes |
| file_tag | Choose the tag to add to an entry to mirror it as a file in ServiceNow. | ForServiceNow |
| close_incident | Close XSOAR Incident. When selected, closing the ServiceNow ticket is mirrored in Cortex XSOAR. | False |
| close_ticket | Close ServiceNow Ticket. When selected, closing the XSOAR incident is mirrored in ServiceNow. | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

5. Click **Test** to validate the URLs, token, and connection.
6. Click **Done.**

## Fetch Incidents
The integration fetches newly created tickets according to the following parameters,
which you define in the instance configuration: ticket_type, query, and limit.
For the first fetch, the integration will fetch incidents that were created 10 minutes earlier. 
After that, it will fetch incidents that were created after the timestamp of the last fetch.

## Configure Incident Mirroring
**This feature is compliant with XSOAR version 6.0 and above.**
This part walks you through setting up the ServiceNow v2 integration to mirror incidents from ServiceNow in Cortex XSOAR. 
It includes steps for configuring the integration and incoming and outgoing mappers. However, it does not cover every option available in the integration nor classification and mapping features. 
For information about **Classification and Mapping** visit: [Classification and Mapping](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/incidents/classification-and-mapping.html).

When mirroring incidents, you can make changes in ServiceNow that will be reflected in Cortex XSOAR, or vice versa. 
You can also attach files from either of the systems, which will then be available in the other system. 

This is made possible by the addition of 3 new functions in the integration, which are applied with the following options:
- External schema support
- Can sync mirror in
- Can sync mirror out

![image](https://raw.githubusercontent.com/demisto/content/d9bd0725e4bce1d68b949e66dcdd8f42931b1a88/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/mirror-configuration.png)

#### STEP 1 - Modify the incoming mapper.
1. Navigate to **Classification and Mapping** and click **ServiceNow - Incoming Mapper**.
2. Under the Incident Type dropdown, select **ServiceNow Ticket**.
3. Change the mapping according to your needs.
4. Save your changes.
    
##### 5 fields have been added to support the mirroring feature:
- **dbotMirrorDirection** - determines whether mirroring is incoming, outgoing, or both. Default is Both.
    - You can choose the mirror direction when configuring the ServiceNow instance using the **Incident Mirroring Direction** field.

- **dbotMirrorId** - determines the incident ID in the 3rd party integration. In this case, the ServiceNow sys ID field.
- **dbotMirrorInstance** - determines the ServiceNow instance with which to mirror.
- **dbotMirrorLastSync** - determines the field by which to indicate the last time that the systems synchronized.
- **dbotMirrorTags** - determines the tags that you need to add in Cortex XSOAR for entries to be pushed to ServiceNow.
    - You can set the tags in the instance configuration, using **Comment Entry Tag**, **Work Note Entry Tag** and **File Entry Tag**.

![image](https://raw.githubusercontent.com/demisto/content/d9bd0725e4bce1d68b949e66dcdd8f42931b1a88/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/mirror-fields.png)

#### STEP 2 - Modify the outgoing mapper.
1. Under **Classification and Mapping**, click **ServiceNow - Outgoing Mapper.**
The left side of the screen shows the ServiceNow fields to which to map and the right side of the
screen shows the Cortex XSOAR fields by which you are mapping.
2. Under the **Incident Type** dropdown, select **ServiceNow Ticket**.
3. Under **Schema Type**, select **incident**. The Schema Type represents the ServiceNow entity that
you are mapping to. In our example it is an incident, but it can also be any other kind of ticket that
ServiceNow supports.
4. On the right side of the screen, under **Incident**, select the incident based on which you want to
match.
5. Change the mapping according to your needs.
6. Save your changes.

![image](https://raw.githubusercontent.com/demisto/content/d9bd0725e4bce1d68b949e66dcdd8f42931b1a88/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/outgoing-mapper.png)



#### STEP 3 - Create an incident in ServiceNow. For purposes of this use case, it can be a very simple incident

#### STEP 4 - In Cortex XSOAR, the new ticket will be ingested in approximately one minute.
1. Add a note to the incident. In the example below, we have written A comment from Cortex XSOAR to ServiceNow.
2. Click Actions > Tags and add the comments tag.
3. Add a file to the incident and mark it with the ForServiceNow tag.

![image](https://raw.githubusercontent.com/demisto/content/d9bd0725e4bce1d68b949e66dcdd8f42931b1a88/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/mirror-files.png)
4. Navigate back to the incident in ServiceNow and within approximately one minute, the changes will be reflected there, too.
* You can make additional changes like closing the incident or changing severity and those will be reflected in both systems.

![image](https://raw.githubusercontent.com/demisto/content/d9bd0725e4bce1d68b949e66dcdd8f42931b1a88/Packs/ServiceNow/Integrations/ServiceNowv2/doc_files/ticket-example.png)


* The final **source of truth** for the incident for Cortex XSOAR are the **values in Cortex XSOAR**. 
Meaning, if you change the severity in Cortex XSOAR and then change it back in ServiceNow, the final value that will be presented is the one in Cortex XSOAR.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### servicenow-login
***
This function should be used once before running any command when using OAuth authentication.

#### Base Command

`servicenow-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username that should be used for login. | Required | 
| password | The password that should be used for login. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-login username=username password=password```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Logged in successfully

### servicenow-test
***
Test the instance configuration when using OAuth authorization.


#### Base Command

`servicenow-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-test```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Instance Configured Successfully


### servicenow-get-ticket
***
Retrieves ticket information by ticket ID.


#### Base Command

`servicenow-get-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket system ID for which to retrieve information. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| number | Ticket number to retrieve. | Optional | 
| get_attachments | If "true" will retrieve ticket attachments. Default is "false". | Optional | 
| custom_fields | Custom fields on which to query. For example: state_code=AR,time_zone=PST. | Optional | 
| additional_fields | Additional fields to display in the War Room entry and incident context. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID. | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID. | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID. | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state. | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary. | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number. | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active. | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments. | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority. | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time. | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID. | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code. | 
| File.Info | string | Attachment file info. | 
| File.Name | string | Attachment file name. | 
| File.Size | number | Attachment file size. | 
| File.SHA1 | string | Attachment file SHA1 hash. | 
| File.SHA256 | string | Attachment file SHA256 hash. | 
| File.EntryID | string | Attachment file entry ID. | 
| File.Type | string | Attachment file type. | 
| File.MD5 | string | Attachment file MD5 hash. | 


#### Command Example
```!servicenow-get-ticket number=INC0000040```

#### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "Active": "true",
            "Assignee": "admin",
            "CreatedOn": "2020-01-26 00:43:54",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0000040",
            "OpenedAt": "2020-01-26 00:42:45",
            "OpenedBy": "admin",
            "Priority": "3 - Moderate",
            "State": "3",
            "Summary": "JavaScript error on hiring page of corporate website"
        }
    },
    "Ticket": {
        "Active": "true",
        "Assignee": "admin",
        "CreatedOn": "2020-01-26 00:43:54",
        "Creator": "admin",
        "ID": "id",
        "Number": "INC0000040",
        "OpenedAt": "2020-01-26 00:42:45",
        "OpenedBy": "admin",
        "Priority": "3 - Moderate",
        "State": "3",
        "Summary": "JavaScript error on hiring page of corporate website"
    }
}
```

#### Human Readable Output

>### ServiceNow ticket
>|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Description|Opened At|Short Description|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| id | INC0000040 | 2 - Medium | 2 - Medium | 3 - Low | 3 - Moderate | 3 - On Hold | 2020-01-26 00:43:54 | admin | true | Seeing JavaScript error message on hiring page on Explorer and Firefox. | 2020-01-26 00:42:45 | JavaScript error on hiring page of corporate website |


### servicenow-create-ticket
***
Creates new ServiceNow ticket.


#### Base Command

`servicenow-create-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| urgency | Ticket urgency. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". | Optional | 
| severity | Ticket severity. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". | Optional | 
| impact | Ticket impact. | Optional | 
| active | Whether to set the ticket as Active. Can be "true" or "false". | Optional | 
| activity_due | The ticket activity due date, in the format "2016-07-02 21:51:11". | Optional | 
| additional_assignee_list | List of users assigned to the ticket. | Optional | 
| approval_history | Ticket history approval. | Optional | 
| approval_set | The ticket approval set date, in the format "2016-07-02 21:51:11". | Optional | 
| assigned_to | User assigned to the ticket. | Optional | 
| business_duration | Business duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| business_service | Business service. | Optional | 
| business_stc | Business source. | Optional | 
| calendar_duration | Calendar duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller_id | Caller ID (UID format). | Optional | 
| category | Category of the ticket. | Optional | 
| caused_by | UID Format | Optional | 
| close_code | Ticket's close code. Can be "Solved (Work Around)", "Solved (Permanently)", "Solved Remotely (Work Around)", "Solved Remotely (Permanently)", "Not Solved (Not Reproducible)", "Not Solved (Too Costly)", or "Closed/Resolved by Caller". | Optional | 
| close_notes | Close notes of the ticket. | Optional | 
| closed_at | When the ticket was closed, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| closed_by | User who closed the ticket. | Optional | 
| cmdb_ci | UID Format. | Optional | 
| comments | Format type journal input. | Optional | 
| comments_and_work_notes | Format type journal input. | Optional | 
| company | Company (UID format). | Optional | 
| contact_type | Contact type. | Optional | 
| correlation_display | Correlation display. | Optional | 
| correlation_id | Correlation ID. | Optional | 
| delivery_plan | Delivery plan (UID format). | Optional | 
| display | Whether to display comments, work notes, and so on. Can be "true" or "false". | Optional | 
| description | Ticket description. | Optional | 
| due_date | Ticket due date, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| escalation | Escalation | Optional | 
| expected_start | Expected start date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| follow_up | Follow up date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| group_list | UID format list (group). | Optional | 
| knowledge | Whether the ticket is solved in the knowledge base. Can be "true" or "false". | Optional | 
| location | Location of the ticket. | Optional | 
| made_sla | SLA of the ticket. | Optional | 
| notify | Whether to be notified about this ticket. Can be "1" or "0". | Optional | 
| order | Order number. | Optional | 
| parent | UID Format | Optional | 
| parent_incident | UID Format | Optional | 
| problem_id | UID Format | Optional | 
| reassignment_count | The number of users included in this ticket. | Optional | 
| reopen_count | How many times the ticket has been reopened. | Optional | 
| resolved_at | The date/time that the ticket was resolved, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| resolved_by | ID of the user that resolved the ticket. | Optional | 
| rfc | UID | Optional | 
| sla_due | SLA due date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| subcategory | Ticket subcategory. | Optional | 
| sys_updated_by | Last updated by. | Optional | 
| sys_updated_on | Last date/time that the system was updated, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| user_input | Input from the end user. | Optional | 
| watch_list | A list of watched tickets. | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| work_notes | Format journal list | Optional | 
| work_notes_list | List work notes UIDs. | Optional | 
| work_start | Date/time when work started on the ticket. | Optional | 
| assignment_group | The sys_id of the group to assign. | Optional | 
| incident_state | The number that represents the incident state. | Optional | 
| number | Ticket number. | Optional | 
| priority | Priority of the ticket. | Optional | 
| template | Template name to use as a base to create new tickets. | Optional | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a "u_". | Optional | 
| change_type | Type of Change Request ticket. Can be "normal", "standard", or "emergency". Default is "normal". | Optional | 
| state | State of the ticket, for example: "Closed" or "7" or "7 - Closed". | Optional | 
| opened_at |  Date/time the ticket was opened, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller | Caller system ID. | Optional | 
| approval | Ticket approval. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value; | Optional | 
| input_display_value | Flag that indicates whether to set field values using the display value or the actual value. True will treat the input value as the display value. False treats the input values as actual values. The default setting is false. | Optional |

For more information regarding the input_display_value Argument, please see: https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/exporting-data/concept/query-parameters-display-value.html


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID. | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID. | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID. | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state. | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary. | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number. | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active. | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments. | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority. | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time. | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID. | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code. | 


#### Command Example
```!servicenow-create-ticket active=true severity="2 - Medium" short_description="Ticket example"```

#### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "Active": "true",
            "CreatedOn": "2020-05-10 09:04:06",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0010002",
            "OpenedAt": "2020-05-10 09:04:06",
            "OpenedBy": "admin",
            "Priority": "5 - Planning",
            "State": "1",
            "Summary": "Ticket exmaple"
        }
    },
    "Ticket": {
        "Active": "true",
        "CreatedOn": "2020-05-10 09:04:06",
        "Creator": "admin",
        "ID": "id",
        "Number": "INC0010002",
        "OpenedAt": "2020-05-10 09:04:06",
        "OpenedBy": "admin",
        "Priority": "5 - Planning",
        "State": "1",
        "Summary": "Ticket example"
    }
}
```

#### Human Readable Output

>### ServiceNow ticket was created successfully.
>|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Opened At|Short Description|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| id | INC0010002 | 3 - Low | 3 - Low | 2 - Medium | 5 - Planning | 1 - New | 2020-05-10 09:04:06 | admin | true | 2020-05-10 09:04:06 | Ticket example |


### servicenow-update-ticket
***
Updates the specified ticket.


#### Base Command

`servicenow-update-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| urgency | Ticket urgency. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". | Optional | 
| severity | Ticket severity. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". | Optional | 
| impact | Ticket impact. | Optional | 
| active | Whether the ticket is Active. Can be "true" or "false". | Optional | 
| activity_due | The ticket activity due date, in the format: "2016-07-02 21:51:11". | Optional | 
| additional_assignee_list | List of users assigned to the ticket. | Optional | 
| approval_history | Ticket history approval. | Optional | 
| approval_set | The ticket approval set date/time, in the format: "2016-07-02 21:51:11". | Optional | 
| assigned_to | User assigned to the ticket. | Optional | 
| business_duration | Business duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| business_service | Business service. | Optional | 
| business_stc | Business source. | Optional | 
| calendar_duration | Calendar duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller_id | Caller ID (UID format). | Optional | 
| category | Category name. | Optional | 
| caused_by | UID format. | Optional | 
| close_code | Ticket's close code. Ticket's close code. Can be "Solved (Work Around)", "Solved (Permanently)", "Solved Remotely (Work Around)", "Solved Remotely (Permanently)", "Not Solved (Not Reproducible)", "Not Solved (Too Costly)", or "Closed/Resolved by Caller". | Optional | 
| close_notes | Close notes of the ticket. | Optional | 
| closed_at | Date/time the ticket was closed, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| closed_by | User who closed the ticket. | Optional | 
| cmdb_ci | UID Format. | Optional | 
| comments | Format type journal input. | Optional | 
| comments_and_work_notes | Format type journal input. | Optional | 
| company | UID Format. | Optional | 
| contact_type | Contact type. | Optional | 
| correlation_display | Correlation display. | Optional | 
| correlation_id | Correlation ID. | Optional | 
| delivery_plan | UID Format. | Optional | 
| display | Whether to display comments, work notes, and so on. Can be "true" or "false". | Optional | 
| description | Ticket description. | Optional | 
| due_date | Ticket due date, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| escalation | Escalation. | Optional | 
| expected_start | Expected start date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| follow_up | Follow up date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| group_list | UID format list. | Optional | 
| knowledge | Whether the ticket is solved in the knowledge base. Can be "true" or "false". | Optional | 
| location | Location of the ticket. | Optional | 
| made_sla | SLA of the ticket. | Optional | 
| notify | Whether to be notified about this ticket. Can be "1" or "0". | Optional | 
| order | Order number. | Optional | 
| parent | Parent (UID format). | Optional | 
| parent_incident | Parent incident (UID format). | Optional | 
| problem_id | Problem ID (UID format). | Optional | 
| reassignment_count | The number of users included in this ticket. | Optional | 
| reopen_count | The number of times the ticket has been reopened. | Optional | 
| resolved_at | Date/time the ticket was resolved, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| resolved_by | Resolved by (UID format). | Optional | 
| rfc | UID | Optional | 
| sla_due | SLA due date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| subcategory | Ticket subcategory. | Optional | 
| sys_updated_by | Last updated by | Optional | 
| sys_updated_on | Date/time the system was last updated. | Optional | 
| user_input | Input from the end user. | Optional | 
| watch_list | A list of watched tickets. | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| work_notes | Format journal list. | Optional | 
| work_notes_list | Comma-separated list of work notes UIDs. | Optional | 
| work_start | Date/time when work started on the ticket. | Optional | 
| assignment_group | Assignment group UID. | Optional | 
| incident_state | Number representing the incident state. | Optional | 
| number | Ticket number. | Optional | 
| priority | Priority of the ticket. | Optional | 
| id | System ID of the ticket to update. | Required | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a "u_". | Optional | 
| change_type | Type of Change Request ticket. Can be "normal", "standard", or "emergency". Default is "normal". | Optional | 
| state | State of the ticket, for example: "Closed" or "7" or "7 - Closed". | Optional | 
| caller | Caller system ID. | Optional | 
| approval | Ticket approval. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value; | Optional | 
| input_display_value | Flag that indicates whether to set field values using the display value or the actual value. True will treat the input value as the display value. False treats the input values as actual values. The default setting is false. | Optional |

For more information regarding the input_display_value Argument, please see: https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/exporting-data/concept/query-parameters-display-value.html

#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-update-ticket id=id severity="2 - Medium"```

#### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "Active": "true",
            "Assignee": "admin",
            "CreatedOn": "2020-01-26 00:43:54",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0000040",
            "OpenedAt": "2020-01-26 00:42:45",
            "OpenedBy": "admin",
            "Priority": "3 - Moderate",
            "State": "3",
            "Summary": "JavaScript error on hiring page of corporate website"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow ticket updated successfully
>Ticket type: incident
>|Active|Created By|Created On|Description|Impact|Number|Opened At|Priority|Severity|Short Description|State|System ID|Urgency|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | admin | 2020-01-26 00:43:54 | Seeing JavaScript error message on hiring page on Explorer and Firefox. | 2 - Medium | INC0000040 | 2020-01-26 00:42:45 | 3 - Moderate | 2 - Medium | JavaScript error on hiring page of corporate website | 3 - On Hold | 471d4732a9fe198100affbf655e59172 | 2 - Medium |


### servicenow-delete-ticket
***
Deletes a ticket from ServiceNow.


#### Base Command

`servicenow-delete-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-delete-ticket id=id```

#### Context Example
```
{}
```

#### Human Readable Output

>Ticket with ID id was successfully deleted.

### servicenow-query-tickets
***
Retrieves ticket information according to the supplied query.


#### Base Command

`servicenow-query-tickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of tickets to retrieve. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| query | The query to run. To learn about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 
| additional_fields | Additional fields to present in the War Room entry and incident context. | Optional | 
| system_params | System parameters in the format: fieldname1=value;fieldname2=value. For example: "sysparm_display_value=al;&amp;sysparm_exclude_reference_link=True" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | The unique ticket identifier. | 
| Ticket.Creator | string | A string field that indicates the user who created the ticket. | 
| Ticket.CreatedOn | date | The date/time when the ticket was created. | 
| Ticket.Assignee | string | Specifies the user assigned to complete the ticket. By default, this field uses a reference qualifier to only display users with the itil role. | 
| Ticket.State | string | Status of the ticket. | 
| Ticket.Summary | string | A human\-readable title for the record. | 
| Ticket.Number | string | The display value of the ticket. | 
| Ticket.Active | boolean | Specifies whether work is still being done on a task or whether the work for the task is complete. | 
| Ticket.AdditionalComments | Unknown | Comments about the task record. | 
| Ticket.Priority | string | Specifies the ticket priority for the assignee. | 
| Ticket.OpenedAt | date | The date/time when the ticket was first opened. | 
| Ticket.Escalation | string | Indicates how long the ticket has been open. | 


#### Command Example
```!servicenow-query-tickets limit="3" query="impact<2^short_descriptionISNOTEMPTY" ticket_type="incident"```

#### Context Example
```
{
    "ServiceNow": {
        "Ticket": [
            {
                "Active": "false",
                "Assignee": "admin",
                "CloseCode": "Closed/Resolved by Caller",
                "CreatedOn": "2018-08-24 18:24:13",
                "Creator": "admin",
                "ID": "id",
                "Number": "INC0000001",
                "OpenedAt": "2020-01-23 23:09:51",
                "OpenedBy": "admin",
                "Priority": "1 - Critical",
                "ResolvedBy": "admin",
                "State": "7",
                "Summary": "Can't read email"
            },
            {
                "Active": "true",
                "Assignee": "admin",
                "CreatedOn": "2018-08-13 22:30:06",
                "Creator": "admin",
                "ID": "id",
                "Number": "INC0000002",
                "OpenedAt": "2020-01-17 23:07:12",
                "OpenedBy": "admin",
                "Priority": "1 - Critical",
                "State": "3",
                "Summary": "Network file shares access issue"
            },
            {
                "Active": "true",
                "Assignee": "admin",
                "CreatedOn": "2018-08-28 14:41:46",
                "Creator": "admin",
                "ID": "id",
                "Number": "INC0000003",
                "OpenedAt": "2020-01-24 23:07:30",
                "OpenedBy": "admin",
                "Priority": "1 - Critical",
                "State": "2",
                "Summary": "Wireless access is down in my area"
            }
        ]
    },
    "Ticket": [
        {
            "Active": "false",
            "Assignee": "admin",
            "CloseCode": "Closed/Resolved by Caller",
            "CreatedOn": "2018-08-24 18:24:13",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0000001",
            "OpenedAt": "2020-01-23 23:09:51",
            "OpenedBy": "admin",
            "Priority": "1 - Critical",
            "ResolvedBy": "admin",
            "State": "7",
            "Summary": "Can't read email"
        },
        {
            "Active": "true",
            "Assignee": "admin",
            "CreatedOn": "2018-08-13 22:30:06",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0000002",
            "OpenedAt": "2020-01-17 23:07:12",
            "OpenedBy": "admin",
            "Priority": "1 - Critical",
            "State": "3",
            "Summary": "Network file shares access issue"
        },
        {
            "Active": "true",
            "Assignee": "admin",
            "CreatedOn": "2018-08-28 14:41:46",
            "Creator": "admin",
            "ID": "id",
            "Number": "INC0000003",
            "OpenedAt": "2020-01-24 23:07:30",
            "OpenedBy": "admin",
            "Priority": "1 - Critical",
            "State": "2",
            "Summary": "Wireless access is down in my area"
        }
    ]
}
```

#### Human Readable Output

>### ServiceNow tickets
>|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Close Notes|Close Code|Description|Opened At|Resolved By|Resolved At|Short Description|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| id | INC0000001 | 1 - High | 1 - High | 1 - High | 1 - Critical | 7 - Closed | 2018-08-24 18:24:13 | pat | false | Closed before close notes were made mandatory<br/>		 | Closed/Resolved by Caller | User can't access email on mail.company.com.<br/>		 | 2020-01-23 23:09:51 | admin | 2020-04-24 19:56:12 | Can't read email |
>| id | INC0000002 | 1 - High | 1 - High | 1 - High | 1 - Critical | 3 - On Hold | 2018-08-13 22:30:06 | pat | true |  |  | User can't get to any of his files on the file server. | 2020-01-17 23:07:12 |  |  | Network file shares access issue |
>| id | INC0000003 | 1 - High | 1 - High | 1 - High | 1 - Critical | 2 - In Progress | 2018-08-28 14:41:46 | admin | true |  |  | I just moved from floor 2 to floor 3 and my laptop cannot connect to any wireless network. | 2020-01-24 23:07:30 |  |  | Wireless access is down in my area |


### servicenow-add-link
***
Adds a link to the specified ticket.


#### Base Command

`servicenow-add-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| link | The actual link to publish in ServiceNow ticket, in a valid URL format, for example, http://www.demisto.com. | Required | 
| post-as-comment | Whether to publish the link as comment on the ticket. Can be "true" or "false". If false will publish the link as WorkNote. | Optional | 
| text | The text to represent the link. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-add-link id=id link="http://www.demisto.com" text=demsito_link```

#### Context Example
```
{}
```

#### Human Readable Output

>### Link successfully added to ServiceNow ticket
>|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Description|Opened At|Short Description|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| id | INC0000040 | 2 - Medium | 2 - Medium | 2 - Medium | 3 - Moderate | 3 - On Hold | 2020-01-26 00:43:54 | admin | true | Seeing JavaScript error message on hiring page on Explorer and Firefox. | 2020-01-26 00:42:45 | JavaScript error on hiring page of corporate website |


### servicenow-add-comment
***
Adds a comment to the specified ticket, by ticket ID.


#### Base Command

`servicenow-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| comment | Comment to add. | Required | 
| post-as-comment | Whether to publish the note as comment on the ticket. Can be "true" or "false". Default is "false". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-add-comment id=id comment="Nice work!"```

#### Context Example
```
{}
```

#### Human Readable Output

>### Comment successfully added to ServiceNow ticket
>|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Description|Opened At|Short Description|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| id | INC0000040 | 2 - Medium | 2 - Medium | 2 - Medium | 3 - Moderate | 3 - On Hold | 2020-01-26 00:43:54 | admin | true | Seeing JavaScript error message on hiring page on Explorer and Firefox. | 2020-01-26 00:42:45 | JavaScript error on hiring page of corporate website |


### servicenow-upload-file
***
Uploads a file to the specified ticket.


#### Base Command

`servicenow-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 
| file_id | War Room entry ID that includes the file. | Required | 
| file_name | Filename of the uploaded file to override the existing file name in the entry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.File.Filename | string | Name of the file. | 
| ServiceNow.Ticket.File.Link | string | Download link for the file. | 
| ServiceNow.Ticket.File.SystemID | string | System ID of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### servicenow-get-record
***
Retrieves record information, by record ID.


#### Base Command

`servicenow-get-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Record System ID. | Required | 
| fields | Comma-separated list of table fields to display and output to the context, for example: name,tag,company. ID field is added by default. | Optional | 
| table_name | The name of the table from which to get the record. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time\-stamp field that indicates when a record was created. | 


#### Command Example
```!servicenow-get-record table_name=alm_asset id=id fields=asset_tag,sys_updated_by,display_name```

#### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "ID": "id",
            "asset_tag": "P1000807",
            "display_name": "P1000807 - Apple MacBook Pro 17\"",
            "sys_updated_by": "system"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow record
>|ID|asset_tag|display_name|sys_updated_by|
>|---|---|---|---|
>| id | P1000807 | P1000807 - Apple MacBook Pro 17" | system |


### servicenow-query-table
***
Queries the specified table in ServiceNow.


#### Base Command

`servicenow-query-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to query | Required | 
| limit | The maximum number of tickets to retrieve. | Optional | 
| query | The query to run. For more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| fields | Comma-separated list of table fields to display and output to the context, for example: name,tag,company. ID field is added by default. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 
| system_params | System parameters in the format: fieldname1=value;fieldname2=value. For example: "sysparm_display_value=al;&amp;sysparm_exclude_reference_link=True" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Results.ID | string | The unique record identifier for the record. | 
| ServiceNow.Results.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Results.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Results.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Results.CreatedOn | date | A time\-stamp field that indicates when a record was created. | 


#### Command Example
```!servicenow-query-table table_name=alm_asset fields=asset_tag,sys_updated_by,display_name query=display_nameCONTAINSMacBook limit=4```

#### Context Example
```
{
    "ServiceNow": {
        "Record": [
            {
                "ID": "id",
                "asset_tag": "P1000637",
                "display_name": "P1000637 - Apple MacBook Air 13\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000412",
                "display_name": "P1000412 - Apple MacBook Pro 17\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000563",
                "display_name": "P1000563 - Apple MacBook Pro 15\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000626",
                "display_name": "P1000626 - Apple MacBook Air 13\"",
                "sys_updated_by": "system"
            }
        ]
    }
}
```

#### Human Readable Output

>### ServiceNow records
>|ID|asset_tag|display_name|sys_updated_by|
>|---|---|---|---|
>| id | P1000637 | P1000637 - Apple MacBook Air 13" | system |
>| id | P1000412 | P1000412 - Apple MacBook Pro 17" | system |
>| id | P1000563 | P1000563 - Apple MacBook Pro 15" | system |
>| id | P1000626 | P1000626 - Apple MacBook Air 13" | system |


### servicenow-create-record
***
Creates a new record in the specified ServiceNow table.


#### Base Command

`servicenow-create-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table in which to create a record. | Required | 
| fields | Fields and their values to create the record with, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value;... | Optional | 
| input_display_value | Flag that indicates whether to set field values using the display value or the actual value. True will treat the input value as the display value. False treats the input values as actual values. The default setting is false. | Optional |

For more information regarding the input_display_value Argument, please see: https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/exporting-data/concept/query-parameters-display-value.html


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time\-stamp field that indicates when a record was created. | 


#### Command Example
```!servicenow-create-record table_name=alm_asset fields="asset_tag=P1000807"```

#### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "CreatedAt": "2020-05-10 09:04:27",
            "CreatedBy": "admin",
            "ID": "id",
            "UpdatedAt": "2020-05-10 09:04:27",
            "UpdatedBy": "admin"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow record created successfully
>|CreatedAt|CreatedBy|ID|UpdatedAt|UpdatedBy|
>|---|---|---|---|---|
>| 2020-05-10 09:04:27 | admin | id | 2020-05-10 09:04:27 | admin |


### servicenow-update-record
***
Updates a record in the specified ServiceNow table.


#### Base Command

`servicenow-update-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to update the record in. | Required | 
| id | The system ID of the ticket to update. | Required | 
| fields | Fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom (user defined) fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional |
| input_display_value | Flag that indicates whether to set field values using the display value or the actual value. True will treat the input value as the display value. False treats the input values as actual values. The default setting is false. | Optional |

For more information regarding the input_display_value Argument, please see: https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/exporting-data/concept/query-parameters-display-value.html

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time\-stamp field that indicates when a record was created. | 


#### Command Example
```!servicenow-update-record table_name=alm_asset id=id custom_fields="display_name=test4"```

#### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "CreatedAt": "2019-07-16 08:14:09",
            "CreatedBy": "admin",
            "ID": "id",
            "UpdatedAt": "2020-05-09 19:08:42",
            "UpdatedBy": "system"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow record with ID 01a92c0d3790200044e0bfc8bcbe5d36 updated successfully
>|CreatedAt|CreatedBy|ID|UpdatedAt|UpdatedBy|
>|---|---|---|---|---|
>| 2019-07-16 08:14:09 | admin | id | 2020-05-09 19:08:42 | system |


### servicenow-delete-record
***
Deletes a record in the specified ServiceNow table.


#### Base Command

`servicenow-delete-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The table name. | Required | 
| id | The system ID of the ticket to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-delete-record table_name=alm_asset id=id```

#### Context Example
```
{}
```

#### Human Readable Output

>ServiceNow record with ID id was successfully deleted.

### servicenow-list-table-fields
***
Lists API fields for the specified ServiceNow table.


#### Base Command

`servicenow-list-table-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Field | string | Table API field name. | 


#### Command Example
```!servicenow-list-table-fields table_name=alm_asset```

#### Context Example
```
{
    "ServiceNow": {
        "Field": [
            {
                "Name": "parent"
            },
            {
                "Name": "skip_sync"
            },
            {
                "Name": "residual_date"
            },
            {
                "Name": "residual"
            },
            {
                "Name": "sys_updated_on"
            },
            {
                "Name": "request_line"
            },
            {
                "Name": "sys_updated_by"
            },
            {
                "Name": "due_in"
            },
            {
                "Name": "model_category"
            },
            {
                "Name": "sys_created_on"
            },
            {
                "Name": "sys_domain"
            },
            {
                "Name": "disposal_reason"
            },
            {
                "Name": "model"
            },
            {
                "Name": "install_date"
            },
            {
                "Name": "gl_account"
            },
            {
                "Name": "invoice_number"
            },
            {
                "Name": "sys_created_by"
            },
            {
                "Name": "warranty_expiration"
            },
            {
                "Name": "depreciated_amount"
            },
            {
                "Name": "substatus"
            },
            {
                "Name": "pre_allocated"
            },
            {
                "Name": "owned_by"
            },
            {
                "Name": "checked_out"
            },
            {
                "Name": "display_name"
            },
            {
                "Name": "sys_domain_path"
            },
            {
                "Name": "delivery_date"
            },
            {
                "Name": "retirement_date"
            },
            {
                "Name": "beneficiary"
            },
            {
                "Name": "install_status"
            },
            {
                "Name": "cost_center"
            },
            {
                "Name": "supported_by"
            },
            {
                "Name": "assigned"
            },
            {
                "Name": "purchase_date"
            },
            {
                "Name": "work_notes"
            },
            {
                "Name": "managed_by"
            },
            {
                "Name": "sys_class_name"
            },
            {
                "Name": "sys_id"
            },
            {
                "Name": "po_number"
            },
            {
                "Name": "stockroom"
            },
            {
                "Name": "checked_in"
            },
            {
                "Name": "resale_price"
            },
            {
                "Name": "vendor"
            },
            {
                "Name": "company"
            },
            {
                "Name": "retired"
            },
            {
                "Name": "justification"
            },
            {
                "Name": "department"
            },
            {
                "Name": "expenditure_type"
            },
            {
                "Name": "depreciation"
            },
            {
                "Name": "assigned_to"
            },
            {
                "Name": "depreciation_date"
            },
            {
                "Name": "old_status"
            },
            {
                "Name": "comments"
            },
            {
                "Name": "cost"
            },
            {
                "Name": "quantity"
            },
            {
                "Name": "acquisition_method"
            },
            {
                "Name": "ci"
            },
            {
                "Name": "sys_mod_count"
            },
            {
                "Name": "old_substatus"
            },
            {
                "Name": "sys_tags"
            },
            {
                "Name": "order_date"
            },
            {
                "Name": "support_group"
            },
            {
                "Name": "reserved_for"
            },
            {
                "Name": "due"
            },
            {
                "Name": "location"
            },
            {
                "Name": "lease_id"
            },
            {
                "Name": "salvage_value"
            }
        ]
    }
}
```

#### Human Readable Output

>### ServiceNow Table fields - alm_asset
>|Name|
>|---|
>| parent |
>| skip_sync |
>| residual_date |
>| residual |
>| sys_updated_on |
>| request_line |
>| sys_updated_by |
>| due_in |
>| model_category |
>| sys_created_on |
>| sys_domain |
>| disposal_reason |
>| model |
>| install_date |
>| gl_account |
>| invoice_number |
>| sys_created_by |
>| warranty_expiration |
>| depreciated_amount |
>| substatus |
>| pre_allocated |
>| owned_by |
>| checked_out |
>| display_name |
>| sys_domain_path |
>| delivery_date |
>| retirement_date |
>| beneficiary |
>| install_status |
>| cost_center |
>| supported_by |
>| assigned |
>| purchase_date |
>| work_notes |
>| managed_by |
>| sys_class_name |
>| sys_id |
>| po_number |
>| stockroom |
>| checked_in |
>| resale_price |
>| vendor |
>| company |
>| retired |
>| justification |
>| department |
>| expenditure_type |
>| depreciation |
>| assigned_to |
>| depreciation_date |
>| old_status |
>| comments |
>| cost |
>| quantity |
>| acquisition_method |
>| ci |
>| sys_mod_count |
>| old_substatus |
>| sys_tags |
>| order_date |
>| support_group |
>| reserved_for |
>| due |
>| location |
>| lease_id |
>| salvage_value |


### servicenow-query-computers
***
Queries the cmdb_ci_computer table in ServiceNow.


#### Base Command

`servicenow-query-computers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_id | Query by computer sys_id. | Optional | 
| computer_name | Query by computer name. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| asset_tag | Query by asset tag. | Optional | 
| limit | Maximum number of query results. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Computer.ID | string | Computer system ID. | 
| ServiceNow.Computer.AssetTag | string | Computer Asset tag. | 
| ServiceNow.Computer.Name | string | Computer name. | 
| ServiceNow.Computer.DisplayName | string | Computer display name. | 
| ServiceNow.Computer.SupportGroup | string | Computer support group. | 
| ServiceNow.Computer.OperatingSystem | string | Computer operating system. | 
| ServiceNow.Computer.Company | string | Computer company system ID. | 
| ServiceNow.Computer.AssignedTo | string | Computer assigned to user system ID. | 
| ServiceNow.Computer.State | string | Computer state. | 
| ServiceNow.Computer.Cost | string | Computer cost. | 
| ServiceNow.Computer.Comments | string | Computer comments. | 


#### Command Example
```!servicenow-query-computers asset_tag=P1000412```

#### Context Example
```
{
    "ServiceNow": {
        "Computer": {
            "AssetTag": "P1000412",
            "AssignedTo": "admin",
            "Company": "admin",
            "Cost": "2499.99 USD",
            "DisplayName": "P1000412 - MacBook Pro 17\"",
            "ID": "id",
            "Name": "MacBook Pro 17\"",
            "OperatingSystem": "Mac OS 10 (OS/X)",
            "State": "In use"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow Computers
>|ID|Asset Tag|Name|Display Name|Operating System|Company|Assigned To|State|Cost|
>|---|---|---|---|---|---|---|---|---|
>| id | P1000412 | MacBook Pro 17" | P1000412 - MacBook Pro 17" | Mac OS 10 (OS/X) | admin | admin | In use | 2499.99 USD |


### servicenow-query-groups
***
Queries the sys_user_group table in ServiceNow.


#### Base Command

`servicenow-query-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Query by group system ID. | Optional | 
| group_name | Query by group name. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| limit | Maximum number of query results. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Group.ID | string | Group system ID. | 
| ServiceNow.Group.Description | string | Group description. | 
| ServiceNow.Group.Name | string | Group name. | 
| ServiceNow.Group.Manager | string | Group manager system ID. | 
| ServiceNow.Group.Updated | date | Date/time the group was last updated. | 


#### Command Example
```!servicenow-query-groups group_name=test1```

#### Context Example
```
{}
```

#### Human Readable Output

>No groups found.

### servicenow-query-users
***
Queries the sys_user table in ServiceNow.


#### Base Command

`servicenow-query-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Query by user system ID. | Optional | 
| user_name | Query by username. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| limit | Maximum number of query results. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.User.ID | string | User system ID. | 
| ServiceNow.User.Name | string | User name \(first and last\). | 
| ServiceNow.User.UserName | string | User username. | 
| ServiceNow.User.Email | string | User email address. | 
| ServiceNow.User.Created | date | Date/time the user was created. | 
| ServiceNow.User.Updated | date | Date/time the user was last updated. | 


#### Command Example
```!servicenow-query-users user_name=sean.bonnet```

#### Context Example
```
{
    "ServiceNow": {
        "User": {
            "Created": "2012-02-18 03:04:50",
            "Email": "sean.bonnet@example.com",
            "ID": "id",
            "Name": "Sean Bonnet",
            "Updated": "2020-04-25 19:01:46",
            "UserName": "sean.bonnet"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow Users
>|ID|Name|User Name|Email|Created|Updated|
>|---|---|---|---|---|---|
>| id | Sean Bonnet | sean.bonnet | sean.bonnet@example.com | 2012-02-18 03:04:50 | 2020-04-25 19:01:46 |


### servicenow-get-table-name
***
Gets table names by a label to use in commands.


#### Base Command

`servicenow-get-table-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The table label, for example: Asset, Incident, IP address, and so on. | Required | 
| limit | Maximum number of query results. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Table.ID | string | Table system ID. | 
| ServiceNow.Table.Name | string | Table name to use in commands, for example: alm\_asset. | 
| ServiceNow.Table.SystemName | string | Table system name, for example: Asset. | 


#### Command Example
```!servicenow-get-table-name label=ACE```

#### Context Example
```
{
    "ServiceNow": {
        "Table": {
            "ID": "id",
            "Name": "cmdb_ci_lb_ace",
            "SystemName": "CMDB CI Lb Ace"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow Tables for label - ACE
>|ID|Name|System Name|
>|---|---|---|
>| id | cmdb_ci_lb_ace | CMDB CI Lb Ace |


### servicenow-get-ticket-notes
***
Gets notes from the specified ServiceNow ticket. "Read permissions" are required for the sys_journal_field table.


#### Base Command

`servicenow-get-ticket-notes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| limit | Maximum number of ticket notes. Default is 10. | Optional | 
| offset | Offset of the ticket notes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | Ticket ID. | 
| ServiceNow.Ticket.Note.Value | unknown | Ticket note value. | 
| ServiceNow.Ticket.Note.CreatedOn | date | Date/time the ticket note was created. | 
| ServiceNow.Ticket.Note.CreatedBy | string | User that created the ticket note. | 
| ServiceNow.Ticket.Note.Type | string | Ticket note type. | 


#### Command Example
```!servicenow-get-ticket-notes id=id```

#### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "ID": "id",
            "Note": [
                {
                    "CreatedBy": "admin",
                    "CreatedOn": "2020-01-26 00:43:54",
                    "Type": "Comment",
                    "Value": "JavaScript error (line 202) on the home page. Not sure what is\n\t\t\tgoing on, does not happen on my Windows machine!\n\t\t"
                },
                {
                    "CreatedBy": "admin",
                    "CreatedOn": "2020-04-17 23:12:43",
                    "Type": "Comment",
                    "Value": "Added an attachment"
                },
                {
                    "CreatedBy": "admin",
                    "CreatedOn": "2020-05-10 09:04:15",
                    "Type": "Work Note",
                    "Value": "[code]<a class=\"web\" target=\"_blank\" href=\"http://www.demisto.com\" >demsito_link</a>[/code]"
                },
                {
                    "CreatedBy": "admin",
                    "CreatedOn": "2020-05-10 09:04:18",
                    "Type": "Work Note",
                    "Value": "Nice work!"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ServiceNow notes for ticket 471d4732a9fe198100affbf655e59172
>|Value|Created On|Created By|Type|
>|---|---|---|---|
>| JavaScript error (line 202) on the home page. Not sure what is<br/>			going on, does not happen on my Windows machine!<br/>		 | 2020-01-26 00:43:54 | admin | Comment |
>| Added an attachment | 2020-04-17 23:12:43 | admin | Comment |
>| [code]<a class="web" target="_blank" href="http://www.demisto.com" >demsito_link</a>[/code] | 2020-05-10 09:04:15 | admin | Work Note |
>| Nice work! | 2020-05-10 09:04:18 | admin | Work Note |


### servicenow-add-tag
***
Adds a tag to a ticket. The tag will be visible in the label_entry table and can be retrieved using the "!servicenow-query-table table_name=label_entry fields=title,table,sys_id,id_display,id_type" command.


#### Base Command

`servicenow-add-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| tag_id | Tag system ID. Can be retrieved using the "!servicenow-query-table table_name=label fields=name,active,sys_id" command. | Required | 
| title | Tag title. For example: "Incident - INC000001". | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | String | The unique ticket identifier. | 
| ServiceNow.Ticket.TagTitle | String | Ticket tag title. | 
| ServiceNow.Ticket.TagID | String | Ticket tag ID. | 


### servicenow-query-items
***
Queries the sc_cat_item table in ServiceNow.


#### Base Command

`servicenow-query-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Query by name. Does not require an exact match. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 
| limit | Maximum number of query results. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.CatalogItem.ID | String | Catalog item system ID. | 
| ServiceNow.CatalogItem.Name | String | Catalog item name. | 
| ServiceNow.CatalogItem.Description | String | Catalog item description. | 
| ServiceNow.CatalogItem.Price | Number | Catalog item price. | 


#### Command Example
```!servicenow-query-items name=laptop limit=2```

#### Context Example
```
{
    "ServiceNow": {
        "CatalogItem": [
            {
                "Description": "Lenovo - Carbon x1",
                "ID": "id",
                "Name": "Standard Laptop",
                "Price": "1100"
            },
            {
                "Description": "Dell XPS 13",
                "ID": "id",
                "Name": "Development Laptop (PC)",
                "Price": "1100"
            }
        ]
    }
}
```

#### Human Readable Output

>### ServiceNow Catalog Items
>|ID|Name|Price|Description|
>|---|---|---|---|
>| id | Standard Laptop | 1100 | Lenovo - Carbon x1 |
>| id | Development Laptop (PC) | 1100 | Dell XPS 13 |


### servicenow-get-item-details
***
Retrieves item details by system ID.


#### Base Command

`servicenow-get-item-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Catalog item system ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.CatalogItem.ID | String | Catalog item system ID. | 
| ServiceNow.CatalogItem.Name | String | Catalog item name. | 
| ServiceNow.CatalogItem.Description | String | Catalog item description. | 
| ServiceNow.CatalogItem.Price | Number | Catalog item price. | 
| ServiceNow.CatalogItem.Variables.Mandatory | Boolean | Is the variable mandatory as part of the ordering process. | 
| ServiceNow.CatalogItem.Variables.Name | String | A name to identify the question. | 
| ServiceNow.CatalogItem.Variables.Question | String | Question to ask users ordering the catalog item. | 
| ServiceNow.CatalogItem.Variables.Type | String | The variable type. | 


#### Command Example
```!servicenow-get-item-details id=id```

#### Context Example
```
{
    "ServiceNow": {
        "CatalogItem": {
            "Description": "Dell XPS 13",
            "ID": "id",
            "Name": "Development Laptop (PC)",
            "Price": "$1,000.00",
            "Variables": [
                {
                    "Mandatory": false,
                    "Name": "hard_drive",
                    "Question": "What size solid state drive do you want?",
                    "Type": "Multiple Choice"
                },
                {
                    "Mandatory": false,
                    "Name": "requested_os",
                    "Question": "Please specify an operating system",
                    "Type": "Multiple Choice"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ServiceNow Catalog Item
>|ID|Name|Description|
>|---|---|---|
>| id | Development Laptop (PC) | Dell XPS 13 |
>### Item Variables
>|Question|Type|Name|Mandatory|
>|---|---|---|---|
>| What size solid state drive do you want? | Multiple Choice | hard_drive | false |
>| Please specify an operating system | Multiple Choice | requested_os | false |


### servicenow-create-item-order
***
Orders the specified catalog item.


#### Base Command

`servicenow-create-item-order`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Catalog item system ID. | Required | 
| quantity | Quantity of the item to order. | Required | 
| variables | If there are mandatory variables defined for the item, they must be passed to the endpoint. Can be retrieved using the servicenow-get-item-details command. For example, var1=value1;var2=value2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.OrderRequest.ID | String | Generated request system ID. | 
| ServiceNow.OrderRequest.RequestNumber | String | Number of the generated request. | 


#### Command Example
```!servicenow-create-item-order id=id quantity=1 variables="hard_drive=16GB;requested_os=linux"```

#### Context Example
```
{
    "ServiceNow": {
        "OrderRequest": {
            "ID": "id",
            "RequestNumber": "REQ0010004"
        }
    }
}
```

#### Human Readable Output

>### ServiceNow Order Request
>|ID|Request Number|
>|---|---|
>| id | REQ0010004 |


### servicenow-document-route-to-queue
***
Documents a route to a queue. Requires an installation of the Advanced Work Assignments plugin. An active queue and service channel to the designated table.


#### Base Command

`servicenow-document-route-to-queue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_id | Queue ID. Can be retrieved using the "!servicenow-query-table table_name=awa_queue fields=name,number,order" command. | Required | 
| document_table | Document table. | Optional | 
| document_id | Document ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.WorkItem.WorkItemID | String | Unique ID of the work item assigned to the queue. | 
| ServiceNow.WorkItem.DocumentTable | String | Name of the table associated with the document | 
| ServiceNow.WorkItem.DocumentID | String | Unique ID of the document to be routed to the queue. | 
| ServiceNow.WorkItem.QueueID | String | Unique ID of the queue on which to route a document. | 
| ServiceNow.WorkItem.DisplayName | String | Name of the document to be routed by this work item, for example: case record. | 


### get-mapping-fields
***
Returns the list of fields for an incident type. This command is for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.



### get-remote-data
***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate. | Required | 


#### Context Output

There is no context output for this command.



