CybelAngel receives reports from the CybelAngel platform, which specializes in external attack surface protection and management

## Configure CybelAngel in XSOAR / XSIAM


| **Parameter**                                                     | **Required** |
|-------------------------------------------------------------------|--------------|
| Server URL                                                        | True         |
| Client ID                                                         | True         |
| Client Secret                                                     | True         |
| First fetch timestamp (number, time unit, e.g., 12 hours, 7 days) | False        |
| The maximum number of events per fetch                            | True         |
| Trust any certificate (not secure)                                | False        |
| Use system proxy settings                                         | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybelangel-get-events

***
Send events from CybelAngel to XSIAM. Used mainly for debugging.

#### Base Command

`cybelangel-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date. | Required | 
| end_date | Get reports until a specific end date. If not provided, uses current date. | Required | 

#### Context Output

There is no context output for this command.
### cybelangel-report-get

***
Retrieve reports from CybelAngel.

#### Base Command

`cybelangel-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report to retrieve. | Required | 
| pdf | If true, retrieves the report as a PDF file. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report | unknown | The retrieved report\(s\). | 
| File.EntryID | String | Entry ID of the saved PDF file. | 

### cybelangel-report-attachment-get

***
Retrieve an attachment from a report.

#### Base Command

`cybelangel-report-attachment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| attachment_id | The ID of the attachment. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.EntryID | unknown | Entry ID of the retrieved file. | 

### cybelangel-report-status-update

***
Update the status of one or multiple reports.

#### Base Command

`cybelangel-report-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_ids | List of report IDs to update. | Required | 
| status | New status of the reports. Possible values are: draft, open, in_progress, resolved, discarded. Default is False. | Required | 

#### Context Output

There is no context output for this command.
### cybelangel-report-comments-get

***
Retrieve comments from a report.

#### Base Command

`cybelangel-report-comments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.Comments | unknown | The list of comments for the report. | 

### cybelangel-archive-report-by-id-get

***
Retrieve an archived report by ID.

#### Base Command

`cybelangel-archive-report-by-id-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the archived report. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.ArchiveReport | unknown | The archived report details. | 

### cybelangel-mirror-report-get

***
Retrieve mirror details for a report.

#### Base Command

`cybelangel-mirror-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| csv | If true, retrieves the mirror report in CSV format. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.ReportMirror | unknown | Mirror details of the report. | 
| CybelAngel.ReportMirror.CSV | unknown | CSV file with mirror details. | 

### cybelangel-report-comment-create

***
Create a new comment on a report.

#### Base Command

`cybelangel-report-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| content | The content of the comment. | Required | 
| parent_id | The ID of the parent comment (for replies). | Optional | 
| assigned | Whether the comment is assigned to analysts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.Comments | unknown | Updated comment list with the new comment included. | 

### cybelangel-report-list

***
Retrieve reports from CybelAngel.

#### Base Command

`cybelangel-report-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date formatted with ISO 8601. | Required | 
| end_date | Get reports until a specific end date formatted with ISO 8601. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report | unknown | The retrieved reports. | 

### cybelangel-report-remediation-request-create

***
Create a remediation request for a report.

#### Base Command

`cybelangel-report-remediation-request-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| requestor_email | Email of the requestor. | Required | 
| requestor_fullname | Full name of the requestor. | Required | 

#### Context Output

There is no context output for this command.
