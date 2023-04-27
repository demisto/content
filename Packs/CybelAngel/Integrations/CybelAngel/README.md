CybelAngel integration
## Configure CybelAngel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CybelAngel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API URL from the CybelAngel platform | https://platform.cybelangel.com/api | True |
    | Client ID | Client ID provided by the Cybelangel platform | True |
    | Secret client | Client ID provided by the Cybelangel platform | True |
    | First fetch date | Reports are going to be pulled from this date. Date format yyyy-mm-ddTHH:MM:SS | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |
    | Tenant ID | Tenant ID provided by the Cybelangel platform | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybelangel-get-reports

***
Get all the reports from a certain time, if end_time  is not specified it will return data until current time

#### Base Command

`cybelangel-get-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Reports are being pulled from this date. Date format yyyy-mm-ddTHH:MM:SS . | Required | 
| end_date | Reports are being pulled until this date, if no specified current time will be taken as the end_date. Date formatyyyy-mm-ddTHH:MM:SS. | Optional | 
| status | Report list will be filtered out using the status provided. Possible values are: open, in_progress, resolved, discarded. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Reports | unknown | CybelAngel reports created between dates provided | 

### cybelangel-get-single-report

***
Returns a CybelAngel report using the ID provided

#### Base Command

`cybelangel-get-single-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID found on the CybelAngel platform  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.id | string | Report ID | 
| CybelAngel.Report.report_content | string | Markdown styled report content | 
| CybelAngel.Report.url | string | CybelAngel report url | 
| CybelAngel.Report.category | string | Report category | 
| CybelAngel.Report.created_at | date | Creation date of report | 
| CybelAngel.Report.incident_type | unknown | Incident type of report | 

### cybelangel-get-single-attachment

***
Returns a single attachment from report

#### Base Command

`cybelangel-get-single-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 
| attachment_id | Attachment ID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.attachment | unknown | Attachment from report | 

### cybelangel-get-attachments-from-report

***
Returns a list of all attachments from a CybelAngel report

#### Base Command

`cybelangel-get-attachments-from-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.attachments | string | Returns a list of all attachments from a report | 

### cybelangel-update-report-status

***
Updates the status of a CybelAngel report. 

#### Base Command

`cybelangel-update-report-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 
| status | This will be the new status of the report. Possible values are: resolved, open. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.status | unknown | Updated status | 

### cybelangel-get-comments

***
Gets all the comments from a CybelAngel report

#### Base Command

`cybelangel-get-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Reports.comments | unknown | Comments from a repor t | 

### cybelangel-create-comment

***
Created a comment on a CybelAngel report

#### Base Command

`cybelangel-create-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). | Required | 
| comment | Comment content that will be added. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Reports.comment | unknown | Comment entity from new comment | 
