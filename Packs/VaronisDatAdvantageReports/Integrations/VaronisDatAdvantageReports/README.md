Leverages the Varonis DatAdvantage Reports API. Allows users to submit queries and retrieve reports on the Varonis DSP.
## Configure Varonis DatAdvantage Reports on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Varonis DatAdvantage Reports.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., http://varonisdsp.local:80) | http&lt;s&gt;://&lt;server&gt;:&lt;port&gt; | True |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### varonis-reports-get-queries

***
Retrieves a list of resources containing query results, which were created by run-query.

#### Base Command

`varonis-reports-get-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Reports | string |  | 
| Varonis.Reports.ID | string |  | 

### varonis-reports-run-query

***
Submits a query and returns the Query ID to retrieve the report. See Varonis Reports documentation for syntax details.

#### Base Command

`varonis-reports-run-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Please see Varonis Documentation on Syntax. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Reports.Query | string |  | 
| Varonis.Reports.Query_ID | string |  | 

### varonis-reports-get-report

***
Returns information on the specified report.

#### Base Command

`varonis-reports-get-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The unique ID given to a report. | Required | 
| full_table | Option to produce the full table, including empty whitespace where columns are entirely empty on every row. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Varonis.Reports.Report | string |  | 
