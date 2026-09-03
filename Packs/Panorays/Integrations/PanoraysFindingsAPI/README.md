Retrieve and monitor internal security findings for your organization, and critical findings across your supplier (third-party) portfolio, from the Panorays platform to automate incident response within Cortex XSOAR.
This integration was integrated and tested with version v2 of PanoraysFindingsAPI.

## Configure Panorays Findings API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Panorays PAPI base URL |  | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum API requests per minute | The Panorays API permits 150 requests per minute and blocks the caller for one hour when that is exceeded. Keep this below 150. | False |
| Findings scope | Whether this instance fetches your own organization's findings or findings across your supplier portfolio. Configure a separate instance for each scope. | False |
| Maximum number of incidents to fetch per run | When fetching supplier findings, a run that reaches this limit part-way through a supplier resumes on that same supplier next run, so the limit is honored without skipping findings. | False |
| First fetch timestamp (e.g., 7 days) |  | False |
| Supplier finding severities | Only applies when Findings scope is "Supplier Findings". Only findings with these severities create incidents. | False |
| Supplier finding statuses | Comma-separated finding statuses to fetch. Known values are OPEN, REOPENED, and DONE. The default excludes DONE so that remediated findings do not create incidents, while still covering findings that were reopened. Only applies when Findings scope is "Supplier Findings". Leave empty to fetch all statuses. | False |
| Date field to fetch by | Use update_ts to also pick up findings whose severity or status changed. Use insert_ts to fetch only newly discovered findings. | False |
| Supplier segment IDs | Optional comma-separated segment IDs. When set, only suppliers in these segments are polled. | False |
| Supplier tags | Optional comma-separated supplier tags. When set, only suppliers carrying these tags are polled. | False |
| Supplier list cache TTL (hours) | How long the supplier portfolio is cached before being re-enumerated. Lower this if suppliers are added frequently. | False |
| Incident type |  | False |
| Incidents Fetch Interval |  | False |
| Fetch incidents |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### panorays-finding-list

***
Lists your own organization's findings as detected by Panorays.

#### Base Command

`panorays-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of findings to return. Default is 50. | Optional | 
| page | Deprecated. The Panorays API uses cursor pagination, so this argument is ignored. | Optional | 
| severity | Comma-separated list of severities to filter by, for example "CRITICAL,HIGH". | Optional | 
| status | Comma-separated list of finding statuses to filter by, for example "OPEN". | Optional | 
| asset_name | Comma-separated list of asset names to filter by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorays.Finding.id | String | The unique identifier of the finding. | 
| Panorays.Finding.severity | String | The severity of the finding. | 
| Panorays.Finding.status | String | The status of the finding. | 
| Panorays.Finding.category | String | The category of the finding. | 
| Panorays.Finding.sub_category | String | The sub category of the finding. | 
| Panorays.Finding.asset_name | String | The asset the finding was detected on. | 
| Panorays.Finding.finding_text | String | The finding text. | 
| Panorays.Finding.insert_ts | Date | The timestamp the finding was first detected. | 
| Panorays.Finding.update_ts | Date | The timestamp the finding was last updated. | 

### panorays-supplier-finding-list

***
Lists the findings detected by Panorays for a specific supplier (third party).

#### Base Command

`panorays-supplier-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| supplier_id | The ID of the supplier whose findings are returned. Use panorays-supplier-list to obtain supplier IDs. | Required | 
| limit | The maximum number of findings to return. Default is 50. | Optional | 
| severity | Comma-separated list of severities to filter by, for example "CRITICAL,HIGH". | Optional | 
| status | Comma-separated list of finding statuses to filter by, for example "OPEN". | Optional | 
| asset_name | Comma-separated list of asset names to filter by. | Optional | 
| date_field | The date field the date range filter applies to. Possible values are: insert_ts, update_ts. | Optional | 
| date_range_from | Start date for the date range filter, in YYYY-MM-DD format. | Optional | 
| date_range_to | End date for the date range filter, in YYYY-MM-DD format. Defaults to today. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorays.SupplierFinding.id | String | The unique identifier of the finding. | 
| Panorays.SupplierFinding.supplier_id | String | The ID of the supplier the finding belongs to. | 
| Panorays.SupplierFinding.severity | String | The severity of the finding. | 
| Panorays.SupplierFinding.status | String | The status of the finding. | 
| Panorays.SupplierFinding.category | String | The category of the finding. | 
| Panorays.SupplierFinding.sub_category | String | The sub category of the finding. | 
| Panorays.SupplierFinding.asset_name | String | The asset the finding was detected on. | 
| Panorays.SupplierFinding.finding_text | String | The finding text. | 
| Panorays.SupplierFinding.insert_ts | Date | The timestamp the finding was first detected. | 
| Panorays.SupplierFinding.update_ts | Date | The timestamp the finding was last updated. | 

### panorays-supplier-list

***
Lists the suppliers (third parties) in your Panorays portfolio.

#### Base Command

`panorays-supplier-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of suppliers to return. Default is 50. | Optional | 
| names | Comma-separated list of supplier names to search by. | Optional | 
| ids | Comma-separated list of supplier IDs to search by. | Optional | 
| tags | Comma-separated list of supplier tags to search by. | Optional | 
| segment_ids | Comma-separated list of segment IDs to search by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorays.Supplier.id | String | The unique identifier of the supplier. | 
| Panorays.Supplier.name | String | The name of the supplier. | 
| Panorays.Supplier.primary_domain | String | The primary domain of the supplier. | 
| Panorays.Supplier.business_impact | String | The business impact classification of the supplier. | 
| Panorays.Supplier.combined_score | Number | The combined Panorays risk score of the supplier. | 
| Panorays.Supplier.posture_score | Number | The external posture score of the supplier. | 
| Panorays.Supplier.risk | String | The overall risk rating of the supplier. | 
| Panorays.Supplier.tags | String | The tags assigned to the supplier. | 

