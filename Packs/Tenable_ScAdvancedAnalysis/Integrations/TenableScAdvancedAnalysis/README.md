Custom Tenable.sc integration for retrieving detailed vulnerability analysis data, including plugin output, first seen, last seen, mitigation status, and SLA summary.
## Configure Tenable.sc Advanced Analysis in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Tenable.sc Server URL | Tenable.sc base URL, for example https://tenable.example.com | True |
| Access Key |  | True |
| Secret Key |  | True |
| Trust any certificate (not secure) |  | False |
| Request Timeout |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tenable-sc-analysis-test

***
Tests the Tenable.sc Analysis API and returns detailed vulnerability fields for one plugin.

#### Base Command

`tenable-sc-analysis-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plugin_id | No description provided. | Required | 
| repository_ids | No description provided. | Optional | 
| severity | No description provided. | Optional | 
| limit | No description provided. Default is 5. | Optional | 
| source_type | No description provided. Default is cumulative. | Optional | 

#### Context Output

There is no context output for this command.
### tenable-sc-vulnerability-details

***
Retrieves detailed Tenable.sc vulnerability records including plugin output, first seen, last seen, and mitigation status.

#### Base Command

`tenable-sc-vulnerability-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plugin_id | No description provided. | Required | 
| repository_ids | No description provided. | Optional | 
| severity | No description provided. | Optional | 
| limit | No description provided. Default is 50. | Optional | 
| source_type | No description provided. Default is cumulative. | Optional | 

#### Context Output

There is no context output for this command.
### tenable-sc-get-external-sla-summary

***
Retrieves the Tenable.sc SLA summary for active external vulnerabilities, including total, within-SLA, and overdue counts.

#### Base Command

`tenable-sc-get-external-sla-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository_ids | Comma-separated Tenable.sc repository IDs, for example: 17,14. | Required | 
| lookback_days | No description provided. Default is 30. | Optional | 
| critical_sla_days | No description provided. Default is 3. | Optional | 
| high_sla_days | No description provided. Default is 10. | Optional | 
| medium_sla_days | No description provided. Default is 17. | Optional | 
| low_sla_days | Low vulnerability SLA threshold in days. Default is 50. | Optional | 
| last_seen_range | Tenable.sc Last Observed range used for all SLA calculations. Use 0:1 for findings observed within the last day. Default is 0:1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ExternalSLA.Severity | string |  | 
| TenableSC.ExternalSLA.SLADays | number |  | 
| TenableSC.ExternalSLA.TotalVulnerabilities | number |  | 
| TenableSC.ExternalSLA.WithinSLA | number |  | 
| TenableSC.ExternalSLA.Overdue | number |  | 
| TenableSC.ExternalSLA.TotalRange | string |  | 
| TenableSC.ExternalSLA.WithinSLARange | string |  | 
| TenableSC.ExternalSLA.OverdueRange | string |  | 
| TenableSC.ExternalSLA.RepositoryIDs | string |  | 
| TenableSC.ExternalSLA.SourceType | string |  | 
| TenableSC.ExternalSLA.LastUpdated | date |  | 
| TenableSC.ExternalSLA.LastSeenRange | string |  | 

### tenable-sc-get-vulnerability-dataset

***
Retrieves a paginated detailed vulnerability dataset from Tenable.sc and saves it to an XSOAR list for CSV enrichment.

#### Base Command

`tenable-sc-get-vulnerability-dataset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository_ids | No description provided. | Required | 
| severity | No description provided. Default is Critical,High,Medium,Low. | Optional | 
| page_size | No description provided. Default is 200. | Optional | 
| max_pages | No description provided. Default is 30. | Optional | 
| source_type | No description provided. Default is cumulative. | Optional | 
| save_to_list | No description provided. Default is true. | Optional | 
| output_list | No description provided. Default is Tenable_SC_Daily_Advanced_Dataset_JSON. | Optional | 
| preview_rows | No description provided. Default is 5. | Optional | 
| last_seen_range | Optional Tenable.sc Last Seen Analysis range. Use 0:1 for findings observed within the last day. Leave empty to disable this filter. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.VulnerabilityDataset.GeneratedAt | unknown |  | 
| TenableSC.VulnerabilityDataset.RepositoryIDs | unknown |  | 
| TenableSC.VulnerabilityDataset.Severity | unknown |  | 
| TenableSC.VulnerabilityDataset.SourceType | unknown |  | 
| TenableSC.VulnerabilityDataset.CollectedRecords | unknown |  | 
| TenableSC.VulnerabilityDataset.PaginationLimitReached | unknown |  | 
| TenableSC.VulnerabilityDataset.SavedToList | unknown |  | 
| TenableSC.VulnerabilityDataset.OutputList | unknown |  | 
| TenableSC.VulnerabilityDataset.SeverityStats | unknown |  | 
| TenableSC.VulnerabilityDataset.Preview | unknown |  | 
| TenableSC.VulnerabilityDataset.Records | unknown |  | 
