This script runs an O365 Security & Compliance Search using the specified parameters to perform a targeted content search.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| search_name | The name of the compliance search |
| force | Overwrite the existing search if true. Otherwise, uses the existing search without modifying any search parameters. |
| preview | Preview results using the search action - returns additional content from the emails found in the search. |
| case | The name of a Core eDiscovery case to associate with the new compliance search. |
| kql_search | Text search string or a query that is formatted using the Keyword Query Language (KQL). |
| include_mailboxes | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| exchange_location | Comma-separated list of mailboxes/distribution groups to include, or use the value "All" to include all. |
| exchange_location_exclusion | Comma-separated list of mailboxes/distribution groups to exclude when you use the value "All" for the exchange_location parameter. |
| public_folder_location | Comma-separated list of public folders to include, or use the value "All" to include all. |
| share_point_location | Comma-separated list of SharePoint online sites to include. You can identify the sites by their URL value, or use the value "All" to include all sites. |
| share_point_location_exclusion | Comma-separated list of SharePoint online sites to exclude when you use the value "All" for the share_point_location argument. You can identify the sites by their URL value. |
| polling_interval | Compliance search polling interval in seconds. Default is 30. |
| polling_timeout | Compliance search polling timeout in seconds. Default is 300. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| O365SecurityAndComplianceSearch.Search.Name| The search name | String |
| O365SecurityAndComplianceSearch.Search.Status| The search status | String |
| O365SecurityAndComplianceSearch.Search.Results| The search results | Array |
| O365SecurityAndComplianceSearch.Preview.Name| The preview name | String |
| O365SecurityAndComplianceSearch.Preview.Status| The preview status | String |
| O365SecurityAndComplianceSearch.Preview.Results| The preview results | Array |
