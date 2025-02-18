The CyCognito Feed integration retrieves the discovered assets from the CyCognito platform based on user-specified filters. A comprehensive dashboard and layout are also included.
This integration was integrated and tested with CyCognito V1 API.

## Configure CyCognito Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | The API Key required to authenticate to the service. | True |
| Asset Type | The type of assets to be retrieved. | True |
| First Fetch Time | The date or relative timestamp from where to start fetching assets.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | False |
| Max Fetch | The maximum number of assets to fetch every time. The maximum value is '1000'. | False |
| Organizations | Retrieves the assets attributed to a specific organization, subsidiary, or assignee. Supports comma-separated values. | False |
| Security Grade | Filters the assets according to security grade.<br/><br/>Supported values:<br/>A: Very strong,<br/>B: Strong,<br/>C: Less vulnerable,<br/>D: Vulnerable,<br/>F: Highly vulnerable | False |
| Hosting Type | Filters the assets based on their hosting type.<br/><br/>Supported values: 'owned', 'cloud', 'undetermined' | False |
| Locations | Filters the assets based on the geographic locations to which they belong. Multiple selection is supported.<br/><br/>Locations are available only for IP, Domain, and Certificate asset types. | False |
| Fetch indicators | Indicates whether to fetch indicators from the instance. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Fetch Interval | Time interval for fetching indicators. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Default Indicator Mapping | When selected, all the incoming indicators will map to a CyCognito Asset indicator type. | False |
| Fetch only Live Assets | When selected, Fetches only live assets. <br/><br/>Note: This filter supports only IP and IP Range type of assets. | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cycognito-get-indicators
***
Fetches a given limit of indicators from the CyCognito platform and displays them in human-readable format in the war room.


#### Base Command

`cycognito-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The type of asset to be retrieved.<br/><br/>Supported values: 'ip', 'domain', 'cert', 'webapp', 'iprange' | Required | 
| count | The number of results to retrieve.<br/><br/>Maximum value is '1000'<br/><br/>Default value is '50' | Optional | 
| offset | Sets the starting index for the returned results. By specifying offset, you retrieve a subset of records starting with the offset value.<br/><br/>Default value is '0' | Optional | 
| search | An Advanced Search parameter to query the response.<br/><br/>Note: Retrieves all the occurrences that are included in the string. | Optional | 
| sort_by | The name of the field by which to sort the results. The response fields available for sorting the data are found in the following documentation: https://docs.cycognito.com/reference/reference-getting-started | Optional | 
| sort_order | Specifies whether to sort the results in either ascending or descending order.<br/><br/>Supported values: 'asc', 'desc'<br/><br/>Default value is 'desc' | Optional | 
| first_seen | The date and time at which CyCognito first discovered and attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| last_seen | The date and time at which CyCognito most recently attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| organizations | Retrieves the assets attributed to a specific organization, subsidiary, or assignee. Supports comma-separated values. | Optional | 
| hosting_type | Filters the assets according to their hosting type. Supports comma-separated values.<br/><br/>Supported values: 'owned', 'cloud', 'undetermined' | Optional | 
| security_grade | Filters the assets according to security rating. Supports comma-separated values.<br/><br/>Supported values: 'A', 'B', 'C', 'D', 'F'<br/><br/>Where:<br/>A = Very strong<br/>B = Strong<br/>C = Less vulnerable<br/>D = Vulnerable<br/>F = Highly vulnerable | Optional | 
| status | Filters the assets according to their status. Supports comma-separated values.<br/><br/>Supported values: 'changed', 'new', 'normal' | Optional | 
| locations | The geographical locations in which the asset is found. Supported values contain the three-letter ISO country code for the respective countries--e.g., IND, USA.<br/><br/>Locations are available only for IP, Domain, and Certificate asset types. | Optional | 
| tags | A keyword or phrase that can be added to an asset or issue metadata. Supports comma-separated values. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cycognito-get-indicators asset_type=ip count=2```
#### Human Readable Output

>### Indicator Detail:
> #### Asset type: IP
>|Asset ID|Security Grade|Status|Organizations|First Seen|Last Seen|Locations|Hosting Type|
>|---|---|---|---|---|---|---|---|
>| 127.0.0.1 | F | normal | ACME Ticketing, ACME Cleantech Solutions, Acme Holdings | 30 Jun 2021, 12:32 PM | 24 Mar 2022, 04:26 AM | United States | cloud |
>| 127.0.0.2 | D | normal | Acme Interior Design | 22 Jul 2021, 03:07 AM | 24 Mar 2022, 04:26 AM | India | owned |