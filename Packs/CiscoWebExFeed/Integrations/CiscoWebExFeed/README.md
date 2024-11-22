Use the Cisco Webex Feed integration to fetch indicators from WeBex.

## Configure Cisco Webex Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### webex-get-indicators
***
Gets indicators from the feed.


#### Base Command

`webex-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 30. | Optional | 
| indicator_type | The indicator type. Possible values are: CIDR, DOMAIN, Both. Default is Both. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!webex-get-indicators indicator_type=Both limit=3```
#### Human Readable Output

>### Indicators from Webex:
>|value|type|
>|---|---|
>| 1.1.1.1/1 | CIDR |
>| 1.2.3.4/5 | CIDR |
>| 8.8.8.8/8 | CIDR |
>| *.wbx2.com | DomainGlob |
>| *.ciscospark.com | DomainGlob |
>| *.webexcontent.com | DomainGlob |