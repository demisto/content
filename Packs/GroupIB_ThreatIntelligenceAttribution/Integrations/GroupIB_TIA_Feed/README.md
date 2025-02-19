

Use Group-IB Threat Intelligence & Attribution Feed integration to fetch IOCs from various Group-IB collections.
This integration was integrated and tested with version 1.0 of Group-IB Threat Intelligence & Attribution Feed

## Configure Group-IB Threat Intelligence & Attribution Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB TI&amp;A URL | The FQDN/IP the integration should connect to. | True |
| Username | The API Key and Username required to authenticate to the service. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings | Whether to use XSOAR system proxy settings to connect to the API. | False |
| Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator collections | Collections List to include for fetching. | False |
| Indicator first fetch | Date to start fetching indicators from. | False |
| Number of requests per collection | A number of requests per collection that integration sends in one fetch iteration \(each request picks up to 200 objects with different amount of indicators\). If you face some runtime errors, lower the value. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibtia-get-indicators

***
Get limited count of indicators for specified collection and get all indicators from particular events by id.


#### Base Command

`gibtia-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | GIB Collection to get indicators from. Possible values are: compromised/mule, compromised/imei, attacks/ddos, attacks/deface, attacks/phishing, attacks/phishing_kit, hi/threat, apt/threat, osi/vulnerability, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, malware/cnc. | Required | 
| id | Incident Id to get indicators(if set, all the indicators will be provided from particular incident). | Optional | 
| limit | Limit of indicators to display in War Room. Possible values are: 10, 20, 30, 40, 50. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!gibtia-get-indicators collection=compromised/mule```

#### Human Readable Output

>### IP indicators

>|value|type|asn|geocountry|gibmalwarename|
>|---|---|---|---|---|
>| 11.11.11.11 | IP |  |  | Anubis |
>| 11.11.11.11 | IP | AS12121 | France | FlexNet |
>| 11.11.11.11 | IP | AS1313 | United States | FlexNet |
