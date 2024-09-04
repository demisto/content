The Office 365 IP Address and URL web service is a read-only API provided by Microsoft to expose the URLs and IPs used by Office 365. The Office 365 Feed integration fetches indicators from the service, with which you can create a list (allow list, block list, EDL, etc.) for your SIEM or firewall service to ingest and apply to its policy rules.


## Configure Office 365 Feed on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Office 365 Feed.
3. Click __Add instance__ to create and configure a new integration instance.

   | **Parameter** | **Description** | **Example** |
   | ------------- | --------------- | ----------- |
   | Name | A meaningful name for the integration instance. | Office 365 Feed_worldwide_exchange |
   | Fetch indicators | Select this option if you want this integration instance to fetch indicators from the Office 365 feed. | N/A |
   | Regions | The regions from which to fetch indicators. Supports multi-select. For all regions, you need to select each region. | 
   | Services | The services for which to fetch indicators. Supports multi-select. For all services, select the “All” option. | Sharepoint, Exchange |
   | Indicator Reputation | This reputation will be applied to all indicators fetched from this integration instance. | Good |
   | Source Reliability | The reliability of the source providing the intelligence data, which affects how this indicator's fields and reputation are populated. | A - Completely reliable |
   | Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | N/A |
   | feedExpirationPolicy | The method by which to expire indicators from this integration instance. | When removed from the feed |
   | feedExpirationInterval |  |  |
   | Feed Fetch Interval | How often to fetch indicators from this integration instance. You can specify the interval in days, hours, or minutes. | 30 minutes |
   | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed.  This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | N/A |
    | Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
   | Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
   | Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
4. Click __Test__ to validate the URLs and connection.

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed
---
Gets indicators from the feed.

##### Base Command

`office365-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 
| indicator_type | The indicator type. Can be "IPs", "URLs", or "Both". The default value is "IPs". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example

!office365-get-indicators limit="5"

##### Human Readable Output

### Indicators from Office 365 Feed:
|value|type|
|---|---|
| 0.0.0.0/0 | CIDR |
| 0.0.0.0/0 | CIDR |
| 0.0.0.0/0 | CIDR |
| 0.0.0.0/0 | CIDR |
| 0.0.0.0/0 | CIDR |
| 0.0.0.0/0 | CIDR |
