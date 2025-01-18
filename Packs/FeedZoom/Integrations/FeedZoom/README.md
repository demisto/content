Most IT services are moving from on-premise solutions to cloud-based solutions. The public IP addresses, domains, and URLs that function as the endpoints for these solutions are very often not fixed, and the providers of the service publish their details on their websites in a less than ideal format (i.e., HTML) rather than through a proper REST API (i.e., JSON).

This fact makes it very difficult for IT and Security teams to provide these services with an appropriate level of security and automation. Any changes in the HTML schema of the provider website, will break the automation and has the potential to cause serious disruption to the users and the business. The alternative is to compromise on the security posture of the organization.

One example of these providers is Zoom.

This pack addresses this issue by automating the collection of endpoint data in the form of an indicator feed. This will facilitate validation of the indicators before using them in enforcement points, for example firewalls, proxies, and more.

## Zoom Network Settings
For information about Zoom network settings, see the [Zoom documentation](https://support.zoom.us/hc/en-us/articles/201362683-Network-Firewall-or-Proxy-Server-Settings-for-Zoom).


## Configure Zoom Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Firewall rules for certificate validation | Zoom clients for certificate validation. | False |
| Firewall rules for Zoom website | All Zoom Clients. User's web browser. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Feed Fetch Interval | Setting a more frequent fetch interval may cause errors from the vendor. | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### zoom-get-indicators
***
Gets indicators from the feed.


#### Base Command

`zoom-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.