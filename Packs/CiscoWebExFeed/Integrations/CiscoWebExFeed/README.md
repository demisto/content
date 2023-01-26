The WebEx IP Address and Domain web site provided by Cisco to document IPs and Domains used by WebEx. The WebEx Feed integration fetches indicators from the web page, with which you can create a list (allow list, block list, EDL, etc.) for your SIEM or firewall service to ingest and apply to its policy rules.

## Configure Cisco WebEx Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco WebEx Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                      | **Description**                                                                                                                                                                                        | **Required** |
    | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
    | Fetch indicators                   |                                                                                                                                                                                                        | False        |
    | Indicator Reputation               | Indicators from this integration instance will be marked with this reputation                                                                                                                          | False        |
    | Source Reliability                 | Reliability of the source providing the intelligence data                                                                                                                                              | True         |
    | Traffic Light Protocol Color       | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed                                                                                                            | False        |
    | Feed Fetch Interval                |                                                                                                                                                                                                        | False        |
    | Tags                               | Supports CSV values.                                                                                                                                                                                   | False        |
    | Bypass exclusion list              | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False        |
    | Trust any certificate (not secure) |                                                                                                                                                                                                        | False        |
    | Use system proxy settings          |                                                                                                                                                                                                        | False        |

4. Click **Test** to validate the URLs, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### webex-get-indicators
***
Gets indicators from the feed.


#### Base Command

`webex-get-indicators`
#### Input

| **Argument Name** | **Description**                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------- | ------------ |
| limit             | The maximum number of results to return. Default is 20.                                                       | Optional     |
| indicator_type    | The indicator type. Can be "IP", "DOMAIN", or "Both". Possible values are: IP, DOMAIN, Both. Default is Both. | Optional     |


#### Context Output

There is no context output for this command.
#### Command example
```!webex-get-indicators indicator_type=Both limit=3```
#### Human Readable Output

>### Indicators from WebEx:
>|value|type|
>|---|---|
>| 1.1.1.1/1 | CIDR |
>| 1.1.1.1/1 | CIDR |
>| 1.1.1.1/1 | CIDR |
>| *.example.com | DomainGlob |
>| *.example.com | DomainGlob |
>| *.example.com | DomainGlob |

