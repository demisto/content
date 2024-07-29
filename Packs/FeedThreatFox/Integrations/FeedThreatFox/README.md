Use the ThreatFox Feed integration to fetch indicators from the feed.
This integration was integrated and tested with version xx of ThreatFox Feed.

## Configure ThreatFox Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatFox Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Fetch indicators |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Indicator Expiration Method |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Feed Fetch Interval (in days) |  | False |
    | Return IOCs with Ports | If selected, IP indicators will include a tag with the port value | False |
    | Confidence Threshold |  | False |
    | Create relationship | If selected, indicators will be created with relationships | False |

4. Click **Test** to validate the URL and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatfox-get-indicators

***
Retrieves indicators from the ThreatFox API.

#### Base Command

`threatfox-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | Indicator value to search for | Optional | 
| id | Indicator id to search for | Optional | 
| hash | Hash to search for | Optional | 
| tag | Tag to search for | Optional | 
| malware | Malware to search for | Optional | 
| limit | Maximum indicators to search for. Available only when searching by 'malware' or 'tag'. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.
