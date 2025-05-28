Anomali ThreatStream Feed Integration.
This integration was integrated and tested with version xx of Anomali ThreatStream Feed.

## Configure Anomali ThreatStream Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Fetch by |  | True |
| Server URL (e.g., https://www.test.com) |  | True |
| Username |  | True |
| API Key |  | True |
| Feed Fetch Interval |  | False |
| Confidence Threshold | Will only return indicators above the confidence threshold. | False |
| Source Reliability |  | False |
| Traffic Light Protocol Color | Indicator's TLP will override default value. | False |
| Indicator Reputation |  | False |
| Indicator Expiration Method |  | False |
| Create relationships |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatstream-feed-get-indicators

***
Gets indicators from the feed. (Test function)

#### Base Command

`threatstream-feed-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indictor type to analyze. Possible values are: domain, ip, md5, url, email. | Optional | 
| limit | Maximum number of objects to return (default is 10). | Optional | 

#### Context Output

There is no context output for this command.
