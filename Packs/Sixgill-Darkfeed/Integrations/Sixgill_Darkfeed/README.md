Sixgill's premium underground intelligence collection capabilities, real-time collection and advanced warning about IOCs to help you keep your edge against unknown threats.
This integration was integrated and tested with version 0.1.2 of sixgill clients
## Configure Sixgill_Darkfeed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sixgill DarkFeed™ Threat Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Sixgill API client ID | True |
| client_secret | Sixgill API client secret | True |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| maxIndicators | Max number of indicators that can be fetched | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sixgill-get-indicators
***
Fetching Sixgill DarkFeed indicators
##### Required Permissions
 - A valid Sixgill API client id and client secret.
##### Base Command

`sixgill-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devo.AlertsResults | list of dictionaries | List of dictionary alerts in specified time range |
| Devo.QueryLink | string | Link back to Devo table for executed query |

##### Command Example
```!sixgill-get-indicators ```

##### Human Readable Output


## Additional Information
Contact us: support@cybersixgill.com

## Known Limitations
