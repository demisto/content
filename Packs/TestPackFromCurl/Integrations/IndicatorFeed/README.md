This is the Hello World integration for getting started.
This integration was integrated and tested with version xx of Indicator Feed.
## Configure Indicator Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Indicator Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g. https://example.net\) | True |
    | credentials | Username | True |
    | incidentType | Incident type | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | feed | Fetch indicators | False |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | feedExpirationPolicy |  | False |
    | feedExpirationInterval |  | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedIncremental | Is Feed Incremental | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | key |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### helloworld-say-hello
***
Hello command - prints hello to anyone


#### Base Command

`helloworld-say-hello`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here | 


#### Command Example
``` ```

#### Human Readable Output


