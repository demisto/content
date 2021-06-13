Fetch the full daily feed from www.tweettioc.com/v1/tweets/daily/full
This integration was integrated and tested with version v1 of TwitterIOCHunter - Full Daily Feed
## Configure TwitterIOCHunter - Full Daily Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TwitterIOCHunter - Full Daily Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch indicators |  | False |
    | Indicator Verdict | Indicators from this integration instance will be marked with this verdict | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### twitteriochunter-get-indicators
***
Get Indicators from TwitterIOCHunter


#### Base Command

`twitteriochunter-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


