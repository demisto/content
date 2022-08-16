Automate the process of google dorking searches in order to detect leaked data.

## Configure Google Dorking on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Dorking.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Search engine ID |  | True |
    | API Key |  | True |
    | File Types to Search | Comma separated file types that'll be searched and downloaded. | True |
    | Search Keywords | Comma separated keywords to look for in the files. | False |
    | Sites To Search | Provide a single or comma separated list of sites from which to perform the search on. | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Maximum number of incidents per fetch |  | False |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### google-dorking-search
***
Use the google search engine to search a query.


#### Base Command

`google-dorking-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| after | Search after this date. Expected format: YYYY-MM-DD. | Optional | 
| file_types | Comma separated file types that'll be searched and downloaded. | Optional | 
| keywords | Comma separated keywords to look for in the files. | Optional | 
| urls | Provide a single or comma separated list of sites from which to perform the search on. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


