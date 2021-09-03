This integration will query IP-API to enrich IP Addresses with geographical and other data.
This integration was integrated and tested with version xx of IP-API

## Configure IP-API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IP-API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key |  | False |
    | Use HTTPS to make requests (requires API key) | HTTP does not need an API key - but is subject to API limits and data is exchanged in clear text. | False |
    | Use system proxy settings |  | False |
    | Define the fields returned from the API | See https://ip-api.com/docs/api:json to calculate value for the fields you need | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP-API.as | String | The autonomous system name for the IP address. | 
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. | 
| IP.Address | String | IP address. | 


#### Command Example
``` ```

#### Human Readable Output


