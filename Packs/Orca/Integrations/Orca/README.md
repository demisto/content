Agentless, Workload-Deep, Context-Aware Security and Compliance for AWS, Azure, and GCP.
This integration was integrated and tested with version xx of Orca
## Configure Orca on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Orca.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | apikey | API Key | True |
    | first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | incidentType | Incident type | False |
    | isFetch | Fetch incidents | False |
    | max_fetch | Max fetch | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### orca-get-alerts
***
Get the alerts on cloud assets


#### Base Command

`orca-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_type | Type of alert to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Orca.Manager.Alerts | String | All alerts | 


#### Command Example
``` ```

#### Human Readable Output



### orca-get-asset
***
Get Description of An asset


#### Base Command

`orca-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_unique_id | Asset unique id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Orca.Manager.Asset | String | Asset description | 


#### Command Example
```!orca-get-asset asset_unique_id=vm_77777d777777_i-77bcc77efd8777777```

#### Context Example
```json
{}
```

#### Human Readable Output

>could not find vm_77777d777777_i-77bcc77efd8777777
