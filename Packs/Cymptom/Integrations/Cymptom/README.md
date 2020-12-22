Cymptom is a Breach and Attack Simulation solution that revolutionizes the existing approach by transforming attack simulation into a data analysis question. Cymptom agentless scanning brings real-time always-on visibility into the entire security posture.
This integration was integrated and tested with version xx of Cymptom
## Configure Cymptom on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cymptom.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Management URL \(for ex: https://customer_name.cymptom.com/api/\) | True |
    | api_key | API key | True |
    | is_fetch | Fetch incidents | False |
    | proxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | first_fetch | First fetch time range \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 1 hour, 30 minutes\). Default is "3 days" | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cymptom-get-mitigations
***
This command returns mitigations recommended by Cymptom


#### Base Command

`cymptom-get-mitigations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for operation. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymptom.Mitigations.SeverityType | String | The severity of the mitigation | 
| Cymptom.Mitigations.Name | String | The name of the mitigation | 
| Cymptom.Mitigations.AttackVectorsUsedPercentage | String | The percentege of attack vectors used that can be mitigated | 
| Cymptom.Mitigations.ID | String | The mitigation's ID | 
| Cymptom.Mitigations.AttackVectorsCount | number | The attack vectors counts that can be mitigated | 
| Cymptom.Mitigations.Procedures | unknown | Procedures relevant for this mitigation | 
| Cymptom.Mitigations.Techniques | unknown | Techniques relevant for this mitigation | 
| Cymptom.Mitigations.SubTechniques | String | Sub Techniques relevant for this mitigation | 
| Cymptom.Mitigations.References | String | References relevant for this mitigation | 


#### Context Example
``` ```

#### Human Readable Output



### cymptom-get-users-with-cracked-passwords
***
This command returns users with cracked password


#### Base Command

`cymptom-get-users-with-cracked-passwords`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for operation. Default is 60. | Optional | 
| privileged | Return only privileged (Domaind Admin or Local Admin) or unprivileged users. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymptom.CrackedUsers.Username | String | Username of users with cracked passwords | 


#### Command Example
``` ```

#### Human Readable Output


