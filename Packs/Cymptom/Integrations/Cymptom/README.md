Cymptom is a Breach and Attack Simulation solution that revolutionizes the existing approach by transforming attack simulation into a data analysis question. Cymptom agentless scanning brings real-time always-on visibility into the entire security posture.
This integration was integrated and tested with version 0.3.4 of Cymptom.

## Configure Cymptom on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cymptom.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Management URL (for ex: `https://customer_name.cymptom.com/api/`) | True |
    | api_key | API key | True |
    | is_fetch | Fetch incidents | False |
    | proxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | first_fetch | First fetch time range (`<number> <time unit>`, e.g., 1 hour, 30 minutes). Default is "3 days" | False |

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
| Cymptom.Mitigations.AttackVectorsUsedPercentage | String | The percentage of attack vectors used that can be mitigated | 
| Cymptom.Mitigations.ID | String | The mitigation's ID | 
| Cymptom.Mitigations.AttackVectorsCount | number | The attack vectors counts that can be mitigated | 
| Cymptom.Mitigations.Techniques | unknown | Techniques relevant for this mitigation | 


#### Command Example
``` 
!cymptom-get-mitigations
```

#### Human Readable Output
##### Mitigations
|ID|Name|Severity Type|Attack Vectors Use Percentage|Attack Vectors Count|Techniques|
|---|---|---|---|---|---|
| 3936 | Steal or Forge Kerberos Tickets | Critical | 21.16 | 299 | Encrypt Sensitive Information,<br>Privileged Account Management,<br>Active Directory Configuration,<br>Password Policies | 
### cymptom-get-users-with-cracked-passwords
***
This command returns users with cracked password
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for operation. Default is 60. | Optional | 
| privileged | Return only privileged (Domain Admin or Local Admin) or unprivileged users. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymptom.CrackedUsers.Username | String | Username of users with cracked passwords | 

#### Context Example

```
[
    {'Username':'cymptom'},
    {'Username':'chen'}
]
```

#### Command Example
```
!cymptom-get-users-with-cracked-passwords privileged=False 
```


#### Human Readable Output
#### Unprivileged Users With Cracked Passwords
|Username|
|---|
| user1 |
| user2 |


