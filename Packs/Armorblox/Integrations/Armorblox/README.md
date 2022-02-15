Armorblox is an API-based platform that stops targeted email attacks,
  protects sensitive data, and automates incident response.
This integration was integrated and tested with version 4.3.0 of Armorblox

## Configure Armorblox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Armorblox.
3. Click **Add instance** to create and configure a new integration instance.
4. Select **Fetches incidents** to pull incidents from Armorblox to Cortex 
5. Select Classifier as Armorblox-Classifier 
6. Select Mapper as Armorblox-Mapper 

    | **Parameter** | **Required** |
    | --- | --- |
    | Armorblox tenant name | True |
    | Incident type | False |
    | API key | True |
    | Fetch limit | False |
    | First fetch timestamp (last &lt;number&gt; &lt;time unit&gt;, e.g., last7Days) | False |
    | Incidents Fetch Interval | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |

7. Click **Test** to validate the URLs, token, and connection. 
8. Save and Exit to enable the instance. 
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### armorblox-check-remediation-action
***
Check the recommended remediation action for any incident 


#### Base Command

`armorblox-check-remediation-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident id of the incident under inspection. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armorblox.Threat.remediation_actions | string |  | 


#### Command Example
```!armorblox-check-remediation-action ```


#### Context Example
```
   {
        "Armorblox": 
            {
                "Threat": 
                    {
                        "incident_id": "5375",
                        "remediation_actions": "NEEDS REVIEW"
                    }
            }
    }
```

#### Human Readable Output

| **incident_id** | **5375** | 
| --- | --- | 
| **remediation_actions** | **NEEDS REVIEW** |

