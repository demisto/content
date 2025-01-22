Silverfort protects organizations from data breaches by delivering strong authentication across entire corporate networks and cloud environments, without requiring any modifications to endpoints or servers. Using patent-pending technology, Silverfort's agentless approach enables multi-factor authentication and AI-driven adaptive authentication even for systems that don’t support it today, including proprietary systems, critical infrastructure, shared folders, IoT devices, and more.

Use Silverfort integration to get & update Silverfort risk severity.

This integration was integrated and tested with Silverfort version 2.12.

## Silverfort Playbook
---
- Get risk information and block the user if the risk is 'high' or 'critical'
- Update the Silverfort user risk level
## Use Cases
---

- Consume Silverfort user and server risk levels
- Enrich the Silverfort risk engine and trigger MFA on risky entities
## Configure Silverfort in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | a textual name for the integration instance | True |
| url | Server URL | True |
| apikey | APIKEY | True |
| insecure | Trust any certificate (not secure) | False |

- To generate an API token:
    1. On the Silverfort Admin Console, navigate to the **SETTINGS** page, and then select **Silverfort API**.
    2. Next to the Application **User ID** field, click **Create App User**.
    3. Copy the values of the **App User ID** and **App User Secret**.
    4. Click Save all.
    5. The API KEY is "**App USer ID**:**App USer Secret**". (note the ":" between User ID and Secret)
    For more information, see the [Silverfort documentation](https://support.silverfort.com/hc/en-us/articles/360020891537-Silverfort-Risk-Engine-API-Reference).
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### silverfort-get-user-risk
***
User risk commands - get the user entity risk.


##### Base Command

`silverfort-get-user-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upn | The user principal name. | Optional | 
| email | The email address. | Optional | 
| sam_account | The sam account. | Optional | 
| domain | The domain. | Optional | 

Specify one of the following:
* upn
* email address and domain
* sam account and domain

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Silverfort.UserRisk.Risk | String | The risk level. | 
| Silverfort.UserRisk.Reasons | Unknown | The reasons for the risk. | 
| Silverfort.UserRisk.UPN | String | The user principal name. | 


##### Command Example
```!silverfort-get-user-risk upn="sfuser@silverfort.io"```

##### Context Example
```
{
    "Silverfort": {
        "UserRisk": {
            "Reasons": [
                "Suspicious activity",
                "Password never expires"
            ],
            "Risk": "Medium",
            "UPN": "sfuser@silverfort.io"
        }
    }
}
```

##### Human Readable Output
### Silverfort User Risk
|UPN|Risk|Reasons|
|---|---|---|
| sfuser@silverfort.io | Medium | Suspicious activity,Password never expires |


### silverfort-get-resource-risk
***
Gets the resource entity risk information.


##### Base Command

`silverfort-get-resource-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The hostname. | Required | 
| domain_name | The domain. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Silverfort.ResourceRisk.Risk | String | The risk level. | 
| Silverfort.ResourceRisk.Reasons | Array | The reasons for the risk. | 
| Silverfort.ResourceRisk.ResourceName | String | The hostname. | 


##### Command Example
```!silverfort-get-resource-risk resource_name="SF-DC-1" domain_name="silverfort.io"```

##### Context Example
```
{
    "Silverfort": {
        "ResourceRisk": {
            "Reasons": [
                "Unconstrained Delegation"
            ],
            "ResourceName": "SF-DC-1",
            "Risk": "Low"
        }
    }
}
```

##### Human Readable Output
### Silverfort Resource Risk
|ResourceName|Risk|Reasons|
|---|---|---|
| SF-DC-1 | Low | Unconstrained Delegation |


### silverfort-update-user-risk
***
Updates the user entity risk.


##### Base Command

`silverfort-update-user-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upn | The user principal name. | Optional | 
| risk_name | The risk name. | Required | 
| severity | The severity. | Required | 
| valid_for | The number of hours that the risk will be valid for. | Required | 
| description | The risk description. | Required | 
| email | The email address. | Optional | 
| sam_account | The sam account. | Optional | 
| domain | The domain. | Optional | 


Specify one of the following:
* upn
* email address and domain
* sam account and domain

##### Context Output

There is no context output for this command.

##### Command Example
```!silverfort-update-user-risk upn="sfuser@silverfort.io" risk_name="activity_risk" severity=medium valid_for=1 description="Suspicious activity"```

##### Context Example
```
{}
```

##### Human Readable Output
ok

### silverfort-update-resource-risk
***
Update the resource entity risk.


##### Base Command

`silverfort-update-resource-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The hostname. | Required | 
| domain_name | The domain name. | Required | 
| risk_name | The risk name. | Required | 
| severity | The severity. | Required | 
| valid_for | The number of hours the severity will be relevant for. | Required | 
| description | A short description about the risk. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!silverfort-update-resource-risk resource_name="SF-DC-1" domain_name="silverfort.io" risk_name="malware_risk" severity="high" valid_for=1 description="Malware detected"```

##### Context Example
```
{}
```

##### Human Readable Output
ok