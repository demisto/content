## Overview
---
Silverfort protects organizations from data breaches by delivering strong authentication across entire corporate networks and cloud environments, without requiring any modifications to endpoints or servers. Using patent-pending technology, Silverfort's agentless approach enables multi-factor authentication and AI-driven adaptive authentication even for systems that don’t support it today, including proprietary systems, critical infrastructure, shared folders, IoT devices, and more.
<br>Use Silverfort integration to get & update Silverfort risk severity.
<br>This integration was integrated and tested with Silverfort version 2.12.
## Silverfort Playbook
---
- Get risk information and block the user if the risk is 'high' or 'critical'
- Update the Silverfort user risk level
## Use Cases
---

- Consume Silverfort user and server risk levels
- Enrich the Silverfort risk engine and trigger MFA on risky entities
## Configure Silverfort on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Silverfort.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance
    * __Server URL__
    * __APIKEY__
    * __Trust any certificate (not secure)__
4. Click __Test__ to validate the URL, token, and connection.
- To generate an API token:
    1. From the Silverfort Admin Console, navigate to __Settings__ > __Advanced__.
    2. In the Authentication Tokens section, click __Generate Token__.
    3. Copy the generated token and save it in a safe place.
## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. silverfort-get-user-risk
2. silverfort-get-resource-risk
3. silverfort-update-user-risk
4. silverfort-update-resource-risk
### 1. silverfort-get-user-risk
---
User risk commands - get the user entity risk
##### Base Command

`silverfort-get-user-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upn | User principal name | Optional | 
| email | Email address | Optional | 
| sam_account | Sam account | Optional | 
| domain | Domain | Optional | 

Specify one of the following:
* upn
* email address and domain, or
* sam account and domain.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Silverfort.UserRisk.Risk | String | Risk level | 
| Silverfort.UserRisk.Reasons | Array | Risk reasons | 
| Silverfort.UserRisk.UPN | String | User principal name | 


##### Command Example
```!silverfort-get-user-risk upn="sfuser@silverfort.io"```

##### Context Example
```
{
    "Silverfort.UserRisk": {
        "Reasons": [
            "Password never expires"
        ], 
        "UPN": "sfuser@silverfort.io", 
        "Risk": "Low"
    }
}
```

##### Human Readable Output
### Silverfort User Risk
|UPN|Risk|Reasons|
|---|---|---|
| sfuser@silverfort.io | Low | Password never expires |


### 2. silverfort-get-resource-risk
---
Resource risk commands - get the resource entity risk
##### Base Command

`silverfort-get-resource-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Hostname | Required | 
| domain_name | Domain | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Silverfort.ResourceRisk.Risk | String | Resource risk | 
| Silverfort.ResourceRisk.Reasons | Array | Risk reasons | 
| Silverfort.ResourceRisk.ResourceName | String | Hostname | 


##### Command Example
```!silverfort-get-resource-risk resource_name="SF-DC-1" domain_name="silverfort.io"```

##### Context Example
```
{
    "Silverfort.ResourceRisk": {
        "Reasons": [
            "Malware detected"
        ], 
        "ResourceName": "SF-DC-1", 
        "Risk": "High"
    }
}
```

##### Human Readable Output
### Silverfort Resource Risk
|ResourceName|Risk|Reasons|
|---|---|---|
| SF-DC-1 | High | Malware detected |


### 3. silverfort-update-user-risk
---
User risk commands - update the user entity risk
##### Base Command

`silverfort-update-user-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upn | User principal name | Optional | 
| risk_name | Risk name | Required | 
| severity | Severity | Required | 
| valid_for | Number of days the risk will be valid for | Required | 
| description | Risk description | Required | 
| email | Email | Optional | 
| sam_account | Sam account | Optional | 
| domain | Domain | Optional | 


Specify one of the following:
* upn
* email address and domain, or
* sam account and domain.

##### Context Output

There is no context output for this command.

##### Command Example
```!silverfort-update-user-risk upn="sfuser@silverfort.io" risk_name="activity_risk" severity=medium valid_for=1 description="Suspicious activity"```

##### Human Readable Output
ok

### 4. silverfort-update-resource-risk
---
Resource risk commands - update the resource entity risk
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`silverfort-update-resource-risk`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Hostname | Required | 
| domain_name | Domain name | Required | 
| risk_name | Risk name | Required | 
| severity | Severity | Required | 
| valid_for | Number of days the severity will be relevant for | Required | 
| description | Short description about the risk | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!silverfort-update-resource-risk resource_name="SF-DC-1" domain_name="silverfort.io" risk_name="malware_risk" severity="high" valid_for=1 description="Malware detected"```

##### Human Readable Output
ok

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
