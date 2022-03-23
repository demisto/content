This playbook handles impossible traveler alerts.

Impossible Traveler event occurs when a multiple login attempts seen for a user from multiple remote countries in a short period of time, which should normally be impossible. This may indicate the account is compromised.

**Attacker's Goals:**

Gain user-account credentials.

**Investigative Actions:**

Investigate the IP addresses and identities involved in the detected activity using:

* Impossible Traveler - Enrichment playbook
* CalculateGeoDistance automation

**Response Actions**

The playbook's first response actions are based on the data available within the alert. In that phase, the playbook will execute:

* Manual block indicators if the IP address found malicious
* Manual disable user
* Manual clear of the user’s sessions (Okta)

When the playbook continues, after validating the activity with the user’s manager, another phase of response actions is being executed, which includes:

* Auto block indicators 


**External Resources:**

[Impossible traveler alert](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/impossible-traveler---sso.html)

## How to use this playbook

### Create a new playbook trigger

1. Click on the **Incident Response** icon on the left menu ![img.png](img.png)
2. Under **Automation** click on **Incident Configuration**.
3. Select **Playbook Triggers** on the left panel.
4. Click on **New Trigger**.
5. Choose a trigger name e.g. Impossible Traveler Response.
6. Under **Playbook To Run**, select Impossible Traveler.
7. Add trigger description - optional.
8. Create a filter for the playbook trigger.
    1. Click on 'select field'.
    2. Choose 'Alert name'.
    3. Fill the value with 'Impossible traveler' and keep the 'contains' condition.
    4. Click **Create**.

* **Note** that the playbook triggers are being executed by their order, please consider changing the trigger position for the execution order to be as intended. If not, other trigger may override the new trigger.

Click **Save**.

### Playbook inputs

Before executing the playbook, please review the inputs and change them default values if needed.

Important playbook inputs you should pay attention to:

1. MaxMilesPerHourAllowed - This input is being used as a threshold for the maximum allowed miles an employee can travel in one hour, later on, the distance between the involved IP addresses will be checked and filtered against this input. 

2. AutoContainment - This input is responsible for whether to execute the following response actions automatically or manually:
    1. Block indicators
    2. Quarantine file
    3. Disable user

3. WhitelistedIPs - CSV of IP addresses that are allowed to be used across long distances. Note that if your organization is actively using VPN services, we highly recommend whitelisting the known IP addresses to reduce the risk of false positives. 

4. ContactUserManager - This input is responsible for whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler.

5. AbuseIPDBThreshold - This input is being used as a threshold for the minimum score AbuseIPDB gives the IP address to be considered a malicious IP.

### Playbook remediation plan

In this playbook the remediation plan happens in two different phases:

1. On an early stage of the playbook execution, the Containment Plan sub-playbook is being used for blocking the IP if found malicious and, if Oktav2 is enabled, clearing the suspected user active sessions.
2. On a later stage, If the distance between the checked IP addresses was allowed by the manager (configured in the MaxMilesPerHourAllowed playbook input), the playbook will close the alert, otherwise, if the distance isn’t allowed, the manager (if configured) will be asked to approve/disapprove the source country involved in the abnormal activity.

On the final phase, the IP addresses marked as suspicious will be filtered against the whitelisted IPs provided in the playbook inputs, and the ones that aren’t whitelisted will be blocked.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Containment Plan
* Impossible Traveler - Enrichment

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* CreateArray
* impossibleTravelerGetDistance

### Commands
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MaxMilesPerHourAllowed | The maximum miles per hour that is still considered reasonable. If the geographical distance and difference in time between logins is greater than this value, the user will be considered an impossible traveler. | 400 | Optional |
| WhitelistedIPs | CSV of IP addresses that are allowed to be used across long distances. |  | Optional |
| ContactUserManager | Whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler. | True | Optional |
| UserManagerEmail | The user's manager email address | poc@demistodev.com | Optional |
| AutoContainment | Whether to execute auto containment or not | False | Optional |
| AbuseIPDBThreshold | The score needed from AbuseIPDB to consider IP address as malicious | 80 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email address object associated with the Account | string |
| DBotScore | Indicator, Score, Type, Vendor | unknown |
| Account.ID | The unique Account DN \(Distinguished Name\) | string |
| Account.Username | The Account username | string |
| Account.Email | The email address associated with the Account | unknown |
| Account.Type | Type of the Account entity | string |
| Account.Groups | The groups the Account is a part of | unknown |
| Account | Account object | unknown |
| Account.DisplayName | The Account display name | string |
| Account.Manager | The Account's manager | string |
| DBotScore.Indicator | The indicator value | string |
| DBotScore.Type | The indicator's type | string |
| DBotScore.Vendor | The indicator's vendor | string |
| DBotScore.Score | The indicator's score | number |
| IP | The IP objects | unknown |
| Endpoint | The Endpoint's object | unknown |
| Endpoint.Hostname | The hostname to enrich | string |
| Endpoint.OS | Endpoint OS | string |
| Endpoint.IP | List of endpoint IP addresses | unknown |
| Endpoint.MAC | List of endpoint MAC addresses | unknown |
| Endpoint.Domain | Endpoint domain name | string |

## Playbook Image
---
![Impossible Traveler](https://raw.githubusercontent.com/demisto/content/b9b3e36e6893e95be5de09876efce94acec09da8/Packs/Core/doc_files/Impossible_Traveler.png)