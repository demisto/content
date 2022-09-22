This playbook handles impossible traveler alerts.

An Impossible Traveler event occurs when multiple login attempts are seen for a user from multiple remote countries in a short period of time, which shouldn't be possible. This may indicate the account is compromised.

**Attacker's Goals**

Gain user-account credentials.

**Investigative Actions**

Investigate IP addresses and identities involved in the detected activity, by using the following:

* Impossible Traveler - Enrichment playbook
* CalculateGeoDistance automation

**Response Actions**

The playbook's first response actions are based on the data available within the alert. In this phase, the playbook executes the following:

* Manually blocks indicators if the IP address is malicious
* Manually disables the user
* Manually clears the user’s sessions (Okta)

When the playbook continues, after validating the activity with the user’s manager, another phase of response actions is executed, which includes:

* Automatically blocking indicators 


**External Resources**

See the [Impossible traveler alert single sign on](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/impossible-traveler---sso.html) reference topic.

## How to use this playbook

### Create a new playbook trigger

1. On the left-hand menu, click the **Incident Response** icon.
2. Under **Automation**, click **Incident Configuration**.
3. On the left-hand panel, select **Playbook Triggers**.
4. Click **New Trigger**.
5. Type a trigger name. For Example, Impossible Traveler Response.
6. Under **Playbook To Run**, select Impossible Traveler.
7. Add trigger description - optional.
8. Create a filter for the playbook trigger.
    1. Click on 'select field'.
    2. Choose 'Alert name'.
    3. Fill the value with 'Impossible traveler' and keep the 'contains' condition.
    4. Click **Create**.

**Note**: The playbook triggers are being executed according to its order. Consider changing the trigger position for the execution order, as required. If not, other triggers may override the new trigger.

Click **Save**.

### Playbook inputs

Before executing the playbook, review the inputs and change the default values, if needed. Go to **Incident Response** > **Playbooks** and search for **Impossible Traveler**.

Important playbook inputs you should pay attention to:

1. *MaxMilesPerHourAllowed*:  Used as a threshold for the maximum allowed miles an employee can travel in one hour. Later on, the distance between the involved IP addresses will be checked and filtered against this input. 

2. *AutoContainment*: Whether to execute the following response actions automatically or manually:
    1. Block indicators
    2. Quarantine file
    3. Disable user

3. *WhitelistedIPs*: A comma separated list of IP addresses that are allowed to be used across long distances. If your organization is actively using VPN services, we highly recommend whitelisting the known IP addresses to reduce the risk of false positives. 

4. *ContactUserManager*: Whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler.

5. *AbuseIPDBThreshold*: Used as a threshold for the minimum score AbuseIPDB gives the IP address to be considered a malicious IP.

### Playbook remediation plan

In this playbook the remediation plan happens in two phases:

1. At an early stage of playbook execution, the Containment Plan sub-playbook blocks the IP (if found malicious) and if Okta v2 is enabled, clears the suspected user active sessions.
2. At a later stage, if the distance between the checked IP addresses was allowed by the manager (configured in the MaxMilesPerHourAllowed playbook input), the playbook closes the alert. If the distance isn’t allowed, the manager (if configured) will be asked to approve/disapprove the source country involved in the abnormal activity.

In the final phase, the IP addresses marked as suspicious will be filtered against the whitelisted IPs provided in the playbook inputs, and the ones that aren’t whitelisted will be blocked.

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
| MaxMilesPerHourAllowed | The maximum miles per hour that is considered reasonable. If the geographical distance and difference in time between logins is greater than this value, the user will be considered an impossible traveler. | 400 | Optional |
| WhitelistedIPs | CSV of IP addresses that are allowed to be used across long distances. |  | Optional |
| ContactUserManager | Whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler. | True | Optional |
| UserManagerEmail | The user's manager email address. | `poc@demistodev.com` | Optional |
| AutoContainment | Whether to execute auto containment. | False | Optional |
| AbuseIPDBThreshold | The score needed from AbuseIPDB to consider IP address as malicious. | 80 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email address object associated with the Account. | string |
| DBotScore | Indicator, Score, Type, Vendor. | unknown |
| Account.ID | The unique Account DN \(Distinguished Name\). | string |
| Account.Username | The username of the Account. | string |
| Account.Email | The email address associated with the Account. | unknown |
| Account.Type | The type of the Account entity. | string |
| Account.Groups | The groups that the Account is part of. | unknown |
| Account | The Account object. | unknown |
| Account.DisplayName | The display name of the Account. | string |
| Account.Manager | The manager of the Account. | string |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator's type. | string |
| DBotScore.Vendor | The indicator's vendor. | string |
| DBotScore.Score | The indicator's score. | number |
| IP | The IP objects. | unknown |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The endpoint OS. | string |
| Endpoint.IP | The list of endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The endpoint domain name. | string |

## Playbook Image
---
![Impossible Traveler](https://raw.githubusercontent.com/demisto/content/b9b3e36e6893e95be5de09876efce94acec09da8/Packs/Core/doc_files/Impossible_Traveler.png)
