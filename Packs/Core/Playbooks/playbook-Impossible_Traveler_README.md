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