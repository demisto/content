Investigates an event whereby a user has multiple application login attempts from various locations in a short time period (impossible traveler). The playbook gathers user, timestamp and IP address information associated with the multiple application login attempts.

The playbook then measures the time difference between the multiple login attempts and computes the distance between the two locations to verify whether it is possible the user could traverse the distance
in the amount of time determined. Also, it takes steps to remediate the incident by blocking the offending IP addresses and disabling the user account, if chosen to do so.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Enrichment - Generic v2
* Block IP - Generic v2

### Integrations
* Builtin

### Scripts
* EmailAskUser
* CalculateTimeDifference
* CalculateGeoDistance
* Set

### Commands
* ip
* closeInvestigation
* rasterize
* setIncident
* ad-disable-account
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MaxMilesPerHourAllowed | The maximum miles per hour that is still considered reasonable. If the geographical distance and difference in time between logins is greater than this value, the user will be considered an impossible traveler. | 600 | Optional |
| WhitelistedIPs | CSV of IP addresses that are allowed to be used across long distances. | - | Optional |
| AutomaticallyBlockIPs | Whether to automatically block the source IP addresses that the login originated from. Can be "False" or "True". | False | Optional |
| DefaultMapLink | The default link from which to create a travel map. The "SOURCE" and "DESTINATION" words are replaced with the previous coordinates and current coordinates of the traveler, respectively. | https://bing.com/maps/default.aspx?rtp=pos.SOURCE~pos.DESTINATION | Optional |
| AutomaticallyDisableUser | Whether to automatically disable the impossible traveler account using Active Directory. | False | Optional |
| ContactUserManager | Whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler. | False | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email address object associated with the account. | string |
| DBotScore | The Indicator, Score, Type, and Vendor. | unknown |
| Account.ID | The unique account DN (Distinguished Name). | string |
| Account.Username | The account username. | string |
| Account.Email | The email address associated with the account. | unknown |
| Account.Type | Type of the account entity. | string |
| Account.Groups | The groups the Account is a part of. | unknown |
| Account | account object. | unknown |
| Account.DisplayName | The account display name. | string |
| Account.Manager | The account's manager. | string |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator's type. | string |
| DBotScore.Vendor | The indicator's vendor. | string |
| DBotScore.Score | The indicator's score. | number |
| IP | The IP address objects. | unknown |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

## Playbook Image
---
![Impossible_Traveller](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Impossible_Traveler.png)
