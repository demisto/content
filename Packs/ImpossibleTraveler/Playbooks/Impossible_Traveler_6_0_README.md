This playbook investigates an event whereby a user has multiple application login attempts from various locations in a short time period (impossible traveler). The playbook gathers user, timestamp and IP information
associated with the multiple application login attempts.

The playbook then measures the time difference between the multiple login attempts and computes the distance between the two locations to verify whether it is possible the user could traverse the distance
in the amount of time determined. Also, it takes steps to remediate the incident by blocking the offending IPs and disabling the user account, if chosen to do so.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block IP - Generic v3
* IP Enrichment - Generic v2
* Active Directory - Get User Manager Details

### Integrations

This playbook does not use any integrations.

### Scripts

* Set
* EmailAskUser
* CalculateTimeDifference
* CalculateGeoDistance

### Commands

* rasterize
* ip
* setIncident
* ad-get-user
* ad-disable-account
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MaxMilesPerHourAllowed | The maximum miles per hour that is still considered reasonable. If the geographical distance and difference in time between logins is greater than this value, the user will be considered an impossible traveler. | 600 | Optional |
| WhitelistedIPs | CSV of IP addresses that are allowed to be used across long distances. |  | Optional |
| AutomaticallyBlockIPs | Whether to automatically block the source IPs that the login originated from. Can be False or True. | False | Optional |
| DefaultMapLink | The default link from which to create a travel map. The "SOURCE" and "DESTINATION" words are replaced with the previous coordinates and current coordinates of the traveler, respectively. | https://bing.com/maps/default.aspx?rtp=pos.SOURCE~pos.DESTINATION | Optional |
| AutomaticallyDisableUser | Whether to automatically disable the impossible traveler account using Active Directory. | False | Optional |
| ContactUserManager | Whether to ask the user manager for the legitimacy of the login events, in case of an alleged impossible traveler. | False | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The comma-separated list should be provided in CIDR notation. For example, a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). | lists.PrivateIPs | Optional |

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

![Impossible Traveler](../doc_files/Impossible_Traveler.png)
