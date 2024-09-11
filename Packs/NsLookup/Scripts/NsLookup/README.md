This script performs an nslookup and returns the IP address the domain resolves to.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domain | Domain to look up |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NsLookup | Entire nslookup object | Unknown |
| NsLookup.ip | IP of domain that was looked up | string |
| NsLookup.domain | Domain that was looked up | string |
