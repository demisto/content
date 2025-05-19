Enrich an IP using SecureTrack.  Returns information such as the associated zones, network objects and policies for the address, and if the address is network device.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Tufin

### Scripts
This playbook does not use any scripts.

### Commands
* tufin-policy-search
* tufin-object-resolve
* tufin-search-devices
* tufin-get-zone-for-ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | IP address to enrich \(ex: 192.168.1.1\) |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tufin.Zone.ID | Tufin Zone ID | unknown |
| Tufin.Zone.Name | Tufin Zone Name | unknown |
| Tufin.ObjectResolve.NumberOfObjects | Number of objects that resolve to given IP address. | unknown |
| Tufin.Policysearch.NumberRulesFound | Number of rules found via search | unknown |
| Tufin.Device.ID | Device ID | unknown |
| Tufin.Device.Name | Device name | unknown |
| Tufin.Device.Vendor | Device vendor | unknown |
| Tufin.Device.Model | Device model | unknown |
| Tufin.Device.IP | Device IP | unknown |

## Playbook Image
---
![Tufin - Enrich IP Address(es)](../doc_files/tufin_-_Enrich_a_single_ip_address.png)
