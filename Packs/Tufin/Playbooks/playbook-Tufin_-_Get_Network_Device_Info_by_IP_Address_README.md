Use a device's IP address to gather information about the device, including basic device information, USP zone(s), and policies related to the device.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Tufin

### Scripts
This playbook does not use any scripts.

### Commands
* tufin-get-zone-for-ip
* tufin-search-devices
* tufin-policy-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DeviceIP | IP address of the network device \(ex: 192.168.1.1\) |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tufin.Device.ID | Device ID | unknown |
| Tufin.Device.Name | Device name | unknown |
| Tufin.Device.Vendor | Device vendor | unknown |
| Tufin.Device.Model | Device model | unknown |
| Tufin.Device.IP | Device IP | unknown |
| Tufin.Zone.ID | Tufin Zone ID | unknown |
| Tufin.Zone.Name | Tufin Zone Name | unknown |
| Tufin.Policysearch.NumberRulesFound | Number of rules found via search | unknown |

## Playbook Image
---
![Tufin - Get Network Device Info by IP Address](../doc_files/playbook-Tufin_-_Get_Network_Device_Info_by_IP_Address.png)
