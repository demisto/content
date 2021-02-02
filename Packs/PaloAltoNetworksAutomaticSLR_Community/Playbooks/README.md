Automatically generate a Palo Alto Networks Security Lifecycle Report (SLR)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo Alto Networks Automatic SLR

### Scripts
* Set (Built In)

### Commands
This playbook uses the following commands from the integrations/scripts

* `!autoslr-ngfw-system-info`
* `!autoslr-ngfw-generate`
* `!autoslr-ngfw-check`
* `!autoslr-ngfw-download`
* `!set`
* `!autoslr-csp-upload`

## Playbook Inputs
---
This playbook will inherit all the parameters defined in the Palo Alto Networks Automatic SLR (Community) integration as inputs

## Playbook Outputs
---
### As Incident "Note"

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| AutoSLR.ngfw_system_info.hostname | The hostname of the target firewall | String |
| AutoSLR.ngfw_system_info.serial | The serial number of the target firewall | String |
| AutoSLR.ngfw_system_info.software | The PAN-OS software version of the target firewall | String |

### As Incident "Evidence"

| **Context Key** | **Description** | **Type** |
| --- | --- | --- |
| InfoFile.EntryID | The EntryID of the downloaded file | String |

__Note:__ In the default playbook supplied with the content pack, `InfoFile.EntryID` is copied to `AutoSLR.generate.EntryID` for use in the upload function.

### As Other Output

| **Output** | **Description** | **Type** |
| --- | --- | --- |
| SLR Report | This will output the SLR report as a PDF, attached to an email as defined by the `slr_sent_to` parameter in the integration | Email |

## Playbook Image
---
![Palo Alto Networks Automatic SLR (Community)](https://raw.githubusercontent.com/xsoar-contrib/content/Mediab0t-contrib-PaloAltoNetworksAutomaticSLR_Community/Packs/PaloAltoNetworksAutomaticSLR_Community/Playbooks/Palo_Alto_Networks_-_Automatic_SLR_(Community)_Fri_Nov_27_2020.png)
