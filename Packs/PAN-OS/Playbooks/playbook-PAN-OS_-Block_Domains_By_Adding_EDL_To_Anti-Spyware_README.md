This playbook goal is to block domains using Panorama Anti-Spyware. it assigning External Dynamic List URL that contains domains to block to Panorama Anti-Spyware. You can create External Dynamic List(EDL) and add domains to it using XSOAR pack called "Generic Export Indicators Service". 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
* Panorama

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-create-anti-spyware-best-practice-profile
* pan-os-create-edl
* pan-os-apply-dns-signature-policy
* pan-os-get-edl
* pan-os-edit-edl

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EDL_URL | The URL from which to pull the EDL. |  | Optional |
| Add_To_Existing_PAN-OS_EDL | input "true" to use existing PAN-OS EDL |  | Optional |
| PAN-OS_EDL_Name | PAN-OS EDL Name to create/To edit if exist\(depend on inputs.Add_To_Existing_PAN-OS_EDL\) |  | Optional |
| Device_Group | The device group for which to return addresses for the EDL \(Panorama instances\).<br/> |  | Optional |
| Certificate_Profile | The certificate profile name for the URL that was previously uploaded. to PAN OS.<br/> |  | Optional |
| Anti_Spyware_Profile | Name of the Anti Spyware Profile to Create OR to edit if exist\(depand on inputs,Use_Existing_AntiSpyware_Profile\). |  | Optional |
| Use_Existing_AntiSpyware_Profile | input "true" to create new anti spyware profile |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS -Block Domains By Adding EDL To Anti-Spyware](../doc_files/PAN-OS_-Block_Domains_By_Adding_EDL_To_Anti-Spyware.png)