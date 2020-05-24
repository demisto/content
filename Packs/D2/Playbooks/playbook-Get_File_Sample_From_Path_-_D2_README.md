Returns a file sample, to the War Room from a path on an endpoint using Demisto Dissolvable Agent (D2).

Input:
* Credentials - The credentials to use when trying to deploy Demisto Dissolvable Agent (D2)  (default: Admin).
* ${Endpoint.Hostname} - Deploys an agent on the target endpoint.
* ${File.Path} - The file's path to collect.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* FetchFileD2
* IncidentAddSystem

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Credentials | The name of the credential set from Demisto **Settings -> Integrations -> Credentials.** | Admin | Optional |
| Hostname | The Endpoint hostname. | ${Endpoint.Hostname} | Optional |
| Path | The file path. | ${File.Path} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The file to sample. | unknown |

## Playbook Image
---
![Get_File_Sample_From_Path_D2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Get_File_Sample_From_Path_D2.png)
