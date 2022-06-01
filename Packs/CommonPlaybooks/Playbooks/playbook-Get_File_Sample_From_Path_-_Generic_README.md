
Returns a file sample, to the War Room from a path on an endpoint using one or more integrations.

inputs:
* UseD2 - If "True", use the Demisto Dissolvable Agent (D2) to return the file. The default is "False".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample From Path - Carbon Black Enterprise Response
* Get File Sample From Path - D2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UseD2 |  | no | Optional |
| Hostname | The endpoint hostname.  | ${Endpoint.Hostname} | Optional |
| Path | The path of the file. | ${File.Path} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The file to sample. | unknown |

## Playbook Image
---
![Get_File_Sample_From_Path_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Get_File_Sample_From_Path_Generic.png)
