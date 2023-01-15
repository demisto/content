This playbook searches for a specific hash in the supported sandboxes. If the hash is known the playbook provides a detailed analysis of the sandbox report. Currently, supported sandboxes are Falcon Intelligence Sandbox, Wildfire and Joe Sandbox.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Mitre Attack - Extract Technique Information From ID

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* cs-fx-get-full-report
* rasterize-pdf
* cs-fx-find-reports
* wildfire-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileSha256 | The SHA256 hash to search for. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AttackPattern.MITREID | The MITRE ID of the attack pattern. | string |
| AttackPattern.KillChainPhases | The kill chain phases of the attack pattern. | string |
| NonFoundHashes | A list of hashes that are not found in the sandboxes. | string |
| WildFire.Report | The results of the Wildfire report. | string |
| csfalconx.resource.sandbox | The results of the Falcon Intelligence Sandbox report. | string |

## Playbook Image
---
![Search For Hash In Sandbox - Generic](../doc_files/Search_For_Hash_In_Sandbox_-_Generic.png)