Deprecated. Use the Search Endpoints By Hash - Generic V2 playbook instead. Hunts using available tools.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search Endpoints By Hash - Carbon Black Protection
* Search Endpoints By Hash - Carbon Black Response
* Search Endpoints By Hash - TIE
* Search Endpoints By Hash - CrowdStrike
* Search Endpoints By Hash - Cybereason

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5Hash | The MD5 file hash. | MD5 | File | Optional |
| SHA1Hash | The SHA1 file hash. | SHA1 | File | Optional |
| SHA256Hash | The SHA256 file hash. | SHA256 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The device hostname. | string |
| Endpoint | The endpoint. | unknown |

## Playbook Image
---
<!-- disable-secrets-detection-start -->
![Search_Endpoints_By_Hash_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Search_Endpoints_By_Hash_Generic.png)
<!-- disable-secrets-detection-end -->
