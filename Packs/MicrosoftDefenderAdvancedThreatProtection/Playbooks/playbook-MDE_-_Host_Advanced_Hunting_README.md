This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook uses the Microsoft Defender For Endpoint Advanced Hunting feature based on the provided inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* MDE - Host Advanced Hunting For Powershell Executions
* MDE - Host Advanced Hunting For Persistence
* MDE - Host Advanced Hunting For Network Activity

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-advanced-hunting-lateral-movement-evidence
* microsoft-atp-advanced-hunting-tampering
* microsoft-atp-get-file-info
* microsoft-atp-advanced-hunting-privilege-escalation
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileSha1 | A comma-separated list of file SHA1 hashes to hunt. |  | Optional |
| FileSha256 | A comma-separated list of file Sha256 hashes to hunt. |  | Optional |
| IP | A comma-separated list of IPs to hunt. |  | Optional |
| DeviceName | A comma-separated list of host names to hunt. |  | Optional |
| FileName | A comma-separated list of file names to hunt. |  | Optional |
| DeviceID | A comma-separated list of device ID to hunt. |  | Optional |
| FileMd5 | A comma-separated list of file MD5 hashes to hunt. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.HuntTampering |  | unknown |
| MicrosoftATP.HuntTampering.Result | The query results. | unknown |
| MicrosoftATP.HuntPrivilegeEscalation |  | unknown |
| MicrosoftATP.HuntPrivilegeEscalation.Result | The query results. | unknown |
| MicrosoftATP.HuntLateralMovementEvidence.Result |  | unknown |
| MicrosoftATP.HuntLateralMovementEvidence.Result.network_connections | The query results for network_connections query_purpose. | unknown |
| MicrosoftATP.HuntLateralMovementEvidence.Result.smb_connections | The query results for smb_connections query_purpose. | unknown |
| MicrosoftATP.HuntLateralMovementEvidence.Result.credential_dumping | The query results for credential_dumping query_purpose. | unknown |
| MicrosoftATP.HuntLateralMovementEvidence.Result.management_connection | The query results for management_connection query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence |  | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result |  | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.scheduled_job | The query results for scheduled_job query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.registry_entry | The query results for registry_entry query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.startup_folder_changes | The query results for startup_folder_changes query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.new_service_created | The query results for new_service_created query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.service_updated | The query results for service_updated query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.file_replaced | The query results for file_replaced query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.new_user | The query results for new_user query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.new_group | The query results for new_group query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.group_user_change | The query results for group_user_change query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.local_firewall_change | The query results for local_firewall_change query_purpose. | unknown |
| MicrosoftATP.HuntPersistenceEvidence.Result.host_file_change | The query results for host_file_change query_purpose. | unknown |
| MicrosoftATP.File |  | unknown |

## Playbook Image
---
![MDE - Host Advanced Hunting](../doc_files/MDE_-_Host_Advanced_Hunting.png)