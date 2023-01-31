This playbook provides response playbooks for:
- AWS
- Azure
- GCP

The response actions available are:
- Terminate/Shut down/Power off an instance
- Delete/Disable a user
- Delete/Revoke/Disable credentials
- Block indicators

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cloud Response - GCP
* Cloud Response - AWS
* Cloud Response - Azure

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
| cloudProvider | The cloud service provider involved. |  | Optional |
| autoResourceRemediation | Whether to execute the resource remediation flow automatically. |  | Optional |
| AWS-resourceRemediationType | Choose the remediation type for the instances created.<br/><br/>AWS available types:<br/>Stop - for stopping the instances.<br/>Terminate - for terminating the instances. |  | Optional |
| Azure-resourceRemediationType | Choose the remediation type for the instances created.<br/><br/>Azure available types:<br/>Poweroff - for shutting down the instances.<br/>Delete - for deleting the instances. |  | Optional |
| GCP-resourceRemediationType | Choose the remediation type for the instances created.<br/><br/>GCP available types:<br/>Stop - For stopping the instances.<br/>Delete - For deleting the instances. |  | Optional |
| autoAccessKeyRemediation | Whether to execute the user remediation flow automatically. |  | Optional |
| AWS-accessKeyRemediationType | Choose the remediation type for the user's access key.<br/><br/>AWS available types:<br/>Disable - for disabling the user's access key.<br/>Delete - for the user's access key deletion. |  | Optional |
| GCP-accessKeyRemediationType | Choose the remediation type for the user's access key.<br/><br/>GCP available types:<br/>Disable - For disabling the user's access key.<br/>Delete - For the deleting user's access key. |  | Optional |
| autoUserRemediation | Whether to execute the user remediation flow automatically. |  | Optional |
| AWS-userRemediationType | Choose the remediation type for the user involved.<br/><br/>AWS available types:<br/>Delete - for the user deletion.<br/>Revoke - for revoking the user's credentials. |  | Optional |
| Azure-userRemediationType | Choose the remediation type for the user involved.<br/><br/>Azure available types:<br/>Disable - for disabling the user.<br/>Delete - for deleting the user. |  | Optional |
| GCP-userRemediationType | Choose the remediation type for the user involved.<br/><br/>GCP available types:<br/>Delete - For deleting the user.<br/>Disable - For disabling the user. |  | Optional |
| autoBlockIndicators | Whether to block the indicators automatically. |  | Optional |
| resourceName | The resource name to take action on.<br/><br/>Supports: AWS, GCP and Azure |  | Optional |
| resourceZone | The resource's zone to take action on.<br/><br/>Supports: GCP |  | Optional |
| resourceGroup | Supports: Azure<br/>The resource group to take action on. |  | Optional |
| accessKeyName | The access key name in the following format:<br/>projects/\{PROJECT_ID\}/serviceAccounts/\{ACCOUNT\}/keys/\{key\}.<br/><br/>Supports: GCP |  | Optional |
| accessKeyId | The user's access key ID.<br/><br/>Supports: AWS |  | Optional |
| region | The resource's region.<br/><br/>Supports: AWS |  | Optional |
| username | The username to take action on.<br/><br/>Supports: AWS, GCP and Azure |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cloud Response - Generic](../doc_files/Cloud_Response_-_Generic.png)