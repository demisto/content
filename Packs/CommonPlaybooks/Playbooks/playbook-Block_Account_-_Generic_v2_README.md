This playbook blocks malicious usernames using all integrations that you have enabled.

Supported integrations for this playbook:
* Active Directory
* PAN-OS - This requires PAN-OS 9.1 or higher.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Active Directory Query v2

### Scripts
* SetAndHandleEmpty
* IsIntegrationAvailable

### Commands
* panorama-register-user-tag
* pingone-deactivate-user
* identityiq-disable-account
* ad-disable-account
* iam-disable-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | Array of malicious usernames to block. | DEM359748,DEM531065,DEM185402,cpwquwbs@test.com,b1d4aqjp | Optional |
| Tag | PAN-OS Tag name to apply to the username that you want to block. | Bad Account | Optional |
| NamingConvention | In case you are using naming convention in your IDP, please specify a prefix for special/service accounts \(use comma separated\) | DEM,106 | Optional |
| UserVerification | Possible values:True/False. Default:True.<br/>Specify if User Verification is Requrired | True | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Blocklist.Final | Blocked accounts | unknown |

## Playbook Image
---
![Block Account - Generic v2](../doc_files/Block_Account_-_Generic_v2.png)