This playbook investigates a "User Persmission Changed” alert by gathering user and IP information  and performs remediation based on the information gathered and received from the user.

Used Sub-playbooks:
* Enrichment for Verdict
* Block IP - Generic v3
* Block Account - Generic v2



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Enrichment for Verdict
* Block IP - Generic v3
* Block Account - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* setAlert

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InternalRange | List of Internal IP ranges |  | Optional |
| UserVerification | Whether to provide user verification for blocking those IPs. <br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Gitlab - User Permission Changed Alert](../doc_files/Gitlab_-_User_Permission_Changed_Alert.png)