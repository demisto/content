Sync users into Salesforce.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* 40102808-670f-4424-81cd-de6437e79e85
* f548aa32-1aed-4459-8d15-59aafb709788
* b12324a1-d668-482d-80eb-6c2b31255acf
* 1b509870-e890-4c31-8bca-d025dfb3730d

### Integrations
* Salesforce_IAM

### Scripts
* SalesforceIAMExtendUserProfileData

### Commands
* iam-update-user
* iam-create-user
* iam-get-user
* send-mail
* iam-disable-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| salesforceInstance | Salesforce app instance name | lists.app-provisioning-settings | Required |
| ITNotificationEmail | Email to notify about errors in the provisioning process. |  | Required |
| welcomeEmailBody |  | &lt;p&gt;Hi, <br/>&lt;BR/&gt;&lt;BR/&gt; <br/>Your Salesforce account has been created successfully. Please click on the link below and enter your network credentials to login to Salesforce. <br/>&lt;BR/&gt;&lt;BR/&gt;<br/>https://paloaltonetworks.my.salesforce.com<br/>&lt;BR/&gt;&lt;BR/&gt;<br/>Please feel free to create a ticket with IT Services at https://panservicedesk.service-now.com/services, if you have any questions or issues. <br/>&lt;BR/&gt;&lt;BR/&gt;<br/>Regards,<br/>&lt;BR/&gt;Salesforce Admin Team&lt;BR/&gt; | Optional |
| PreviousRun | Provisioning results from previous run. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IAM.Vendor | Salesforce Provisioning Details | unknown |

## Playbook Image
---
![Salesforce IAM - Sync User](./../doc_files/Salesforce_IAM_-Sync_User.png)