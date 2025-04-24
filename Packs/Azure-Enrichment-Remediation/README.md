##### What does this pack do?

The pack contains Azure playbooks and scripts that conduct enrichment and/or remediation and can use multiple other Azure 
content packs.

There are multiple Azure content packs for multiple Azure products (Compute, MSGraphUsers, etc).  The intent was so that 
users can install and use only the packs they need.  However, if an Azure playbook uses multiple pack integrations (such 
as Compute and MSGraphUsers), they can't reside in one of the current packs because they include content from multiple integrations.  This pack was created as a place to put Azure playbooks that use Azure integrations from multiple packs with a focus on enrichment and remediation.

### Scripts

#### AzureFindAvailableNSGPriorities

This script takes in a list of numbers that represent Azure priorities for NSG rules, a target priority number, and a number of available priorities to return available priorities from the provided list.

### Playbooks

Users are only able to run playbooks in v6.5.0 or higher as it requires commands to execute the task.
This content pack includes the following playbook:

#### Azure - Enrichment

![Azure - Enrichment](doc_files/Azure_-_Enrichment.png)

#### Azure - Network Security Group Remediation

![Azure - Network Security Group Remediation](doc_files/Azure_-_Network_Security_Group_Remediation.png)

#### Azure - User Investigation

![Azure - User Investigation](doc_files/Azure_-_User_Investigation.png)

#### Cloud Credentials Rotation - Azure

![Cloud Credentials Rotation - Azure](doc_files/Cloud_Credentials_Rotation_-_Azure.png)


#### Cloud Response - Azure

![Cloud Response - Azure](doc_files/Cloud_Response_-_Azure.png)
