##### What does this pack do?

The pack contains AWS playbooks that conduct enrichment and/or remediation and can use multiple other AWS content packs:
- Enrichment: Give an IP address, see if there is a EC2 instance associated and if so pull information on the security group associated and IAM information for the user that created that security group.
- Remediation: Give the information collected from enrichment, replace the security group with a "quarantine" security group until vulnerabilities are resolved.

There are multiple AWS content packs for multiple AWS products (EC2, IAM, Route53, etc).  The intent was that users can install and use only the packs they need.  However, if an AWS playbook uses multiple pack integrations (such as EC2 and IAM), the integrations can't reside in one of the current packs because they include content from multiple pack integrations.  This pack was created as a place to put AWS playbooks that use AWS integrations from multiple packs with a focus on enrichment and remediation.

### Playbooks

Users are only able to run the playbook in v6.5.0 or higher as it requires commands to execute the task.
This content pack includes the following playbooks: 
- AWS - Enrichment
- AWS - Security Group Remediation
- Cloud Response - AWS

#### AWS - Enrichment
AWS - Enrichment playbook reports EC2 and IAM information given an IP address of an EC2 instance.

![AWS - Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Enrichment.png)

#### AWS - Security Group Remediation
AWS - Security Group Remediation playbook replaces current security groups associated to NIC with Remediation security group.

![AWS - Security Group Remediation](https://raw.githubusercontent.com/demisto/content/master/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Security_Group_Remediation.png)

