##### What does this pack do?

The pack contains AWS playbooks that conduct enrichment and/or remediation and can use multiple other AWS content packs:
- Enrichment: Give an IP address, see if there is a EC2 instance associated and if so pull information on the security group associated and IAM information for the user that created that security group.
- Remediation: Give the information collected from enrichment, replace the security group with a "quarantine" security group until vulnerabilities are resolved.
- Unclaimed S3 Bucket Validation: The playbook sends a HTTP get response to the domain and validates the missing bucket information.
- Unclaimed S3 Bucket Remediation: The playbook will create the unclaimed S3 bucket.

There are multiple AWS content packs for multiple AWS products (EC2, IAM, Route53, S3, etc).  The intent was that users can install and use only the packs they need.  However, if an AWS playbook uses multiple pack integrations (such as EC2, S3 and IAM), the integrations can't reside in one of the current packs because they include content from multiple pack integrations.  This pack was created as a place to put AWS playbooks that use AWS integrations from multiple packs with a focus on enrichment and remediation.

### Playbooks

Users are only able to run the playbook in v6.5.0 or higher as it requires commands to execute the task.
This content pack includes the following playbooks: 
- AWS - Enrichment
- AWS - Security Group Remediation
- Cloud Response - AWS
- AWS - Unclaimed S3 Bucket Validation
- AWS - Unclaimed S3 Bucket Remediation

#### AWS - Enrichment
AWS - Enrichment playbook reports EC2 and IAM information given an IP address of an EC2 instance.

![AWS - Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Enrichment.png)

#### AWS - Security Group Remediation
AWS - Security Group Remediation playbook replaces current security groups associated to NIC with Remediation security group.

![AWS - Security Group Remediation](https://raw.githubusercontent.com/demisto/content/master/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Security_Group_Remediation.png)

#### AWS - Unclaimed S3 Bucket Validation
AWS - Unclaimed S3 Bucket Validation playbook validates the unclaimed S3 bucket details.

![AWS - Unclaimed S3 Bucket Validation](https://raw.githubusercontent.com/demisto/content/f0d7512f35321b195b59e8e677fbe7b2e1319c74/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Unclaimed_S3_Bucket_Validation.png)

#### AWS - Unclaimed S3 Bucket Remediation
AWS - Unclaimed S3 Bucket Remediation playbook creates the unclaimed S3 bucket so other vectors can't claim the bucket.

![AWS - Unclaimed S3 Bucket Remediation](https://raw.githubusercontent.com/demisto/content/7f3e223a86964eda5689a9c3e1f22511021c5f40/Packs/AWS-Enrichment-Remediation/doc_files/AWS_-_Unclaimed_S3_Bucket_Remediation.png)