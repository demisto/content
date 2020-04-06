Provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services. To remediate Prisma Cloud Alert "CloudTrail is not enabled on the account", this playbook creates a S3 bucket to host Cloudtrail logs and enable Cloudtrail (includes all region events and global service events).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* aws-s3-put-bucket-policy
* aws-cloudtrail-start-logging
* aws-cloudtrail-create-trail
* aws-s3-create-bucket
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoEnableCloudTrail | The following resources will be created, `S3 bucket cloudtrail-<account_id>`, and `Cloudtrail cloudtrail-<account_id>`. Type "Yes" to auto-enable CloudTrail. | No | Optional |
| CloudTrailRegion | S3 bucket and (global) Cloudtrail will be created on this region | us-west-2 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PrismaCloudRemediation_AWSCloudTrailIsNotEnabledOnTheAccount](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PrismaCloudRemediation_AWSCloudTrailIsNotEnabledOnTheAccount.png)
