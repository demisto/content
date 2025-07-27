This playbook remediates the following Prisma Cloud AWS CloudTrail alerts.

Prisma Cloud policies remediated:

 - AWS CloudTrail Is Not Integrated With CloudWatch Logs

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS - CloudTrail
* AWS - CloudWatchLogs
* AWS - IAM

### Scripts

* Sleep
* isError

### Commands

* aws-cloudtrail-describe-trails
* aws-cloudtrail-update-trail
* aws-iam-attach-policy
* aws-iam-create-policy
* aws-iam-create-role
* aws-iam-get-role
* aws-logs-create-log-group
* aws-logs-describe-log-groups

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.
