The playbook sends a HTTP get response to the domain and enriches the missing bucket information. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* http
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteUrl | Remote IP address in an incident/alert.  | alert.hostname | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BucketName | This is the bucket name extracted from HTTP response body. | unknown |

## Playbook Image
---
![AWS - Unclaimed S3 Bucket Enrichment](../doc_files/AWS_-_Unclaimed_S3_Bucket_Enrichment.png)