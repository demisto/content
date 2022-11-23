There are multiple GCP content packs for multiple GCP products (GSuiteAdmin, GCP-IAM, Google Cloud Compute, etc).  The intent of 
this was so that users can install and use only the packs they need.  However, in that case that an GCP playbook uses multiple pack integartions (such 
as Compute and MSGraphUsers), they can't reside in one of the current packs because they include content from multiple.  This 
pack was created as a place to but GCP playbooks that use GCP integrations from multiple packs with a focus on enrichment and 
remediation.

##### What does this pack do?

The pack is intended to contain GCP playbooks that conduct enrichment and/or remediation and can use multiple other GCP 
content packs.

### Playbooks

Users are only able to run the playbook in v6.5.0 or higher as it requires commands to execute the task.
This content pack includes the following playbooks: 
1. Cloud Response - GCP

![Cloud Response - GCP](/Users/bmelamed/dev/demisto/content/Packs/GCP-Enrichment-Remediation/doc_files/Cloud_Response_-_GCP.png)