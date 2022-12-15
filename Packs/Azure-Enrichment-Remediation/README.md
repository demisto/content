##### What does this pack do?

The pack is intended to contain Azure playbooks that conduct enrichment and/or remediation and can use multiple other Azure 
content packs.

There are multiple Azure content packs for multiple Azure products (Compute, MSGraphUsers, etc).  The intent was so that 
users can install and use only the packs they need.  However, if an Azure playbook uses multiple pack integrations (such 
as Compute and MSGraphUsers), they can't reside in one of the current packs because they include content from multiple integrations.  This 
pack was created as a place to put Azure playbooks that use Azure integrations from multiple packs with a focus on enrichment and 
remediation.


### Playbooks

Users are only able to run the playbook in v6.5.0 or higher as it requires commands to execute the task.
This content pack includes the following playbook: 
- Cloud Response - Azure

![Cloud Response - Azure](https://raw.githubusercontent.com/demisto/content/37db8986e1fd776d2264975f321ef82022c24512/Packs/Azure-Enrichment-Remediation/doc_files/Cloud_Response_-_Azure.png)
