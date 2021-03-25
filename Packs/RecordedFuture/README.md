# Pack Documentation
This pack is used to access Recorded Future data to enrich IPs, domains, URLs, CVEs, and files and assess threats in regards to a specific context.

## Integration
The integration is used to access the data from the API.

### Available Actions
* Reputation actions
    * Using the new Recorded Future SOAR Enrichment API
    * Available actions: ip, domain, url, file(hashes), and cve
* Intelligence action
    * Fetches full information for the entity.
    * Supports IPs, Domains, URLs, Files(hashes), and vulnerabilities(cve)
* Alert actions
    * Fetch alerting rules defined at Recorded Future
    * Fetch alert summaries from one or more alerting rules
    * Fetch a single alert to get a detailed report on that alert.
* Threat assessment action
    * Takes a context, such as phishing or malware and one or more IOC as input
    * Outputs a verdict (true/false) and related evidence (risk rules) for this context

## Dashboards and indicators
Includes a dashboard that details various metrics related to indicators that was generated from Recorded Future data and incidents that was created from Recorded Future data.

There are two indicator fields added to record which risk rules indicators have triggered as well as whether an indicator is a malware, c2, or phishing when it has gone through the playbook for threat assessment.

## Playbooks
All the playbooks are meant to be used as sub-playbooks to get reputation, intelligence or assess the threat level in regards to a context.
### Available Reputation sub-playbooks
* IP
* Domain
* CVE
* File
* URL
* One combined playbook that returns the reputation for all of the above types

### Available Intelligence/Enrichment sub-playbooks
* IP
* Domain
* CVE
* File
* URL

### Threat assessment sub-playbooks for the following contexts
* Malware
* Phishing
* Command and Control (C2)


---
Copyright 2020 Recorded Future, Inc.
