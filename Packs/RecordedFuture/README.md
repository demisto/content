# "Recorded Future Intelligence" Pack Documentation
​
## Integrations
​
### Recorded Future v2 
Access Recorded Future data to enrich IPs, domains, URLs, CVEs, Files, and Malwares and assess
threats in regards to a specific context. Use this integration to fetch Recorded Future non-playbook alerts
​
#### Available Actions
​
* Reputation actions: 
    * Gets a reputaion lookup based on Recorded Future's risk assessment for IPs, Domains, Files (hashes), URLs and CVEs
    * Using the new Recorded Future SOAR Enrichment API.
    * Available actions: ip, domain, url, file(hashes), cve.
* Intelligence action
    * Fetches full information for the entity.
    * Supports IPs, Domains, URLs, Files(hashes), Vulnerabilities(cve), Malwares.
* Malware search action
    * Search for malware family names curated by Recorded Future
    * Look up and enrich malware families with Recorded Future context
* Alert actions
    * Fetch alerting rules defined at Recorded Future.
    * Fetch alert summaries from one or more alerting rules.
    * Set alert status in Recorded Future
    * Set alert note in Recorded Future
* Threat assessment action
    * Takes a context, such as phishing or malware and one or more IOC as input.
    * Outputs a verdict (true/false) and related evidence (risk rules) for this context.
​
​
#### Relevant Playbooks
​
All the playbooks are meant to be used as sub-playbooks to get reputation, intelligence or assess the threat level in
regards to a context.
* Available Reputation sub-playbooks
    * IP
    * Domain
    * CVE
    * File
    * URL
    * One combined playbook that returns the reputation for all of the above types
​
* Available Intelligence/Enrichment sub-playbooks
    * IP
    * Domain
    * CVE
    * File
    * URL
​
* Threat assessment sub-playbooks for the following contexts
    * Malware
    * Phishing
    * Command and Control (C2)
​
    * Available template playbooks
    * Recorded Future Entity Enrichment
    * Recorded Future Sandbox (Hatching)
    * Recorded Future Leaked Credentials Alert Handling
    * Recorded Future Typosquat Alert Handling
    * Recorded Future Vulnerability Alert Handling
    
#### Relevant Classifiers
Classifier and Incoming Mapper allows you to classify and map fetched incident onto Recorded Future Incident Types.
​
* Recorded Future - Classifier
* Recorded Future - Incoming Mapper
    
#### Relevant Incident Types
​
* Recorded Future Alert
* Recorded Future Leaked Credential Monitoring
* Recorded Future New Critical or Pre NVD Vulnerabilities
* Recorded Future Potential Typosquat 
    
#### Relevant Layouts
​
* Custom layout for Recorded Future incident type
    
---
​
### Recorded Future - Playbook Alerts
Fetch & triage Recorded Future Playbook Alerts
​
#### Available Actions
​
* recordedfuture-playbook-alerts-details
    * View details of a specific Recorded Future playbook alert
    * Get Playbook alert details by id
* recordedfuture-playbook-alerts-update
    * Update the status of one or multiple Playbook alerts
* recordedfuture-playbook-alerts-search
    * View which Recorded Future playbook alerts  are set up in Recorded Future enterprise to be brought into XSOAR
    * Search playbook alerts based on filters
​
#### Relevant Playbooks
The template playbooks included help you save time and keep your incidents in sync. They also aid with automating repetitive tasks associated with playbook alerts. Template playbooks should be used as launching points to build playbooks for specific use cases supported by Recorded Future. Certain playbook steps in a template playbook need to be configured to function.
​
* Recorded Future Playbook Alert Details 
    * A default playbook to fetch details of Playbook alert that does not yet have mapping made by Recorded Future
* Recorded Future Domain Abuse
    * This playbook was developed as a template to handle the ingestion of Recorded Future Domain Abuse playbook alerts.
* Recorded Future Vulnerability
    * This playbook was developed as a template to handle the ingestion of Recorded Future Cyber Vulnerability playbook alerts.
​
#### Relevant Classifiers
Classifier and Incoming Mapper allows you to classify and map fetched incident onto Recorded Future Incident Types.
​
* Recorded Future Playbook Alert Classifier
* Recorded Future Playbook Alert Mapper
    
#### Relevant Incident Types
​
* Recorded Future Playbook Alert
* Recorded Future Domain Abuse
* Recorded Future Vulnerability
* Recorded Future Code Repo Leakage
​
#### Relevant Layouts
​
* Recorded Future Playbook Alert Domain Abuse
* Recorded Future Playbook Alert Vulnerability
* Recorded Future Alert Layout
​
---
### Recorded Future - Lists
Search and manage watchlists and lists in Recorded Future
​
#### Available Actions
* recordedfuture-lists-add-entities
	* Add entities to a list, separate entities by commas. "NOTE:" if entity type is specified, only one entity type can be added with each action.
* recordedfuture-lists-remove-entities
    * Remove entities from a list. Separate entities with commas. "NOTE:" If entity type is specified, only one entity type can be added with each action.
* recordedfuture-lists-search
	* Search for a Recorded Future list. Returns list entities  
* recordedfuture-lists-entities
    * Fetch entities from given lists. Use search command to find the unique ID of a list.

---
#### Dashboards and indicators
​
Includes a dashboard that details various metrics related to indicators that was generated from Recorded Future data and
incidents that was created from Recorded Future data.  

There are two indicator fields added to record which risk rules indicators have triggered as well as whether an
indicator is a malware, c2, or phishing when it has gone through the playbook for threat assessment.
