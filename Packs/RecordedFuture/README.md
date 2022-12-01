# "Recorded Future Intelligence" Pack Documentation

This pack is used to access Recorded Future data to enrich IPs, domains, URLs, CVEs, Files, and Malwares and assess
threats in regards to a specific context.

## Integration

The integration is used to access the data from the API.

### Available Actions

* Reputation actions
    * Using the new Recorded Future SOAR Enrichment API.
    * Available actions: ip, domain, url, file(hashes), cve.
* Intelligence action
    * Fetches full information for the entity.
    * Supports IPs, Domains, URLs, Files(hashes), Vulnerabilities(cve), Malwares.
* Malware search action
* Alert actions
    * Fetch alerting rules defined at Recorded Future.
    * Fetch alert summaries from one or more alerting rules.
    * Set alert status in Recorded Future
    * Set alert note in Recorded Future
* Threat assessment action
    * Takes a context, such as phishing or malware and one or more IOC as input.
    * Outputs a verdict (true/false) and related evidence (risk rules) for this context.

## Dashboards and indicators

Includes a dashboard that details various metrics related to indicators that was generated from Recorded Future data and
incidents that was created from Recorded Future data.

There are two indicator fields added to record which risk rules indicators have triggered as well as whether an
indicator is a malware, c2, or phishing when it has gone through the playbook for threat assessment.

## Playbooks

All the playbooks are meant to be used as sub-playbooks to get reputation, intelligence or assess the threat level in
regards to a context.

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

### Available template playbooks

* Recorded Future Entity Enrichment
* Recorded Future Sandbox (Hatching)
* Recorded Future Leaked Credentials Alert Handling
* Recorded Future Typosquat Alert Handling
* Recorded Future Vulnerability Alert Handling

## Incident Types

* Recorded Future Alert
* Recorded Future Leaked Credential Monitoring
* Recorded Future New Critical or Pre NVD Vulnerabilities
* Recorded Future Potential Typosquat

## Classifier and Incoming Mapper

Classifier and Incoming Mapper allows you to classify and map fetched incident onto Recorded Future Incident Types.

### Available classifier and incoming mapper

* Recorded Future - Classifier
* Recorded Future - Incoming Mapper

---
