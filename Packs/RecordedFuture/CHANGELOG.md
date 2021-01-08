## 2.1
* Added dashboard that covers six widgets. Three for indicators and three for incidents.
* Added two indicator fields; an indicator field for risk rules and and indicator field for threat assessment.
* Modified sub-playbooks to populate new indicator fields if relevant.
* Added a new alert action to fetch a single alert.

## [Initial Release]
* Reputation actions
    * Using the new and faster Recorded Future SOAR Enrichment API
    * Available actions: ip, domain, url, file(hashes), cve(vulnerabilities)
* Intelligence action
    * Fetches full information for the entity.
    * Supports IPs, Domains, URLs, Files(hashes) and CVE(vulnerabilities)
* Alert actions
    * Fetch alerting rules defined at Recorded Future
    * Fetch alert summaries from one or more alerting rules
* Threat assessment action
    * Takes a context, such as phishing or malware and one or more IOC as input
    * Outputs a verdict (true/false) and related evidence (risk rules) in regards to the context chosen
* Example playbooks
    * TODO
    * TODO
* Dashboard
    * TODO
