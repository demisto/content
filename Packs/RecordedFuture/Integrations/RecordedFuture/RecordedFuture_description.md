## Information
A valid API Token for XSOAR from Recorded Future needed to fetch information.
[Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/support/demisto-integration/).

---

## Configuration
| Parameter                        | Description                                                       |
|----------------------------------|-------------------------------------------------------------------|
| Server URL                       | The URL to the Recorded Future ConnectAPI                         |
| API Token                        | Valid API Token from Recorded Future                              |
| File/IP/Domain/URL/CVE Threshold | Minimum risk score from Recorded Future needed to mark IOC as malicious when doing reputation or intelligence lookups  |
| unsecure                         | Trust any certificate \(unsecure\)                                |
| proxy                            | Use system proxy settings                                         |

---

## Available Actions
* Reputation actions
    * Using the new Recorded Future SOAR Enrichment API.
    * Available actions: ip, domain, url, file(hashes), cve.
* Intelligence action
    * Fetches full information for the entity.
    * Supports IPs, Domains, URLs, Files(hashes), vulnerabilities(cve).
* Alert actions
    * Fetch alerting rules defined at Recorded Future.
    * Fetch alert summaries from one or more alerting rules.
    * Set alert status in Recorded Future
    * Add note to alert in Recorded Future
* Threat assessment action
    * Takes a context, such as phishing or malware and one or more IOC as input.
    * Outputs a verdict (true/false) and related evidence (risk rules) for this context.

Copyright 2021 Recorded Future, Inc.