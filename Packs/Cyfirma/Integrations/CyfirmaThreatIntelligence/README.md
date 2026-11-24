# CYFIRMA Threat Intelligence
 
CYFIRMA is an AI-powered Preemptive External Threat Landscape Management platform that enables organizations to predict, identify, and prevent cyber threats by gaining visibility into external exposure and adversary intent. By transforming threat intelligence into predictive insights and actionable risk intelligence, CYFIRMA helps organizations reduce cyber risk, protect critical digital assets, and move from reactive defence to proactive threat prevention.
 
This integration is a feed integration. It ingests CYFIRMA threat intelligence indicators, including tailored indicators and tailored vulnerabilities, into Cortex XSOAR / Cortex XSIAM. It also provides commands to retrieve indicators and to search CYFIRMA for indicators, threat actors, malware, and vulnerabilities.
 
This integration was integrated and tested with the CYFIRMA API.
 
## Prerequisites
 
- A CYFIRMA account with access to the Threat Intelligence API.
- A valid CYFIRMA API key.
- Network access from the Cortex engine or server to the CYFIRMA API URL (default: `https://api.cyfirma.com`).
## Configure CYFIRMA Threat Intelligence in Cortex
 
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL (e.g. https://api.cyfirma.com) | The base URL of the CYFIRMA API. Default: `https://api.cyfirma.com`. | True |
| API Key | The API key used to authenticate with CYFIRMA. | True |
| Trust any certificate (not secure) | Skip SSL certificate verification. Not recommended for production use. | False |
| Use system proxy settings | Use the system proxy settings for requests to the CYFIRMA API. | False |
| Fetch threat intelligence feeds | Enable fetching of CYFIRMA threat intelligence feeds. Default: enabled. | False |
| Fetch tailored indicator feeds | Fetch tailored indicator feeds. Default: enabled. | False |
| Fetch tailored Vulnerability feeds | Fetch tailored vulnerability feeds. Default: enabled. | False |
| Indicator Reputation | The reputation assigned to indicators from this integration instance. Options: None, Good, Suspicious, Bad. | False |
| Tags | Tags to apply to the fetched indicators. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Options: RED, AMBER, GREEN, WHITE. | False |
| How much time before the first fetch to retrieve feeds for tailored indicators and vulnerabilities. (e.g. 30 days) | How far back to look on the first fetch. Options: 1 day, 3 days, 7 days, 15 days, 30 days, 60 days. Default: 15 days. | False |
| Feed Fetch Interval | How often the feed is fetched. Default: 240. | False |
| Feed expiration interval | Controls when fetched indicators expire. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
 

## Commands
 
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
 
### cyfirma-ip-get
 
***
Retrieves IP indicators from CYFIRMA.
 
#### Base Command
 
`cyfirma-ip-get`
 
#### Input
 
There are no input arguments for this command.
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Indicator.value | String | The indicator value (IP, domain, URL, file hash, etc.). |
| Cyfirma.Indicator.type | String | The indicator type, or Unknown if it could not be determined. |
| Cyfirma.Indicator.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Indicator.role | String | The role of the indicator (e.g. C2, Malware, Phishing). |
| Cyfirma.Indicator.threat_actor | Unknown | Threat actor(s) associated with the indicator. |
| Cyfirma.Indicator.vendors | Unknown | Security vendor detections for the indicator. |
| Cyfirma.Indicator.action | String | The recommended action for the indicator. |
 
#### Command example
 
```
!cyfirma-ip-get
```
 
### cyfirma-domain-get
 
***
Retrieves domain indicators from CYFIRMA.
 
#### Base Command
 
`cyfirma-domain-get`
 
#### Input
 
There are no input arguments for this command.
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Indicator.value | String | The indicator value (IP, domain, URL, file hash, etc.). |
| Cyfirma.Indicator.type | String | The indicator type, or Unknown if it could not be determined. |
| Cyfirma.Indicator.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Indicator.role | String | The role of the indicator (e.g. C2, Malware, Phishing). |
| Cyfirma.Indicator.threat_actor | Unknown | Threat actor(s) associated with the indicator. |
| Cyfirma.Indicator.vendors | Unknown | Security vendor detections for the indicator. |
| Cyfirma.Indicator.action | String | The recommended action for the indicator. |
 
#### Command example
 
```
!cyfirma-domain-get
```
 
### cyfirma-url-get
 
***
Retrieves URL indicators from CYFIRMA.
 
#### Base Command
 
`cyfirma-url-get`
 
#### Input
 
There are no input arguments for this command.
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Indicator.value | String | The indicator value (IP, domain, URL, file hash, etc.). |
| Cyfirma.Indicator.type | String | The indicator type, or Unknown if it could not be determined. |
| Cyfirma.Indicator.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Indicator.role | String | The role of the indicator (e.g. C2, Malware, Phishing). |
| Cyfirma.Indicator.threat_actor | Unknown | Threat actor(s) associated with the indicator. |
| Cyfirma.Indicator.vendors | Unknown | Security vendor detections for the indicator. |
| Cyfirma.Indicator.action | String | The recommended action for the indicator. |
 
#### Command example
 
```
!cyfirma-url-get
```
 
### cyfirma-file-get
 
***
Retrieves file hash indicators from CYFIRMA.
 
#### Base Command
 
`cyfirma-file-get`
 
#### Input
 
There are no input arguments for this command.
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Indicator.value | String | The indicator value (IP, domain, URL, file hash, etc.). |
| Cyfirma.Indicator.type | String | The indicator type, or Unknown if it could not be determined. |
| Cyfirma.Indicator.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Indicator.role | String | The role of the indicator (e.g. C2, Malware, Phishing). |
| Cyfirma.Indicator.threat_actor | Unknown | Threat actor(s) associated with the indicator. |
| Cyfirma.Indicator.vendors | Unknown | Security vendor detections for the indicator. |
| Cyfirma.Indicator.action | String | The recommended action for the indicator. |
 
#### Command example
 
```
!cyfirma-file-get
```
 
### cyfirma-ioc-search-get
 
***
Searches CYFIRMA for an indicator by value.
 
#### Base Command
 
`cyfirma-ioc-search-get`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The indicator value to search for (IP, domain, URL, file hash, etc.). | Required |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Indicator.value | String | The indicator value (IP, domain, URL, file hash, etc.). |
| Cyfirma.Indicator.type | String | The indicator type, or Unknown if it could not be determined. |
| Cyfirma.Indicator.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Indicator.role | String | The role of the indicator (e.g. C2, Malware, Phishing). |
| Cyfirma.Indicator.threat_actor | Unknown | Threat actor(s) associated with the indicator. |
| Cyfirma.Indicator.vendors | Unknown | Security vendor detections for the indicator. |
| Cyfirma.Indicator.action | String | The recommended action for the indicator. |
 
#### Command example
 
```
!cyfirma-ioc-search-get value=<indicator_value>
```
 
### cyfirma-threat-actor-search-get
 
***
Searches CYFIRMA for a threat actor by name.
 
#### Base Command
 
`cyfirma-threat-actor-search-get`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The threat actor name to search for. | Required |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.ThreatActor.value | String | The threat actor name. |
| Cyfirma.ThreatActor.type | String | The object type (ThreatActor). |
| Cyfirma.ThreatActor.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.ThreatActor.origin_of_country | String | Country of origin of the threat actor. |
| Cyfirma.ThreatActor.target_countries | String | Countries targeted by the threat actor. |
| Cyfirma.ThreatActor.motivation | String | Motivation of the threat actor. |
| Cyfirma.ThreatActor.target_technologies | String | Technologies targeted by the threat actor. |
| Cyfirma.ThreatActor.target_industries | String | Industries targeted by the threat actor. |
| Cyfirma.ThreatActor.associated_malware | String | Malware associated with the threat actor. |
| Cyfirma.ThreatActor.associated_campaigns | String | Campaigns associated with the threat actor. |
 
#### Command example
 
```
!cyfirma-threat-actor-search-get value=<threat_actor_name>
```
 
### cyfirma-malware-search-get
 
***
Searches CYFIRMA for malware by name.
 
#### Base Command
 
`cyfirma-malware-search-get`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The malware name to search for. | Required |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Malware.value | String | The malware name. |
| Cyfirma.Malware.type | String | The object type (Malware). |
| Cyfirma.Malware.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Malware.target_technologies | String | Technologies targeted by the malware. |
| Cyfirma.Malware.target_industries | String | Industries targeted by the malware. |
| Cyfirma.Malware.target_countries | String | Countries targeted by the malware. |
| Cyfirma.Malware.country | String | Country associated with the malware. |
| Cyfirma.Malware.threat_actors | String | Threat actors associated with the malware. |
 
#### Command example
 
```
!cyfirma-malware-search-get value=<malware_name>
```
 
### cyfirma-vulnerability-search-get
 
***
Searches CYFIRMA for a vulnerability by CVE ID.
 
#### Base Command
 
`cyfirma-vulnerability-search-get`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The CVE ID to search for, for example CVE-2024-12345. | Required |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Vulnerability.value | String | The CVE ID. |
| Cyfirma.Vulnerability.type | String | The object type (CVE). |
| Cyfirma.Vulnerability.score | Number | The XSOAR score derived from confidence (1 - Benign, 2 - Suspicious, 3 - Malicious). |
| Cyfirma.Vulnerability.confidence | Number | The confidence value (0-100) of the vulnerability. |
| Cyfirma.Vulnerability.cvss_version | String | The CVSS version. |
| Cyfirma.Vulnerability.cvss_base_score | Number | The CVSS base score. |
| Cyfirma.Vulnerability.cvss_vector | String | The CVSS vector string. |
| Cyfirma.Vulnerability.impact_score | Number | The CVSS impact score. |
| Cyfirma.Vulnerability.exploitability_score | Number | The CVSS exploitability score. |
| Cyfirma.Vulnerability.attack_vector | String | The CVSS attack vector. |
| Cyfirma.Vulnerability.attack_complexity | String | The CVSS attack complexity. |
| Cyfirma.Vulnerability.privileges_required | String | The CVSS privileges required. |
| Cyfirma.Vulnerability.user_interaction | String | The CVSS user interaction requirement. |
| Cyfirma.Vulnerability.scope | String | The CVSS scope. |
| Cyfirma.Vulnerability.confidentiality_impact | String | The CVSS confidentiality impact. |
| Cyfirma.Vulnerability.integrity_impact | String | The CVSS integrity impact. |
| Cyfirma.Vulnerability.availability_impact | String | The CVSS availability impact. |
| Cyfirma.Vulnerability.vendors | Unknown | Vendors affected by the vulnerability. |
 
#### Command example
 
```
!cyfirma-vulnerability-search-get value=CVE-2024-12345
```
 
## Troubleshooting
 
- **Authorization or connection errors on Test:** Verify that the API URL is correct and that the API key is valid and active.
- **SSL errors:** Ensure the certificate chain is trusted. Use **Trust any certificate (not secure)** only for troubleshooting.
- **No indicators ingested:** Confirm that **Fetch threat intelligence feeds** is enabled, that at least one of the tailored indicator or tailored vulnerability options is enabled, and that the first fetch period covers the time range you expect.
- **Indicators missing from the system:** If the exclusion list is blocking them, enable **Bypass exclusion list** for this instance.
- **Proxy issues:** If your environment requires a proxy, enable **Use system proxy settings**.
 