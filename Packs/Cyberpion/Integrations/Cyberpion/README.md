Vulnerabilities management
This integration was integrated and tested with version 1.0 of Cyberpion
## Configure Cyberpion in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://api.example.com/security/api) |  | True |
| API Key |  | True |
| Maximum number of incidents per fetch |  | False |
| Action items category to fetch as incidents. | Allowed values: "Network", "Web", "Cloud", "DNS", "PKI", "Vulnerabilities", "TLS", "Email Server", "Mobile". | True |
| Minimum Action items severity level to fetch incidents from. | Allowed values are integers between 1 to 10.<br/>1 will fetch all incidents. | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Show only active issues |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberpion-get-domain-action-items
***
Retrieves domain's action items


#### Base Command

`cyberpion-get-domain-action-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Get action items for this domain. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberpion.DomainData.Vulnerabilities.id | String | Action item ID | 
| Cyberpion.DomainData.Domain | String | Domain to get action items that are related to | 
| Cyberpion.DomainData.Vulnerabilities.category | String | Category of action item. can be DNS, PKI, Cloud, Vulnerability | 
| Cyberpion.DomainData.Vulnerabilities.urgency | Number | Action item urgency | 
| Cyberpion.DomainData.Vulnerabilities.is_open | Boolean | Is action item still relevant \(open\) | 
| Cyberpion.DomainData.Vulnerabilities.creation_time | Date | Action item's creation time | 
| Cyberpion.DomainData.Vulnerabilities.link | String | Link to the action item in Cyberpion's portal | 
| Cyberpion.DomainData.Vulnerabilities.title | String | Action item's title | 
| Cyberpion.DomainData.Vulnerabilities.impact | String | Action item's potential impact from a security perspective | 
| Cyberpion.DomainData.Vulnerabilities.summary | String | Action item summary | 
| Cyberpion.DomainData.Vulnerabilities.solution | String | The necessary course of action needed to remediate the threat | 
| Cyberpion.DomainData.Vulnerabilities.description | String | Description of the source of the issue that was detected | 
| Cyberpion.DomainData.Vulnerabilities.technical_details | String | Technical details of the issue | 


#### Command Example
```!cyberpion-get-domain-action-items domain="$anon100-2.com"```

#### Context Example
```json
{
    "Cyberpion": {
        "DomainData": {
            "Domain": "$anon100-2.com",
            "Vulnerabilities": [
                {
                    "alert_type": "cyberpion_action_item",
                    "category": "PKI",
                    "creation_time": "2020-11-19 14:27:07.430866 UTC",
                    "description": "Certificates are used to authenticate the identities in online communications. Certificate must be both valid (format, cryptographic schemes, etc.) and issued by a trusted certificate authority (CA). The certificate of the domain is about to become invalid, because:\n1) The domain shares certificate with other domains that are vulnerable. Sharing trust with vulnerable domains exposes the domain to risk if the vulnerable domains are hacked. For exmaple, a stolen private key can be abused to impersonate the domain, and in some cases also to intercept live traffic.\n2) Other vulnerable domains use a certificate that is valid for the domain. Sharing trust with vulnerable domains exposes the domain to risk if the vulnerable domains are hacked. Although the certificates are different, if the other certificate is valid for the domain and it is compromised, attackers can abuse it to impersonate the domain.\n",
                    "domain": "$anon100-2.com",
                    "id": 175692,
                    "impact": "Bad PKI design (anomalies, inconsistency, or ignoring best practices) indicates on missing management. PKI anomalies might become security vulnerability, mainly, due to the difficulty in following them.",
                    "is_open": true,
                    "link": "https://api.test.com/static/new/index.html#/pages/assessments/certificates/cert_test_report;$anon100-2.com",
                    "solution": "Issue a new certificate for the domain",
                    "summary": "The domain $anon100-2.com uses certificate that is used also for vulnerable domains and can be forged with another valid certificate that is used for another vulnerable domain",
                    "technical_details": "shares a certificate with the vulnerable domains: $anon100-265.com (risk rank: 98), sd2.$anon100-2.com (risk rank: 98), sd2.$anon100-265.com (risk rank: 98)\ncould be authenticated with the certificate that is used by the vulnerable domains: $anon100-265.com (cvss: 98.39526778), sd2.$anon100-2.com (cvss: 98.39526778), sd2.$anon100-265.com (cvss: 98.39526778)",
                    "title": "Fix PKI issues: Vulnerable domain use certificate that valid fo domain, Domain shares a certificate with vulnerable domain",
                    "urgency": 5
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Cyberpion
>### Action Items
>|domain|category|urgency|is_open|creation_time|link|title|impact|summary|solution|description|technical_details|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| $anon100-2.com | PKI | 5.0 | true | 2020-11-19 14:27:07.430866 UTC | https://api.test.com/static/new/index.html#/pages/assessments/certificates/cert_test_report;$anon100-2.com | Fix PKI issues: Vulnerable domain use certificate that valid fo domain, Domain shares a certificate with vulnerable domain | Bad PKI design (anomalies, inconsistency, or ignoring best practices) indicates on missing management. PKI anomalies might become security vulnerability, mainly, due to the difficulty in following them. | The domain $anon100-2.com uses certificate that is used also for vulnerable domains and can be forged with another valid certificate that is used for another vulnerable domain | Issue a new certificate for the domain | Certificates are used to authenticate the identities in online communications. Certificate must be both valid (format, cryptographic schemes, etc.) and issued by a trusted certificate authority (CA). The certificate of the domain is about to become invalid, because:<br/>1) The domain shares certificate with other domains that are vulnerable. Sharing trust with vulnerable domains exposes the domain to risk if the vulnerable domains are hacked. For exmaple, a stolen private key can be abused to impersonate the domain, and in some cases also to intercept live traffic.<br/>2) Other vulnerable domains use a certificate that is valid for the domain. Sharing trust with vulnerable domains exposes the domain to risk if the vulnerable domains are hacked. Although the certificates are different, if the other certificate is valid for the domain and it is compromised, attackers can abuse it to impersonate the domain.<br/> | shares a certificate with the vulnerable domains: $anon100-265.com (risk rank: 98), sd2.$anon100-2.com (risk rank: 98), sd2.$anon100-265.com (risk rank: 98)<br/>could be authenticated with the certificate that is used by the vulnerable domains: $anon100-265.com (cvss: 98.39526778), sd2.$anon100-2.com (cvss: 98.39526778), sd2.$anon100-265.com (cvss: 98.39526778) |


### cyberpion-get-domain-state
***
Retrieves domain's info and current state


#### Base Command

`cyberpion-get-domain-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Get info and current state of this domain. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberpion.DomainState.id | String | Domain State ID | 
| Cyberpion.DomainState.domain | String | The Domain | 
| Cyberpion.DomainState.ips | String | Reverse Ip's of domain's ips | 
| Cyberpion.DomainState.risk_rank | Number | Domain's risk rank | 
| Cyberpion.DomainState.vuln_count | Number | Number of vulnerabilities associated with domain | 
| Cyberpion.DomainState.cname_chain | String | Domain's CName chain \(DNS record\)  | 
| Cyberpion.DomainState.domain_types | String | Domain's infrastructure info \(provider etc.\) | 
| Cyberpion.DomainState.discovery_date | Date | The Date domain was discovered | 


#### Command Example
```!cyberpion-get-domain-state domain="$anon100-2.com"```

#### Context Example
```json
{
    "Cyberpion": {
        "DomainState": {
            "cname_chain": null,
            "discovery_date": "2021-03-07",
            "domain": "$anon100-2.com",
            "domain_types": "1.\nservice_type: CBSP\nprovider: Incapsula\nservice: None\ndescription: None",
            "id": "9ab5474a-3da2-4910-9d59-9a1f11a2193e",
            "ips": "153.228.75.31: None\n235.125.130.90: None",
            "risk_rank": 0,
            "vuln_count": 0
        }
    }
}
```

#### Human Readable Output

>### Cyberpion
>### Domain State
>|id|domain|ips|risk_rank|vuln_count|cname_chain|domain_types|discovery_date|
>|---|---|---|---|---|---|---|---|
>| 9ab5474a-3da2-4910-9d59-9a1f11a2193e | $anon100-2.com | 153.228.75.31: None<br/>235.125.130.90: None | 0 | 0 |  | 1.<br/>service_type: CBSP<br/>provider: Incapsula<br/>service: None<br/>description: None | 2021-03-07 |
