Intelligence-Driven Digital Risk Protection
## Configure cyberint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for cyberint.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | access_token | Cyberint Access Token | True |
    | environment | Cyberint API Environment | True |
    | isFetch | Fetch incidents | False |
    | fetch_severity | Fetch Severities | False |
    | fetch_status | Fetch Statuses | False |
    | fetch_environment | Fetch Environments | False |
    | fetch_type | Fetch Types | False |
    | max_fetch | Fetch Limit | False |
    | fetch_time | First Fetch Time | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberint-list-alerts
***
List alerts according to parameters


#### Base Command

`cyberint-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to return. Default is 1. | Optional | 
| page_size | Number of results in a page. Must be between 10 and 100. Default is 10. | Optional | 
| created_date_from | ISO-Formatted creation date. Get alerts created since this date (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| created_date_to | ISO-Formatted creation date. Get alerts created before this date (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| created_date_range | You can specify a date range to search for from the current time. (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) instead of a start/end time. created_date_range will overwrite created_date. | Optional | 
| modification_date_from | ISO-Formatted modification date. Get alerts modified since this date (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| modification_date_to | ISO-Formatted modification date. Get alerts modified before this date (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| modified_date_range | You can specify a date range to search for from the current time. (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) instead of a start/end time. modified_date_range will overwrite modified_date. | Optional | 
| environments | Environment in which the alerts were created. Can be more than one. | Optional | 
| statuses | Status of the alert. Can be more than one. Possible values are: open, acknowledged, closed. | Optional | 
| severities | Severity of the alert. Can be more than one. Possible values are: low, medium, high, very_high. | Optional | 
| types | Type of the alert, can be more than one. Possible values are: refund_fraud, carding, coupon_fraud, money_laundering, victim_report, malicious_insider, extortion, phishing_email, phishing_kit, phishing_website, lookalike_domain, phishing_target_list, malicious_file, reconnaissance, automated_attack_tools, business_logic_bypass, target_list, official_social_media_profile, impersonation, intellectual_property_infringement, unauthorized_trading, negative_sentiment, fake_job_posting, defacement, compromised_pii, internal_information_disclosure, compromised_payment_cards, compromised_employee_credentials, compromised_customer_credentials, compromised_access_token, ransomware, exposed_web_interfaces, hijackable_subdomains, website_vulnerabilities, exposed_cloud_storage, exploitable_ports, mail_servers_in_blacklist, server_connected_to_botnet, email_security_issues, certificate_authority_issues, other. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberint.Alert.ref_id | String | Reference ID of the alert. | 
| Cyberint.Alert.confidence | Number | Confidence score of the alert. | 
| Cyberint.Alert.status | String | Status of the alert. | 
| Cyberint.Alert.severity | String | Severity of the alert | 
| Cyberint.Alert.created_by.email | String | User which has created the alert. | 
| Cyberint.Alert.created_date | Date | Date in which the alert was created. | 
| Cyberint.Alert.category | String | Category of the alert. | 
| Cyberint.Alert.type | String | Type of the alert. | 
| Cyberint.Alert.source_category | String | Source category of the alert. | 
| Cyberint.Alert.source | String | Source of the alert. | 
| Cyberint.Alert.targeted_vectors | String | Vectors targeted by the threat. | 
| Cyberint.Alert.targeted_brands | String | Brands targeted by the threat. | 
| Cyberint.Alert.related_entities | String | Entities related to the alert. | 
| Cyberint.Alert.impacts | String | Impacts made by the threat. | 
| Cyberint.Alert.acknowledged_date | String | Date in which the alert was acknowledged. | 
| Cyberint.Alert.acknowledged_by.email | String | User which has acknowledged the alert. | 
| Cyberint.Alert.publish_date | String | Date in which the alert was published. | 
| Cyberint.Alert.title | String | Title of the alert. | 
| Cyberint.Alert.alert_data.url | String | URL impacted by the event. | 
| Cyberint.Alert.alert_data.detection_reasons | String | Reasons why a phishing event has been detected. | 
| Cyberint.Alert.alert_data.tool_name | String | Name of a tool used for an exploit if available. | 
| Cyberint.Alert.alert_data.application | String | Application affected by an event. | 
| Cyberint.Alert.alert_data.source | String | Source of an event if available. | 
| Cyberint.Alert.alert_data.domain | String | Domain related to an event if available. | 
| Cyberint.Alert.alert_data.subdomian | String | Subdomain related to an event if available. | 
| Cyberint.Alert.alert_data.misconfiguration_type | String | Type of misconfiguration for a misconfigured domain. | 
| Cyberint.Alert.alert_data.ip | String | IP related to an event. | 
| Cyberint.Alert.alert_data.port | String | Port related to an event. | 
| Cyberint.Alert.alert_data.service | String | Service related to an event. | 
| Cyberint.Alert.alert_data.access_token | String | Access token exposed in an event. | 
| Cyberint.Alert.alert_data.access_token_type | String | Access token exposed in an event. | 
| Cyberint.Alert.alert_data.username | String | Username of an account related to an event. | 
| Cyberint.Alert.alert_data.email | String | Email of an account related to an event. | 
| Cyberint.Alert.alert_data.author_email_address | String | Email of an author related to an event. | 
| Cyberint.Alert.alert_data.repository_name | String | Repository name related to an event. | 
| Cyberint.Alert.alert_data.mail_server | String | Mail server related to an event. | 
| Cyberint.Alert.alert_data.blacklist_repository | String | Blacklist repository name related to an event. | 
| Cyberint.Alert.ioc.type | String | Type of IOC related to the alert. | 
| Cyberint.Alert.ioc.value | String | Value of the IOC related to the alert. | 
| Cyberint.Alert.ticket_id | String | Ticket ID of the alert. | 
| Cyberint.Alert.threat_actor | String | Actor to the threat related to the alert. | 
| Cyberint.Alert.modification_date | String | Date the alert was last modified. | 
| Cyberint.Alert.closure_date | String | Date the alert was closed. | 
| Cyberint.Alert.closed_by.email | String | User which has closed the alert. | 
| Cyberint.Alert.closure_reason | String | Reason for closing the alert. | 
| Cyberint.Alert.description | String | Description of the alert. | 
| Cyberint.Alert.recommendation | String | Recommendation for the alert | 
| Cyberint.Alert.tags | String | Tags related to the alert | 


#### Command Example
```!cyberint-list-alerts created_date_from="2020-01-07T00:00:00Z" page_size=100```

#### Context Example
```json
{
    "alerts": [
        {
            "acknowledged_by": null,
            "acknowledged_date": null,
            "alert_data": {
                "application": null,
                "csv": {
                    "id": 329,
                    "mimetype": "text/csv",
                    "name": "Company Customer Credentials Exposed.csv"
                },
                "designated_url": "https://www.barclaycardus.com/servicing/authenticate"
            },
            "analysis_report": null,
            "attachments": [
                {
                    "id": 18,
                    "mimetype": "image/png",
                    "name": "Compromised Account As Appears On Argos.png"
                }
            ],
            "category": "data",
            "closed_by": null,
            "closure_date": null,
            "closure_reason": null,
            "confidence": 100,
            "created_by": {
                "email": "email@cyberint.com"
            },
            "created_date": "2020-12-30T00:00:56",
            "description": "CyberInt detected breached credentials of several Barclays customers, which were uploaded to an anti-virus repository. The credentials seem to have been obtained through malware, sending user inputs to the operator, and the various credentials were logged in the uploaded .txt files. As such, the file contains users’ credentials not only for barclaycardus.com but for other websites as well. \nBreached customers credentials may be used by Threat Actors to carry out fraudulent transactions on their behalf, exposing Barclays to both financial impact and legal claims.\n\n\n\n",
            "environment": "Argos Demo",
            "impacts": [
                "data_compromise",
                "unauthorized_access",
                "account_takeover",
                "revenue_loss",
                "brand_degradation",
                "customer_churn",
                "financial_penalties"
            ],
            "iocs": [],
            "modification_date": "2020-12-30T00:00:56",
            "publish_date": "2020-11-28T12:45:36",
            "recommendation": "1. CyberInt recommends enforcing password reset on the compromised accounts. \n2. In addition, CyberInt advises Barclays to investigate internally whether any of the accounts have been involved in fraudulent transactions, at least up to the time of detection. In case the accounts were involved in any fraudulent activity, it is recommended to identify and extract relevant IOC’s where possible and monitor them within the bank's systems.\n3. To reduce the chance of customer account takeovers by TAs, Cyberint recommends Barclays implement MFA and CAPTCHA mechanisms. The former will help set another obstacle for a TA trying to abuse the account, and the latter can help blocking credentials-stuffing tools.",
            "ref_id": "ARG-3",
            "related_entities": [],
            "severity": "high",
            "source": "argos.1",
            "source_category": "antivirus_repository",
            "status": "open",
            "tags": [],
            "targeted_brands": [],
            "targeted_vectors": [
                "customer"
            ],
            "threat_actor": "",
            "ticket_id": null,
            "title": "Company Customer Credentials Exposed",
            "type": "compromised_customer_credentials"
        },
        {
            "acknowledged_by": null,
            "acknowledged_date": null,
            "alert_data": {
                "a_record": "8.8.8.8",
                "detection_reasons": [
                    "url_mentioned_assets_or_twists",
                    "similar_logo_detected"
                ],
                "has_ssl_certificate": false,
                "ip_reputation": "malicious",
                "mx_records": null,
                "nameservers": null,
                "registrant_email": null,
                "registrant_name": null,
                "registrar": "NameSilo, LLC",
                "requests_user_details": true,
                "screenshot": {
                    "id": 166,
                    "mimetype": "image/png",
                    "name": "Argos Screenshot of the Phishing Website.png"
                },
                "site_status": null,
                "url": "http://website.com",
                "url_reputation": "malicious",
                "whois_created_date": null,
                "whois_record": null
            },
            "analysis_report": {
                "id": 26,
                "mimetype": "application/pdf",
                "name": "Expert Analysis - Active Phishing Website Targeting Company.pdf"
            },
            "attachments": [
                {
                    "id": 21,
                    "mimetype": "image/png",
                    "name": "Forensic Canvas Investigation of website.com.png"
                }
            ],
            "category": "phishing",
            "closed_by": null,
            "closure_date": null,
            "closure_reason": null,
            "confidence": 100,
            "created_by": {
                "email": "avital@cyberint.com"
            },
            "created_date": "2020-12-30T00:00:56",
            "description": "CyberInt detected an active phishing website impersonating Barclays login page while abusing the brand’s name, logo and photos.\nThe website contains login, registration and checkout forms, where unsuspecting victims could be lured to fill in their PII, credentials and payment details.\nPhishing websites such as the above are often used by attackers to obtain users' credentials and PII. This information can be utilized to take over customers' accounts, causing customer churn and damage to the brand's reputation.",
            "environment": "Argos Demo",
            "impacts": [
                "brand_degradation",
                "account_takeover",
                "user_data_compromise",
                "data_compromise",
                "unauthorized_access"
            ],
            "iocs": [
                {
                    "type": "domain",
                    "value": "website.com"
                },
                {
                    "type": "ip",
                    "value": "8.8.8.8"
                },
                {
                    "type": "url",
                    "value": "http://website.com"
                }
            ],
            "modification_date": "2020-12-30T00:00:56",
            "publish_date": "2020-09-02T00:06:49",
            "recommendation": "CyberInt recommends Barclays take down the site; upon request, CyberInt can submit the take down request on behalf of Barclays. ",
            "ref_id": "ARG-4",
            "related_entities": [],
            "severity": "very_high",
            "source": "",
            "source_category": "online_protection",
            "status": "open",
            "tags": [],
            "targeted_brands": [],
            "targeted_vectors": [
                "customer"
            ],
            "threat_actor": "",
            "ticket_id": null,
            "title": "Active Phishing Website Targeting Company",
            "type": "phishing_website"
        },
        {
            "acknowledged_by": null,
            "acknowledged_date": null,
            "alert_data": {
                "service": "Azure",
                "subdomain": "s7k.paymebiz.hsbc.com.hk",
                "vulnerable_cname_record": "s7k-paymebiz.trafficmanager.net"
            },
            "analysis_report": null,
            "attachments": [],
            "category": "vulnerabilities",
            "closed_by": null,
            "closure_date": null,
            "closure_reason": null,
            "confidence": 100,
            "created_by": {
                "email": "avital@cyberint.com"
            },
            "created_date": "2020-12-30T00:00:56",
            "description": "CyberInt discovered a misconfiguration on an HSBC subdomain which exposes it to takeover.\nCurrently, the domain names refer to the CNAME records listed above. However, those CNAME records are no longer owned by Target, and they may have expired. This situation allows others to obtain the record, and practically get access to the HSBC subdomain.\n\nTaking over HSBC subdomains could be used to conduct complex phishing attack on the organization's employees and customers, as well potentially hijack sessions of logged-in users in any service using the vulnerable domains.",
            "environment": "Argos Demo",
            "impacts": [
                "data_compromise",
                "unauthorized_access",
                "account_takeover"
            ],
            "iocs": [],
            "modification_date": "2020-12-30T00:00:56",
            "publish_date": "2020-11-24T20:28:00",
            "recommendation": "CyberInt advises HSBC to choose either of the following courses of action:\n1. Update the CNAME record of the subdomains so that they no longer redirect traffic to the vulnerable subdomains.\n2. Re-purchase the record and thus avoid contradiction between the CNAME record and the Fastly interface.",
            "ref_id": "ARG-8",
            "related_entities": [],
            "severity": "very_high",
            "source": "",
            "source_category": "my_digital_presence",
            "status": "open",
            "tags": [],
            "targeted_brands": [
                "HSBC"
            ],
            "targeted_vectors": [
                "business"
            ],
            "threat_actor": "",
            "ticket_id": null,
            "title": "Company Subdomain Vulnerable to Hijacking",
            "type": "hijackable_subdomains"
        }
    ],
    "total": 3
}
```

#### Human Readable Output

>### Found alerts:
>|ref_id|title|status|severity|created_date|type|environment|
>|---|---|---|---|---|---|---|
>| ADS10-3 | Company Employee Corporate Credentials Exposed | open | high | 2020-11-18T12:19:48 | compromised_employee_credentials | Argos Demo S 10 |
>| ARG-3 | Company Customer Credentials Exposed | open | high | 2021-01-05T00:00:23 | compromised_customer_credentials | Argos Demo |
>| ARG-15 | Active Phishing Website Targeting Company | acknowledged | very_high | 2021-01-01T00:00:23 | phishing_website | Argos Demo |
>| ARG-4 | Active Phishing Website Targeting Company | open | very_high | 2021-01-05T00:00:23 | phishing_website | Argos Demo |
>| ARG-8 | Company Subdomain Vulnerable to Hijacking | open | very_high | 2021-01-05T00:00:23 | hijackable_subdomains | Argos Demo |
>| ARG-2 | Company Source Code Exposed | acknowledged | very_high | 2021-01-01T00:00:23 | internal_information_disclosure | Argos Demo |
>| ARG-6 | Fraudulent Refund Services Targeting Company | acknowledged | medium | 2021-01-01T00:00:23 | refund_fraud | Argos Demo |
>| ARG-16 | Fraudulent Refund Services Targeting Company | closed | medium | 2021-01-01T00:00:23 | refund_fraud | Argos Demo |
>| ARG-1 | Company Customer Payment Cards Offered for Sale | acknowledged | medium | 2020-12-30T00:00:23 | compromised_payment_cards | Argos Demo |
>| ARG-5 | Company Customer Credentials Offered for Sale | acknowledged | medium | 2020-12-30T00:00:23 | compromised_customer_credentials | Argos Demo |
>| ARG-11 | Company Executive PII Offered for Sale | acknowledged | high | 2020-12-27T00:00:23 | compromised_pii | Argos Demo |
>| ARG-12 | Credential Stuffing Tool Targeting Company | acknowledged | high | 2020-12-27T00:00:23 | automated_attack_tools | Argos Demo |
>| ARG-10 | Brand Abusing Website Impersonating Company | open | medium | 2020-12-24T00:00:23 | impersonation | Argos Demo |
>| ARG-18 | Missing Company Domain DMARC Records Detected | closed | high | 2020-12-22T00:00:23 | email_security_issues | Argos Demo |
>| ARG-13 | Company Product Unauthorized Resale | acknowledged | medium | 2020-12-20T00:00:23 | unauthorized_trading | Argos Demo |
>| ARG-9 | Exploitable Port on Company Server Detected | open | medium | 2020-12-17T00:00:23 | exploitable_ports | Argos Demo |
>| ARG-17 | Email Phishing Campaign Targeting Company | closed | high | 2020-12-15T00:00:23 | phishing_email | Argos Demo |
>| ARG-14 | Company Customer Credentials Exposed | closed | high | 2020-12-07T00:00:23 | compromised_customer_credentials | Argos Demo |
>| ARG-7 | Potentially Exploitable Web Application Vulnerability Detected | acknowledged | low | 2020-12-03T00:00:23 | website_vulnerabilities | Argos Demo |
>| ADS10-10 | Company Employee Corporate Credentials Exposed | acknowledged | very_high | 2020-11-18T12:46:05 | compromised_employee_credentials | Argos Demo S 10 |
>| ADS10-11 | Active Phishing Website Targeting Company | open | very_high | 2020-11-18T12:54:07 | phishing_website | Argos Demo S 10 |
>| ADS10-1 | Active Phishing Website Targeting Company | open | very_high | 2020-11-18T12:12:44 | phishing_website | Argos Demo S 10 |
>| ADS10-6 | Company Source Code Exposed | acknowledged | low | 2020-11-18T12:27:59 | internal_information_disclosure | Argos Demo S 10 |
>| ADS10-12 | Email Phishing Campaign Targeting Company | closed | high | 2020-11-18T12:59:59 | phishing_email | Argos Demo S 10 |
>| ADS10-5 | Company Internal Email Correspondence Exposed | closed | medium | 2020-11-18T12:24:47 | internal_information_disclosure | Argos Demo S 10 |
>| ADS10-8 | Look-Alike Domain Potentially Targeting Company | acknowledged | medium | 2020-11-18T12:35:57 | lookalike_domain | Argos Demo S 10 |
>| ADS10-7 | Web Application Vulnerability Exploit Published | acknowledged | very_high | 2020-11-18T12:34:15 | website_vulnerabilities | Argos Demo S 10 |
>| ADS10-4 | Phishing Kit Targeting Company | acknowledged | high | 2020-11-18T12:22:06 | phishing_kit | Argos Demo S 10 |
>| ADS10-2 | Company Customer Payment Cards Exposed | open | high | 2020-11-18T12:15:05 | compromised_payment_cards | Argos Demo S 10 |
>| ADS10-9 | Missing Company Domain DMARC Records Detected | open | medium | 2020-11-18T12:38:47 | email_security_issues | Argos Demo S 10 |
>Total alerts: 30
>Current page: 1

### cyberint-update-alerts
***
Update the status of one or more alerts.


#### Base Command

`cyberint-update-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ref_ids | Reference IDs for the alert(s). | Required | 
| status | Desired status to update for the alert(s). Possible values are: open, acknowledged, closed. | Required | 
| closure_reason | Reason for updating the alerts status to closed. Possible values are: resolved, irrelevant, false_positive. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberint.Alert.ref_id | String | Reference ID of the alert. | 
| Cyberint.Alert.status | String | Status of the alert. | 
| Cyberint.Alert.closure_reason | String | Reason for updating the alert to closed. | 


#### Command Example
```!cyberint-update-alerts alert_ref_ids=ADS10-3 status=acknowledged```

#### Context Example
```json
{
    "Cyberint": {
        "Alert": {
            "closure_reason": null,
            "ref_id": "ADS10-3",
            "status": "acknowledged"
        }
    }
}
```

#### Human Readable Output

>### Alerts Updated
>|ref_id|status|
>|---|---|
>| ADS10-3 | acknowledged |

