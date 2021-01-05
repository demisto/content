Intelligence-Driven Digital Risk Protection
This integration was integrated and tested with version xx of cyberint
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
    "Cyberint": {
        "Alert": [
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "csv": {
                        "id": 155,
                        "mimetype": "text/csv",
                        "name": "Credentials Details CSV.csv"
                    },
                    "domain": "brand.com",
                    "total_credentials": 28,
                    "total_first_seen": 9
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:19:48",
                "description": "Cyberint detected breached credentials of employees, which were uploaded to a darknet data leak blog. ",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "account_takeover"
                ],
                "iocs": [],
                "modification_date": "2021-01-05T12:56:46",
                "publish_date": null,
                "recommendation": "Cyberint recommends enforcing password reset on the compromised account and to investigate internally whether the accounts have been involved in suspicious activities.\nIn case the account was involved in any suspicious activities, it is recommended to identify and extract relevant IOC\u2019s where possible and monitor them within systems.",
                "ref_id": "ADS10-3",
                "related_entities": [],
                "severity": "high",
                "source": "dataleakblog.onion",
                "source_category": "darknet",
                "status": "open",
                "tags": [
                    "Admin Credentials",
                    "Internal Systems",
                    "Sensitive Information"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "TheAxs",
                "ticket_id": null,
                "title": "Company Employee Corporate Credentials Exposed",
                "type": "compromised_employee_credentials"
            },
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
                    "designated_url": "https://chaseonline.chase.com/"
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
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-01-05T00:00:23",
                "description": "CyberInt detected breached credentials of several Chase customers, which were uploaded to an anti-virus repository. The credentials seem to have been obtained through malware, sending user inputs to the operator, and the various credentials were logged in the uploaded .txt files. As such, the file contains users\u2019 credentials not only for chase.com but for other websites as well. \nBreached customers credentials may be used by Threat Actors to carry out fraudulent transactions on their behalf, exposing Chase to both financial impact and legal claims.\n\n\n\n",
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
                "modification_date": "2021-01-05T12:11:33",
                "publish_date": "2020-11-23T17:44:42",
                "recommendation": "1. CyberInt recommends enforcing password reset on the compromised accounts. \n2. In addition, CyberInt advises Chase to investigate internally whether any of the accounts have been involved in fraudulent transactions, at least up to the time of detection. In case the accounts were involved in any fraudulent activity, it is recommended to identify and extract relevant IOC\u2019s where possible and monitor them within the bank's systems.\n3. To reduce the chance of customer account takeovers by TAs, Cyberint recommends Chase implement MFA and CAPTCHA mechanisms. The former will help set another obstacle for a TA trying to abuse the account, and the latter can help blocking credentials-stuffing tools.",
                "ref_id": "ARG-3",
                "related_entities": [],
                "severity": "high",
                "source": "argos.1",
                "source_category": "antivirus_repository",
                "status": "open",
                "tags": [],
                "targeted_brands": [
                    "Chase"
                ],
                "targeted_vectors": [
                    "customer"
                ],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Customer Credentials Exposed",
                "type": "compromised_customer_credentials"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T05:46:23",
                "alert_data": {
                    "detection_reasons": [
                        "similar_logo_detected",
                        "source_code_mentioned_assets"
                    ],
                    "has_ssl_certificate": null,
                    "ip_reputation": null,
                    "requests_user_details": true,
                    "site_status": null,
                    "url": "http://hacking.enterprises/PayPal/banks/bank.barclays.co.uk/",
                    "url_reputation": "malicious",
                    "whois_created_date": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "phishing",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-01-01T00:00:23",
                "description": "CyberInt detected an active phishing website impersonating Barclays login page while abusing the brand\u2019s name, logo and photos.\nThe website contains login, registration and checkout forms, where unsuspecting victims could be lured to fill in their PII, credentials and payment details.\nPhishing websites such as the above are often used by attackers to obtain users' credentials and PII. This information can be utilized to take over customers' accounts, causing customer churn and damage to the brand's reputation.",
                "environment": "Argos Demo",
                "impacts": [
                    "brand_degradation",
                    "account_takeover",
                    "user_data_compromise",
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2021-01-05T12:11:19",
                "publish_date": "2020-11-29T05:00:38",
                "recommendation": "CyberInt recommends Barclays take down the site; upon request, CyberInt can submit the take down request on behalf of the bank.",
                "ref_id": "ARG-15",
                "related_entities": [],
                "severity": "very_high",
                "source": "",
                "source_category": "online_protection",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Barclays"
                ],
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
                    "a_record": "129.146.184.83",
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
                    "url": "http://supportcenter-ee.com/banks/bank.barclays.co.uk",
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
                        "name": "Forensic Canvas Investigation of supportcenter-ee.com.png"
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
                "created_date": "2021-01-05T00:00:23",
                "description": "CyberInt detected an active phishing website impersonating Barclays login page while abusing the brand\u2019s name, logo and photos.\nThe website contains login, registration and checkout forms, where unsuspecting victims could be lured to fill in their PII, credentials and payment details.\nPhishing websites such as the above are often used by attackers to obtain users' credentials and PII. This information can be utilized to take over customers' accounts, causing customer churn and damage to the brand's reputation.",
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
                        "value": "supportcenter-ee.com"
                    },
                    {
                        "type": "ip",
                        "value": "129.146.184.83"
                    },
                    {
                        "type": "url",
                        "value": "http://supportcenter-ee.com/banks/bank.barclays.co.uk"
                    }
                ],
                "modification_date": "2021-01-05T00:00:23",
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
                "created_date": "2021-01-05T00:00:23",
                "description": "CyberInt discovered a misconfiguration on an HSBC subdomain which exposes it to takeover.\nCurrently, the domain names refer to the CNAME records listed above. However, those CNAME records are no longer owned by Target, and they may have expired. This situation allows others to obtain the record, and practically get access to the HSBC subdomain.\n\nTaking over HSBC subdomains could be used to conduct complex phishing attack on the organization's employees and customers, as well potentially hijack sessions of logged-in users in any service using the vulnerable domains.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "account_takeover"
                ],
                "iocs": [],
                "modification_date": "2021-01-05T00:00:23",
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
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T15:46:23",
                "alert_data": {
                    "author_email_address": null,
                    "code_leak_sample": "# Working credentials, no need to replace\nawesome_sauce:\n  login: 'test-api'\n  password: 'c271ee995dd79671dc19f3ba4bb435e26bee68b0e831b7e9e4ae858c1584e0a33bc93b8d9ca3cedc'\n\n# Working credentials, no need to replace\nbalanced:\n  login: 'e1c5ad38d1c711e1b36c026ba7e239a9'",
                    "exposed_code_link": "https://github.com/brpandey/active-merchant-sample-gateway-adapter/blob/b18b7faa10e1b4a6b6347b95933ce92ada600a17/test/fixtures.yml"
                },
                "analysis_report": null,
                "attachments": [
                    {
                        "id": 15,
                        "mimetype": "image/png",
                        "name": "Argos Intel Item Containing Exposed Information.png"
                    }
                ],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 90,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-01-01T00:00:23",
                "description": "CyberInt detected exposed credentials and RSA private key of a developer working with a Barclays API, which were published on a Github repository.\nThese credentials can allow an attacker to gain access to sensitive internal information of Barclays.\n",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "competitive_advantage_loss"
                ],
                "iocs": [],
                "modification_date": "2021-01-01T00:00:23",
                "publish_date": "2017-01-08T05:21:51",
                "recommendation": "CyberInt recommends Barclays validate the authenticity of the credentials and key and in case they are relevant, reset them immediately.\nUpon request, CyberInt can take down the code on behalf of Barclays.",
                "ref_id": "ARG-2",
                "related_entities": [],
                "severity": "very_high",
                "source": "github.com",
                "source_category": "code_repository",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Barclays"
                ],
                "targeted_vectors": [],
                "threat_actor": "Bibek Pandey",
                "ticket_id": null,
                "title": "Company Source Code Exposed",
                "type": "internal_information_disclosure"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T15:46:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "fraud",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-01-01T00:00:23",
                "description": "Argos detected a thread published in a fraudsters' forum, concerning fraudulent refund services against various US retailers, including Nike and Costco. \nThe thread contains vouches from dozens of satisfied customers, who used the TA's refunding service.\n\nRefund fraud refers to the process of abusing a company\u2019s refund policy using social engineering techniques to receive a partial or complete refund on an order. Threat actors who offer this service are usually paid 7-20% of the order\u2019s value, and usually require a minimum of $15 per order to start the process. Given the commonness of the service, refund fraud may result in significant financial loss to organizations.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss"
                ],
                "iocs": [],
                "modification_date": "2021-01-01T00:00:23",
                "publish_date": "2020-11-16T09:09:44",
                "recommendation": "CyberInt advises Costco to search their systems for refunds accepted in recent months, and try to cross-reference similarities and IOCs between the transactions. Such investigation can help identify potentially fraudulent patterns.\nAdditionally, as part of a full engagement, CyberInt can further investigate the TA in order to gain more information about their methods.",
                "ref_id": "ARG-6",
                "related_entities": [],
                "severity": "medium",
                "source": "nulled.to",
                "source_category": "forum",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Target"
                ],
                "targeted_vectors": [
                    "business"
                ],
                "threat_actor": "JonThaDon",
                "ticket_id": null,
                "title": "Fraudulent Refund Services Targeting Company",
                "type": "refund_fraud"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T05:46:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "fraud",
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2021-01-04T10:18:23",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-01-01T00:00:23",
                "description": "Argos detected a thread published in a fraudsters' forum, concerning fraudulent refund services against various US retailers, including Apple, Sam's Club and more.\nThe thread contains vouches from dozens of satisfied customers, who used the TA's refunding service.\n\nRefund fraud refers to the process of abusing a company\u2019s refund policy using social engineering techniques to receive a partial or complete refund on an order. Threat actors who offer this service are usually paid 7-20% of the order\u2019s value, and usually require a minimum of $15 per order to start the process. Given the commonness of the service, refund fraud may result in significant financial loss to organizations.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss"
                ],
                "iocs": [],
                "modification_date": "2021-01-01T00:00:23",
                "publish_date": "2020-11-29T20:42:29",
                "recommendation": "CyberInt advises Apple to search their systems for refunds accepted in recent months, and try to cross-reference similarities and IOCs between the transactions. Such investigation can help identify potentially fraudulent patterns.\nAdditionally, as part of a full engagement, CyberInt can further investigate the TA in order to gain more information about their methods.",
                "ref_id": "ARG-16",
                "related_entities": [],
                "severity": "medium",
                "source": "mpgh.net",
                "source_category": "forum",
                "status": "closed",
                "tags": [],
                "targeted_brands": [
                    "Apple"
                ],
                "targeted_vectors": [
                    "business"
                ],
                "threat_actor": "Felix_dsp",
                "ticket_id": null,
                "title": "Fraudulent Refund Services Targeting Company",
                "type": "refund_fraud"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [
                    {
                        "id": 14,
                        "mimetype": "image/png",
                        "name": "Company Customer Payment Cards Offered for Sale.png"
                    }
                ],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-30T00:00:23",
                "description": "Cyberint detected payment cards belonging to Wells Fargo customers being offered for sale online for 18$. The cards' information, published by a threat actors named Dolly, includes the BIN number of the card, expiration date and CVV digits as well as some PII of the card owner.\nCompromised payment card details, especially when combined with exposed PII, can be purchased and abused by threat actors for illegitimate and fraudulent activities. Those, in turn, will result in chargeback costs for the bank and potential customer churn.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss",
                    "brand_degradation",
                    "customer_churn",
                    "financial_penalties"
                ],
                "iocs": [],
                "modification_date": "2020-12-30T00:00:23",
                "publish_date": "2020-08-17T00:00:00",
                "recommendation": "Cyberint recommends Wells Fargo purchase one of the payment cards in order to then verify validity. Upon confirmation, Cyberint recommends cancelling the payment cards in order to prevent their abuse, and informing the card holders of the cancellation.\nCyberint can make the test purchase on behalf of the bank.",
                "ref_id": "ARG-1",
                "related_entities": [],
                "severity": "medium",
                "source": "bestvalid.onion",
                "source_category": "darknet",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "Dolly",
                "ticket_id": null,
                "title": "Company Customer Payment Cards Offered for Sale",
                "type": "compromised_payment_cards"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-01-02T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [
                    {
                        "id": 186,
                        "mimetype": "image/png",
                        "name": "AAX's post with full link.png"
                    }
                ],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-30T00:00:23",
                "description": "Cyberint identified 40 accounts of Gucci customers being offered for sale in a hacking forum. It is unclear where the threat actors had obtained the accounts, but the thread been commented on by 20 interested buyers.\nThose are later abused by the buyers for account takeovers, to make fraudulent purchases on the victims\u2019 behalf. Account takeovers result in financial loss to the organization and may cause customer churn.",
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
                "modification_date": "2020-12-30T00:00:23",
                "publish_date": "2020-10-15T11:31:43",
                "recommendation": "Cyberint can contact the threat actor on behalf of Gucci, using an Avatar, in order to lure them into sharing how they had obtained the accounts. If relevant, Cyberint recommends Gucci consider purchasing a sample of the compromised accounts, to verify their validity and whether the rest of the batch could be worth purchasing as well.",
                "ref_id": "ARG-5",
                "related_entities": [],
                "severity": "medium",
                "source": "cracked.to",
                "source_category": "forum",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Gucci"
                ],
                "targeted_vectors": [
                    "customer"
                ],
                "threat_actor": "aax",
                "ticket_id": null,
                "title": "Company Customer Credentials Offered for Sale",
                "type": "compromised_customer_credentials"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-28T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [
                    {
                        "id": 249,
                        "mimetype": "image/png",
                        "name": "Argos automatic threat actor enrichment.png"
                    },
                    {
                        "id": 250,
                        "mimetype": "image/png",
                        "name": "The listing as appears on the PII marketplace.png"
                    }
                ],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-27T00:00:23",
                "description": "CyberInt detected the Social Security Number (SSN) of Google director John A. Smith being offered for sale on an online PII marketplace for $5. The SSN, alongside Someone\u2019s full Date of Birth (DOB), is redacted in the listing and should be unveiled once payment is made.\nAdditional investigation revealed that the associated addresses appeared in other online sources as well, which strengthens the suspicion that the PII indeed belongs to the Google executive (and not another person by the same name).  \nThe threat actor operating the marketplace, dubbed \u201cInfoDigger\u201d, is mainly active in notable Russian forums and the posts \u2013 most of them in Russian \u2013 are usually concerning accounts and PII for sale. The TA uses the Jabber address admin@infodig.is. \nSSN and DOB of American citizens can be abused for identify theft, which could impact one\u2019s credit score and result in fraudulent activities made on one\u2019s behalf.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "account_takeover"
                ],
                "iocs": [],
                "modification_date": "2020-12-27T00:00:23",
                "publish_date": "2020-11-26T13:23:53",
                "recommendation": "CyberInt recommends Google purchase the listing in order to validate the authenticity of the information. (notice: once purchased, the item is not delisted from the marketplace and could be bought over and over by multiple customers.)\nShould the SSN turn out to be genuine, the affected employee should take the following measures:  \n1. Freeze their credit score at the main 3 credit bureaus: Equifax, Transunion and Experian.\n2. Monitor all bank, credit card and insurance statements for fraudulent transactions",
                "ref_id": "ARG-11",
                "related_entities": [],
                "severity": "high",
                "source": "",
                "source_category": "marketplace",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [
                    "employee"
                ],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Executive PII Offered for Sale",
                "type": "compromised_pii"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-28T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [
                    {
                        "id": 254,
                        "mimetype": "image/png",
                        "name": "Argos detection.png"
                    }
                ],
                "category": "attackware",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-27T00:00:23",
                "description": "Argos\u2122 detected a configuration file (\u201cconfig\u201d) and method targeting Quidco, offered for sale on a popular fraudsters\u2019 forum.\nThe config offered by the TA is likely intended to be used on any of the popular \"credential stuffing\" attack tools (like SentryMBA or OpenBullet). Such tools tests stolen credentials (\u201ccombos\u201d) against websites' authentication mechanism; the configuration file navigates the unique characteristics of the targeted site so that the attack can continue longer without getting blocked.\nThe threat actor further offers to supply several users' accounts for testing before purchasing the config, and shares a Telegram account for conact: @husslerj\nIn successful credentials\u2019 stuffing attacks, masses of customers\u2019 accounts can be breached, resulting in a surge of fraudulent transactions.",
                "environment": "Argos Demo",
                "impacts": [
                    "account_takeover",
                    "user_data_compromise",
                    "brand_degradation",
                    "financial_penalties"
                ],
                "iocs": [],
                "modification_date": "2020-12-27T00:00:23",
                "publish_date": "2020-09-13T18:50:00",
                "recommendation": "Cyberint can approach the threat actor using an avatar and attempt to gain additional information on how the config file works and what vulnerabilities it may be exploiting on Quidco's website; we could also try to obtain the already compromised accounts the TA possesses. Upon request, Cyberint can purchase the config on behalf of Quidco.\nIn general, CyberInt recommends Quidco implement anti-automation tools on the login and registration pages of its website.\nIn addition, implementing CAPTCHA or multi-factor authentication mechanisms should block the vast majority of automated attack tools.",
                "ref_id": "ARG-12",
                "related_entities": [],
                "severity": "high",
                "source": null,
                "source_category": "forum",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Quidco"
                ],
                "targeted_vectors": [
                    "customer"
                ],
                "threat_actor": "logicarsenal",
                "ticket_id": null,
                "title": "Credential Stuffing Tool Targeting Company",
                "type": "automated_attack_tools"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "a_record": "104.27.134.172",
                    "detection_reasons": [
                        "url_mentioned_assets_or_twists",
                        "similar_logo_detected"
                    ],
                    "ip_reputation": "unknown",
                    "mx_records": [
                        "77.81.121.210"
                    ],
                    "registrar": "Namecheap Inc.",
                    "site_status": "active",
                    "url": "http://chipotlevouchers.com/index.html",
                    "url_reputation": "malicious",
                    "whois_created_date": 1587643500
                },
                "analysis_report": {
                    "id": 34,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Brand Abusing Website Impersonating Company.pdf"
                },
                "attachments": [],
                "category": "brand",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-24T00:00:23",
                "description": "Cyberint identified a suspicious website abusing Chipotle\u2019s brand name and logo, hosted on the following URL:\nhttp://chipotlevouchers.com/index.html\nWhile the website does not contain any user input form at the moment, within days it may evolve into a fully-realized phishing website, which could target company employees, customers or vendors and steal their PII. Furthermore, the domain is currently available for sale, which could allow anyone to purchase this existing infrastructure.",
                "environment": "Argos Demo",
                "impacts": [
                    "brand_degradation",
                    "customer_churn"
                ],
                "iocs": [],
                "modification_date": "2020-12-24T00:00:23",
                "publish_date": "2020-11-26T13:11:09",
                "recommendation": "Cyberint advises Chipotle to approach the website owner at the address: 1e6cec9b15354d3d95dab5381bc8a364.protect@whoisguard.com and request they remove the brand abusing content from there; should that not yield results, Chipotle may request the website be taken down (DMCA request).\nIt is also recommended to later purchase the domain (UDRP).",
                "ref_id": "ARG-10",
                "related_entities": [],
                "severity": "medium",
                "source": "",
                "source_category": "online_protection",
                "status": "open",
                "tags": [],
                "targeted_brands": [
                    "Chipotle"
                ],
                "targeted_vectors": [
                    "customer"
                ],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Brand Abusing Website Impersonating Company",
                "type": "impersonation"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-23T00:00:23",
                "alert_data": {
                    "domain": "mcdonalds.com"
                },
                "analysis_report": null,
                "attachments": [],
                "category": "vulnerabilities",
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2020-12-23T00:00:23",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-22T00:00:23",
                "description": "Cyberint found that McDonald's main domain, mcdonalds.com, lacks DMARC record, which renders them vulnerable to spoofing.\nDMARC is an email authentication, policy, and reporting protocol, which allows administrators to specify which hosts can send emails on behalf of a given domain.\n\"Spoofable\" domains are often used for:\n1. Phishing campaigns targeting customers, which may cause churn and damage the brand reputation.\n2. Phishing campaigns targeting employees, which might spread malware within the organization's network, as well as access internal information.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "brand_degradation"
                ],
                "iocs": [],
                "modification_date": "2020-12-22T00:00:23",
                "publish_date": "2020-11-23T12:42:20",
                "recommendation": "Cyberint recommends McDonald's configure a DMARC record on its main domain and apply an email security alignment process.",
                "ref_id": "ARG-18",
                "related_entities": [],
                "severity": "high",
                "source": "",
                "source_category": "my_digital_presence",
                "status": "closed",
                "tags": [],
                "targeted_brands": [
                    "McDonald's"
                ],
                "targeted_vectors": [
                    "business",
                    "customer",
                    "employee"
                ],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Missing Company Domain DMARC Records Detected",
                "type": "email_security_issues"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-21T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": {
                    "id": 28,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Company Product Unauthorized Resale.pdf"
                },
                "attachments": [
                    {
                        "id": 253,
                        "mimetype": "image/png",
                        "name": "Snippet from Zambrana's Facebook page.png"
                    }
                ],
                "category": "brand",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-20T00:00:23",
                "description": "Cyberint detected a potential threat actress offering PayMaya cards for sale on Facebook. The TA, Rosie Zambrana, seems to operate through one main Facebook pages:\nhttps://www.facebook.com/Negosyofree/\n\nUnauthorized resale of PayMaya cards may violate the company\u2019s terms of use, resulting in financial loss to PayMaya and brand abuse which could lead to customer churn.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss",
                    "brand_degradation",
                    "customer_churn"
                ],
                "iocs": [],
                "modification_date": "2020-12-20T00:00:23",
                "publish_date": "2020-11-25T16:34:00",
                "recommendation": "Cyberint recommends PayMaya validate whether Zambrana is a legitimate reseller of its cards. If not, the company should remove the brand-abusing content from Facebook and consider taking additional legal measures against the abuser. Upon request, Cyberint can perform the takedown on behalf of PayMaya.",
                "ref_id": "ARG-13",
                "related_entities": [],
                "severity": "medium",
                "source": "facebook.com",
                "source_category": "social_network",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [
                    "Paymaya"
                ],
                "targeted_vectors": [
                    "business"
                ],
                "threat_actor": "@negosyofree",
                "ticket_id": null,
                "title": "Company Product Unauthorized Resale",
                "type": "unauthorized_trading"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "additional_technologies_detected": null,
                    "cves": null,
                    "ip": "69.10.19.249",
                    "port": 23,
                    "port_description": "Telnet is a program that enables to remotely access a machine. The communication passing through telnet is in the form of unencrypted clear text, including user name and passwords used for the remote access.",
                    "service": "Telnet",
                    "service_version": null
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
                "created_date": "2020-12-17T00:00:23",
                "description": "Argos\u2122 detected a potentially exploitable open port on an IP address belonging to IGN. The IP address 69.10.19.249 was identified as part of a netblock that was registered by a company email address.\n\nIn general, open ports may be used by an attacker to perform an initial reconnaissance and scan the organization externally, in order to figure out which ports are open. Some open ports are vulnerable and can pose a risk to the organization; an attacker can exploit these open ports for malicious purposes in order to gain access to the organization.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "financial_penalties"
                ],
                "iocs": [],
                "modification_date": "2020-12-17T00:00:23",
                "publish_date": null,
                "recommendation": "Cyberint advises blocking any use of unnecessary ports. Cyberint recommends IGN the following mitigation steps:\n1. Unnecessary ports should be disabled.\n2. Necessary open ports that do not provide a public service should be enforced for appropriate authentication.",
                "ref_id": "ARG-9",
                "related_entities": [],
                "severity": "medium",
                "source": "",
                "source_category": "my_digital_presence",
                "status": "open",
                "tags": [],
                "targeted_brands": [
                    "IGN"
                ],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Exploitable Port on Company Server Detected",
                "type": "exploitable_ports"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-16T00:00:23",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "phishing",
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2020-12-16T00:00:23",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-15T00:00:23",
                "description": "Cyberint identified a phishing email targeting HSBC employees. The email impersonates as sent from accounts@hsbc.com, while after an analysis of the email header, the sender appears to be atomlink@mcc.krasnoyarsk.su. The message encourages the recipients to open an attachment, a malicious .ace file.\nkrasnoyarsk.su seems to be a legitimate domain, therefore it was presumably abused by the threat actor easily due to it's lack of DMARC and SPF records.\nPhishing email campaigns, if successful, can result in data loss and further proliferation of malware within a company's systems. ",
                "environment": "Argos Demo",
                "impacts": [
                    "brand_degradation",
                    "account_takeover",
                    "user_data_compromise",
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2020-12-15T00:00:23",
                "publish_date": "2020-11-20T03:43:27",
                "recommendation": "Cyberint advises HSBC to verify that no internal data has been exposed in response to the email address; a compromise assessment may be needed.\nIn addition, it is highly recommended to educate the organizations employees against the dangers of phishing attacks targeting them.",
                "ref_id": "ARG-17",
                "related_entities": [],
                "severity": "high",
                "source": "argos.1",
                "source_category": "antivirus_repository",
                "status": "closed",
                "tags": [],
                "targeted_brands": [
                    "HSBC"
                ],
                "targeted_vectors": [
                    "employee"
                ],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Email Phishing Campaign Targeting Company",
                "type": "phishing_email"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-08T00:00:23",
                "alert_data": {
                    "application": null,
                    "csv": {
                        "id": 294,
                        "mimetype": "text/csv",
                        "name": "Credentials Details Template CSV.csv"
                    },
                    "designated_url": "https://signin.ebay.com/ws/ebayisapi.dll"
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2020-12-08T00:00:23",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2020-12-07T00:00:23",
                "description": "CyberInt detected breached credentials of several eBay customers, which were uploaded to an anti-virus repository. The credentials seem to have been obtained through malware, sending user inputs to the operator, and the various credentials were logged in the uploaded .txt files. As such, the file contains users\u2019 credentials not only for ebay.com but for other websites as well.\nBreached customers credentials may be used by Threat Actors to carry out fraudulent transactions on their behalf, exposing eBay to both financial impact and legal claims.",
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
                "modification_date": "2020-12-07T00:00:23",
                "publish_date": "2020-11-30T01:23:51",
                "recommendation": "1. CyberInt recommends enforcing password reset on the compromised accounts.\n2. In addition, CyberInt advises eBay to investigate internally whether any of the accounts have been involved in fraudulent transactions, at least up to the time of detection. In case the accounts were involved in any fraudulent activity, it is recommended to identify and extract relevant IOC\u2019s where possible and monitor them within the company's systems.\n3. To reduce the chance of customer account takeovers by TAs, Cyberint recommends eBay implement MFA and CAPTCHA mechanisms. The former will help set another obstacle for a TA trying to abuse the account, and the latter can help blocking credentials-stuffing tools.",
                "ref_id": "ARG-14",
                "related_entities": [],
                "severity": "high",
                "source": "argos.1",
                "source_category": "antivirus_repository",
                "status": "closed",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Customer Credentials Exposed",
                "type": "compromised_customer_credentials"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2020-12-04T00:00:23",
                "alert_data": {
                    "tool_name": null
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
                "created_date": "2020-12-03T00:00:23",
                "description": "Cyberint identified a report on OpenBugBouny where a security researcher claims to have reported to Barclays on a Cross-Site Scripting (XSS) vulnerability on its website, help.barclaycard.co.uk. The researcher, who goes by the nickname \"Sprachlos\", is well acclaimed on the website and has helped patch over 60 uvlnerabilities.\nThe researcher's profile is https://www.openbugbounty.org/researchers/Sprachlos/ and their email address is goktug__kaya@outlook.com.\n\nAccording to OBB's standards, the researcher may publicly disclose the details of the vulnerability on December 11, 2020.\n\nXSS attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. An attacker can use XSS to send a malicious script to an unsuspecting user. The end user\u2019s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2020-12-03T00:00:23",
                "publish_date": "2020-11-11T19:15:00",
                "recommendation": "Barclays should check internally whether a report on a vulnerability on its website has been made over the past few days. If so, Barclays should operate to patch the vulnerability and mitigate the issue before it is explicitly published.\nIn case no such report is identified, it is recommended to approach the researcher Sprachlos directly through the email address they had supplied of via OpenBugBounty, and collaborate with them for swift and effective remediation of the vulnerability.",
                "ref_id": "ARG-7",
                "related_entities": [],
                "severity": "low",
                "source": "openbugbounty.org",
                "source_category": "deface_site",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "Sprachlos",
                "ticket_id": null,
                "title": "Potentially Exploitable Web Application Vulnerability Detected",
                "type": "website_vulnerabilities"
            },
            {
                "acknowledged_by": {
                    "email": "hadas@cyberint.com"
                },
                "acknowledged_date": "2020-11-30T13:20:20",
                "alert_data": {
                    "csv": {
                        "id": 161,
                        "mimetype": "text/csv",
                        "name": "Credentials Details CSV.csv"
                    },
                    "domain": "maindomain.com",
                    "total_credentials": 99,
                    "total_first_seen": 30
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:46:05",
                "description": "Argos detected compromised credentials of employees which were shared online.\n\nIn May 2020, the online marketplace for independent artists Minted suffered a data breach that exposed 4.4M unique customer records subsequently sold on a dark web marketplace. The exposed data also included names, physical addresses, phone numbers and passwords stored as bcrypt hashes. The data was provided to HIBP by dehashed.com.\n\nCompromised credentials of employees can be utilized by Threat Actors in attempts to access internal systems and information of the company.\n\nIn addition, as users often reuse their passwords among several online platforms, such breaches may cause the disclosure of the employee accounts credentials of the involved employees. Compromised credentials of employees can be utilized by Threat Actors in attempts to access to internal systems and information of the company.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "account_takeover"
                ],
                "iocs": [],
                "modification_date": "2020-11-30T13:23:20",
                "publish_date": null,
                "recommendation": "Cyberint recommends to check whether the accounts are valid and belong to current employees. If so, the employees should be informed, and the passwords should be reset immediately.\n\nIn general, employees should be instructed not to use their organizational credentials for personal online activities and platforms.",
                "ref_id": "ADS10-10",
                "related_entities": [],
                "severity": "very_high",
                "source": "blogspot",
                "source_category": "my_digital_presence",
                "status": "acknowledged",
                "tags": [
                    "Finance Team",
                    "Sensitive Information"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Employee Corporate Credentials Exposed",
                "type": "compromised_employee_credentials"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "a_record": "129.146.184.83",
                    "detection_reasons": null,
                    "has_ssl_certificate": false,
                    "ip_reputation": "malicious",
                    "mx_records": null,
                    "nameservers": null,
                    "registrant_email": null,
                    "registrant_name": null,
                    "registrar": "NameSilo, LLC",
                    "requests_user_details": true,
                    "screenshot": {
                        "id": 159,
                        "mimetype": "image/png",
                        "name": "Argos Screenshot of the Phishing Website.png"
                    },
                    "site_status": null,
                    "url": "http://supportcenter-ee.com/banks/bank.barclays.co.uk",
                    "url_reputation": null,
                    "whois_created_date": "2020-10-06T11:46:00+00:00",
                    "whois_record": null
                },
                "analysis_report": {
                    "id": 16,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Active Phishing Website Targeting Company.pdf"
                },
                "attachments": [
                    {
                        "id": 158,
                        "mimetype": "image/png",
                        "name": "Forensic Canvas Investigation of the Phishing Website.png"
                    }
                ],
                "category": "phishing",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:54:07",
                "description": "CyberInt detected an active phishing website impersonating the main login page while abusing the brand\u2019s name, logo and photos.\nThe website contains login, registration and checkout forms, where unsuspecting victims could be lured to fill in their PII, credentials and payment details.\nPhishing websites such as the above are often used by attackers to obtain users' credentials and PII. This information can be utilized to take over customers' accounts, causing customer churn and damage to the brand's reputation.",
                "environment": "Argos Demo S 10",
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
                        "value": "supportcenter-ee.com"
                    },
                    {
                        "type": "ip",
                        "value": "129.146.184.83"
                    },
                    {
                        "type": "url",
                        "value": "http://supportcenter-ee.com/banks/bank.barclays.co.uk"
                    }
                ],
                "modification_date": "2020-11-23T16:00:09",
                "publish_date": null,
                "recommendation": "CyberInt recommends to take down the site; upon request, CyberInt can submit the take down request on behalf of the company.",
                "ref_id": "ADS10-11",
                "related_entities": [],
                "severity": "very_high",
                "source": "",
                "source_category": "online_protection",
                "status": "open",
                "tags": [
                    "Finance Team"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Active Phishing Website Targeting Company",
                "type": "phishing_website"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "a_record": "69.163.128.0",
                    "has_ssl_certificate": false,
                    "ip_reputation": "malicious",
                    "nameservers": [
                        "NS3.DREAMHOST.COM",
                        "NS12.DREAMHOST.COM",
                        "NS1.DREAMHOST.COM"
                    ],
                    "registrar": "DreamHost, LLC",
                    "requests_user_details": true,
                    "site_status": "active",
                    "url": "https://www.zonaensegura1.bn-acceso-web.com/",
                    "url_reputation": "malicious",
                    "whois_created_date": 1605564000,
                    "whois_record": "   Domain Name: BN-ACCESO-WEB.COM\n   Registry Domain ID: 2561654023_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.dreamhost.com\n   Registrar URL: http://www.DreamHost.com\n   Updated Date: 2020-09-23T20:08:57Z\n   Creation Date: 2020-09-23T20:08:57Z\n   Registry Expiry Date: 2021-09-23T20:08:57Z\n   Registrar: DreamHost, LLC\n   Registrar IANA ID: 431\n   Registrar Abuse Contact Email:\n   Registrar Abuse Contact Phone:\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Name Server: NS1.DREAMHOST.COM\n   Name Server: NS2.DREAMHOST.COM\n   Name Server: NS3.DREAMHOST.COM\n   DNSSEC: unsigned"
                },
                "analysis_report": null,
                "attachments": [],
                "category": "phishing",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:12:44",
                "description": "CyberInt detected an active phishing website impersonating the login page while abusing the brand\u2019s name, logo and photos.\nThe website contains login, registration and checkout forms, where unsuspecting victims could be lured to fill in their PII, credentials and payment details.\nPhishing websites such as the above are often used by attackers to obtain users' credentials and PII. This information can be utilized to take over customers' accounts, causing customer churn and damage to the brand's reputation.",
                "environment": "Argos Demo S 10",
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
                        "value": "bn-acceso-web.com"
                    },
                    {
                        "type": "ip",
                        "value": "69.163.128.0"
                    }
                ],
                "modification_date": "2020-11-19T12:57:16",
                "publish_date": null,
                "recommendation": "CyberInt recommends to take down the site; upon request, CyberInt can submit the take down request on behalf of the company.",
                "ref_id": "ADS10-1",
                "related_entities": [],
                "severity": "very_high",
                "source": "Phishing Detection",
                "source_category": "online_protection",
                "status": "open",
                "tags": [
                    "Phishing",
                    "Phishing Website"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Active Phishing Website Targeting Company",
                "type": "phishing_website"
            },
            {
                "acknowledged_by": {
                    "email": "hadas@cyberint.com"
                },
                "acknowledged_date": "2020-11-19T09:57:51",
                "alert_data": {
                    "author_email_address": "aaronmarks@gmail.com",
                    "code_leak_sample": "<Sample code>",
                    "exposed_code_link": "https://www.heypsasteit.com/clip/0iv213214"
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:27:59",
                "description": "Argos detected configuration code publicly available online. The code was detected as internal according to several indicators. The code was pasted on November 6, 2020 and uploaded by an employee who has access to the information.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "competitive_advantage_loss"
                ],
                "iocs": [],
                "modification_date": "2020-11-19T09:57:51",
                "publish_date": null,
                "recommendation": "Cyberint recommends to check whether the code includes sensitive internal information. If so, it is recommended to approach the hosting provider of the repository and request to remove the sensitive content from the website. Upon request, Cyberint can request the takedown of the content.\n\nAdditionally, it is recommended to raise employees' awareness regarding the risks of internal code exposure.",
                "ref_id": "ADS10-6",
                "related_entities": [],
                "severity": "low",
                "source": "",
                "source_category": "code_repository",
                "status": "acknowledged",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Source Code Exposed",
                "type": "internal_information_disclosure"
            },
            {
                "acknowledged_by": {
                    "email": "hadas@cyberint.com"
                },
                "acknowledged_date": "2020-11-19T09:57:20",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "phishing",
                "closed_by": {
                    "email": "hadas@cyberint.com"
                },
                "closure_date": "2020-11-19T09:57:20",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:59:59",
                "description": "CyberInt detected an phishing email targeting employees while abusing the brand\u2019s name, logo and photos.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "brand_degradation",
                    "account_takeover",
                    "user_data_compromise",
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2020-11-19T09:57:20",
                "publish_date": null,
                "recommendation": "CyberInt recommends to track the sender and block any related IOCs.",
                "ref_id": "ADS10-12",
                "related_entities": [],
                "severity": "high",
                "source": "",
                "source_category": "code_repository",
                "status": "closed",
                "tags": [
                    "Credentials",
                    "Data Dump",
                    "Sensitive Information"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Email Phishing Campaign Targeting Company",
                "type": "phishing_email"
            },
            {
                "acknowledged_by": {
                    "email": "hadas@cyberint.com"
                },
                "acknowledged_date": "2020-11-18T15:13:14",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": {
                    "email": "hadas@cyberint.com"
                },
                "closure_date": "2020-11-18T15:13:14",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:24:47",
                "description": "Argos\u2122 detected emails sent from employees\u2019 mailbox to vendor, which were scanned to an anti-virus repository. The mails are labeled as \u201cauto generated\". ",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "competitive_advantage_loss"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T15:13:14",
                "publish_date": null,
                "recommendation": "Cyberint recommends to inform the affected employees that their files and email communications have been publicly disclosed. Additionally, Cyberint recommends to contact the vendor and verify which side of the correspondence is responsible for the scanning. It is advised raising employees\u2019 awareness regarding sharing of internal files, as it can lead to social engineering and fraud attempts.\nUpon request, Cyberint can have the files removed at their source, in order to prevent malicious usage of the information it contains",
                "ref_id": "ADS10-5",
                "related_entities": [],
                "severity": "medium",
                "source": null,
                "source_category": "antivirus_repository",
                "status": "closed",
                "tags": [
                    "Sensitive Information",
                    "Vendor Risk"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Internal Email Correspondence Exposed",
                "type": "internal_information_disclosure"
            },
            {
                "acknowledged_by": {
                    "email": "hadas@cyberint.com"
                },
                "acknowledged_date": "2020-11-18T15:12:39",
                "alert_data": {
                    "csv": {
                        "id": 156,
                        "mimetype": "text/csv",
                        "name": "Domains Details CSV.csv"
                    },
                    "number_of_domains": 26
                },
                "analysis_report": {
                    "id": 18,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Active Phishing Website Targeting Company.pdf"
                },
                "attachments": [],
                "category": "phishing",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:35:57",
                "description": "Argos\u2122 has detected recently registered lookalike domains which highly resembles the main domain name pattern. ",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "brand_degradation",
                    "account_takeover",
                    "user_data_compromise",
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T15:12:39",
                "publish_date": null,
                "recommendation": "Cyberint recommends to take these steps:\n\n1. Take the domains down by filing a UDRP legal complaint due to trademark abuse.\n2. Once suspended, consider purchasing the domains to prevent any future phishing attempts.",
                "ref_id": "ADS10-8",
                "related_entities": [],
                "severity": "medium",
                "source": "",
                "source_category": "online_protection",
                "status": "acknowledged",
                "tags": [
                    "Phishing",
                    "Squatting"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Look-Alike Domain Potentially Targeting Company",
                "type": "lookalike_domain"
            },
            {
                "acknowledged_by": {
                    "email": "dorin@cyberint.com"
                },
                "acknowledged_date": "2020-11-18T12:58:37",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "vulnerabilities",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 30,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:34:15",
                "description": "Argos\u2122 has detected an XSS vulnerability on the domain, which was reported to openbugbounty.org on October 9, 2020 by a security researcher. According to OpenBugBounty, the details were reported on October 9, 2020. It was also mentioned that the public disclosure of the vulnerability\u2019s details is scheduled for January 7, 2021.\n\nXSS refers to client-side code injection attack wherein an attacker can execute malicious scripts into a legitimate website. By leveraging XSS, an attacker would exploit a vulnerability within a website that the victim would visit, essentially using the vulnerable website as a vehicle to deliver a malicious script to the victim\u2019s browser.\n\nFor an XSS attack to take place, the vulnerable website needs to directly include user input in its pages. An attacker can then insert a string that will be used within the web page and treated as code by the victim\u2019s browser.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T12:58:37",
                "publish_date": null,
                "recommendation": "Cyberint recommends to investigate the full vulnerability report sent to it and mitigate the issue within the private disclosure time frame. Upon further agreement, Cyberint\u2019s penetration testing team can operate to examine the website from a technical perspective.\n\nIn order to prevent any future exploitation of XSS vulnerabilities, Cyberint advises to validate all user-controlled data including server-side and client-side, and to assure that all user data be encoded when returned in the HTML page.",
                "ref_id": "ADS10-7",
                "related_entities": [],
                "severity": "very_high",
                "source": "openbugbounty.org",
                "source_category": "code_repository",
                "status": "acknowledged",
                "tags": [
                    "Vulnerabilities",
                    "XSS"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "ravisdp1004",
                "ticket_id": null,
                "title": "Web Application Vulnerability Exploit Published",
                "type": "website_vulnerabilities"
            },
            {
                "acknowledged_by": {
                    "email": "dorin@cyberint.com"
                },
                "acknowledged_date": "2020-11-18T12:58:33",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": {
                    "id": 17,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Active Phishing Website Targeting Company.pdf"
                },
                "attachments": [],
                "category": "phishing",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:22:06",
                "description": "Argos\u2122 detected a phishing campaign for emails credentials hosted on the following domain:\n- https://at.com.bxr/.../upgrade/index.php?\n\nThe URL hosts an email login interface titled \"Email Security : For\", while the rest of the title is filled with the victim's email address. The page is usually detected when the victim's address is already inserted in the Username field. This happens automatically when the address is added to the URL, as shown in the example below taken from Argos\u2122 original detection.\n\nIt is assumed that the page was generated using a phishing kit and that the campaign\u2019s purpose is obtaining credentials\nof different email accounts. It is believed that the TA behinds it generates the URL, adding a different address each time.\n\nA platform through which the victims are exposed to the campaign\u2019s URL was not detected.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "brand_degradation",
                    "account_takeover",
                    "user_data_compromise"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T12:58:33",
                "publish_date": null,
                "recommendation": "Cyberint recommends to block employees' access to the reported URL.\nIn case the employee cooperated and shared their password, they should be instructed to reset their\npasswords among all online platforms.\nAdditionally, it is advised to check whether any suspicious activity related to the compromised account can be detected.\nIt may be advisable to raise the employees\u2019 awareness regarding the campaign and instruct them to use their organizational\ncredentials only on official designated platforms.",
                "ref_id": "ADS10-4",
                "related_entities": [],
                "severity": "high",
                "source": "",
                "source_category": "my_digital_presence",
                "status": "acknowledged",
                "tags": [
                    "Phishing",
                    "Phishing Kit"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Phishing Kit Targeting Company",
                "type": "phishing_kit"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "csv": {
                        "id": 153,
                        "mimetype": "text/csv",
                        "name": "Payment Cards Details CSV.csv"
                    },
                    "total_first_seen": 1,
                    "total_payment_cards": 1
                },
                "analysis_report": null,
                "attachments": [],
                "category": "data",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:15:05",
                "description": "Compromised payment cards of customers have been detected. Compromised payment card details, especially when combined with exposed PII, can be abused by threat actors for illegitimate and fraudulent activities.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "revenue_loss",
                    "brand_degradation",
                    "customer_churn",
                    "financial_penalties"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T12:57:15",
                "publish_date": null,
                "recommendation": "Best practices include verifying if the payment cards are genuine and active. Upon confirmation, it is recommended to cancel the payment cards to prevent their abuse and informing the card holders of the cancellation.",
                "ref_id": "ADS10-2",
                "related_entities": [],
                "severity": "high",
                "source": "crackingpro.com",
                "source_category": "darknet",
                "status": "open",
                "tags": [
                    "ATM Scam"
                ],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Company Customer Payment Cards Exposed",
                "type": "compromised_payment_cards"
            },
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "domain": "domaindemo.com"
                },
                "analysis_report": null,
                "attachments": [],
                "category": "vulnerabilities",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "dorin@cyberint.com"
                },
                "created_date": "2020-11-18T12:38:47",
                "description": "Argos\u2122 has detected the following domain which has not had DMARC records published for it.\n\nDMARC (Domain-based Message Authentication, Reporting & Conformance) is an email authentication, policy, and reporting protocol. It allows administrators to specify which hosts can send emails on behalf of a given domain. Domains lacking in valid DMARC records can be used to send out forged email messages to Hellman & Friedman customers and employees. This could lead to the distribution of spam and malware as part of phishing and social engineering campaigns.",
                "environment": "Argos Demo S 10",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "brand_degradation"
                ],
                "iocs": [],
                "modification_date": "2020-11-18T12:38:47",
                "publish_date": null,
                "recommendation": "Cyberint recommends to publish valid DMARC records. This practice is recommended even if the domain is not used for sending out emails, due to the possibility of spoofing by threat actors.",
                "ref_id": "ADS10-9",
                "related_entities": [],
                "severity": "medium",
                "source": "",
                "source_category": "search_engine",
                "status": "open",
                "tags": [],
                "targeted_brands": [],
                "targeted_vectors": [],
                "threat_actor": "",
                "ticket_id": null,
                "title": "Missing Company Domain DMARC Records Detected",
                "type": "email_security_issues"
            }
        ]
    }
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

