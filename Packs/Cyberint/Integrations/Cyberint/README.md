Cyberint provides intelligence-driven digital risk protection. This integration will help your enterprise effectively consume actionable cyber alerts to increase your security posture.
This integration was integrated and tested with version v1 of cyberint

## Configure cyberint in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| Cyberint Access Token | Cyberint API access token. | True |
| Cyberint API Environment | Cyberint environment on which the services run \(i.e http://\{environment\}.cyberint.io/...\) | True |
| Fetch incidents |  | False |
| Create an incident per CSV record | An incident will be created with the originated Alert details per CSV file record | False |
| Fetch Severity | Severities to fetch. If none is chosen, all severity levels will be returned. | False |
| Fetch Status | Statuses to fetch. If none is chosen, all statuses will be returned. | False |
| Fetch Environment | Environments to fetch \(comma separated\). If empty, all available environments will be returned. | False |
| Fetch Types | Types to fetch. If none is chosen, all types will be returned. | False |
| Fetch Limit | Max number of alerts per fetch. Defaults to  the minimum 10, max is 100. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberint-alerts-fetch

***
List alerts according to parameters


#### Base Command

`cyberint-alerts-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to return. Default is 1. Default is 1. | Optional |
| page_size | Number of results in a page. Default is 10. Must be between 10 and 100. Default is 10. | Optional |
| created_date_from | ISO-Formatted creation date. Get alerts created since this date (YYYY-MM-DDTHH:MM:SSZ). | Optional |
| created_date_to | ISO-Formatted creation date. Get alerts created before this date (YYYY-MM-DDTHH:MM:SSZ). | Optional |
| created_date_range | You can specify a date range to search for from the current time. (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) instead of a start/end time. created_date_range will overwrite created_date. | Optional |
| updated_date_from | ISO-Formatted creation date. Get alerts updated since this date (YYYY-MM-DDTHH:MM:SSZ). | Optional |
| updated_date_to | ISO-Formatted creation date. Get alerts updated before this date (YYYY-MM-DDTHH:MM:SSZ). | Optional |
| updated_date_range | You can specify a date range to search for from the current time. (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) instead of a start/end time. updated_date_range will overwrite updated_date. | Optional |
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
| Cyberint.Alert.acknowledged_date | Date | Date in which the alert was acknowledged. |
| Cyberint.Alert.acknowledged_by.email | String | User which has acknowledged the alert. |
| Cyberint.Alert.publish_date | Date | Date in which the alert was published. |
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
| Cyberint.Alert.alert_data.csv.username | String | Username of an account found in a report CSV. |
| Cyberint.Alert.alert_data.csv.password | String | Password of an account found in a report CSV. |
| Cyberint.Alert.alert_data.email | String | Email of an account related to an event. |
| Cyberint.Alert.alert_data.author_email_address | String | Email of an author related to an event. |
| Cyberint.Alert.alert_data.repository_name | String | Repository name related to an event. |
| Cyberint.Alert.alert_data.mail_server | String | Mail server related to an event. |
| Cyberint.Alert.alert_data.blacklist_repository | String | Blacklist repository name related to an event. |
| Cyberint.Alert.alert_data.screenshot | String | Screenshot related to an event. |
| Cyberint.Alert.alert_data.spf_records | String | SPF records if applicable to the event. |
| Cyberint.Alert.alert_data.dmarc_record | String | DMARC records if applicable to the event. |
| Cyberint.Alert.alert_data.storage_link | String | Storage link if applicable to the event. |
| Cyberint.Alert.alert_data.interface_type | String | Interface type if applicable to the event. |
| Cyberint.Alert.alert_data.vulnerable_cname_record | String | Vulnerable CName record if applicable to the event. |
| Cyberint.Alert.ioc.type | String | Type of IOC related to the alert. |
| Cyberint.Alert.ioc.value | String | Value of the IOC related to the alert. |
| Cyberint.Alert.ticket_id | String | Ticket ID of the alert. |
| Cyberint.Alert.threat_actor | String | Actor to the threat related to the alert. |
| Cyberint.Alert.modification_date | Date | Date the alert was last modified. |
| Cyberint.Alert.closure_date | String | Date the alert was closed. |
| Cyberint.Alert.closed_by.email | String | User which has closed the alert. |
| Cyberint.Alert.closure_reason | String | Reason for closing the alert. |
| Cyberint.Alert.description | String | Description of the alert. |
| Cyberint.Alert.recommendation | String | Recommendation for the alert |
| Cyberint.Alert.tags | String | Tags related to the alert |
| Cyberint.Alert.attachments | String | Attachments related to the alert |


#### Command Example

```!cyberint-alerts-fetch page="1" page_size="100" created_date_range="7 days"```

#### Context Example

```json
{
    "Cyberint": {
        "Alert": [
            {
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "csv": [
                        {
                            "password": "Carroza1947",
                            "username": "cabuneta47"
                        }
                    ],
                    "hashed_attachment_content_csv": "e0857ec24c39125644e1db0c3d04de110b75ff3e34824a9a890fff47f2d9f461",
                    "total_credentials": 1
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
                "created_date": "2021-04-12T00:01:12",
                "csv_data": {
                    "csv_id": 1981,
                    "name": "Company Customer Credentials Exposed.csv"
                },
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
                "modification_date": "2021-04-12T00:01:12",
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
                "acknowledged_by": null,
                "acknowledged_date": null,
                "alert_data": {
                    "a_record": "129.146.184.83",
                    "detection_reasons": [
                        "similar_logo_detected",
                        "url_mentioned_assets_or_twists"
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
                    "site_status": "not_active",
                    "url": "http://supportcenter-ee.com/banks/bank.barclays.co.uk",
                    "url_reputation": "malicious",
                    "whois_created_date": null,
                    "whois_record": null
                },
                "analysis_report": {
                    "id": 104,
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
                "created_date": "2021-04-12T00:01:12",
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
                "modification_date": "2021-04-12T00:01:12",
                "publish_date": "2020-09-02T00:06:49",
                "recommendation": "CyberInt recommends reporting the website to Google Safe Browsing, so that upon attempting to browse to the phishing website, a warning would be triggered on the victim's browser, informing them of the danger and suggesting they don't enter.\nBarclays is also advised to take down the site; upon request, Cyberint can carry out both the report and the take down request on behalf of Barclays.",
                "ref_id": "ARG-4",
                "related_entities": [],
                "severity": "very_high",
                "source": "",
                "source_category": "online_protection",
                "status": "open",
                "tags": [
                    "Phishing Kit",
                    "Finance"
                ],
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
                "created_date": "2021-04-12T00:01:12",
                "description": "CyberInt discovered a misconfiguration on an HSBC subdomain which exposes it to takeover.\nCurrently, the domain names refer to the CNAME records listed above. However, those CNAME records are no longer owned by Target, and they may have expired. This situation allows others to obtain the record, and practically get access to the HSBC subdomain.\n\nTaking over HSBC subdomains could be used to conduct complex phishing attack on the organization's employees and customers, as well potentially hijack sessions of logged-in users in any service using the vulnerable domains.",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "unauthorized_access",
                    "account_takeover"
                ],
                "iocs": [],
                "modification_date": "2021-04-12T00:01:12",
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
                "acknowledged_date": "2021-04-09T15:47:12",
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
                "created_date": "2021-04-08T00:01:12",
                "description": "CyberInt detected exposed credentials and RSA private key of a developer working with a Barclays API, which were published on a Github repository.\nThese credentials can allow an attacker to gain access to sensitive internal information of Barclays.\n",
                "environment": "Argos Demo",
                "impacts": [
                    "data_compromise",
                    "competitive_advantage_loss"
                ],
                "iocs": [],
                "modification_date": "2021-04-08T00:01:12",
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
                "acknowledged_date": "2021-04-09T15:47:12",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": {
                    "id": 106,
                    "mimetype": "application/pdf",
                    "name": "Expert Analysis - Fraudulent Refund Services Targeting Company.pdf"
                },
                "attachments": [],
                "category": "fraud",
                "closed_by": null,
                "closure_date": null,
                "closure_reason": null,
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-04-08T00:01:12",
                "description": "Argos detected a thread published in a fraudsters' forum, concerning fraudulent refund services against various US retailers, including Nike and Costco. \nThe thread contains vouches from dozens of satisfied customers, who used the TA's refunding service.\n\nRefund fraud refers to the process of abusing a company\u2019s refund policy using social engineering techniques to receive a partial or complete refund on an order. Threat actors who offer this service are usually paid 7-20% of the order\u2019s value, and usually require a minimum of $15 per order to start the process. Given the commonness of the service, refund fraud may result in significant financial loss to organizations.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss"
                ],
                "iocs": [],
                "modification_date": "2021-04-08T00:01:12",
                "publish_date": "2020-11-16T09:09:44",
                "recommendation": "CyberInt advises Costco to search their systems for refunds accepted in recent months, and try to cross-reference similarities and IOCs between the transactions. Such investigation can help identify potentially fraudulent patterns.\nAdditionally, as part of a full engagement, CyberInt can further investigate the TA in order to gain more information about their methods.",
                "ref_id": "ARG-6",
                "related_entities": [],
                "severity": "medium",
                "source": "nulled.to",
                "source_category": "forum",
                "status": "acknowledged",
                "tags": [
                    "Retail"
                ],
                "targeted_brands": [
                    "Target"
                ],
                "targeted_vectors": [
                    "business"
                ],
                "threat_actor": "BigBoi",
                "ticket_id": null,
                "title": "Fraudulent Refund Services Targeting Company",
                "type": "refund_fraud"
            },
            {
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-04-09T05:47:12",
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
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2021-04-11T10:19:12",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-04-08T00:01:12",
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
                "modification_date": "2021-04-08T00:01:12",
                "publish_date": "2020-11-29T05:00:38",
                "recommendation": "CyberInt recommends Barclays take down the site; upon request, CyberInt can submit the take down request on behalf of the bank.",
                "ref_id": "ARG-15",
                "related_entities": [],
                "severity": "very_high",
                "source": "",
                "source_category": "online_protection",
                "status": "closed",
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
                "acknowledged_by": {
                    "email": "avital@cyberint.com"
                },
                "acknowledged_date": "2021-04-09T05:47:12",
                "alert_data": {
                    "tool_name": null
                },
                "analysis_report": null,
                "attachments": [],
                "category": "fraud",
                "closed_by": {
                    "email": "avital@cyberint.com"
                },
                "closure_date": "2021-04-11T10:19:12",
                "closure_reason": "resolved",
                "confidence": 100,
                "created_by": {
                    "email": "avital@cyberint.com"
                },
                "created_date": "2021-04-08T00:01:12",
                "description": "Argos detected a thread published in a fraudsters' forum, concerning fraudulent refund services against various US retailers, including Apple, Sam's Club and more.\nThe thread contains vouches from dozens of satisfied customers, who used the TA's refunding service.\n\nRefund fraud refers to the process of abusing a company\u2019s refund policy using social engineering techniques to receive a partial or complete refund on an order. Threat actors who offer this service are usually paid 7-20% of the order\u2019s value, and usually require a minimum of $15 per order to start the process. Given the commonness of the service, refund fraud may result in significant financial loss to organizations.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss"
                ],
                "iocs": [],
                "modification_date": "2021-04-08T00:01:12",
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
                "acknowledged_date": "2021-04-09T00:01:12",
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
                "created_date": "2021-04-06T00:01:12",
                "description": "Cyberint detected payment cards belonging to customers being offered for sale online for 18$. The cards' information, published by a threat actors named Dolly, includes the BIN number of the card, expiration date and CVV digits as well as some PII of the card owner.\nCompromised payment card details, especially when combined with exposed PII, can be purchased and abused by threat actors for illegitimate and fraudulent activities. Those, in turn, will result in chargeback costs for the bank and potential customer churn.",
                "environment": "Argos Demo",
                "impacts": [
                    "revenue_loss",
                    "brand_degradation",
                    "customer_churn",
                    "financial_penalties"
                ],
                "iocs": [],
                "modification_date": "2021-04-06T00:01:12",
                "publish_date": "2020-08-17T00:00:00",
                "recommendation": "Cyberint recommends Joe purchase one of the payment cards in order to then verify validity. Upon confirmation, Cyberint recommends cancelling the payment cards in order to prevent their abuse, and informing the card holders of the cancellation.\nCyberint can make the test purchase on behalf of the bank.",
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
                "acknowledged_date": "2021-04-09T00:01:12",
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
                "created_date": "2021-04-06T00:01:12",
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
                "modification_date": "2021-04-06T00:01:12",
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
            }
        ]
    }
}
```

#### Human Readable Output

>Total alerts: 9
>Current page: 1

>### CyberInt alerts:

>|ref_id|title|status|severity|created_date|type|environment|
>|---|---|---|---|---|---|---|
>| ARG-3 | Company Customer Credentials Exposed | open | high | 2021-04-12T00:01:12 | compromised_customer_credentials | Argos Demo |
>| ARG-4 | Active Phishing Website Targeting Company | open | very_high | 2021-04-12T00:01:12 | phishing_website | Argos Demo |
>| ARG-8 | Company Subdomain Vulnerable to Hijacking | open | very_high | 2021-04-12T00:01:12 | hijackable_subdomains | Argos Demo |
>| ARG-2 | Company Source Code Exposed | acknowledged | very_high | 2021-04-08T00:01:12 | internal_information_disclosure | Argos Demo |
>| ARG-6 | Fraudulent Refund Services Targeting Company | acknowledged | medium | 2021-04-08T00:01:12 | refund_fraud | Argos Demo |
>| ARG-15 | Active Phishing Website Targeting Company | closed | very_high | 2021-04-08T00:01:12 | phishing_website | Argos Demo |
>| ARG-16 | Fraudulent Refund Services Targeting Company | closed | medium | 2021-04-08T00:01:12 | refund_fraud | Argos Demo |
>| ARG-1 | Company Customer Payment Cards Offered for Sale | acknowledged | medium | 2021-04-06T00:01:12 | compromised_payment_cards | Argos Demo |
>| ARG-5 | Company Customer Credentials Offered for Sale | acknowledged | medium | 2021-04-06T00:01:12 | compromised_customer_credentials | Argos Demo |


### cyberint-alerts-status-update

***
Update the status of one or more alerts.


#### Base Command

`cyberint-alerts-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ref_ids | Reference IDs for the alert(s). | Required |
| status | Desired status to update for the alert(s). Possible values are: open, acknowledged, closed. | Required |
| closure_reason | Reason for updating the alerts status to closed. Required when status is closed. Possible values are: resolved, irrelevant, false_positive. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberint.Alert.ref_id | String | Reference ID of the alert. |
| Cyberint.Alert.status | String | Status of the alert. |
| Cyberint.Alert.closure_reason | String | Reason for updating the alert to closed if closed. |


#### Command Example

```!cyberint-alerts-status-update alert_ref_ids="ADS10-3" status="acknowledged"```

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

>### CyberInt alerts updated information:

>|ref_id|status|
>|---|---|
>| ADS10-3 | acknowledged |


### cyberint-alerts-get-attachment

***
Get alert attachment.


#### Base Command

`cyberint-alerts-get-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ref_id | Reference ID of the alert. | Required |
| attachment_id | Attachment ID. | Required |
| attachment_name | Attachment file name. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.MD5 | String | The MD5 hash of the file. |
| File.Extension | String | The file extension. |


#### Command Example

```!cyberint-alerts-get-attachment alert_ref_id="ARG-3" attachment_id="18" attachment_name="Compromised Account As Appears On Argos.png"```

#### Context Example

```json
{
    "File": {
        "EntryID": "1071@01674117-479d-4af5-89d6-cbf4584ae0e8",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "1bcab0883881e84802d859baea3810f5",
        "Name": "Compromised Account As Appears On Argos.png",
        "SHA1": "a232483be0ff6f912a2367e96c399dc311c8cfb1",
        "SHA256": "635d7c00bb5f11f13b2fd2cab1b352c45f758467b7a00fed13e2d4669c83f35d",
        "SHA512": "72128496b305dbd9e2e916bb92feea6314cfc9990da0ffbdf6364c8676ea5b681ab01c9f5ee97b9e5ec22999bf5795ed3424517ffbf6f0ad8455a4c2cce5e60c",
        "SSDeep": "768:FYCj7zNaryIJPjoLRRQeD6hFvqvWOu5sUzdVL9EfNj0Aof:FpnNKyMPjoLzQE+DHVhoNj1of",
        "Size": 35665,
        "Type": "PNG image data, 711 x 531, 8-bit/color RGB, non-interlaced"
    }
}
```




### cyberint-alerts-analysis-report

***
Get alert analysis report.


#### Base Command

`cyberint-alerts-analysis-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ref_id | Reference ID of the alert. | Required |
| report_name | Analysis report file name. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.MD5 | String | The MD5 hash of the file. |
| File.Extension | String | The file extension. |


#### Command Example

```!cyberint-alerts-analysis-report alert_ref_id="ARG-4" report_name="Expert Analysis - Active Phishing Website Targeting Company.pdf"```

#### Context Example

```json
{
    "File": {
        "EntryID": "1075@01674117-479d-4af5-89d6-cbf4584ae0e8",
        "Extension": "pdf",
        "Info": "application/pdf",
        "MD5": "6786164b6cfb00c54622b2f974dc53f4",
        "Name": "Expert Analysis - Active Phishing Website Targeting Company.pdf",
        "SHA1": "e7a6ceca8a216ba81527d423cf50d0dbf01bce5f",
        "SHA256": "1890ad48da918d3f416a14b2fd22c1ca144cc5b47da4835c32e1341e0e2e880a",
        "SHA512": "8228a78cc0a0411436b6086801654fdf2bff9a25bdf3bdbdec16692bd2fe6b4edf99012af68559900f6680456e1aaa84179c38df192adc866595298ebbc4b767",
        "SSDeep": "6144:mMI1j8kEaLJviZ1dK80NyPUqZq/32pSjQNu1KwDaacfurJgT2vJWIp+YGh:mMIaa1UTLYVYuS2vJ3p+Lh",
        "Size": 279550,
        "Type": "PDF document, version 1.3"
    }
}
```