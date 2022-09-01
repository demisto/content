# Configure SecurityScorecard on Cortex XSOAR

Provides scorecards for domains.

## Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SecurityScorecard.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | SecurityScorecard API Base URL |  | True |
    | Username/Email | The SecurityScorecard username/email. | True |
    | API Token |  | True |
    | Incidents Fetch Interval | Scheduled interval for alert fetching.| False |
    | Fetch Limit | Maximum number of alerts per fetch. The maximum is 50. | False|
    | First fetch | First fetch query `<number> <time unit>`, e.g. `7 days`| False|

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation,
or in a playbook.
After you successfully execute a command,
a DBot message appears in the War Room with the command details.

### securityscorecard-portfolios-list

***
List all Portfolios

#### Base Command

`securityscorecard-portfolios-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the amount of Portfolios to return. Defaults to 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Portfolio.id | String | Portfolio ID |
| SecurityScorecard.Portfolio.name | String | Portfolio name |
| SecurityScorecard.Portfolio.description | String | Portfolio description |
| SecurityScorecard.Portfolio.privacy | String | Portfolio privacy. |
| SecurityScorecard.Portfolio.read_only | Boolean | Whether the portfolio is read-only.|

#### Command Example

```!securityscorecard-portfolios-list limit=3```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Portfolio": [
            {
                "created_at": "2021-06-14T17:07:14.266Z",
                "id": "60c78cc2d63162001a68c2b8",
                "name": "username@domain.com",
                "privacy": "private",
                "read_only": true
            },
            {
                "id": "60b7e8ea8242c000b8000000",
                "name": "Company Portfolio",
                "privacy": "shared",
                "read_only": true
            },
            {
                "created_at": "2021-06-15T15:23:37.476Z",
                "id": "60c8c5f9139e40001908c6a4",
                "name": "test_portfolio",
                "privacy": "private"
            }
        ]
    }
}
```

#### Human Readable Output

> Your SecurityScorecard Portfolios (first 3)
>|id|name|privacy|
>|---|---|---|
>| 60c78cc2d63162001a68c2b8 | username@domain.com | private |
>| 60b7e8ea8242c000b8000000 | Paloaltonetworks App | shared |
>| 60c8c5f9139e40001908c6a4 | test_portfolio | private |

### securityscorecard-portfolio-list-companies

***
Lists all companies in Portfolio.

#### Base Command

`securityscorecard-portfolio-list-companies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portfolio_id | Portfolio ID. The Portfolio ID can be retrieved using the 'securityscorecard-portfolios-list' command. | Required |
| grade | Grade filter. To filter multiple grades, comma-separate them, e.g. A,B. Possible values are: A, B, C, D, E, F. | Optional |
| industry | Industry filter. To filter multiple industries, comma-separate them, e.g. education,financial_services. Possible values are: education, financial_services, food, government, healthcare, information_services, manufacturing, retail, technology. | Optional |
| vulnerability | Vulnerability filter. | Optional |
| issue_type | Comma-separated list of issue types. Possible values are: adware_installation_trail, adware_installation, alleged_breach_incident, chatter, anonymous_proxy, service_cassandra, service_couchdb, attack_detected, attack_feed, new_booter_shell, spa_browser, cdn_hosting, tlscert_expired, tlscert_revoked, tlscert_self_signed, tlscert_excessive_expiration, tlscert_weak_signature, tlscert_no_revocation, service_cloud_provider, csp_no_policy_v2, csp_unsafe_policy_v2, csp_too_broad_v2, marketing_site, cookie_missing_secure_attribute, short_term_lending_site, leaked_credentials, leaked_credentials_info, service_dns, new_defacement, ransomware_victim, domain_uses_hsts_preloading, service_elasticsearch, employee_satisfaction, service_end_of_life, service_end_of_service, exposed_personal_information, exposed_personal_information_info, admin_subdomain_v2, tlscert_extended_validation, service_ftp, patching_cadence_high, web_vuln_host_high, service_vuln_host_high, service_imap, iot_camera, industrial_control_device, insecure_https_redirect_pattern_v2, service_ldap, service_ldap_anonymous, social_network_issues, patching_cadence_low, web_vuln_host_low, service_vuln_host_low, spf_record_malformed, malware_controller, malware_1_day, malware_30_day, malware_365_day, malware_infection, malware_infection_trail, patching_cadence_medium, web_vuln_host_medium, service_vuln_host_medium, service_microsoft_sql, minecraft_server, service_mongodb, no_browser_policy, service_mysql, service_neo4j, service_networking, object_storage_bucket_with_risky_acl, open_resolver, exposed_ports, service_open_vpn, service_oracle_db, outdated_os, outdated_browser, non_malware_events_last_month, service_pop3, service_pptp, phishing, typosquat, service_postgresql, exploited_product, public_text_credit_cards, public_text_database_dump, public_text_hashes, public_text_mention, public_text_password_dump, service_pulse_vpn, service_rdp, ransomware_association, redirect_chain_contains_http_v2, service_redis, remote_access, service_smb, mail_server_unusual_port, service_soap, spf_record_wildcard, spf_record_softfail, spf_record_missing, ssh_weak_protocol, ssh_weak_cipher, ssh_weak_mac, tls_weak_protocol, github_information_leak_disclosure, google_information_leak_disclosure, cookie_missing_http_only, domain_missing_https_v2, suspicious_traffic, tls_ocsp_stapling, tls_weak_cipher, telephony, service_telnet, tor_node_events_last_month, upnp_accessible, unsafe_sri_v2, uce, service_vnc, dnssec_detected, waf_detected_v2, hsts_incorrect_v2, hosted_on_object_storage_v2, references_object_storage_v2, x_content_type_options_incorrect_v2, x_frame_options_incorrect_v2, x_xss_protection_incorrect_v2, service_rsync. | Optional | 
| had_breach_within_last_days | Domains with breaches in the last X days. Possible values are numbers, e.g. 1000. | Optional

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Portfolio.Company.domain | String | Company domain. |
| SecurityScorecard.Portfolio.Company.name | String | Company name. |
| SecurityScorecard.Portfolio.Company.score | Number | Company overall score in numeric form \(55-100\). |
| SecurityScorecard.Portfolio.Company.grade | String | Company overall score in letter grade. |
| SecurityScorecard.Portfolio.Company.grade_url | String | Company overall score URL to SVG asset. |
| SecurityScorecard.Portfolio.Company.last30days_score_change | Number | Company overall score numeric change \(±\) in the last month. |
| SecurityScorecard.Portfolio.Company.industry | String | Industry category of the domain. |
| SecurityScorecard.Portfolio.Company.size | String | Company size, e.g. 'size_more_than_10000' |
| SecurityScorecard.Portfolio.Company.is_custom_vendor | Boolean | Whether the company is a custom vendor. |
| SecurityScorecard.Portfolio.Company.total | Number | Total number of companies in Portfolio. |

#### Command Example

```!securityscorecard-portfolio-list-companies portfolio_id=60c78cc2d63162001a68c2b8 grade=A industry=information_services```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Portfolio": {
            "Company": {
                "domain": "berkshirehathaway.com",
                "grade": "A",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                "industry": "information_services",
                "is_custom_vendor": false,
                "last30days_score_change": 0,
                "name": "Berkshire Hathaway Inc.",
                "score": 98,
                "size": "size_more_than_10000"
            }
        }
    }
}
```

#### Human Readable Output

>### **1** companies found in Portfolio 60c78cc2d63162001a68c2b8
>
>|domain|name|score|last30days_score_change|industry|size|
>|---|---|---|---|---|---|
>| berkshirehathaway.com | Berkshire Hathaway Inc. | 98 | 0 | information_services | size_more_than_10000 |

### securityscorecard-company-score-get

***
Retrieve company overall score.

#### Base Command

`securityscorecard-company-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. somecompany.com. The company must first be added to a Portfolio in order to be able to get its score. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.Score.domain | String | Company domain. |
| SecurityScorecard.Company.Score.name | String | Company name. |
| SecurityScorecard.Company.Score.score | Number | Company overall score in numeric form \(55-100\). |
| SecurityScorecard.Company.Score.grade | String | Company overall score in letter grade form \(A-F\). |
| SecurityScorecard.Company.Score.last30days_score_change | Number | Company overall score numeric change \(±\) in the last month. |
| SecurityScorecard.Company.Score.industry | String | ndustry category of the domain. |
| SecurityScorecard.Company.Score.size | String | Company size, e.g. 'size_more_than_10000' |

#### Command Example

```!securityscorecard-company-score-get domain=somecompany.com```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "Score": {
                "created_at": "2014-04-18T23:00:55.588Z",
                "domain": "somecompany.com",
                "grade": "C",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_c.svg",
                "industry": "technology",
                "last30day_score_change": 0,
                "name": "Google",
                "score": 74,
                "size": "size_more_than_10000",
                "tags": [
                    "service_provider"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Domain somecompany.com Scorecard
>|name|grade|score|industry|last30day_score_change|size|
>|---|---|---|---|---|---|
>| Google | C | 74 | technology | 0 | size_more_than_10000 |

### securityscorecard-company-factor-score-get
***
Retrieve company factor score.

#### Base Command

`securityscorecard-company-factor-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain. | Required |
| severity | Issue severity filter. Comma-separated list of the following values: 'positive', 'info', 'low', 'medium', 'high'. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.Factor.name | String | Factor name. |
| SecurityScorecard.Company.Factor.score | Number | Factor score in numeric form \(55-100\) |
| SecurityScorecard.Company.Factor.grade | String | Factor score in letter grade form \(A-F\) |
| SecurityScorecard.Company.Factor.Issue.type | String | Type of issue found |
| SecurityScorecard.Company.Factor.Issue.count | Number | How many times the issue was found |
| SecurityScorecard.Company.Factor.Issue.severity | String | Severity of the issue |
| SecurityScorecard.Company.Factor.Issue.total_score_impact | Number | Contribution of issue on overall score |
| SecurityScorecard.Company.Factor.Issue.detail_url | String | URL to the details of the issue |
| SecurityScorecard.Company.Factor.total | Number | Number of factors returned |

#### Command Example

```!securityscorecard-company-factor-score-get domain=somecompany.com severity_in=high```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "Factor": [
                {
                    "grade": "F",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_f.svg",
                    "issue_summary": [
                        {
                            "count": 14,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/insecure_https_redirect_pattern_v2/",
                            "severity": "medium",
                            "total_score_impact": 2.8799643274287376,
                            "type": "insecure_https_redirect_pattern_v2"
                        },
                        {
                            "count": 5,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/domain_missing_https_v2/",
                            "severity": "high",
                            "total_score_impact": 4.0102975263373395,
                            "type": "domain_missing_https_v2"
                        },
                        {
                            "count": 38,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/csp_no_policy_v2/",
                            "severity": "medium",
                            "total_score_impact": 5.201100632206234,
                            "type": "csp_no_policy_v2"
                        },
                        {
                            "count": 43,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/csp_unsafe_policy_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "csp_unsafe_policy_v2"
                        },
                        {
                            "count": 4,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/redirect_chain_contains_http_v2/",
                            "severity": "medium",
                            "total_score_impact": 1.0326184028639176,
                            "type": "redirect_chain_contains_http_v2"
                        },
                        {
                            "count": 6,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/references_object_storage_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "references_object_storage_v2"
                        },
                        {
                            "count": 56,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/unsafe_sri_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "unsafe_sri_v2"
                        },
                        {
                            "count": 28,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/x_frame_options_incorrect_v2/",
                            "severity": "low",
                            "total_score_impact": 1.091096316549013,
                            "type": "x_frame_options_incorrect_v2"
                        },
                        {
                            "count": 73,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/x_xss_protection_incorrect_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "x_xss_protection_incorrect_v2"
                        },
                        {
                            "count": 26,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/csp_too_broad_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "csp_too_broad_v2"
                        },
                        {
                            "count": 90,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/hsts_incorrect_v2/",
                            "severity": "medium",
                            "total_score_impact": 4.856195629021897,
                            "type": "hsts_incorrect_v2"
                        },
                        {
                            "count": 9,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/x_content_type_options_incorrect_v2/",
                            "severity": "low",
                            "total_score_impact": 0.7205419642483406,
                            "type": "x_content_type_options_incorrect_v2"
                        }
                    ],
                    "name": "application_security",
                    "score": 24
                },
                {
                    "grade": "B",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_b.svg",
                    "issue_summary": [
                        {
                            "count": 5,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/admin_subdomain_v2/",
                            "severity": "low",
                            "total_score_impact": 0.45435810384235253,
                            "type": "admin_subdomain_v2"
                        }
                    ],
                    "name": "cubit_score",
                    "score": 89
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [],
                    "name": "dns_health",
                    "score": 100
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [],
                    "name": "endpoint_security",
                    "score": 100
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [],
                    "name": "hacker_chatter",
                    "score": 100
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [
                        {
                            "count": 4,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/suspicious_traffic/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "suspicious_traffic"
                        },
                        {
                            "count": 31,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/uce/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "uce"
                        }
                    ],
                    "name": "ip_reputation",
                    "score": 100
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [
                        {
                            "count": 14,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/leaked_credentials_info/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "leaked_credentials_info"
                        }
                    ],
                    "name": "leaked_information",
                    "score": 100
                },
                {
                    "grade": "B",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_b.svg",
                    "issue_summary": [
                        {
                            "count": 44,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/tlscert_excessive_expiration/",
                            "severity": "low",
                            "total_score_impact": 0.06768171402700318,
                            "type": "tlscert_excessive_expiration"
                        },
                        {
                            "count": 30,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/tlscert_self_signed/",
                            "severity": "medium",
                            "total_score_impact": 0.18204539659438979,
                            "type": "tlscert_self_signed"
                        },
                        {
                            "count": 71,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/tlscert_no_revocation/",
                            "severity": "low",
                            "total_score_impact": 0.07718961545099035,
                            "type": "tlscert_no_revocation"
                        },
                        {
                            "count": 731,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/tls_weak_cipher/",
                            "severity": "medium",
                            "total_score_impact": 0.3050661902513667,
                            "type": "tls_weak_cipher"
                        }
                    ],
                    "name": "network_security",
                    "score": 89
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [],
                    "name": "patching_cadence",
                    "score": 100
                },
                {
                    "grade": "A",
                    "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                    "issue_summary": [
                        {
                            "count": 770,
                            "detail_url": "https://api.securityscorecard.io/companies/somecompany.com/issues/exposed_personal_information_info/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "exposed_personal_information_info"
                        }
                    ],
                    "name": "social_engineering",
                    "score": 100
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Domain somecompany.com Scorecard
>|name|grade|score|issues|
>|---|---|---|---|
>| application_security | F | 24 | 12 |
>| cubit_score | B | 89 | 1 |
>| dns_health | A | 100 | 0 |
>| endpoint_security | A | 100 | 0 |
>| hacker_chatter | A | 100 | 0 |
>| ip_reputation | A | 100 | 2 |
>| leaked_information | A | 100 | 1 |
>| network_security | B | 89 | 4 |
>| patching_cadence | A | 100 | 0 |
>| social_engineering | A | 100 | 1 |

### securityscorecard-company-history-score-get
***
Retrieve company historical scores

#### Base Command

`securityscorecard-company-history-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. `somecompany.com`. | Required |
| from | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| to | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| timing | Timing granularity. Possible values are: daily, weekly. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.ScoreHistory.domain | String | Company domain. |
| SecurityScorecard.Company.ScoreHistory.date | Date | Score date. |
| SecurityScorecard.Company.ScoreHistory.score | Number | Company historical security score in numeric form \(55-100\) |

#### Command Example

```!securityscorecard-company-history-score-get domain=somecompany.com from=2021-06-01 to=2021-06-28 timing=weekly```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "ScoreHistory": [
                {
                    "date": "2021-06-05T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "score": 76
                },
                {
                    "date": "2021-06-12T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "score": 76
                },
                {
                    "date": "2021-06-19T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "score": 76
                },
                {
                    "date": "2021-06-26T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "score": 75
                },
                {
                    "date": "2021-06-28T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "score": 74
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Historical Scores for Domain `somecompany.com`
>|date|score|
>|---|---|
>| 2021-06-05T00:00:00.000Z | 76 |
>| 2021-06-12T00:00:00.000Z | 76 |
>| 2021-06-19T00:00:00.000Z | 76 |
>| 2021-06-26T00:00:00.000Z | 75 |
>| 2021-06-28T00:00:00.000Z | 74 |

### securityscorecard-company-history-factor-score-get

***
Retrieve company historical factor scores

#### Base Command

`securityscorecard-company-history-factor-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. somecompany.com. | Required |
| from | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| to | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| timing | Timing granularity. or "monthly". Possible values are: daily, weekly, monthly. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.FactorHistory.domain | String | Company domain. |
| SecurityScorecard.Company.FactorHistory.date | Date | Score date. |
| SecurityScorecard.Company.FactorHistory.Factor.name | Number | Factor name. |
| SecurityScorecard.Company.FactorHistory.score | Number | Company historical security score in numeric form \(55-100\) |

#### Command Example

```!securityscorecard-company-history-factor-score-get domain=somecompany.com from=2021-06-01 to=2021-06-30 timing=weekly```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "FactorHistory": [
                {
                    "date": "2021-06-05T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "factors": [
                        {
                            "name": "endpoint_security",
                            "score": 100
                        },
                        {
                            "name": "application_security",
                            "score": 32
                        },
                        {
                            "name": "hacker_chatter",
                            "score": 100
                        },
                        {
                            "name": "leaked_information",
                            "score": 100
                        },
                        {
                            "name": "network_security",
                            "score": 88
                        },
                        {
                            "name": "dns_health",
                            "score": 100
                        },
                        {
                            "name": "social_engineering",
                            "score": 100
                        },
                        {
                            "name": "ip_reputation",
                            "score": 100
                        },
                        {
                            "name": "patching_cadence",
                            "score": 100
                        },
                        {
                            "name": "cubit_score",
                            "score": 80
                        }
                    ]
                },
                {
                    "date": "2021-06-12T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "factors": [
                        {
                            "name": "endpoint_security",
                            "score": 100
                        },
                        {
                            "name": "application_security",
                            "score": 33
                        },
                        {
                            "name": "hacker_chatter",
                            "score": 100
                        },
                        {
                            "name": "leaked_information",
                            "score": 100
                        },
                        {
                            "name": "network_security",
                            "score": 88
                        },
                        {
                            "name": "dns_health",
                            "score": 100
                        },
                        {
                            "name": "social_engineering",
                            "score": 100
                        },
                        {
                            "name": "ip_reputation",
                            "score": 100
                        },
                        {
                            "name": "patching_cadence",
                            "score": 100
                        },
                        {
                            "name": "cubit_score",
                            "score": 80
                        }
                    ]
                },
                {
                    "date": "2021-06-19T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "factors": [
                        {
                            "name": "endpoint_security",
                            "score": 100
                        },
                        {
                            "name": "application_security",
                            "score": 34
                        },
                        {
                            "name": "hacker_chatter",
                            "score": 100
                        },
                        {
                            "name": "leaked_information",
                            "score": 100
                        },
                        {
                            "name": "network_security",
                            "score": 90
                        },
                        {
                            "name": "dns_health",
                            "score": 100
                        },
                        {
                            "name": "social_engineering",
                            "score": 100
                        },
                        {
                            "name": "ip_reputation",
                            "score": 93
                        },
                        {
                            "name": "patching_cadence",
                            "score": 100
                        },
                        {
                            "name": "cubit_score",
                            "score": 80
                        }
                    ]
                },
                {
                    "date": "2021-06-26T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "factors": [
                        {
                            "name": "endpoint_security",
                            "score": 100
                        },
                        {
                            "name": "application_security",
                            "score": 35
                        },
                        {
                            "name": "hacker_chatter",
                            "score": 100
                        },
                        {
                            "name": "leaked_information",
                            "score": 100
                        },
                        {
                            "name": "network_security",
                            "score": 90
                        },
                        {
                            "name": "dns_health",
                            "score": 100
                        },
                        {
                            "name": "social_engineering",
                            "score": 100
                        },
                        {
                            "name": "ip_reputation",
                            "score": 87
                        },
                        {
                            "name": "patching_cadence",
                            "score": 100
                        },
                        {
                            "name": "cubit_score",
                            "score": 80
                        }
                    ]
                },
                {
                    "date": "2021-06-30T00:00:00.000Z",
                    "domain": "somecompany.com",
                    "factors": [
                        {
                            "name": "endpoint_security",
                            "score": 100
                        },
                        {
                            "name": "application_security",
                            "score": 34
                        },
                        {
                            "name": "hacker_chatter",
                            "score": 100
                        },
                        {
                            "name": "leaked_information",
                            "score": 100
                        },
                        {
                            "name": "network_security",
                            "score": 91
                        },
                        {
                            "name": "dns_health",
                            "score": 100
                        },
                        {
                            "name": "social_engineering",
                            "score": 100
                        },
                        {
                            "name": "ip_reputation",
                            "score": 86
                        },
                        {
                            "name": "patching_cadence",
                            "score": 100
                        },
                        {
                            "name": "cubit_score",
                            "score": 80
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Historical Factor Scores for Domain somecompany.com)
>|date|factors|
>|---|---|
>| 2021-06-05 | Endpoint Security: 100<br/>Application Security: 32<br/>Hacker Chatter: 100<br/>Leaked Information: 100<br/>Network Security: 88<br/>Dns Health: 100<br/>Social Engineering: 100<br/>Ip Reputation: 100<br/>Patching Cadence: 100<br/>Cubit Score: 80<br/> |
>| 2021-06-12 | Endpoint Security: 100<br/>Application Security: 33<br/>Hacker Chatter: 100<br/>Leaked Information: 100<br/>Network Security: 88<br/>Dns Health: 100<br/>Social Engineering: 100<br/>Ip Reputation: 100<br/>Patching Cadence: 100<br/>Cubit Score: 80<br/> |
>| 2021-06-19 | Endpoint Security: 100<br/>Application Security: 34<br/>Hacker Chatter: 100<br/>Leaked Information: 100<br/>Network Security: 90<br/>Dns Health: 100<br/>Social Engineering: 100<br/>Ip Reputation: 93<br/>Patching Cadence: 100<br/>Cubit Score: 80<br/> |
>| 2021-06-26 | Endpoint Security: 100<br/>Application Security: 35<br/>Hacker Chatter: 100<br/>Leaked Information: 100<br/>Network Security: 90<br/>Dns Health: 100<br/>Social Engineering: 100<br/>Ip Reputation: 87<br/>Patching Cadence: 100<br/>Cubit Score: 80<br/> |
>| 2021-06-30 | Endpoint Security: 100<br/>Application Security: 34<br/>Hacker Chatter: 100<br/>Leaked Information: 100<br/>Network Security: 91<br/>Dns Health: 100<br/>Social Engineering: 100<br/>Ip Reputation: 86<br/>Patching Cadence: 100<br/>Cubit Score: 80<br/> |

### securityscorecard-alert-grade-change-create

***
Create alert based on grade

#### Base Command

`securityscorecard-alert-grade-change-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are: rises, drops. | Required |
| score_types | Comma-separated list of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. | Required |
| target | What do you want to monitor with this alert. This argument is required if the `portfolios` argument is not specified. Possible values are: my_scorecard, any_followed_company. | Optional |
| portfolios | A comma-separated list of Portfolios. to use as a target for the alert. This argument is require if the `target` argument is not specified. You can get a list of portfolios by running `!securityscorecard-portfolios-list`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.GradeChangeAlert.id | String | Alert ID |

#### Command Example

```!securityscorecard-alert-grade-change-create change_direction=drops score_types=network_security,endpoint_security target=60c8c5f9139e40001908c6a4,my_scorecard```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Alerts": {
            "GradeChangeAlert": "39f82660-1486-11ec-96c5-6991d4f42be9"
        }
    }
}
```

#### Human Readable Output

>Alert **39f82660-1486-11ec-96c5-6991d4f42be9** created

### securityscorecard-alert-score-threshold-create
***
Create alert based threshold met

#### Base Command

`securityscorecard-alert-score-threshold-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are: rises_above, drops_below. | Required |
| threshold | The numeric score used as the threshold to trigger the alert. | Required |
| score_types | Comma separated list of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. For multiple factors, provide comma-separated list, i.e. leaked_information,social_engineering. | Required |
| target | What do you want to monitor with this alert. This argument is required if the `portfolios` argument is not specified. Possible values are: my_scorecard, any_followed_company. | Optional |
| portfolios | A comma-separated list of Portfolios. to use as a target for the alert. This argument is require if the `target` argument is not specified. You can get a list of portfolios by running `!securityscorecard-portfolios-list`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.ScoreThresholdAlert.id | String | Alert ID |

#### Command Example

```!securityscorecard-alert-score-threshold-create change_direction=drops_below threshold=100 score_types=network_security,dns_health target=60c8c5f9139e40001908c6a4,my_scorecard```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Alerts": {
            "ScoreThresholdAlert": "3cede6c0-1486-11ec-92bd-ff2223ac2147"
        }
    }
}
```

#### Human Readable Output

>Alert **3cede6c0-1486-11ec-92bd-ff2223ac2147** created

### securityscorecard-alert-delete
***
Delete an alert

#### Base Command

`securityscorecard-alert-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required |
| alert_type | Type of Alert to delete. Possible values are: score, grade. | Required |

#### Context Output

There is no context output for this command.

#### Command Example
```securityscorecard-alert-delete alert_id=3cede6c0-1486-11ec-92bd-ff2223ac2147 alert_type=score```

#### Human Readable Output

>Alert `3cede6c0-1486-11ec-92bd-ff2223ac2147` deleted

### securityscorecard-alerts-list

***
List alerts triggered in the last week

#### Base Command

`securityscorecard-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portfolio_id | Portfolio ID. Can be retrieved using `!securityscorecard-portfolios-list`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.Alert.id | String | Alert ID |
| SecurityScorecard.Alerts.Alert.email | String | Alert email recipient. |
| SecurityScorecard.Alerts.Alert.change_type | String | Alert change type configured \(score or threshold\) |
| SecurityScorecard.Alerts.Alert.domain | String | Alert domain |
| SecurityScorecard.Alerts.Alert.company_name | String | Alert company name |
| SecurityScorecard.Alerts.Alert.Portfolio.id | array | Alert Portfolio ID |
| SecurityScorecard.Alerts.Alert.my_scorecard | Boolean | Whether the alert was triggered on private scorecard. This depends on whether 'my_scorecard' was added to the optional argument 'target' when creating alerts using the 'securityscorecard-alert-score-threshold-create' and 'securityscorecard-alert-grade-change-create' commands. |
| SecurityScorecard.Alerts.Alert.created_at | Date | Timestamp of when the alert was triggered |

#### Command Example

```!securityscorecard-alerts-list```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Alerts": {
            "Alert": [
                {
                    "Alert ID": "c2f4d398-6e3a-5c2b-a8ad-285427caf9eb",
                    "Company": "Shijigroup",
                    "Creation Time": "2021-09-10T01:04:24.064Z",
                    "Details": "**Patching Cadence** **drops** by -3 to 88 (B)\n",
                    "Domain": "shijigroup.com"
                },
                {
                    "Alert ID": "2314db36-0835-5f66-a733-b4042e858944",
                    "Company": "Palo Alto Networks",
                    "Creation Time": "2021-09-10T01:00:31.348Z",
                    "Details": "**Endpoint Security** **drops** by -1 to 69 (D)\n",
                    "Domain": "paloaltonetworks.com"
                },
                {
                    "Alert ID": "449bba34-b80d-584c-b331-17e73c74c125",
                    "Company": "ClickSoftware",
                    "Creation Time": "2021-09-10T01:00:18.981Z",
                    "Details": "**Network Security** **drops** by -1 to 89 (B)\n",
                    "Domain": "clicksoftware.com"
                },
                {
                    "Alert ID": "d0c8d408-0685-560e-9039-4130b0eabfef",
                    "Company": "GE Healthcare",
                    "Creation Time": "2021-09-08T22:20:09.478Z",
                    "Details": "**Network Security** **drops** by -1 to 69 (D)\n**Patching Cadence** **rises_above** by 4 to 73 (C)\n",
                    "Domain": "gehealthcare.com"
                },
                {
                    "Alert ID": "12242cf9-bb70-5def-896b-1ae3e6ab4054",
                    "Company": "Google",
                    "Creation Time": "2021-09-07T00:12:15.334Z",
                    "Details": "**Endpoint Security** **drops_below** by -8 to 92 (A)\n",
                    "Domain": "google.co.il"
                },
                {
                    "Alert ID": "2608711b-16c8-5382-8855-f86d539060da",
                    "Company": "Apple",
                    "Creation Time": "2021-09-07T00:11:51.044Z",
                    "Details": "**Dns Health** **rises** by 1 to 60 (D)\n",
                    "Domain": "apple.com"
                },
                {
                    "Alert ID": "f0058672-3454-5ed4-85df-97b8cdba6129",
                    "Company": "Fyber GmbH",
                    "Creation Time": "2021-09-07T00:11:23.164Z",
                    "Details": "**Dns Health** **rises_above** by 8 to 70 (C)\n",
                    "Domain": "fyber.com"
                },
                {
                    "Alert ID": "6110b7fb-e6f3-581d-b5a8-d836380ec00a",
                    "Company": "PING AN",
                    "Creation Time": "2021-09-05T05:05:20.922Z",
                    "Details": "**Ip Reputation** **drops** by -16 to 84 (B)\n",
                    "Domain": "pingan.com"
                },
                {
                    "Alert ID": "51b2ea59-010c-5e24-b7ff-eb7085b66238",
                    "Company": "Shijigroup",
                    "Creation Time": "2021-09-04T19:02:51.588Z",
                    "Details": "**Application Security** **rises_above** by 1 to 70 (C)\n",
                    "Domain": "shijigroup.com"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Latest Alerts for user username@domain.com
>|Alert ID|Company|Creation Time|Details|Domain|
>|---|---|---|---|---|
>| c2f4d398-6e3a-5c2b-a8ad-285427caf9eb | Shijigroup | 2021-09-10T01:04:24.064Z | **Patching Cadence** **drops** by -3 to 88 (B)<br/> | shijigroup.com |
>| 2314db36-0835-5f66-a733-b4042e858944 | Palo Alto Networks | 2021-09-10T01:00:31.348Z | **Endpoint Security** **drops** by -1 to 69 (D)<br/> | paloaltonetworks.com |
>| 449bba34-b80d-584c-b331-17e73c74c125 | ClickSoftware | 2021-09-10T01:00:18.981Z | **Network Security** **drops** by -1 to 89 (B)<br/> | clicksoftware.com |
>| d0c8d408-0685-560e-9039-4130b0eabfef | GE Healthcare | 2021-09-08T22:20:09.478Z | **Network Security** **drops** by -1 to 69 (D)<br/>**Patching Cadence** **rises_above** by 4 to 73 (C)<br/> | gehealthcare.com |
>| 12242cf9-bb70-5def-896b-1ae3e6ab4054 | Google | 2021-09-07T00:12:15.334Z | **Endpoint Security** **drops_below** by -8 to 92 (A)<br/> | google.co.il |
>| 2608711b-16c8-5382-8855-f86d539060da | Apple | 2021-09-07T00:11:51.044Z | **Dns Health** **rises** by 1 to 60 (D)<br/> | apple.com |
>| f0058672-3454-5ed4-85df-97b8cdba6129 | Fyber GmbH | 2021-09-07T00:11:23.164Z | **Dns Health** **rises_above** by 8 to 70 (C)<br/> | fyber.com |
>| 6110b7fb-e6f3-581d-b5a8-d836380ec00a | PING AN | 2021-09-05T05:05:20.922Z | **Ip Reputation** **drops** by -16 to 84 (B)<br/> | pingan.com |
>| 51b2ea59-010c-5e24-b7ff-eb7085b66238 | Shijigroup | 2021-09-04T19:02:51.588Z | **Application Security** **rises_above** by 1 to 70 (C)<br/> | shijigroup.com |

### securityscorecard-company-services-get

***
Retrieve the service providers of a domain

#### Base Command

`securityscorecard-company-services-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Service.vendor_domain | String | Vendor domain, e.g. Google, Amazon |
| SecurityScorecard.Service.client_domain | String | Client domain. This value is identical to the input of the domain argument |
| SecurityScorecard.Service.categories | array | Vendor service provider, e.g. mail_provider, nameserver_provider |

#### Command Example

```!securityscorecard-company-services-get domain=somecompany.com```

#### Human Readable Output

>### Services for domain `somecompany.com`

>**No entries.**
