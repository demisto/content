# SecurityScorecard

Provides scorecards for domains.

## Configure SecurityScorecard on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SecurityScorecard.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | SecurityScorecard API Base URL |  | True |
    | Username/Email | The SecurityScorecard username/email. | True |
    | API Token | SecurityScorecard API token. | True |
    | Fetch incidents | Enable/disable fetching SecurityScorecard Alerts to Cortex XSOAR Incidents | False |
    | Incidents Fetch Interval | SecurityScorecard is updated on a daily basis therefore there's no need to modify this value. | False |
    | Fetch Limit | Maximum number of alerts per fetch. Default is 50, maximum is 100. | False |
    | First fetch | First fetch query \(`<number\> <time\>`, e.g., `12 hours`, `7 days`\). SecurityScorecard provides a maximum of 7 days back. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### securityscorecard-portfolios-list

***
List all Portfolios

#### Base Command

`securityscorecard-portfolios-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `limit` | Limit the amount of Portfolios to return. Defaults to `50`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Portfolio.id | String | Portfolio ID |
| SecurityScorecard.Portfolio.name | String | Portfolio name |
| SecurityScorecard.Portfolio.description | String | Portfolio description |
| SecurityScorecard.Portfolio.privacy | String | Portfolio privacy. Can be either private, shared or team. |
| SecurityScorecard.Portfolio.read_only | Boolean | Whether the portfolio is read only. |

#### Command Example

```!securityscorecard-portfolios-list limit=3```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Portfolio": [
            {
                "id": "xxxxxxxxxxxxxxxx",
                "name": "some_name@some_domain.com",
                "privacy": "private",
                "read_only": true
            },
            {
                "id": "yyyyyyyyyyyyyyyy",
                "name": "some_company_name",
                "privacy": "shared",
                "read_only": true
            },
            {
                "id": "zzzzzzzzzzzzzzzz`",
                "name": "test_portfolio",
                "privacy": "private"
            }
        ]
    }
}
```

#### Human Readable Output

### Your SecurityScorecard Portfolios (first 3)

>|id|name|privacy|
>|---|---|---|
>| xxxxxxxxxxxxxxxx | some_name@some_domain.com" | private |
>| yyyyyyyyyyyyyyyy | some_company_name | shared |
>| zzzzzzzzzzzzzzzz | test_portfolio | private |

### securityscorecard-portfolio-list-companies

***
Lists all companies in Portfolio.

#### Base Command

`securityscorecard-portfolio-list-companies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `portfolio_id` | Portfolio ID. A comma-separated list of Portfolio IDs can be retrieved using the `securityscorecard-portfolios-list` command. | Required |
| `grade` | Grade filter. Possible values are: A, B, C, D, E, F. | Optional |
| `industry` | Industry filter. Possible values are: education, financial_services, food, government, healthcare, information_services, manufacturing, retail, technology. | Optional |
| `vulnerability` | Vulnerability filter. | Optional |
| `issue_type` | Issue type filter. | Optional |
| `had_breach_within_last_days` | Domains with breaches in the last X days. Possible values are numbers, e.g. `1000`. | Optional |

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
| SecurityScorecard.Portfolio.Company.size | String | Company size, e.g. `size_more_than_10000` |
| SecurityScorecard.Portfolio.Company.is_custom_vendor | Boolean | Whether the company is a custom vendor. |
| SecurityScorecard.Portfolio.Company.total | Number | Total number of companies in Portfolio. |

#### Command Example
```!securityscorecard-portfolio-list-companies portfolio_id=xxxxxxxxxxxxxxxx grade=A industry=information_services```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Portfolio": {
            "Company": {
                "domain": "some_domain.com",
                "grade": "A",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                "industry": "information_services",
                "is_custom_vendor": false,
                "last30days_score_change": -1,
                "name": "Some Company",
                "score": 98,
                "size": "size_more_than_10000"
            }
        }
    }
}
```

#### Human Readable Output

>### **1** companies found in Portfolio xxxxxxxxxxxxxxxx
>
>|domain|name|score|last30days_score_change|industry|size|
>|---|---|---|---|---|---|
>| some_domain.com | Some Company | 98 | -1 | information_services | size_more_than_10000 |

### securityscorecard-company-score-get

***
Retrieve company overall score.

#### Base Command

`securityscorecard-company-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `domain` | Company domain, e.g. `some_domain.com`. The company must first be added to a Portfolio in order to be able to get its score. | Required |

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

```!securityscorecard-company-score-get domain=some_domain.com```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Company": {
            "Score": {
                "domain": "some_domain.com",
                "grade": "D",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_d.svg",
                "industry": "Technology",
                "last30day_score_change": -9,
                "name": "Some Company",
                "score": 67,
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

>### Domain some_domain.com Scorecard
>|name|domain|grade|score|industry|last30day_score_change|size|
>|---|---|---|---|---|---|---|
>| Some Company | some_domain.com | D | 67 | Technology | -9 | size_more_than_10000 |

### securityscorecard-company-factor-score-get

***
Retrieve company factor score.

#### Base Command

`securityscorecard-company-factor-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `domain` | Company domain. | Required |
| `severity` | Issue severity filter. Comma-separated list of the following values: `positive`, `info`, `low`, `medium`, `high`. | Optional |

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
```!securityscorecard-company-factor-score-get domain=some_domain.com severity_in=high```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Company": {
            "Factor": [
                {
                    "grade": "F",
                    "issue details": [
                        {
                            "count": 26,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/csp_too_broad_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "csp_too_broad_v2"
                        },
                        {
                            "count": 43,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/csp_unsafe_policy_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "csp_unsafe_policy_v2"
                        },
                        {
                            "count": 74,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/x_xss_protection_incorrect_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "x_xss_protection_incorrect_v2"
                        },
                        {
                            "count": 4,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/references_object_storage_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "references_object_storage_v2"
                        },
                        {
                            "count": 122686,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/insecure_https_redirect_pattern_v2/",
                            "severity": "medium",
                            "total_score_impact": 4.168170021326873,
                            "type": "insecure_https_redirect_pattern_v2"
                        },
                        {
                            "count": 90,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/hsts_incorrect_v2/",
                            "severity": "medium",
                            "total_score_impact": 0.8429497863306068,
                            "type": "hsts_incorrect_v2"
                        },
                        {
                            "count": 154905,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/redirect_chain_contains_http_v2/",
                            "severity": "medium",
                            "total_score_impact": 1.2356887748488106,
                            "type": "redirect_chain_contains_http_v2"
                        },
                        {
                            "count": 12,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/x_content_type_options_incorrect_v2/",
                            "severity": "low",
                            "total_score_impact": 0.11544244889822153,
                            "type": "x_content_type_options_incorrect_v2"
                        },
                        {
                            "count": 6,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/domain_missing_https_v2/",
                            "severity": "high",
                            "total_score_impact": 0.7419736257670877,
                            "type": "domain_missing_https_v2"
                        },
                        {
                            "count": 56,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/unsafe_sri_v2/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "unsafe_sri_v2"
                        },
                        {
                            "count": 27,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/x_frame_options_incorrect_v2/",
                            "severity": "low",
                            "total_score_impact": 0.15640660092385872,
                            "type": "x_frame_options_incorrect_v2"
                        },
                        {
                            "count": 38,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/csp_no_policy_v2/",
                            "severity": "medium",
                            "total_score_impact": 0.9240460104538073,
                            "type": "csp_no_policy_v2"
                        }
                    ],
                    "issues": 12,
                    "name": "Application Security",
                    "score": 2
                },
                {
                    "grade": "B",
                    "issue details": [
                        {
                            "count": 5,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/admin_subdomain_v2/",
                            "severity": "low",
                            "total_score_impact": 0.16768823749336548,
                            "type": "admin_subdomain_v2"
                        },
                        {
                            "count": 259,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/typosquat/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "typosquat"
                        }
                    ],
                    "issues": 2,
                    "name": "Cubit Score",
                    "score": 89
                },
                {
                    "grade": "A",
                    "issue details": [],
                    "issues": 0,
                    "name": "Dns Health",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [],
                    "issues": 0,
                    "name": "Endpoint Security",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [],
                    "issues": 0,
                    "name": "Hacker Chatter",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [
                        {
                            "count": 3,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/suspicious_traffic/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "suspicious_traffic"
                        },
                        {
                            "count": 34,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/uce/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "uce"
                        }
                    ],
                    "issues": 2,
                    "name": "Ip Reputation",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [
                        {
                            "count": 14,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/leaked_credentials_info/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "leaked_credentials_info"
                        }
                    ],
                    "issues": 1,
                    "name": "Leaked Information",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [
                        {
                            "count": 8,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/tlscert_self_signed/",
                            "severity": "medium",
                            "total_score_impact": 0.0687465440595787,
                            "type": "tlscert_self_signed"
                        },
                        {
                            "count": 10,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/tlscert_no_revocation/",
                            "severity": "low",
                            "total_score_impact": 0.028265337438469373,
                            "type": "tlscert_no_revocation"
                        },
                        {
                            "count": 8,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/tlscert_excessive_expiration/",
                            "severity": "low",
                            "total_score_impact": 0.02563702450353844,
                            "type": "tlscert_excessive_expiration"
                        },
                        {
                            "count": 322,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/tls_weak_cipher/",
                            "severity": "medium",
                            "total_score_impact": 0.10583226528052592,
                            "type": "tls_weak_cipher"
                        }
                    ],
                    "issues": 4,
                    "name": "Network Security",
                    "score": 90
                },
                {
                    "grade": "A",
                    "issue details": [],
                    "issues": 0,
                    "name": "Patching Cadence",
                    "score": 100
                },
                {
                    "grade": "A",
                    "issue details": [
                        {
                            "count": 770,
                            "detail_url": "https://api.securityscorecard.io/companies/some_domain.com/issues/exposed_personal_information_info/",
                            "severity": "info",
                            "total_score_impact": 0,
                            "type": "exposed_personal_information_info"
                        }
                    ],
                    "issues": 1,
                    "name": "Social Engineering",
                    "score": 100
                }
            ]
        }
    }
}
```

### securityscorecard-company-history-score-get

***
Retrieve company historical scores


#### Base Command

`securityscorecard-company-history-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `domain` | Company domain, e.g. `some_domain.com`. | Required |
| `from` | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| `to` | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| `timing` | Timing granularity. Possible values are: `daily` (default), `weekly`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.ScoreHistory.domain | String | Company domain. |
| SecurityScorecard.Company.ScoreHistory.date | Date | Score date. |
| SecurityScorecard.Company.ScoreHistory.score | Number | Company historical security score in numeric form \(55-100\) |

#### Command Example
```!securityscorecard-company-history-score-get domain=some_domain.com from=2021-06-01 to=2021-06-28 timing=weekly```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Company": {
            "ScoreHistory": [
                {
                    "date": "2021-06-05T00:00:00.000Z",
                    "domain": "some_domain.com",
                    "score": 76
                },
                {
                    "date": "2021-06-12T00:00:00.000Z",
                    "domain": "some_domain.com",
                    "score": 76
                },
                {
                    "date": "2021-06-19T00:00:00.000Z",
                    "domain": "some_domain.com",
                    "score": 76
                },
                {
                    "date": "2021-06-26T00:00:00.000Z",
                    "domain": "some_domain.com",
                    "score": 75
                },
                {
                    "date": "2021-06-28T00:00:00.000Z",
                    "domain": "some_domain.com",
                    "score": 74
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Historical Scores for Domain [`some_domain.com`](https:<span>//</span>some_domain.com)
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
| `domain` | Company domain, e.g. some_domain.com. | Required |
| `from` | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| `to` | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| `timing` | Timing granularity. or "monthly". Possible values are: daily, weekly, monthly. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.FactorHistory.domain | String | Company domain. |
| SecurityScorecard.Company.FactorHistory.date | Date | Score date. |
| SecurityScorecard.Company.FactorHistory.Factor.name | Number | Factor name. |
| SecurityScorecard.Company.FactorHistory.score | Number | Company historical security score in numeric form \(55-100\) |


#### Command Example
```!securityscorecard-company-history-factor-score-get domain=some_domain.com from=2021-06-01 to=2021-06-30 timing=weekly```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Company": {
            "FactorHistory": [
                {
                    "date": "2021-06-05",
                    "factors": "Endpoint Security: 100\nApplication Security: 32\nHacker Chatter: 100\nLeaked Information: 100\nNetwork Security: 88\nDns Health: 100\nSocial Engineering: 100\nIp Reputation: 100\nPatching Cadence: 100\nCubit Score: 80\n"
                },
                {
                    "date": "2021-06-12",
                    "factors": "Endpoint Security: 100\nApplication Security: 33\nHacker Chatter: 100\nLeaked Information: 100\nNetwork Security: 88\nDns Health: 100\nSocial Engineering: 100\nIp Reputation: 100\nPatching Cadence: 100\nCubit Score: 80\n"
                },
                {
                    "date": "2021-06-19",
                    "factors": "Endpoint Security: 100\nApplication Security: 34\nHacker Chatter: 100\nLeaked Information: 100\nNetwork Security: 90\nDns Health: 100\nSocial Engineering: 100\nIp Reputation: 93\nPatching Cadence: 100\nCubit Score: 80\n"
                },
                {
                    "date": "2021-06-26",
                    "factors": "Endpoint Security: 100\nApplication Security: 35\nHacker Chatter: 100\nLeaked Information: 100\nNetwork Security: 90\nDns Health: 100\nSocial Engineering: 100\nIp Reputation: 87\nPatching Cadence: 100\nCubit Score: 80\n"
                },
                {
                    "date": "2021-06-30",
                    "factors": "Endpoint Security: 100\nApplication Security: 34\nHacker Chatter: 100\nLeaked Information: 100\nNetwork Security: 91\nDns Health: 100\nSocial Engineering: 100\nIp Reputation: 86\nPatching Cadence: 100\nCubit Score: 80\n"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Historical Factor Scores for Domain `some_domain.com`)
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
| `change_direction` | Direction of change. Possible values are: `rises`, `drops`. | Required |
| `score_types` | Comma-separated list of risk factors to monitor. Possible values are `overall`, `any_factor_score`, `network_security`, `dns_health`, `patching_cadence`, `endpoint_security`, `ip_reputation`, `application_security`, `cubit_score`, `hacker_chatter`, `leaked_information`, `social_engineering`. | Required |
| `target` | What do you want to monitor with this alert. This argument is required if the `portfolios` argument is not specified. Possible values are: `my_scorecard`, `any_followed_company`. | Optional |
| `portfolios` | A comma-separated list of Portfolios. to use as a target for the alert. This argument is require if the `target` argument is not specified. You can get a list of portfolios by running `!securityscorecard-portfolios-list`. | Optional |


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
            "GradeChangeAlert": "xxxxx-yyyy-zzzz"
        }
    }
}
```

#### Human Readable Output

>Alert **xxxxx-yyyy-zzzz** created

### securityscorecard-alert-score-threshold-create

***
Create alert based threshold met


#### Base Command

`securityscorecard-alert-score-threshold-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `change_direction` | Direction of change. Possible values are: `rises_above`, `drops_below`. | Required |
| `threshold` | The numeric score used as the threshold to trigger the alert. | Required |
| `score_types` | Comma separated list of risk factors to monitor. Possible values are `overall`, `any_factor_score`, `network_security`, `dns_health`, `patching_cadence`, `endpoint_security`, `ip_reputation`, `application_security`, `cubit_score`, `hacker_chatter`, `leaked_information`, `social_engineering`. For multiple factors, provide comma-separated list, i.e. `leaked_information,social_engineering`. | Required |
| `target` | What do you want to monitor with this alert. This argument is require if the `portfolios` argument is not specified. Possible values are: `my_scorecard`, `any_followed_company`. | Optional |
| `portfolios` | A comma-separated list of Portfolios. to use as a target for the alert. This argument is require if the `target` argument is not specified. You can get a list of portfolios by running `securityscorecard-portfolios-list`. | Optional |

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
            "ScoreThresholdAlert": "xxxxx-yyyy-zzzy"
        }
    }
}
```

#### Human Readable Output

>Alert **xxxxx-yyyy-zzzy** created

### securityscorecard-alert-delete

***
Delete an alert


#### Base Command

`securityscorecard-alert-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `alert_id` | Alert ID. | Required |
| `alert_type` | Type of Alert to delete. Possible values are: `score`, `grade`. | Required |

#### Context Output

There is no context output for this command.

#### Command Example
```!securityscorecard-alert-delete alert_id=xxxxx-yyyy-zzzz alert_type=grade```

#### Human Readable Output

>Score alert **xxxxx-yyyy-zzzz** deleted
### securityscorecard-alerts-list
***
List alerts triggered in the last week


#### Base Command

`securityscorecard-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `portfolio_id` | Portfolio ID. Can be retrieved by running  `securityscorecard-portfolios-list`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.Alert.id | String | Alert ID |
| SecurityScorecard.Alerts.Alert.email | String | Alert email recipient. |
| SecurityScorecard.Alerts.Alert.change_type | String | Alert change type configured \(score or threshold\) |
| SecurityScorecard.Alerts.Alert.domain | String | Alert domain |
| SecurityScorecard.Alerts.Alert.company_name | String | Alert company name |
| SecurityScorecard.Alerts.Alert.Portfolio.id | array | Alert Portfolio ID |
| SecurityScorecard.Alerts.Alert.my_scorecard | Boolean | Whether the alert was triggered on private scorecard. This depends on whether `my_scorecard` was added to the optional argument `target` when creating alerts using the `securityscorecard-alert-score-threshold-create` and `securityscorecard-alert-grade-change-create` commands. |
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
                    "change_type": "score_change",
                    "company": "Some Company",
                    "created": "2021-07-21T10:39:58.682Z",
                    "direction": "drops",
                    "domain": "some_domain.com",
                    "factor": "network_security",
                    "grade_letter": "B",
                    "id": "some_id",
                    "score": 89,
                    "score_impact": -1
                },
                ...
            ]
        }
    }
}
```

#### Human Readable Output

>### Latest Alerts for user kgal@paloaltonetworks.com
>|change_type|company|created|direction|domain|factor|grade_letter|id|score|score_impact|
>|---|---|---|---|---|---|---|---|---|---|
>| score_change | Some Company | 2021-07-21T10:39:58.682Z | drops | some_domain.com | network_security | B | some_id | 89 | -1 |
>...

### securityscorecard-company-services-get

***
Retrieve the service providers of a domain

#### Base Command

`securityscorecard-company-services-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| `domain` | Company domain. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Service.vendor_domain | String | Vendor domain, e.g. Google, Amazon |
| SecurityScorecard.Service.client_domain | String | Client domain. This value is identical to the input of the domain argument |
| SecurityScorecard.Service.categories | array | Vendor service provider, e.g. `mail_provider`, `nameserver_provider` |

#### Command Example
```!securityscorecard-company-services-get domain=some_domain.com```

#### Human Readable Output

>### Services for domain [some_domain.com]
>|category|vendor_domain|
>|---|---|
>| nameserver_provider | vendor_domain.com|
>| mail_provider | smtp_domain.com|
