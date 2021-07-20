# SecurityScorecard

## Provides scorecards for domains

This integration was integrated and tested with version 1.0.0 of SecurityScorecard

## Configure SecurityScorecard on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SecurityScorecard.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection | True |
    | Username/Email | The username/email of your SecurityScorecard account. This account must exist in the SecurityScorecard system. | True |
    | Fetch incidents |  | True |
    | Incidents Fetch Interval. SecurityScorecard is updated on a daily basis therefore there's no need to modify this value (24 h * 60 m/h = 1440m). This is hidden from the UI. |  | False |
    | Max incidents |  | False |
    | Fetch days ago | How many days ago to fetch for when fetching for the first time | False |
    | Incident Type |  | False |
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

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Portfolio.id | String | Portfolio ID |
| SecurityScorecard.Portfolio.name | String | Portfolio name |
| SecurityScorecard.Portfolio.description | String | Portfolio description |
| SecurityScorecard.Portfolio.privacy | String | Portfolio privacy. Can be either private, shared or team. |
| SecurityScorecard.Portfolio.read_only | Boolean | Whether the portfolio is read only. |

#### Command Example

```!securityscorecard-portfolios-list```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Portfolio": {
            "entries": [
                {
                    "id": "60c78cxxxxxxxxxxxxx",
                    "name": "name@domain.com",
                    "privacy": "private",
                    "read_only": true
                },
                {
                    "id": "60b7e8xxxxxxxxxxxxx",
                    "name": "name@domain.com",
                    "privacy": "shared",
                    "read_only": true
                },
                {
                    "id": "60c8xxxxxxxxxxxxxxx",
                    "name": "test_portfolio",
                    "privacy": "private"
                }
            ],
            "total": 3
        }
    }
}
```

#### Human Readable Output

None

### securityscorecard-portfolio-list-companies

***
Lists all companies in a Portfolio.

#### Base Command

`securityscorecard-portfolio-list-companies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portfolio_id | Portfolio ID. A list of Portfolio IDs can be retrieved using the `securityscorecard-portfolios-list` command. | Required |
| grade | Grade filter. The acceptable values are capitalized letters between A-F, e.g. B. Possible values are: A, B, C, D, E, F. | Optional |
| industry | Industry filter, e.g. information_services, technology. | Optional |
| vulnerability | Vulnerability filter. TODO NEED TO CHECK POSSIBLE VALUES. | Optional |
| issue_type | Issue type filter. TODO, need to list all possible values, can be found in active findings API. | Optional |
| had_breach_within_last_days | Domains with breaches in the last X days. Possible values are numbers, e.g. 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.domain | String | Company domain. |
| SecurityScorecard.Company.name | String | Company name. |
| SecurityScorecard.Company.score | Number | Company overall score in numeric form \(55-100\). |
| SecurityScorecard.Company.grade | String | Company overall score in letter grade. |
| SecurityScorecard.Company.grade_url | String | Company overall score URL to SVG asset. |
| SecurityScorecard.Company.last30days_score_change | Number | Company overall score numeric change \(±\) in the last month. |
| SecurityScorecard.Company.industry | String | Industry category of the domain. |
| SecurityScorecard.Company.size | String | Company size, e.g. 'size_more_than_10000' |
| SecurityScorecard.Company.is_custom_vendor | Boolean | Whether the company is a custom vendor. |
| SecurityScorecard.Company.total | Number | Total number of companies in Portfolio. |

#### Command Example
```!securityscorecard-portfolio-list-companies portfolio_id=60c78cxxxxxxxxxxxxx grade=A industry=information_services```

#### Context Example
```json
{
    "SecurityScorecard": {
        "Company": [
            {
                "domain": "google.com",
                "grade": "A",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_a.svg",
                "industry": "information_services",
                "is_custom_vendor": false,
                "last30days_score_change": 0,
                "name": "Monday",
                "score": 90,
                "size": "unknown"
            }
        ]
    }
}
```

#### Human Readable Output

None

### securityscorecard-company-score-get

***
Retrieve company overall score.

#### Base Command

`securityscorecard-company-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. google.com. The company must first be added to a Portfolio or else the API will return an error code 403. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.Score.domain | String | Company domain. |
| SecurityScorecard.Company.Score.name | String | Company name. |
| SecurityScorecard.Company.Score.score | Number | Company overall score in numeric form \(55-100\). |
| SecurityScorecard.Company.Score.grade | String | Company overall score in letter grade form \(A-F\). |
| SecurityScorecard.Company.Score.last30days_score_change | Number | Company overall score numeric change \(±\) in the last month. |
| SecurityScorecard.Company.Score.industry | String | Industry category of the domain. |
| SecurityScorecard.Company.Score.size | String | Company size, e.g. 'size_more_than_10000' |

#### Command Example
```!securityscorecard-company-score-get domain=google.com```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "Score": {
                "domain": "[google.com](https://google.com)",
                "grade": "C",
                "grade_url": "https://s3.amazonaws.com/ssc-static/grades/factor_c.svg",
                "industry": "Technology",
                "last30day_score_change": 1,
                "name": "Google",
                "score": 76,
                "size": "size_more_than_10000"
            }
        }
    }
}
```

#### Human Readable Output

None

### securityscorecard-company-factor-score-get

***
Retrieve company factor score.

#### Base Command

`securityscorecard-company-factor-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain. | Required |
| severity_in | Issue severity filter. Optional values can be positive, info, low, medium, high. Can be comma-separated list, e.g. 'medium,high,positive'. | Optional |

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

```!securityscorecard-company-factor-score-get domain=google.com severity_in=high```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "Factor": [
                {
                    "Grade": "F",
                    "Issue Details": [
                        {
                            "count": 1,
                            "detail_url": "https://api.securityscorecard.io/companies/google.com/issues/domain_missing_https/",
                            "severity": "high",
                            "total_score_impact": 1.5673117852559528,
                            "type": "domain_missing_https"
                        }
                    ],
                    "Issues": 1,
                    "Name": "Application Security",
                    "Score": 34
                },
                {
                    "Grade": "B",
                    "Issue Details": [],
                    "Issues": 0,
                    "Name": "Cubit Score",
                    "Score": 80
                },
                {
                    "Grade": "A",
                    "Issue Details": [],
                    "Issues": 0,
                    "Name": "Dns Health",
                    "Score": 100
                },
                ...
            ]
        }
    }
}
```

#### Human Readable Output

None

### securityscorecard-company-history-score-get

***
Retrieve company historical scores

#### Base Command

`securityscorecard-company-history-score-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. `google.com`. | Required | 
| from | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| to | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional |
| timing | Timing granularity. Acceptable values are `weekly` or `daily`. Possible values are: daily, weekly. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.History.domain | String | Company domain. |
| SecurityScorecard.Company.History.date | Date | Score date. |
| SecurityScorecard.Company.History.score | Number | Company historical security score in numeric form \(55-100\) |

#### Command Example

```!securityscorecard-company-history-score-get domain=google.com from=2021-06-01 to=2021-06-28 timing=weekly```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "History": [
                {
                    "date": "2021-06-05T00:00:00.000Z",
                    "domain": "google.com",
                    "score": 76
                },
                {
                    "date": "2021-06-12T00:00:00.000Z",
                    "domain": "google.com",
                    "score": 76
                },
                {
                    "date": "2021-06-19T00:00:00.000Z",
                    "domain": "google.com",
                    "score": 76
                },
                {
                    "date": "2021-06-26T00:00:00.000Z",
                    "domain": "google.com",
                    "score": 75
                },
                {
                    "date": "2021-06-28T00:00:00.000Z",
                    "domain": "google.com",
                    "score": 74
                }
            ]
        }
    }
}
```

### securityscorecard-company-history-factor-score-get

***
Retrieve company historical factor scores

#### Base Command

`securityscorecard-company-history-factor-score-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. google.com. | Required |
| from | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| to | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional |
| timing | Timing granularity. Acceptable values are "daily" (default), "weekly" or "monthly". Possible values are: daily, weekly, monthly. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.FactorHistory.domain | String | Company domain. |
| SecurityScorecard.Company.FactorHistory.date | Date | Score date. |
| SecurityScorecard.Company.FactorHistory.Factor.name | Number | Factor name. |
| SecurityScorecard.Company.FactorHistory.score | Number | Company historical security score in numeric form \(55-100\) |

#### Command Example

```!securityscorecard-company-history-factor-score-get domain=google.com from=2021-06-01 to=2021-06-30 timing=weekly```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Company": {
            "FactorHistory": [
                {
                    "date": "2021-06-05T00:00:00.000Z",
                    "domain": "google.com",
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
                    "domain": "google.com",
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
                    "domain": "google.com",
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
                    "domain": "google.com",
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
                    "domain": "google.com",
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

### securityscorecard-alert-grade-change-create

***
Create an alert based on grade change.

#### Base Command

`securityscorecard-alert-grade-change-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are 'rises' or 'drops'. Possible values are: rises, drops. | Required |
| score_types | Types of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. For multiple factors, leaked_information,social_engineering . | Required |
| target | What do you want to monitor with this alert. It could be one of the following 'my_scorecard', 'any_followed_company' or comma-separated Portfolio IDs, e.g. 60c78cc2d63162001a68c2b8,60c8c5f9139e40001908c6a4 or 60c78cc2d63162001a68c2b8,my_scorecard. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alert.id | String | Alert ID |

#### Command Example

```!securityscorecard-alert-grade-change-create change_direction=drops score_types=network_security,endpoint_security target=60c8c5f9139e40001908c6a4,my_scorecard```

#### Context Example

```json
{
    "SecurityScorecard": {
        "GradeChangeAlert": {
            "id": "7a164b90-dd91-11eb-b078-xxxxxxxxxxx"
        }
    }
}
```

### securityscorecard-alert-score-threshold-create

***
Create an alert based on a met score threshold.

#### Base Command

`securityscorecard-alert-score-threshold-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are: rises_above, drops_below. | Required |
| threshold | The numeric score used as the threshold to trigger the alert. | Required |
| score_types | Types of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. For multiple factors, leaked_information,social_engineering . | Required |
| target | What do you want to monitor with this alert. It could be one of the following 'my_scorecard', 'any_followed_company' or comma-separated Portfolio IDs, e.g. 60c78cc2d63162001a68c2b8,60c8c5f9139e40001908c6a4 or 60c78cc2d63162001a68c2b8,my_scorecard. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alert.id | String | Alert ID |


#### Command Example
```!securityscorecard-alert-score-threshold-create change_direction=drops_below threshold=100 score_types=network_security,dns_health target=60c8c5f9139e40001908c6a4,my_scorecard```

#### Context Example

```json
{
    "SecurityScorecard": {
        "ScoreThresholdAlert": {
            "id": "7bc3ad70-dd91-11eb-825c-b54fd05fe941"
        }
    }
}
```

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
```!securityscorecard-alert-delete alert_id=60c7bc3ad70-dd91-11eb-825c-b54fd05fe941 alert_type=score```

### securityscorecard-alerts-list

***
List alerts

#### Base Command

`securityscorecard-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portfolio_id | Portfolio ID. Can be retrieved using `securityscorecard-portfolios-list`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alert.id | String | Alert ID |
| SecurityScorecard.Alert.email | String | Alert email recipient. |
| SecurityScorecard.Alert.change_type | String | Alert change type configured \(score or threshold\) |
| SecurityScorecard.Alert.domain | String | Alert domain |
| SecurityScorecard.Alert.company_name | String | Alert company name |
| SecurityScorecard.Alert.Portfolio.id | array | Alert Portfolio ID |
| SecurityScorecard.Alert.my_scorecard | Boolean | Whether the alert was triggered on private scorecard. This depends on whether 'my_scorecard' was added to the optional argument 'target' when creating alerts using the `!securityscorecard-alert-score-threshold-create` and `!securityscorecard-alert-grade-change-create` commands. |
| SecurityScorecard.Alert.created_at | Date | Timestamp of when the alert was triggered | 

#### Command Example

```!securityscorecard-alerts-list```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Alert": [
            {
                "change_type": "score_change",
                "company": "Google",
                "created": "2021-07-04T23:08:41.746Z",
                "direction": "drops",
                "domain": "google.com",
                "factor": "endpoint_security",
                "grade_letter": "C",
                "id": "2dd66f12-37f0-5a9c-929d-1255b05053c3",
                "score": 75,
                "score_impact": -5
            },
            {
                "change_type": "score_change",
                "company": "Google",
                "created": "2021-07-01T21:16:52.249Z",
                "direction": "drops",
                "domain": "google.com",
                "factor": "patching_cadence",
                "grade_letter": "B",
                "id": "51ba6fa8-0185-56ec-8b15-e8e4be48b292",
                "score": 88,
                "score_impact": -2
            }
        ]
    }
}
```

### securityscorecard-company-services-get

***
Retrieve the service providers of a domain.

#### Base Command

`securityscorecard-company-services-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vendor_domain | String | Vendor domain, e.g. Google, Amazon |
| client_domain | String | Client domain. This value is identical to the input of the domain argument |
| categories | array | Vendor service provider, e.g. mail_provider, nameserver_provider |

#### Command Example
```!securityscorecard-company-services-get domain=google.com```

#### Context Example

```json
{
    "SecurityScorecard": {
        "Service": [
            {
                "vendor_domain": "proofpoint.com",
                "client_domain": "ml.com",
                "categories": [
                    "mail_provider",
                    "nameserver_provider"
                ]
            }
        ]
    }
}
```
