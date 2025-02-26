Provides commands to access SecurityScorecard's API.
This integration was integrated and tested with the latest version of SecurityScorecard's API as of August 2024.

## Configure SecurityScorecard in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| SecurityScorecard API Base URL |  | True |
| Username/Email | The SecurityScorecard username/email. | True |
| API Token |  | True |
| Fetch incidents |  | False |
| Incidents Fetch Interval | SecurityScorecard is updated on a daily basis therefore there's no need to modify this value. | False |
| Fetch Limit | Maximum number of alerts per fetch. The maximum is 50. | False |
| First fetch | First fetch query \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days. SecurityScorecard provides a maximum of 7 days back. To ensure no alerts are missed, it's recommended to use a value less than 2 days. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Portfolio ID |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### securityscorecard-portfolios-list

***
List all Portfolios.

#### Base Command

`securityscorecard-portfolios-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the amount of Portfolios to return. Defaults to 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Portfolio.id | String | Portfolio ID. | 
| SecurityScorecard.Portfolio.name | String | Portfolio name. | 
| SecurityScorecard.Portfolio.description | String | Portfolio description. | 
| SecurityScorecard.Portfolio.privacy | String | Portfolio privacy. Can be either private, shared or team. | 
| SecurityScorecard.Portfolio.read_only | Boolean | Whether the portfolio is read only. | 

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
| had_breach_within_last_days | Domains with breaches in the last X days. Possible values are numbers, e.g. 1000. | Optional | 

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
| SecurityScorecard.Portfolio.Company.size | String | Company size, e.g. 'size_more_than_10000'. | 
| SecurityScorecard.Portfolio.Company.is_custom_vendor | Boolean | Whether the company is a custom vendor. | 
| SecurityScorecard.Portfolio.Company.total | Number | Total number of companies in Portfolio. | 

### securityscorecard-company-score-get

***
Retrieve company overall score.

#### Base Command

`securityscorecard-company-score-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. google.com. The company must first be added to a Portfolio in order to be able to get its score. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.Score.domain | String | Company domain. | 
| SecurityScorecard.Company.Score.name | String | Company name. | 
| SecurityScorecard.Company.Score.score | Number | Company overall score in numeric form \(55-100\). | 
| SecurityScorecard.Company.Score.grade | String | Company overall score in letter grade form \(A-F\). | 
| SecurityScorecard.Company.Score.last30days_score_change | Number | Company overall score numeric change \(±\) in the last month. | 
| SecurityScorecard.Company.Score.industry | String | ndustry category of the domain. | 
| SecurityScorecard.Company.Score.size | String | Company size, e.g. 'size_more_than_10000'. | 

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
| SecurityScorecard.Company.Factor.score | Number | Factor score in numeric form \(55-100\). | 
| SecurityScorecard.Company.Factor.grade | String | Factor score in letter grade form \(A-F\). | 
| SecurityScorecard.Company.Factor.Issue.type | String | Type of issue found. | 
| SecurityScorecard.Company.Factor.Issue.count | Number | How many times the issue was found. | 
| SecurityScorecard.Company.Factor.Issue.severity | String | Severity of the issue. | 
| SecurityScorecard.Company.Factor.Issue.total_score_impact | Number | Contribution of issue on overall score. | 
| SecurityScorecard.Company.Factor.Issue.detail_url | String | URL to the details of the issue. | 
| SecurityScorecard.Company.Factor.total | Number | Number of factors returned. | 

### securityscorecard-company-history-score-get

***
Retrieve company historical scores.

#### Base Command

`securityscorecard-company-history-score-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. `google.com`. | Required | 
| from | Initial date for historical data. Value should be in format `YYYY-MM-DD`. | Optional | 
| to | End date for historical data. Value should be in format `YYYY-MM-DD`. | Optional | 
| timing | Timing granularity. Possible values are: daily, weekly. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.ScoreHistory.domain | String | Company domain. | 
| SecurityScorecard.Company.ScoreHistory.date | Date | Score date. | 
| SecurityScorecard.Company.ScoreHistory.score | Number | Company historical security score in numeric form \(55-100\). | 

### securityscorecard-company-history-factor-score-get

***
Retrieve company historical factor scores.

#### Base Command

`securityscorecard-company-history-factor-score-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. google.com. | Required | 
| from | Initial date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional | 
| to | End date for historical data. Value should be in format 'YYYY-MM-DD'. | Optional | 
| timing | Timing granularity. or "monthly". Possible values are: daily, weekly, monthly. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Company.FactorHistory.domain | String | Company domain. | 
| SecurityScorecard.Company.FactorHistory.date | Date | Score date. | 
| SecurityScorecard.Company.FactorHistory.Factor.name | Number | Factor name. | 
| SecurityScorecard.Company.FactorHistory.score | Number | Company historical security score in numeric form \(55-100\). | 

### securityscorecard-alert-grade-change-create

***
Create alert based on grade.

#### Base Command

`securityscorecard-alert-grade-change-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are: rises, drops. | Required | 
| score_types | Comma-separated list of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. | Required | 
| target | What do you want to monitor with this alert. This argument is required if the `portfolio` argument is not specified. Possible values are: my_scorecard, any_followed_company. | Optional | 
| portfolio | A portfolio_id to use as a target for the alert. This argument is required if the `target` argument is not specified. You can get a list of portfolios by running `!securityscorecard-portfolios-list`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.GradeChangeAlert.id | String | Alert ID. | 

### securityscorecard-alert-score-threshold-create

***
Create alert based threshold met.

#### Base Command

`securityscorecard-alert-score-threshold-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_direction | Direction of change. Possible values are: rises_above, drops_below. | Required | 
| threshold | The numeric score used as the threshold to trigger the alert. | Required | 
| score_types | Comma separated list of risk factors to monitor. Possible values are 'overall', 'any_factor_score', 'network_security', 'dns_health', 'patching_cadence', 'endpoint_security', 'ip_reputation', 'application_security', 'cubit_score', 'hacker_chatter', 'leaked_information', 'social_engineering'. For multiple factors, provide comma-separated list, i.e. leaked_information,social_engineering. | Required | 
| target | What do you want to monitor with this alert. This argument is required if the `portfolio` argument is not specified. Possible values are: my_scorecard, any_followed_company. | Optional | 
| portfolio | A portfolio_id to use as a target for the alert. This argument is required if the `target` argument is not specified. You can get a list of portfolios by running `!securityscorecard-portfolios-list`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.ScoreThresholdAlert.id | String | Alert ID. | 

### securityscorecard-alert-delete

***
Delete an alert.

#### Base Command

`securityscorecard-alert-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 

#### Context Output

There is no context output for this command.

### securityscorecard-alerts-list

***
List alerts triggered in the last week.

#### Base Command

`securityscorecard-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portfolio_id | Portfolio ID. Can be retrieved using `!securityscorecard-portfolios-list`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Alerts.Alert.id | String | Alert ID. | 
| SecurityScorecard.Alerts.Alert.email | String | Alert email recipient. | 
| SecurityScorecard.Alerts.Alert.change_type | String | Alert change type configured \(score or threshold\). | 
| SecurityScorecard.Alerts.Alert.domain | String | Alert domain. | 
| SecurityScorecard.Alerts.Alert.company_name | String | Alert company name. | 
| SecurityScorecard.Alerts.Alert.Portfolio.id | array | Alert Portfolio ID. | 
| SecurityScorecard.Alerts.Alert.my_scorecard | Boolean | Whether the alert was triggered on private scorecard. This depends on whether 'my_scorecard' was added to the optional argument 'target' when creating alerts using the 'securityscorecard-alert-score-threshold-create' and 'securityscorecard-alert-grade-change-create' commands. | 
| SecurityScorecard.Alerts.Alert.created_at | Date | Timestamp of when the alert was triggered. | 

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
| SecurityScorecard.Service.vendor_domain | String | Vendor domain, e.g. Google, Amazon. | 
| SecurityScorecard.Service.client_domain | String | Client domain. This value is identical to the input of the domain argument. | 
| SecurityScorecard.Service.categories | array | Vendor service provider, e.g. mail_provider, nameserver_provider. | 

### securityscorecard-company-events-get

***
Retrieve a company's historical events.

#### Base Command

`securityscorecard-company-events-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Company domain, e.g. google.com. | Required | 
| date_from | Initial date for historical data. Value should be in format `2020-01-30T00:00:00.000Z`. | Optional | 
| date_to | End date for historical data. Value should be in format `2020-01-30T00:00:00.000Z`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Events.Event.ssc_event_id | string | event id. | 
| SecurityScorecard.Events.Event.date | date | event date. | 
| SecurityScorecard.Events.Event.status | unknown | event status. | 
| SecurityScorecard.Events.Event.issue_count | number | event issue count. | 
| SecurityScorecard.Events.Event.score_impact | number | event score impact. | 
| SecurityScorecard.Events.Event.issue_type | string | event issue type. | 
| SecurityScorecard.Events.Event.severity | string | event severity. | 
| SecurityScorecard.Events.Event.factor | string | event factor. | 
| SecurityScorecard.Events.Event.ssc_detail_url | string | event detail url. | 

### securityscorecard-company-findings-get

***
Retrieve an issue_type's historical findings in a scorecard.

#### Base Command

`securityscorecard-company-findings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Retrieve the service providers of a domain. | Required | 
| date | The effective_date for historical data. Value should be in format 'YYYY-MM-DD'. | Required | 
| issue_type | Key representing issue type, e.g. api_key_exposed. | Required | 
| status | group_status filter. Comma-separated list of the following values: 'active', 'inactive', 'all'. | Optional | 

#### Context Output

There is no context output for this command.

### securityscorecard-issue-metadata

***
Retrieve metadata for an issue type, including description and recommendation.

#### Base Command

`securityscorecard-issue-metadata`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_type | Key representing issue type, e.g. api_key_exposed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.Metadata.Issues.key | string | Key representing issue type, e.g. api_key_exposed. | 
| SecurityScorecard.Metadata.Issues.severity | string | issue severity. | 
| SecurityScorecard.Metadata.Issues.factor | string | issue factor. | 
| SecurityScorecard.Metadata.Issues.title | string | issue title. | 
| SecurityScorecard.Metadata.Issues.short_description | string | issue short description. | 
| SecurityScorecard.Metadata.Issues.long_description | string | issue long description. | 
| SecurityScorecard.Metadata.Issues.recommendation | string | issue recommendation. | 

### securityscorecard-alert-rules-list

***
List alert subscriptions for the user.

#### Base Command

`securityscorecard-alert-rules-list`

#### Input

This command does not require any arguments.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.AlertRules.Rule.id | String | Alert Rule ID. | 
| SecurityScorecard.AlertRules.Rule.name | String | Alert Rule name. | 
| SecurityScorecard.AlertRules.Rule.target | String | Target of the Rule. | 
| SecurityScorecard.AlertRules.Rule.updated_at | Date | Timestamp when the alert rule was last updated. | 
| SecurityScorecard.AlertRules.Rule.paused_at | String | Timestamp when the alert rule was paused. |

### securityscorecard-issue-details-get

***
Retrieve issue details for a specific issue type and domain.

##### Base Command

`securityscorecard-issue-details-get`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to get the issue details for. | Required |
| issue_type | The issue type to get the details for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityScorecard.IssueDetails.issue_id | String | Unique UUID for this measurement. | 
| SecurityScorecard.IssueDetails.parent_domain | String | Parent domain aka vendor. | 
| SecurityScorecard.IssueDetails.issue_type | String | issue_type of the findings. | 
| SecurityScorecard.IssueDetails.count | Number | The number of findings. | 
| SecurityScorecard.IssueDetails.group_status | String | If findings are active or not. |
| SecurityScorecard.IssueDetails.first_seen_time | Date | Epoch of observation in nanoseconds. |
| SecurityScorecard.IssueDetails.last_seen_time | Date | Epoch of observation in nanoseconds. |
| SecurityScorecard.IssueDetails.port | Number | Port number of the observation if applicable. |
| SecurityScorecard.IssueDetails.domain | String | Domain of the observation if applicable. |
| SecurityScorecard.IssueDetails.ip | String | IP address of the observation if applicable. |
| SecurityScorecard.IssueDetails.protocol | String | Protocol of the observation if applicable. |
| SecurityScorecard.IssueDetails.observations | String | Observation data in raw JSON format. |