# DomainTools Iris Detect

#### Threat Actors Move Fast. Detect Helps You Move Faster.

Iris Detect is an Internet infrastructure detection, monitoring, and enforcement tool built on the industry’s fastest and broadest domain discovery engine and the largest databases of domain data. Capturing key data on new domains and risk-scoring them within minutes of discovery, Detect is a game-changer for brand managers, digital risk and fraud prevention teams, and network defenders.

#### Key Benefits

Rapid Discovery of Infringing Domains Continuous Monitoring of Evolving Infrastructure Enforcement Actions for Dangerous Domains

#### Fastest New Domain Discovery

Iris Detect employs the most sophisticated and extensive new-domain discovery capabilities, across all TLDs globally. Domains are enriched with preliminary Whois, DNS, and Risk Score data. The Iris Detect for Cortex XSOAR integration can create incidents as frequently as hourly,  incidents containing mapped indicators of newly-discovered domains matching the monitored keywords.

#### Watch Suspicious Domains for Changes

Through ad-hoc War-Room commands or on the incidents directly, domains of interest may be added to Iris Detect’s Watchlist, which triggers automatic daily updates, looking for hosting infrastructure or webpage changes. These changes can be consumed as their own incidents or sent to a separate workflow, giving you the ability to track evolving threat campaigns, classify, and identify which domains are most likely to do harm.

#### Enable Effective Enforcement

Merely knowing about malicious infrastructure is not enough. Iris Detect offers impactful enforcement options: Block flagged domains from incidents directly or using ad-hoc War-Room commands. Additionally, blocked domains can appear on their own feed, enabling you to take scripted enforcement actions in your security controls. Take action by sending domains to Google Phishing Protection, which can block them in Chrome, Firefox, and Safari, among other browsers.


## Configure DomainTools Iris Detect on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DomainTools Iris Detect.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                               | **Required** |
      |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- | --- |
   | DomainTools API Username | DomainTools API Username                                                                                                                                                                                                                                                                                                                                                                                                                      | True |
   | DomainTools API Key | DomainTools API Key to use for authentication                                                                                                                                                                                                                                                                                                                                                                                                                          | True |
   | Enabled on New Domains | Monitors the Iris Detect endpoint for newly discovered domains for active monitors in an account. This is the most commonly used option. If selected, each pull will create a new incident every time the enrichment is run, with the new domains attached as indicators to the incident. Whois and DNS information is preserved in comments.                                                                                                 | False |
   | Enabled on Changed Domains | Monitors the Iris Detect endpoint for recent changes to domains added to the watchlist. This is useful for monitoring changes to infrastructure after a domain has been triaged from the "new" endpoint or within the Iris Detect UI. If selected, each pull will create a new incident every time the enrichment is run, with the new domains attached as indicators to the incident. Whois and DNS information is preserved in comments.    | False |
   | Enabled on Blocked Domains | Monitors the Iris Detect endpoint for additions to domains added to the blocklist. Additions can be made via this app or the Iris Detect UI. This is useful for teams wishing to route triage domains to firewall software for blocking. If selected, each pull will create a new incident every time the enrichment is run, with the new domains attached as indicators to the incident. Whois and DNS information is preserved in comments. | False |
   | Risk score Ranges | Optionally specify a risk score range to triage higher risk indicators to different routing. A higher number indicates higher confidence a domain is likely to be used for malicious purposes.                                                                                                                                                                                                                                                | False |
   | Include Domain Data | Includes DNS and whois data in the response                                                                                                                                                                                                                                                                                                                                                                                                   | False |
   | First fetch timestamp | For the first time the enrichment is run, specify how far back should it pull indicators. First Fetch timestamp, Default is 3 days. The maximum time range is 30 days.                                                                                                                                                                                                                                                                        | False |
   | Trust any certificate (not secure) | Trust any certificate \(not secure\)                                                                                                                                                                                                                                                                                                                                                                                                          | False |
   | Use system proxy settings | Use system proxy settings                                                                                                                                                                                                                                                                                                                                                                                                                     | False |
   | Incident type | Optionally specify an incident type for incidents created by this integration to work with specific playbooks                                                                                                                                                                                                                                                                                                                                 | False |
   | Fetch incidents | This is a required field by XSOAR and should be set to 3, one for each possible feed type: new, changed, blocked.                                                                                                                                                                                                                                                                                                                             | False |
4. To ensure that fetch incidents works:
   1. Select the **Fetches incidents** radio button.
   2. Select **DomainTools Iris Detect - Classifier** from classifier drop-down.
   3. Select **DomainTools Iris Detect - Incoming Mapper** from mapper drop-down.
   4. Select **Create Incidents and Import Indicators** from Enabled on New Domains drop-down.
   5. Select **Create Incidents and Import Indicators** from Enabled on Changed Domains drop-down.
   6. Select **Create Incidents and Import Indicators** from Enabled on Blocked Domains drop-down.
5. Click **Test** to validate the URLs, token, and connection.


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### domaintools-iris-detect-escalate-domains

***
Reports a domain to Google's Safe Browsing API. After approval, their block list is picked up by Chrome and most modern browsers.

#### Base Command

`domaintools-iris-detect-escalate-domains`

#### Input

| **Argument Name**    | **Description**                                                                                                              | **Required** |
|----------------------|------------------------------------------------------------------------------------------------------------------------------|--------------|
| watchlist_domain_ids | List of Iris Detect domain IDs to escalate. The domain ID can be found using 'domaintools-iris-detect-get-new-domains' command. | Required     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainToolsIrisDetect.EscalatedDomain.watchlist_domain_id | String | The blocked domain ID. | 
| DomainToolsIrisDetect.EscalatedDomain.escalation_type | String | The escalation type. | 
| DomainToolsIrisDetect.EscalatedDomain.id | String | The ID. | 
| DomainToolsIrisDetect.EscalatedDomain.created_date | String | The date and time when the domain was created. | 
| DomainToolsIrisDetect.EscalatedDomain.updated_date | String | The date and time when the domain was updated. | 
| DomainToolsIrisDetect.EscalatedDomain.created_by | String | The email address of the person who created the escalated entry. | 

#### Command example

```!domaintools-iris-detect-escalate-domains watchlist_domain_ids="ba476NwNJW"```

#### Context Example

```json
{
    "DomainToolsIrisDetect": {
        "EscalatedDomain": [
            {
                "dt_created_by": "user@example.com",
                "dt_created_date_result": "2023-06-18T07:09:56.638704+00:00",
                "dt_escalation_type": "google_safe",
                "dt_id": "LpbmA0lboB",
                "dt_updated_date": "2023-06-18T07:09:56.638704+00:00",
                "dt_watchlist_domain_id": "ba476NwNJW"
            }
        ]
    }
}
```

#### Human Readable Output

>### Escalated Domains
>
>|dt_created_by|dt_created_date_result|dt_escalation_type|dt_id|dt_updated_date|dt_watchlist_domain_id|
>|---|---|---|---|---|---|
>| <user@example.com> | 2023-06-18T07:09:56.638704+00:00 | google_safe | LpbmA0lboB | 2023-06-18T07:09:56.638704+00:00 | ba476NwNJW |

### domaintools-iris-detect-blocklist-domains

***
Mark a given domain as blocked, which allows a script against the Iris Detect API to pass these domains on to other teams or security controls within your organization to block them in email, web, or other filtering controls.

#### Base Command

`domaintools-iris-detect-blocklist-domains`

#### Input

| **Argument Name**    | **Description**      | **Required**                                                                                                                            |
|----------------------|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| watchlist_domain_ids | List of Iris Detect domain IDs to escalate. The domain ID can be found using 'domaintools-iris-detect-get-new-domains, domaintools-iris-detect-get-watched-domains' commands. | Required     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainToolsIrisDetect.BlockedDomain.watchlist_domain_id | String | The blocked domain ID. | 
| DomainToolsIrisDetect.BlockedDomain.escalation_type | String | The escalation type. | 
| DomainToolsIrisDetect.BlockedDomain.id | String | The ID. | 
| DomainToolsIrisDetect.BlockedDomain.created_date | String | The date and time when the domain was created. | 
| DomainToolsIrisDetect.BlockedDomain.updated_date | String | The date and time when the domain was updated. | 
| DomainToolsIrisDetect.BlockedDomain.created_by | String | The email address of the person who created the blocked entry. | 

#### Command example

```!domaintools-iris-detect-blocklist-domains watchlist_domain_ids="7WbwkN9wGa"```

#### Context Example

```json
{
    "DomainToolsIrisDetect": {
        "BlockedDomain": [
            {
                "dt_created_by": "user@example.com",
                "dt_created_date_result": "2023-06-18T07:09:48.626367+00:00",
                "dt_escalation_type": "blocked",
                "dt_id": "qabz2ekbP1",
                "dt_updated_date": "2023-06-18T07:09:48.626367+00:00",
                "dt_watchlist_domain_id": "7WbwkN9wGa"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blocked Domains
>
>|dt_created_by|dt_created_date_result|dt_escalation_type|dt_id|dt_updated_date|dt_watchlist_domain_id|
>|---|---|---|---|---|---|
>| <user@example.com> | 2023-06-18T07:09:48.626367+00:00 | blocked | qabz2ekbP1 | 2023-06-18T07:09:48.626367+00:00 | 7WbwkN9wGa |

### domaintools-iris-detect-watch-domains

***
Mark a given domain as watched, which will trigger more frequent scanning by DomainTools automation. Changes to watched domains can trigger incidents if enabled, or manually queried via the domaintools-iris-detect-get-watched-domains command.

#### Base Command

`domaintools-iris-detect-watch-domains`

#### Input

| **Argument Name**    | **Description**                                                                                                               | **Required** |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------|--------------|
| watchlist_domain_ids | List of Iris Detect domain IDs to escalate. The domain ID can be found using 'domaintools-iris-detect-get-new-domains' command. | Required     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainToolsIrisDetect.WatchedDomain.state | String | Indicates that the domain is watched. | 
| DomainToolsIrisDetect.WatchedDomain.domain | String | The domain name. | 
| DomainToolsIrisDetect.WatchedDomain.discovered_date | String | The date and time when the domain was discovered \(e.g., "2023-04-21T01:56:14.652000\+00:00"\). | 
| DomainToolsIrisDetect.WatchedDomain.changed_date | String | The date and time when the domain information was last changed \(e.g., "2023-04-21T01:56:14.652000\+00:00"\). | 
| DomainToolsIrisDetect.WatchedDomain.id | String | The domain ID. | 
| DomainToolsIrisDetect.WatchedDomain.assigned_by | String | The email address of the person who assigned the domain to the watchlist. | 
| DomainToolsIrisDetect.WatchedDomain.assigned_date | String | The date and time when the domain was assigned to the watchlist \(e.g.,"2023-04-20T13:13:23.000000\+00:00"\). | 

#### Command example

```!domaintools-iris-detect-watch-domains watchlist_domain_ids="Ya2q68ldnW"```

#### Context Example

```json
{
    "DomainToolsIrisDetect": {
        "WatchedDomain": [
            {
                "dt_changed_date": "2023-06-18T02:18:06.000000+00:00",
                "dt_discovered_date": "2023-06-18T02:08:14.821000+00:00",
                "dt_domain": "suspicious-domain",
                "dt_domain_id": "Ya2q68ldnW",
                "dt_state": "watched"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watched Domains
>
>|dt_changed_date|dt_discovered_date|dt_domain|dt_domain_id|dt_state|
>|---|---|---|---|---|
>| 2023-06-18T02:18:06.000000+00:00 | 2023-06-18T02:08:14.821000+00:00 | suspicious-domain | Ya2q68ldnW | watched |

### domaintools-iris-detect-ignore-domains

***
Ignore a given domain, removing it from new and block lists, if applicable.

#### Base Command

`domaintools-iris-detect-ignore-domains`

#### Input

| **Argument Name**    | **Description**                           | **Required** |
|----------------------|-------------------------------------------|--------------|
| watchlist_domain_ids | List of Iris Detect domain IDs to escalate. The domain ID can be found using 'domaintools-iris-detect-get-new-domains, domaintools-iris-detect-get-watched-domains' command. | Required     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainToolsIrisDetect.IgnoredDomain.state | String | Indicates that the domain is ignored. | 
| DomainToolsIrisDetect.IgnoredDomain.domain | String | The domain name. | 
| DomainToolsIrisDetect.IgnoredDomain.discovered_date | String | The date and time when the domain was discovered \(e.g., "2023-04-21T01:56:14.652000\+00:00"\). | 
| DomainToolsIrisDetect.IgnoredDomain.changed_date | String | The date and time when the domain information was last changed \(e.g., "2023-04-21T01:56:14.652000\+00:00"\). | 
| DomainToolsIrisDetect.IgnoredDomain.id | String | The domain ID. | 
| DomainToolsIrisDetect.IgnoredDomain.assigned_by | String | The email address of the person who assigned the domain to the watchlist. | 
| DomainToolsIrisDetect.IgnoredDomain.assigned_date | String | The date and time when the domain was assigned to the watchlist \(e.g.,"2023-04-20T13:13:23.000000\+00:00"\). | 

#### Command example

```!domaintools-iris-detect-ignore-domains watchlist_domain_ids="XEmKQoLBPW"```

#### Context Example

```json
{
    "DomainToolsIrisDetect": {
        "IgnoredDomain": [
            {
                "dt_changed_date": "2023-06-18T03:21:47.000000+00:00",
                "dt_discovered_date": "2023-06-18T02:44:42.448000+00:00",
                "dt_domain": "benign-domain.com",
                "dt_domain_id": "XEmKQoLBPW",
                "dt_state": "ignored"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ignored Domains
>
>|dt_changed_date|dt_discovered_date|dt_domain|dt_domain_id|dt_state|
>|---|---|---|---|---|
>| 2023-06-18T03:21:47.000000+00:00 | 2023-06-18T02:44:42.448000+00:00 | benign-domain.com | XEmKQoLBPW | ignored |

### domaintools-iris-detect-get-monitors-list

***
This command allows users to retrieve the list of monitored terms and respective IDs associated with your organization's Iris Detect account. New terms can only be set up and configured directly within the Iris Detect UI (<https://iris.domaintools.com/detect/>). The results are limited to 100 monitors if include_counts is True, or 500 otherwise.

#### Base Command

`domaintools-iris-detect-get-monitors-list`

#### Input

| **Argument Name**     | **Description**                                                                                                                                                | **Required** |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| datetime_counts_since | ISO 8601 datetime format: default None. Conditionally required if the include_counts parameter is set to True. for example 2022-05-18T12:19:51.685496.         | Required     | 
| include_counts        | Includes counts for each monitor for new, watched, changed, and escalated domains. Possible values are: True, False.                                           | Optional     | 
| sort                  | Sort order for monitor list. Valid values are an ordered list of the following: ["term", "created_date", "domain_counts_changed", "domain_counts_discovered"]. | Optional     | 
| order                 | Sort order "asc" or "desc".                                                                                                                                    | Optional     | 

#### Context Output

| **Path**                                                 | **Type** | **Description**                                                                  |
|----------------------------------------------------------|----------|----------------------------------------------------------------------------------|
| DomainToolsIrisDetect.Monitor.term                       | String   | The keyword being monitored.                                                     | 
| DomainToolsIrisDetect.Monitor.match_substring_variations | Boolean  | A boolean indicating whether substring variations of the term should be matched. | 
| DomainToolsIrisDetect.Monitor.nameserver_exclusions      | Unknown  | An array for nameserver exclusions.                                              | 
| DomainToolsIrisDetect.Monitor.text_exclusions            | unknown  | An array for text exclusions.                                                    | 
| DomainToolsIrisDetect.Monitor.id                         | String   | A unique identifier for the monitor entry.                                       | 
| DomainToolsIrisDetect.Monitor.created_date               | String   | The timestamp when the monitor entry was created.                                | 
| DomainToolsIrisDetect.Monitor.updated_date               | String   | The timestamp when the monitor entry was last updated.                           | 
| DomainToolsIrisDetect.Monitor.state                      | String   | The state of the monitor entry.                                                  | 
| DomainToolsIrisDetect.Monitor.status                     | String   | The status of the monitor entry.                                                 | 
| DomainToolsIrisDetect.Monitor.created_by                 | String   | The email address of the person who created the monitor entry..                  | 

#### Command example

```!domaintools-iris-detect-get-monitors-list datetime_counts_since="2022-01-01"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "Monitor": [
      {
        "created_by": "user@example.com",
        "created_date": "2022-09-20T06:01:56.760955+00:00",
        "id": "QEMba8wmXo",
        "match_substring_variations": false,
        "nameserver_exclusions": [],
        "state": "active",
        "status": "completed",
        "term": "monitored_term1",
        "text_exclusions": [],
        "updated_date": "2022-09-20T06:02:33.358799+00:00"
      },
      {
        "created_by": "user@example.com",
        "created_date": "2022-09-16T22:29:20.567614+00:00",
        "id": "rA7bn46jq3",
        "match_substring_variations": false,
        "nameserver_exclusions": [],
        "state": "active",
        "status": "completed",
        "term": "monitored_term2",
        "text_exclusions": [],
        "updated_date": "2022-09-16T22:30:16.212269+00:00"
      },
      {
        "created_by": "user@example.com",
        "created_date": "2022-09-20T05:35:21.203482+00:00",
        "id": "YNrbr6GbKx",
        "match_substring_variations": false,
        "nameserver_exclusions": [],
        "state": "active",
        "status": "completed",
        "term": "monitored_term3",
        "text_exclusions": [],
        "updated_date": "2022-09-20T05:35:28.630194+00:00"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Monitor List
>
>|dt_created_by|dt_created_date|dt_match_substring_variations|dt_monitor_id|dt_nameserver_exclusions|dt_state|dt_status|dt_term|dt_text_exclusions|dt_updated_date|
>|---|---|---|---|---|---|---|---|---|---|
>| <user@example.com> | 2022-09-20T06:01:56.760955+00:00 | false | QEMba8wmXo |  | active | completed | monitored_term1 |  | 2022-09-20T06:02:33.358799+00:00 |
>| <user@example.com> | 2022-09-16T22:29:20.567614+00:00 | false | rA7bn46jq3 |  | active | completed | monitored_term2 |  | 2022-09-16T22:30:16.212269+00:00 |
>| <user@example.com> | 2022-09-20T05:35:21.203482+00:00 | false | YNrbr6GbKx |  | active | completed | monitored_term3 |  | 2022-09-20T05:35:28.630194+00:00 |

### domaintools-iris-detect-get-new-domains

***
Manually retrieve new domains matching all of your monitored terms, or a specific term specified by a "monitor_id" that can be retrieved using the domaintools-iris-detect-get-monitors-list command. The number of domains returned is limited to 50 if including DNS and whois details, or 100 otherwise. Use the page and page_size parameter for pagination.

#### Base Command

`domaintools-iris-detect-get-new-domains`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                     | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| discovered_since    | Filter domains by when they were discovered. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                         | Optional     | 
| monitor_id          | Monitor ID is used when requesting domains for a specific monitor. The monitor ID can be found using the 'domaintools-iris-detect-get-monitors-list' command.                                                                                        | Optional     | 
| tlds                | List of TLDs to filter domains by. E.g. top.                                                                                                                                        | Optional     | 
| mx_exists           | Filter domains by if they have an MX record in DNS. Possible values are: True, False.                                                                                               | Optional     | 
| risk_score_ranges   | List of risk score ranges to filter domains by. Valid values are: ["0-0", "1-39", "40-69", "70-99", "100-100"].                                                                     | Optional     | 
| search              | A "contains" search for any portion of a domain name.                                                                                                                               | Optional     | 
| sort                | Sort order for domain list. Valid values are an ordered list of the following: ["discovered_date", "changed_date", "risk_score"].                                                   | Optional     | 
| include_domain_data | Includes DNS and whois data in the response. Possible values are: True, False.                                                                                                      | Optional     | 
| preview             | "Preview" mode is helpful for initial setup and configuration. It limits the results to the first 10 results but removes hourly API restrictions. Possible values are: True, False. | Optional     | 
| order               | Sort order "asc" or "desc".                                                                                                                                                         | Optional     | 
| limit               | Default 100. Limit for pagination. Restricted to maximum 50 if include_domain_data is set to True.                                                                                  | Optional     |
| page                | The page number. Default is 1.                                                                                                                                                      | Optional     | 
| page_size           | The number of requested results per page. Default is 50.                                                                                                                            | Optional     |

#### Context Output

| **Path**                                                                | **Type** | **Description**                                                                                            |
|-------------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------|
| DomainToolsIrisDetect.New.state                                         | String   | Indicates that the domain is newly discovered.                                                             | 
| DomainToolsIrisDetect.New.domain                                        | String   | The domain name.                                                                                           | 
| DomainToolsIrisDetect.New.status                                        | String   | Indicates the status of the Domain (e.g., "active").                                                       | 
| DomainToolsIrisDetect.New.discovered_date                               | String   | The date and time when the domain was discovered (e.g., "2023-04-21T01:56:14.652000+00:00").               | 
| DomainToolsIrisDetect.New.changed_date                                  | String   | The date and time when the domain information was last changed (e.g., "2023-04-21T01:56:14.652000+00:00"). | 
| DomainToolsIrisDetect.New.risk_score                                    | String   | The risk score associated with the domain.                                                                 | 
| DomainToolsIrisDetect.New.risk_score_status                             | Number   | The status of the risk score.                                                                              | 
| DomainToolsIrisDetect.New.risk_score_components.proximity               | Number   | The domain's proximity risk score.                                                                         | 
| DomainToolsIrisDetect.New.risk_score_components.threat_profile.phishing | Number   | The domain's phishing threat score.                                                                        | 
| DomainToolsIrisDetect.New.risk_score_components.threat_profile.malware  | Number   | The domain's malware threat score.                                                                         | 
| DomainToolsIrisDetect.New.risk_score_components.threat_profile.spam     | Number   | The domain's spam threat score.                                                                            | 
| DomainToolsIrisDetect.New.risk_score_components.threat_profile.evidence | unknown  | The list of evidence supporting the threat scores.                                                         | 
| DomainToolsIrisDetect.New.mx_exists                                     | Boolean  | Indicates that there is no MX record for the domain.                                                       | 
| DomainToolsIrisDetect.New.tld                                           | String   | The top-level domain.                                                                                      | 
| DomainToolsIrisDetect.New.id                                            | String   | The domain ID.                                                                                             | 
| DomainToolsIrisDetect.New.escalations.escalation_type                   | String   | The type of escalation.                                                                                    | 
| DomainToolsIrisDetect.New.escalations.id                                | String   | The escalation ID.                                                                                         | 
| DomainToolsIrisDetect.New.escalations.created                           | String   | The date and time when the escalation was created.                                                         | 
| DomainToolsIrisDetect.New.escalations.created_by                        | String   | The email address of the person who assigned the domain to the watchlist.                                  | 
| DomainToolsIrisDetect.New.monitor_ids                                   | String   | An array containing a single monitor ID.                                                                   | 
| DomainToolsIrisDetect.New.assigned_by                                   | String   | The email address of the person who assigned the domain to the watchlist.                                  | 
| DomainToolsIrisDetect.New.assigned_date                                 | String   | The date and time when the domain was assigned to the watchlist (e.g.,"2023-04-20T13:13:23.000000+00:00"). | 
| DomainToolsIrisDetect.New.registrant_contact_email                      | String   | Registrant Email.                                                                                          | 
| DomainToolsIrisDetect.New.name_server                                   | String   | An array of objects containing name server information.                                                    | 
| DomainToolsIrisDetect.New.registrar                                     | String   | The domain registrar.                                                                                      | 
| DomainToolsIrisDetect.New.create_date                                   | String   | The date when the domain was created.                                                                      | 
| DomainToolsIrisDetect.New.ip.country_code                               | String   | Country code for the ip.                                                                                   | 
| DomainToolsIrisDetect.New.ip.ip                                         | String   | Associated ip for the Domain.                                                                              | 
| DomainToolsIrisDetect.New.ip.isp                                        | String   | Associated isp for the Domain.                                                                             | 

#### Command example

```!domaintools-iris-detect-get-new-domains limit="2"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "New": [
      {
        "changed_date": "2023-04-11T05:16:56.483000+00:00",
        "discovered_date": "2023-04-11T05:16:56.483000+00:00",
        "domain": "fakedomaintask.shop",
        "escalations": [],
        "id": "KW3ykVGZRE",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": null,
        "risk_score_status": null,
        "state": "new",
        "status": "active",
        "tld": "shop"
      },
      {
        "changed_date": "2023-04-11T05:15:42.000000+00:00",
        "discovered_date": "2023-04-11T05:12:22.081000+00:00",
        "domain": "fakedomain.com",
        "escalations": [],
        "id": "gWlYVZxmJa",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": 79,
        "risk_score_components": {
          "proximity": 4,
          "threat_profile": {
            "phishing": 79
          }
        },
        "risk_score_status": "provisional",
        "state": "new",
        "status": "active",
        "tld": "com"
      }
    ]
  }
}
```

#### Human Readable Output

> ### New Domains
>
>|dt_changed_date|dt_create_date|dt_discovered_date|dt_domain|dt_domain_id|dt_escalations|dt_monitor_ids|dt_mx_exists|dt_proximity_score|dt_registrant_contact_email|dt_registrar|dt_risk_score|dt_risk_status|dt_state|dt_status|dt_threat_profile_evidence|dt_threat_profile_malware|dt_threat_profile_phishing|dt_threat_profile_spam|dt_tld|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2023-04-11T05:16:56.483000+00:00 |  | 2023-04-11T05:16:56.483000+00:00 | fakedomaintask.shop | KW3ykVGZRE |  | rA7bn46jq3 | false |  |  |  |  |  | new | active |  |  |  |  | shop |
>| 2023-04-11T05:15:42.000000+00:00 |  | 2023-04-11T05:12:22.081000+00:00 | fakedomain.com | gWlYVZxmJa |  | rA7bn46jq3 | false | 4 |  |  | 79 | provisional | new | active |  |  | 79 |  | com |

### domaintools-iris-detect-get-watched-domains

***
Manually retrieve changes to domains that have been marked as "watched" by users of your organization, matching all of your monitored terms, or a specific term specified by a "monitor_id" that can be retrieved using the domaintools-iris-detect-get-monitors-list command. The number of domains returned is limited to 50 if including DNS and whois details, or 100 otherwise. Use the page and page_size parameter for pagination.

#### Base Command

`domaintools-iris-detect-get-watched-domains`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                     | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| escalation_types    | escalation_types: List[str]: default None. List of escalation types to filter domains by. Valid values are: ["blocked", "google_safe"].                                             | Optional     | 
| monitor_id          | Monitor ID is used when requesting domains for a specific monitor. The monitor ID can be found using the 'domaintools-iris-detect-get-monitors-list' command.                                                                                        | Optional     | 
| tlds                | List of TLDs to filter domains by. E.g. top.                                                                                                                                        | Optional     | 
| mx_exists           | Filter domains by if they have an MX record in DNS. Possible values are: True, False.                                                                                               | Optional     | 
| changed_since       | Filter domains by when they were last changed. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                       | Optional     | 
| search              | A "contains" search for any portion of a domain name.                                                                                                                               | Optional     | 
| sort                | Sort order for domain list. Valid values are an ordered list of the following: ["discovered_date", "changed_date", "risk_score"].                                                   | Optional     | 
| include_domain_data | Includes DNS and whois data in the response. Possible values are: True, False.                                                                                                      | Optional     | 
| preview             | "Preview" mode is helpful for initial setup and configuration. It limits the results to the first 10 results but removes hourly API restrictions. Possible values are: True, False. | Optional     | 
| escalated_since     | Filter domains by when they were last escalated. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                     | Optional     | 
| order               | Sort order "asc" or "desc".                                                                                                                                                         | Optional     | 
| risk_score_ranges   | List of risk score ranges to filter domains by. Valid values are: ["0-0", "1-39", "40-69", "70-99", "100-100"].                                                                     | Optional     | 
| limit               | Default 100. Limit for pagination. Restricted to maximum 50 if include_domain_data is set to True.                                                                                  | Optional     |
| page                | The page number. Default is 1.                                                                                                                                                      | Optional     | 
| page_size           | The number of requested results per page. Default is 50.                                                                                                                            | Optional     |

#### Context Output

| **Path**                                                                    | **Type** | **Description**                                                                                            |
|-----------------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------|
| DomainToolsIrisDetect.Watched.state                                         | String   | Indicates that the domain is being watched.                                                                | 
| DomainToolsIrisDetect.Watched.domain                                        | String   | The domain name.                                                                                           | 
| DomainToolsIrisDetect.Watched.status                                        | String   | Indicates the status of the Domain (e.g., "active").                                                       | 
| DomainToolsIrisDetect.Watched.discovered_date                               | String   | The date and time when the domain was discovered (e.g., "2023-04-21T01:56:14.652000+00:00").               | 
| DomainToolsIrisDetect.Watched.changed_date                                  | String   | The date and time when the domain information was last changed (e.g., "2023-04-21T01:56:14.652000+00:00"). | 
| DomainToolsIrisDetect.Watched.risk_score                                    | String   | The risk score associated with the domain.                                                                 | 
| DomainToolsIrisDetect.Watched.risk_score_status                             | Number   | The status of the risk score.                                                                              | 
| DomainToolsIrisDetect.Watched.risk_score_components.proximity               | Number   | The domain's proximity risk score.                                                                         | 
| DomainToolsIrisDetect.Watched.risk_score_components.threat_profile.phishing | Number   | The domain's phishing threat score.                                                                        | 
| DomainToolsIrisDetect.Watched.risk_score_components.threat_profile.malware  | Number   | The domain's malware threat score.                                                                         | 
| DomainToolsIrisDetect.Watched.risk_score_components.threat_profile.spam     | Number   | The domain's spam threat score.                                                                            | 
| DomainToolsIrisDetect.Watched.risk_score_components.threat_profile.evidence | Unknown  | The list of evidence supporting the threat scores.                                                         | 
| DomainToolsIrisDetect.Watched.mx_exists                                     | Boolean  | Indicates that there is no MX record for the domain.                                                       | 
| DomainToolsIrisDetect.Watched.tld                                           | String   | The top-level domain.                                                                                      | 
| DomainToolsIrisDetect.Watched.id                                            | String   | The domain ID.                                                                                             | 
| DomainToolsIrisDetect.Watched.escalations.escalation_type                   | String   | The type of escalation.                                                                                    | 
| DomainToolsIrisDetect.Watched.escalations.id                                | String   | The escalation ID.                                                                                         | 
| DomainToolsIrisDetect.Watched.escalations.created                           | String   | The date and time when the escalation was created.                                                         | 
| DomainToolsIrisDetect.Watched.escalations.created_by                        | String   | The email address of the person who created the escalation.                                                | 
| DomainToolsIrisDetect.Watched.monitor_ids                                   | String   | An array containing a single monitor ID.                                                                   | 
| DomainToolsIrisDetect.Watched.assigned_by                                   | String   | The email address of the person who assigned the domain to the watchlist.                                  | 
| DomainToolsIrisDetect.Watched.assigned_date                                 | String   | The date and time when the domain was assigned to the watchlist (e.g.,"2023-04-20T13:13:23.000000+00:00"). | 
| DomainToolsIrisDetect.Watched.registrant_contact_email                      | String   | Registrant Email.                                                                                          | 
| DomainToolsIrisDetect.Watched.name_server                                   | String   | The domain registrar.                                                                                      | 
| DomainToolsIrisDetect.Watched.registrar                                     | String   | The domain registrar.                                                                                      | 
| DomainToolsIrisDetect.Watched.create_date                                   | String   | The date when the domain was created.                                                                      | 
| DomainToolsIrisDetect.Watched.ip.country_code                               | String   | Country code for the ip.                                                                                   | 
| DomainToolsIrisDetect.Watched.ip.ip                                         | String   | Associated ip for the Domain.                                                                              | 
| DomainToolsIrisDetect.Watched.ip.isp                                        | String   | Associated isp for the Domain.                                                                             | 

#### Command example

```!domaintools-iris-detect-get-watched-domains limit="2"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "Watched": [
      {
        "assigned_by": "user@example.com",
        "assigned_date": "2023-04-11T04:46:39.000000+00:00",
        "changed_date": "2023-04-10T07:52:11.000000+00:00",
        "discovered_date": "2023-04-10T07:45:31.478000+00:00",
        "domain": "fakedomain.net.tr",
        "escalations": [
          {
            "created": "2023-04-11T04:46:39.181378+00:00",
            "created_by": "user@example.com",
            "escalation_type": "google_safe",
            "id": "43gB2PwG6m"
          }
        ],
        "id": "8Wq8Qj9x7P",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": 8,
        "risk_score_components": {
          "proximity": 5,
          "threat_profile": {
            "evidence": [],
            "malware": 1,
            "phishing": 6,
            "spam": 8
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "net.tr"
      },
      {
        "changed_date": "2023-04-10T05:58:01.000000+00:00",
        "discovered_date": "2023-04-10T04:52:28.545000+00:00",
        "domain": "fakedomain.co",
        "escalations": [
          {
            "created": "2023-04-10T14:33:11.342255+00:00",
            "created_by": "user@example.com",
            "escalation_type": "blocked",
            "id": "nzgWDr3B9Y"
          }
        ],
        "id": "gaeMyYl1va",
        "monitor_ids": [
          "QEMba8wmXo"
        ],
        "mx_exists": true,
        "risk_score": 21,
        "risk_score_components": {
          "proximity": 21,
          "threat_profile": {
            "evidence": [],
            "malware": 20,
            "phishing": 15,
            "spam": 17
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "co"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Watched Domains
>
>|dt_changed_date|dt_create_date|dt_discovered_date|dt_domain|dt_domain_id|dt_escalations|dt_monitor_ids|dt_mx_exists|dt_proximity_score|dt_registrant_contact_email|dt_registrar|dt_risk_score|dt_risk_status|dt_state|dt_status|dt_threat_profile_evidence|dt_threat_profile_malware|dt_threat_profile_phishing|dt_threat_profile_spam|dt_tld|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2023-04-10T07:52:11.000000+00:00 |  | 2023-04-10T07:45:31.478000+00:00 | fakedomain.net.tr | 8Wq8Qj9x7P | {'escalation_type': 'google_safe', 'id': '43gB2PwG6m', 'created': '2023-04-11T04:46:39.181378+00:00', 'created_by': '<user@example.com>'} | rA7bn46jq3 | false | 5 |  |  | 8 | full | watched | active |  | 1 | 6 | 8 | net.tr |
>| 2023-04-10T05:58:01.000000+00:00 |  | 2023-04-10T04:52:28.545000+00:00 | fakedomain.co | gaeMyYl1va | {'escalation_type': 'blocked', 'id': 'nzgWDr3B9Y', 'created': '2023-04-10T14:33:11.342255+00:00', 'created_by': '<user@example.com>'} | QEMba8wmXo | true | 21 |  |  | 21 | full | watched | active |  | 20 | 15 | 17 | co |

### domaintools-iris-detect-get-ignored-domains

***
Manually retrieve domains that your organization has marked as ignored, matching all of your monitored terms, or a specific term specified by a "monitor_id" that can be retrieved using the domaintools-iris-detect-get-monitors-list command. This is most useful in cases when a domain might have been mistakenly ignored. The number of domains returned is limited to 50 if including DNS and whois details, or 100 otherwise. Use the page and page_size parameter for pagination.

#### Base Command

`domaintools-iris-detect-get-ignored-domains`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                     | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| risk_score_ranges   | List of risk score ranges to filter domains by. Valid values are: ["0-0", "1-39", "40-69", "70-99", "100-100"].                                                                     | Optional     | 
| monitor_id          | Monitor ID is used when requesting domains for a specific monitor. The monitor ID can be found using the 'domaintools-iris-detect-get-monitors-list' command.                                                                                        | Optional     | 
| tlds                | List of TLDs to filter domains by. E.g. top.                                                                                                                                        | Optional     | 
| mx_exists           | Filter domains by if they have an MX record in DNS. Possible values are: True, False.                                                                                               | Optional     | 
| changed_since       | Filter domains by when they were last changed. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                       | Optional     | 
| escalated_since     | Filter domains by when they were last escalated. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                     | Optional     | 
| search              | A "contains" search for any portion of a domain name.                                                                                                                               | Optional     | 
| sort                | Sort order for domain list. Valid values are an ordered list of the following: ["discovered_date", "changed_date", "risk_score"].                                                   | Optional     | 
| include_domain_data | Includes DNS and whois data in the response. Possible values are: True, False.                                                                                                      | Optional     | 
| preview             | "Preview" mode is helpful for initial setup and configuration. It limits the results to the first 10 results but removes hourly API restrictions. Possible values are: True, False. | Optional     | 
| order               | Sort order "asc" or "desc".                                                                                                                                                         | Optional     | 
| limit               | Default 100. Limit for pagination. Restricted to maximum 50 if include_domain_data is set to True.                                                                                  | Optional     |
| page                | The page number. Default is 1.                                                                                                                                                      | Optional     | 
| page_size           | The number of requested results per page. Default is 50.                                                                                                                            | Optional     |

#### Context Output

| **Path**                                                                    | **Type** | **Description**                                                                                            |
|-----------------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------|
| DomainToolsIrisDetect.Ignored.state                                         | String   | Indicates that the domain is being ignored.                                                                | 
| DomainToolsIrisDetect.Ignored.domain                                        | String   | The domain name.                                                                                           | 
| DomainToolsIrisDetect.Ignored.status                                        | String   | Indicates the status of the Domain (e.g., "active").                                                       | 
| DomainToolsIrisDetect.Ignored.discovered_date                               | String   | The date and time when the domain was discovered (e.g., "2023-04-21T01:56:14.652000+00:00").               | 
| DomainToolsIrisDetect.Ignored.changed_date                                  | String   | The date and time when the domain information was last changed (e.g., "2023-04-21T01:56:14.652000+00:00"). | 
| DomainToolsIrisDetect.Ignored.risk_score                                    | String   | The risk score associated with the domain.                                                                 | 
| DomainToolsIrisDetect.Ignored.risk_score_status                             | Number   | The status of the risk score.                                                                              | 
| DomainToolsIrisDetect.Ignored.risk_score_components.proximity               | Number   | The domain's proximity risk score.                                                                         | 
| DomainToolsIrisDetect.Ignored.risk_score_components.threat_profile.phishing | Number   | The domain's phishing threat score.                                                                        | 
| DomainToolsIrisDetect.Ignored.risk_score_components.threat_profile.malware  | Number   | The domain's malware threat score.                                                                         | 
| DomainToolsIrisDetect.Ignored.risk_score_components.threat_profile.spam     | Number   | The domain's spam threat score.                                                                            | 
| DomainToolsIrisDetect.Ignored.risk_score_components.threat_profile.evidence | unknown  | The list of evidence supporting the threat scores.                                                         | 
| DomainToolsIrisDetect.Ignored.mx_exists                                     | Boolean  | Indicates that there is no MX record for the domain.                                                       | 
| DomainToolsIrisDetect.Ignored.tld                                           | String   | The top-level domain.                                                                                      | 
| DomainToolsIrisDetect.Ignored.id                                            | String   | The domain ID.                                                                                             | 
| DomainToolsIrisDetect.Ignored.escalations.escalation_type                   | String   | The type of escalation.                                                                                    | 
| DomainToolsIrisDetect.Ignored.escalations.id                                | String   | The escalation ID.                                                                                         | 
| DomainToolsIrisDetect.Ignored.escalations.created                           | String   | The date and time when the escalation was created.                                                         | 
| DomainToolsIrisDetect.Ignored.escalations.created_by                        | String   | The email address of the person who created the escalation.                                                | 
| DomainToolsIrisDetect.Ignored.monitor_ids                                   | String   | An array containing a single monitor ID.                                                                   | 
| DomainToolsIrisDetect.Ignored.assigned_by                                   | String   | The email address of the person who assigned the domain to the watchlist.                                  | 
| DomainToolsIrisDetect.Ignored.assigned_date                                 | String   | The date and time when the domain was assigned to the watchlist (e.g.,"2023-04-20T13:13:23.000000+00:00"). | 
| DomainToolsIrisDetect.Ignored.registrant_contact_email                      | String   | Registrant Email.                                                                                          | 
| DomainToolsIrisDetect.Ignored.name_server                                   | String   | An array of objects containing name server information.                                                    | 
| DomainToolsIrisDetect.Ignored.registrar                                     | String   | The domain registrar.                                                                                      | 
| DomainToolsIrisDetect.Ignored.create_date                                   | String   | The date when the domain was created.                                                                      | 
| DomainToolsIrisDetect.Ignored.ip.country_code                               | String   | Country code for the ip.                                                                                   | 
| DomainToolsIrisDetect.Ignored.ip.ip                                         | String   | Associated ip for the Domain.                                                                              | 
| DomainToolsIrisDetect.Ignored.ip.isp                                        | String   | Associated isp for the Domain.                                                                             | 

#### Command example

```!domaintools-iris-detect-get-ignored-domains limit="2"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "Ignored": [
      {
        "assigned_by": "user@example.com",
        "assigned_date": "2023-03-27T04:45:19.000000+00:00",
        "changed_date": "2023-03-30T09:07:59.000000+00:00",
        "discovered_date": "2023-03-21T13:57:47.094000+00:00",
        "domain": "fakedomainn.shop",
        "escalations": [
          {
            "created": "2023-03-21T17:33:51.787271+00:00",
            "created_by": "user@example.com",
            "escalation_type": "blocked",
            "id": "VrxaQQ2xNK"
          },
          {
            "created": "2023-03-21T17:35:10.150279+00:00",
            "created_by": "user@example.com",
            "escalation_type": "google_safe",
            "id": "kzbwQQ2EY2"
          }
        ],
        "id": "VE87zKvOxa",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": true,
        "risk_score": 100,
        "risk_score_components": {
          "proximity": 100,
          "threat_profile": {
            "evidence": [
              "registrant",
              "domain name",
              "name server"
            ],
            "malware": 98,
            "phishing": 99,
            "spam": 82
          }
        },
        "risk_score_status": "full",
        "state": "ignored",
        "status": "active",
        "tld": "shop"
      },
      {
        "changed_date": "2023-03-25T08:04:15.000000+00:00",
        "discovered_date": "2023-02-08T10:32:18.665000+00:00",
        "domain": "walletfakedomain.com",
        "escalations": [],
        "id": "ya6dKwrRzP",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": true,
        "risk_score": 100,
        "risk_score_components": {
          "proximity": 100,
          "threat_profile": {
            "evidence": [
              "domain name",
              "registrar",
              "name server"
            ],
            "malware": 19,
            "phishing": 95,
            "spam": 43
          }
        },
        "risk_score_status": "full",
        "state": "ignored",
        "status": "active",
        "tld": "com"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Ignored Domains
>
>|dt_changed_date|dt_create_date|dt_discovered_date|dt_domain|dt_domain_id|dt_escalations|dt_monitor_ids|dt_mx_exists|dt_proximity_score|dt_registrant_contact_email|dt_registrar|dt_risk_score|dt_risk_status|dt_state|dt_status|dt_threat_profile_evidence|dt_threat_profile_malware|dt_threat_profile_phishing|dt_threat_profile_spam|dt_tld|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2023-03-30T09:07:59.000000+00:00 |  | 2023-03-21T13:57:47.094000+00:00 | fakedomainn.shop | VE87zKvOxa | {'escalation_type': 'blocked', 'id': 'VrxaQQ2xNK', 'created': '2023-03-21T17:33:51.787271+00:00', 'created_by': '<user@example.com>'}, {'escalation_type': 'google_safe', 'id': 'kzbwQQ2EY2', 'created': '2023-03-21T17:35:10.150279+00:00', 'created_by': '<user@example.com>'} | rA7bn46jq3 | true | 100 |  |  | 100 | full | ignored | active | registrant, domain name, name server | 98 | 99 | 82 | shop |
>| 2023-03-25T08:04:15.000000+00:00 |  | 2023-02-08T10:32:18.665000+00:00 | walletfakedomain.com | ya6dKwrRzP |  | rA7bn46jq3 | true | 100 |  |  | 100 | full | ignored | active | domain name, registrar, name server | 19 | 95 | 43 | com |

### domaintools-iris-detect-get-escalated-domains

***
Manually retrieve domains that your organization has escalated to Google Safe Browsing, matching all of your monitored terms, or a specific term specified by a "monitor_id" that can be retrieved using the domaintools-iris-detect-get-monitors-list command. The number of domains returned is limited to 50 if including DNS and whois details, or 100 otherwise. Use the page and page_size parameter for pagination.

#### Base Command

`domaintools-iris-detect-get-escalated-domains`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                     | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| risk_score_ranges   | List of risk score ranges to filter domains by. Valid values are: ["0-0", "1-39", "40-69", "70-99", "100-100"].                                                                     | Optional     | 
| monitor_id          | Monitor ID is used when requesting domains for a specific monitor. The monitor ID can be found using the 'domaintools-iris-detect-get-monitors-list' command.                                                                                        | Optional     | 
| tlds                | List of TLDs to filter domains by. E.g. top.                                                                                                                                        | Optional     | 
| mx_exists           | Filter domains by if they have an MX record in DNS.                                                                                                                                 | Optional     | 
| changed_since       | Filter domains by when they were last changed. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                       | Optional     | 
| escalated_since     | Filter domains by when they were last escalated. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                     | Optional     | 
| search              | A "contains" search for any portion of a domain name.                                                                                                                               | Optional     | 
| sort                | Sort order for domain list. Valid values are an ordered list of the following: ["discovered_date", "changed_date", "risk_score"].                                                   | Optional     | 
| include_domain_data | Includes DNS and whois data in the response. Possible values are: True, False.                                                                                                      | Optional     | 
| preview             | "Preview" mode is helpful for initial setup and configuration. It limits the results to the first 10 results but removes hourly API restrictions. Possible values are: True, False. | Optional     | 
| order               | Sort order "asc" or "desc".                                                                                                                                                         | Optional     | 
| limit               | Default 100. Limit for pagination. Restricted to maximum 50 if include_domain_data is set to True.                                                                                  | Optional     |
| page                | The page number. Default is 1.                                                                                                                                                      | Optional     | 
| page_size           | The number of requested results per page. Default is 50.                                                                                                                            | Optional     |

#### Context Output

| **Path**                                                                      | **Type** | **Description**                                                                                                 |
|-------------------------------------------------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------|
| DomainToolsIrisDetect.Escalated.state                                         | String   | Indicates that the domain is being watched.                                                                     | 
| DomainToolsIrisDetect.Escalated.domain                                        | String   | The domain name.                                                                                                | 
| DomainToolsIrisDetect.Escalated.status                                        | String   | Indicates the status of the Domain (e.g., "active").                                                            | 
| DomainToolsIrisDetect.Escalated.discovered_date                               | String   | The date and time when the domain was discovered (e.g., "2023-04-21T01:56:14.652000+00:00").                    | 
| DomainToolsIrisDetect.Escalated.changed_date                                  | String   | The date and time when the domain information was last changed (e.g., "2023-04-21T01:56:14.652000+00:00").      | 
| DomainToolsIrisDetect.Escalated.risk_score                                    | String   | The risk score associated with the domain.                                                                      | 
| DomainToolsIrisDetect.Escalated.risk_score_status                             | Number   | The status of the risk score.                                                                                   | 
| DomainToolsIrisDetect.Escalated.risk_score_components.proximity               | Number   | The domain's proximity risk score.                                                                              | 
| DomainToolsIrisDetect.Escalated.risk_score_components.threat_profile.phishing | Number   | The domain's phishing threat score.                                                                             | 
| DomainToolsIrisDetect.Escalated.risk_score_components.threat_profile.malware  | Number   | The domain's malware threat score.                                                                              | 
| DomainToolsIrisDetect.Escalated.risk_score_components.threat_profile.spam     | Number   | The domain's spam threat score.                                                                                 | 
| DomainToolsIrisDetect.Escalated.risk_score_components.threat_profile.evidence | Unknown  | The list of evidence supporting the threat scores.                                                              | 
| DomainToolsIrisDetect.Escalated.mx_exists                                     | Boolean  | Indicates that there is no MX record for the domain.                                                            | 
| DomainToolsIrisDetect.Escalated.tld                                           | String   | The top-level domain.                                                                                           | 
| DomainToolsIrisDetect.Escalated.id                                            | String   | The domain ID.                                                                                                  | 
| DomainToolsIrisDetect.Escalated.escalations.escalation_type                   | String   | The type of escalation.                                                                                         | 
| DomainToolsIrisDetect.Escalated.escalations.id                                | String   | The escalation ID.                                                                                              | 
| DomainToolsIrisDetect.Escalated.escalations.created                           | String   | The date and time when the escalation was created.                                                              | 
| DomainToolsIrisDetect.Escalated.escalations.created_by                        | String   | The email address of the person who created the escalation.                                                     | 
| DomainToolsIrisDetect.Escalated.monitor_ids                                   | String   | An array containing monitor IDs.                                                                                | 
| DomainToolsIrisDetect.Escalated.assigned_by                                   | String   | The email address of the person who assigned the domain to the watchlist.                                       | 
| DomainToolsIrisDetect.Escalated.assigned_date                                 | String   | The date and time when the domain was assigned to the escalated list (e.g.,"2023-04-20T13:13:23.000000+00:00"). | 
| DomainToolsIrisDetect.Escalated.registrant_contact_email                      | String   | Registrant Email.                                                                                               | 
| DomainToolsIrisDetect.Escalated.name_server                                   | String   | An array of objects containing name server information.                                                         | 
| DomainToolsIrisDetect.Escalated.registrar                                     | String   | The domain registrar.                                                                                           | 
| DomainToolsIrisDetect.Escalated.create_date                                   | String   | The date when the domain was created.                                                                           | 
| DomainToolsIrisDetect.Escalated.ip.country_code                               | String   | Country code for the ip.                                                                                        | 
| DomainToolsIrisDetect.Escalated.ip.ip                                         | String   | Associated ip for the Domain.                                                                                   | 
| DomainToolsIrisDetect.Escalated.ip.isp                                        | String   | Associated isp for the Domain.                                                                                  | 

#### Command example

```!domaintools-iris-detect-get-escalated-domains limit="2"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "Escalated": [
      {
        "assigned_by": "user@example.com",
        "assigned_date": "2023-04-11T04:46:39.000000+00:00",
        "changed_date": "2023-04-10T07:52:11.000000+00:00",
        "discovered_date": "2023-04-10T07:45:31.478000+00:00",
        "domain": "fakedomain.net.tr",
        "escalations": [
          {
            "created": "2023-04-11T04:46:39.181378+00:00",
            "created_by": "user@example.com",
            "escalation_type": "google_safe",
            "id": "43gB2PwG6m"
          }
        ],
        "id": "8Wq8Qj9x7P",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": 8,
        "risk_score_components": {
          "proximity": 5,
          "threat_profile": {
            "evidence": [],
            "malware": 1,
            "phishing": 6,
            "spam": 8
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "net.tr"
      },
      {
        "assigned_by": "user@example.com",
        "assigned_date": "2023-04-11T05:18:05.000000+00:00",
        "changed_date": "2023-04-05T12:44:21.000000+00:00",
        "discovered_date": "2023-04-05T12:07:54.646000+00:00",
        "domain": "fakedomain.nexus",
        "escalations": [
          {
            "created": "2023-04-11T05:18:05.262047+00:00",
            "created_by": "user@example.com",
            "escalation_type": "google_safe",
            "id": "43gB2a3G6m"
          }
        ],
        "id": "ZadmVQOj0E",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": 0,
        "risk_score_components": {
          "proximity": 0,
          "threat_profile": {
            "phishing": 53
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "nexus"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Escalated Domains
>
>|dt_changed_date|dt_create_date|dt_discovered_date|dt_domain|dt_domain_id|dt_escalations|dt_monitor_ids|dt_mx_exists|dt_proximity_score|dt_registrant_contact_email|dt_registrar|dt_risk_score|dt_risk_status|dt_state|dt_status|dt_threat_profile_evidence|dt_threat_profile_malware|dt_threat_profile_phishing|dt_threat_profile_spam|dt_tld|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2023-04-10T07:52:11.000000+00:00 |  | 2023-04-10T07:45:31.478000+00:00 | fakedomain.net.tr | 8Wq8Qj9x7P | {'escalation_type': 'google_safe', 'id': '43gB2PwG6m', 'created': '2023-04-11T04:46:39.181378+00:00', 'created_by': '<user@example.com>'} | rA7bn46jq3 | false | 5 |  |  | 8 | full | watched | active |  | 1 | 6 | 8 | net.tr |
>| 2023-04-05T12:44:21.000000+00:00 |  | 2023-04-05T12:07:54.646000+00:00 | fakedomain.nexus | ZadmVQOj0E | {'escalation_type': 'google_safe', 'id': '43gB2PwG6m', 'created': '2023-04-11T05:18:05.262047+00:00', 'created_by': '<user@example.com>'} | rA7bn46jq3 | false | 0 |  |  | 0 | full | watched | active |  |  | 53 |  | nexus |

### domaintools-iris-detect-get-blocklist-domains

***
Manually retrieve domains that your organization has marked as "blocklisted", matching all of your monitored terms, or a specific term specified by a "monitor_id" that can be retrieved using the domaintools-iris-detect-get-monitors-list command. The number of domains returned is limited to 50 if including DNS and whois details, or 100 otherwise. Use the page and page_size parameter for pagination. Use the page and page_size parameter for pagination.

#### Base Command

`domaintools-iris-detect-get-blocklist-domains`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                     | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| monitor_id          | Monitor ID is used when requesting domains for a specific monitor. The monitor ID can be found using the 'domaintools-iris-detect-get-monitors-list' command.                                                                                        | Optional     | 
| tlds                | List of TLDs to filter domains by. E.g. top.                                                                                                                                        | Optional     | 
| mx_exists           | Filter domains by if they have an MX record in DNS. Possible values are: True, False.                                                                                               | Optional     | 
| changed_since       | Filter domains by when they were last changed. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                       | Optional     | 
| search              | Sort order for domain list. Valid values are an ordered list.                                                                                                                       | Optional     | 
| sort                | Sort order for domain list. Possible values are: discovered_date, changed_date, risk_score.                                                                                         | Optional     | 
| include_domain_data | Includes DNS and whois data in the response. Possible values are: True, False.                                                                                                      | Optional     | 
| preview             | "Preview" mode is helpful for initial setup and configuration. It limits the results to the first 10 results but removes hourly API restrictions. Possible values are: True, False. | Optional     | 
| escalated_since     | Filter domains by when they were last escalated. Provide a datetime in ISO 8601 format, for example 2022-05-18T12:19:51.685496.                                                     | Optional     | 
| order               | Sort order "asc" or "desc".                                                                                                                                                         | Optional     | 
| risk_score_ranges   | List of risk score ranges to filter domains by. Valid values are: ["0-0", "1-39", "40-69", "70-99", "100-100"].                                                                     | Optional     | 
| limit               | Default 100. Limit for pagination. Restricted to maximum 50 if include_domain_data is set to True.                                                                                  | Optional     |
| page                | The page number. Default is 1.                                                                                                                                                      | Optional     | 
| page_size           | The number of requested results per page. Default is 50.                                                                                                                            | Optional     |

#### Context Output

| **Path**                                                                    | **Type** | **Description**                                                                                               |
|-----------------------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------------------------|
| DomainToolsIrisDetect.Blocked.state                                         | String   | Indicates that the domain is being watched.                                                                   | 
| DomainToolsIrisDetect.Blocked.domain                                        | String   | The domain name.                                                                                              | 
| DomainToolsIrisDetect.Blocked.status                                        | String   | Indicates the status of the Domain (e.g., "active").                                                          | 
| DomainToolsIrisDetect.Blocked.discovered_date                               | String   | The date and time when the domain was discovered (e.g., "2023-04-21T01:56:14.652000+00:00").                  | 
| DomainToolsIrisDetect.Blocked.changed_date                                  | String   | The date and time when the domain information was last changed (e.g., "2023-04-21T01:56:14.652000+00:00").    | 
| DomainToolsIrisDetect.Blocked.risk_score                                    | String   | The risk score associated with the domain.                                                                    | 
| DomainToolsIrisDetect.Blocked.risk_score_status                             | Number   | The status of the risk score.                                                                                 | 
| DomainToolsIrisDetect.Blocked.risk_score_components.proximity               | Number   | The domain's proximity risk score.                                                                            | 
| DomainToolsIrisDetect.Blocked.risk_score_components.threat_profile.phishing | Number   | The domain's phishing threat score.                                                                           | 
| DomainToolsIrisDetect.Blocked.risk_score_components.threat_profile.malware  | Number   | The domain's malware threat score.                                                                            | 
| DomainToolsIrisDetect.Blocked.risk_score_components.threat_profile.spam     | Number   | The domain's spam threat score.                                                                               | 
| DomainToolsIrisDetect.Blocked.risk_score_components.threat_profile.evidence | Unknown  | The list of evidence supporting the threat scores.                                                            | 
| DomainToolsIrisDetect.Blocked.mx_exists                                     | Boolean  | Indicates that there is no MX record for the domain.                                                          | 
| DomainToolsIrisDetect.Blocked.tld                                           | String   | The top-level domain.                                                                                         | 
| DomainToolsIrisDetect.Blocked.id                                            | String   | The domain ID.                                                                                                | 
| DomainToolsIrisDetect.Blocked.escalations.escalation_type                   | String   | The type of escalation.                                                                                       | 
| DomainToolsIrisDetect.Blocked.escalations.id                                | String   | The escalation ID.                                                                                            | 
| DomainToolsIrisDetect.Blocked.escalations.created                           | String   | The date and time when the escalation was created.                                                            | 
| DomainToolsIrisDetect.Blocked.escalations.created_by                        | String   | The email address of the person who created the escalation.                                                   | 
| DomainToolsIrisDetect.Blocked.monitor_ids                                   | String   | An array containing monitor IDs.                                                                              | 
| DomainToolsIrisDetect.Blocked.assigned_by                                   | String   | The email address of the person who assigned the domain to the watchlist..                                    | 
| DomainToolsIrisDetect.Blocked.assigned_date                                 | String   | The date and time when the domain was assigned to the blocked list (e.g.,"2023-04-20T13:13:23.000000+00:00"). | 
| DomainToolsIrisDetect.Blocked.registrant_contact_email                      | String   | Registrant Email.                                                                                             | 
| DomainToolsIrisDetect.Blocked.name_server                                   | String   | An array of objects containing name server information.                                                       | 
| DomainToolsIrisDetect.Blocked.registrar                                     | String   | The domain registrar.                                                                                         | 
| DomainToolsIrisDetect.Blocked.create_date                                   | String   | The date when the domain was created.                                                                         | 
| DomainToolsIrisDetect.Blocked.ip.country_code                               | String   | Country code for the ip.                                                                                      | 
| DomainToolsIrisDetect.Blocked.ip.ip                                         | String   | Associated ip for the Domain.                                                                                 | 
| DomainToolsIrisDetect.Blocked.ip.isp                                        | String   | Associated isp for the Domain.                                                                                | 

#### Command example

```!domaintools-iris-detect-get-blocklist-domains limit="2"```

#### Context Example

```json
{
  "DomainToolsIrisDetect": {
    "Blocked": [
      {
        "changed_date": "2023-04-10T05:58:01.000000+00:00",
        "discovered_date": "2023-04-10T04:52:28.545000+00:00",
        "domain": "fakedomain.co",
        "escalations": [
          {
            "created": "2023-04-10T14:33:11.342255+00:00",
            "created_by": "user@example.com",
            "escalation_type": "blocked",
            "id": "nzgWDr3B9Y"
          }
        ],
        "id": "gaeMyYl1Va",
        "monitor_ids": [
          "QEMba8wmXo"
        ],
        "mx_exists": true,
        "risk_score": 21,
        "risk_score_components": {
          "proximity": 21,
          "threat_profile": {
            "evidence": [],
            "malware": 20,
            "phishing": 15,
            "spam": 17
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "co"
      },
      {
        "assigned_by": "user@example.com",
        "assigned_date": "2023-04-11T05:18:00.000000+00:00",
        "changed_date": "2023-04-05T15:08:54.000000+00:00",
        "discovered_date": "2023-04-05T15:01:50.701000+00:00",
        "domain": "fakedomain.mov",
        "escalations": [
          {
            "created": "2023-04-11T05:17:59.782456+00:00",
            "created_by": "user@example.com",
            "escalation_type": "blocked",
            "id": "nzgWDAzB9Y"
          }
        ],
        "id": "gaeMVJX8ea",
        "monitor_ids": [
          "rA7bn46jq3"
        ],
        "mx_exists": false,
        "risk_score": 0,
        "risk_score_components": {
          "proximity": 0,
          "threat_profile": {
            "phishing": 53
          }
        },
        "risk_score_status": "full",
        "state": "watched",
        "status": "active",
        "tld": "mov"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Blocked Domains
>
>|dt_changed_date|dt_create_date|dt_discovered_date|dt_domain|dt_domain_id|dt_escalations|dt_monitor_ids|dt_mx_exists|dt_proximity_score|dt_registrant_contact_email|dt_registrar|dt_risk_score|dt_risk_status|dt_state|dt_status|dt_threat_profile_evidence|dt_threat_profile_malware|dt_threat_profile_phishing|dt_threat_profile_spam|dt_tld|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2023-04-10T05:58:01.000000+00:00 |  | 2023-04-10T04:52:28.545000+00:00 | fakedomain.co | gaeMyYl1Va | {'escalation_type': 'blocked', 'id': 'nzgWDr3B9Y', 'created': '2023-04-10T14:33:11.342255+00:00', 'created_by': '<user@example.com>'} | QEMba8wmXo | true | 21 |  |  | 21 | full | watched | active |  | 20 | 15 | 17 | co |
>| 2023-04-05T15:08:54.000000+00:00 |  | 2023-04-05T15:01:50.701000+00:00 | fakedomain.mov | gaeMVJX8ea | {'escalation_type': 'blocked', 'id': 'nzgWDr3B9Y', 'created': '2023-04-11T05:17:59.782456+00:00', 'created_by': '<user@example.com>'} | rA7bn46jq3 | false | 0 |  |  | 0 | full | watched | active |  |  | 53 |  | mov |

### domaintools-iris-detect-reset-fetch-indicators

***
This command will reset your fetch history.

#### Base Command

`domaintools-iris-detect-reset-fetch-indicators`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!domaintools-iris-detect-reset-fetch-indicators```

#### Human Readable Output

> Fetch history deleted successfully
