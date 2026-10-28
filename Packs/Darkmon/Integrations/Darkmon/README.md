Stay ahead of cyber threats with Darkmon TIP - real-time threat intelligence from the Clear, Deep, and Dark Web tailored to your assets.
Pack also helps with integration with Cortex XSOAR and provides pre-made playbooks/templates to ease integration use.

## Configure Darkmon in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Base URL | Override the Darkmon TIP API base URL only if your tenant points at a non-default endpoint. The default value already targets the production Darkmon TIP service \(https://api.darkmon.com/tip/2025.1\). Leave blank to use the default. | False |
| API key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Redact secrets in War Room output | When enabled, replaces password/card-number values in markdown table output with '\*\*\*'. Raw values remain in rawJSON for playbook automation. Disable only in non-production debugging contexts. | False |
| Employee compromise disable mode | Controls how the Compromised Employee Auto-Disable playbook reacts when a new compromised employee account is observed. notify-only \(default - safe\): creates an incident, no AD action.  approval-required: creates an incident with a manual approval task; on approve, runs the disable.  auto-disable: disables the account immediately. Accounts in the "Darkmon - Auto-Disable Allowlist" list are NEVER auto-disabled regardless of mode. | False |
| First fetch time | First fetch query time range when starting from a clean state. Accepts ISO timestamps or relative durations \(e.g. "3 days", "12 hours"\). | False |
| Maximum number of incidents per fetch | Caps the number of Darkmon records ingested as incidents per fetch cycle to protect the war room from sudden backlogs. | False |
| Darkmon incident types to fetch | Which Darkmon record kinds the integration ingests as XSOAR incidents. Defaults to the high-signal trio. Lower-signal kinds \(e.g. Ransomware Mention\) are typically better handled via the monitoring playbooks rather than native fetch. | False |
| Incident type |  |  |
| Fetch incidents |  |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dmontip-global-search

***
The dmontip-global-search command performs a comprehensive search across the Darkmon Threat Intelligence Platform. This command allows users to search for indicators, threat actors, malware, and other intelligence data using keywords or specific search terms. It queries multiple data sources simultaneously and returns consolidated results, helping analysts quickly find relevant intelligence across the platform.

#### Base Command

`dmontip-global-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of the value. Possible values are: Domain, IP, URL, Hash, CVE, Email, Username, Malware, Source, Keyword, Card, CardNumber, CardHolder. | Required |
| query | A specific value. | Required |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results matching the query, with type-specific fields. |
| Darkmon.Pagination.number | Number | Current page number \(zero-indexed at the API\). |
| Darkmon.Pagination.totalPages | Number | Total number of pages available. |
| Darkmon.Pagination.totalElements | Number | Total number of items across all pages. |

### ip

***
Searches the Darkmon platform for intelligence related to a specific IP address. A focused interface for threat intelligence lookup of IP indicators.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | One or more IP addresses to enrich (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results for the IP indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Source reliability per the Admiralty code. |
| IP.Address | String | The IP address. |
| IP.Malicious.Vendor | String | The vendor that flagged this IP as malicious. |
| IP.Malicious.Description | String | Reason this IP was flagged as malicious. |

### url

***
Searches for URL-specific threat intelligence across the Darkmon platform. Quickly identifies malicious or suspicious URLs and associated threat data.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | One or more URLs to enrich (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results for the URL indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Source reliability per the Admiralty code. |
| URL.Data | String | The URL. |
| URL.Malicious.Vendor | String | The vendor that flagged this URL as malicious. |
| URL.Malicious.Description | String | Reason this URL was flagged as malicious. |

### domain

***
Performs domain-focused threat intelligence searches in the Darkmon platform. Returns comprehensive information about potentially malicious domains.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | One or more domains to enrich (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results for the domain indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Source reliability per the Admiralty code. |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor | String | The vendor that flagged this domain as malicious. |
| Domain.Malicious.Description | String | Reason this domain was flagged as malicious. |

### email

***
Searches for threat intelligence related to specific email addresses. Identifies compromised accounts or emails associated with malicious activities.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | One or more email addresses to enrich (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results for the email indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Source reliability per the Admiralty code. |
| Account.Email.Address | String | The email address. |
| Account.Email.Malicious.Vendor | String | The vendor that flagged this email as malicious. |
| Account.Email.Malicious.Description | String | Reason this email was flagged as malicious. |

### file

***
Searches the Darkmon platform using file hash values (MD5, SHA-1, SHA-256). Identifies malware and provides associated threat intelligence data.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | One or more file hashes (MD5, SHA-1, SHA-256) to enrich (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.SearchResult | Unknown | Search results for the file-hash indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Source reliability per the Admiralty code. |
| File.MD5 | String | MD5 of the file \(when the input was an MD5 hash\). |
| File.SHA1 | String | SHA-1 of the file \(when the input was a SHA-1 hash\). |
| File.SHA256 | String | SHA-256 of the file \(when the input was a SHA-256 hash\). |
| File.Malicious.Vendor | String | The vendor that flagged this file as malicious. |
| File.Malicious.Description | String | Reason this file was flagged as malicious. |

### dmontip-get-compromised

***
Retrieve compromised data of a given type from Darkmon - leaked accounts, leaked bank cards, combo lists, public breaches, or compromised employee accounts. Use the 'type' argument to choose the data set.

#### Base Command

`dmontip-get-compromised`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Which compromised data set to retrieve. Possible values are: accounts, bank-cards, combo-lists, public-breaches, employees. | Required |
| size | Page size (1-500). Default is 20. | Optional |
| page | 1-indexed page number. Default is 1. | Optional |
| sort | Sort field and direction in Spring Pageable format, e.g. 'firstSeen,desc' or 'lastCompromiseDate,asc'. Leave blank to use the default: combo-lists defaults to firstSeen,desc; other types use the backend default order. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.Compromised.Account | Unknown | Leaked account records \(when type=accounts\). |
| Darkmon.Compromised.BankCard | Unknown | Leaked bank card records \(when type=bank-cards\). |
| Darkmon.Compromised.ComboList | Unknown | Combo list records \(when type=combo-lists\). |
| Darkmon.Compromised.PublicBreach | Unknown | Public breach records \(when type=public-breaches\). |
| Darkmon.Compromised.Employee | Unknown | Compromised employee account records \(when type=employees\). |
| Darkmon.Compromised.Page | Unknown | Pagination metadata \(number, totalPages, totalElements\). |

### dmontip-get-vpn

***
Retrieve known VPN exit-node IOCs with pagination, sorted newest first by firstSeen unless overridden.

#### Base Command

`dmontip-get-vpn`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| sort | Sort field and direction in Spring Pageable format. Default sorts newest first by firstSeen. Default is firstSeen,desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.VPN | Unknown | Known VPN exit-node records. |
| Darkmon.VPN.Page | Unknown | Pagination metadata. |

### dmontip-get-proxy

***
Retrieve known open-proxy IOCs with pagination, sorted newest first by firstSeen unless overridden.

#### Base Command

`dmontip-get-proxy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| sort | Sort field and direction in Spring Pageable format. Default sorts newest first by firstSeen. Default is firstSeen,desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.Proxy | Unknown | Known open-proxy records. |
| Darkmon.Proxy.Page | Unknown | Pagination metadata. |

### dmontip-get-cve

***
Retrieve security vulnerabilities (CVEs) with severity, CVSS score, published/lastModified timestamps, source identifier, and tags.

#### Base Command

`dmontip-get-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.CVE | Unknown | CVE records. |
| Darkmon.CVE.Page | Unknown | Pagination metadata. |

### dmontip-get-nrd

***
Retrieve newly registered domains (NRD) recently observed by Darkmon, sorted newest first by timestamp unless overridden. Filters the IOC feed by classification NEWLY_REGISTERED_DOMAIN.

#### Base Command

`dmontip-get-nrd`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| sort | Sort field and direction in Spring Pageable format. Default sorts newest first by timestamp. Default is timestamp,desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.NRD | Unknown | Newly registered domain records. |
| Darkmon.NRD.Page | Unknown | Pagination metadata. |

### dmontip-get-tbf

***
Retrieve telnet brute-force IOCs - sources observed attempting telnet brute-force attacks, sorted newest first by timestamp unless overridden. Filters the IOC feed by classification TELNET_BRUTE_FORCE.

#### Base Command

`dmontip-get-tbf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| sort | Sort field and direction in Spring Pageable format. Default sorts newest first by timestamp. Default is timestamp,desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.TBF | Unknown | Telnet brute-force IOC records. |
| Darkmon.TBF.Page | Unknown | Pagination metadata. |

### dmontip-get-ransomware

***
Retrieve ransomware articles or company-specific ransomware mentions with details such as victim name, threat actor, published date, and matched keywords. Sorted newest first by publishedAt unless overridden.

#### Base Command

`dmontip-get-ransomware`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 10. | Optional |
| type | Use 'mentions' to retrieve company-specific ransomware mentions, or 'all-topics' to retrieve all ransomware articles. Possible values are: mentions, all-topics. Default is mentions. | Required |
| sort | Sort field and direction in Spring Pageable format. Default sorts newest first by publishedAt. Default is publishedAt,desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.Ransomware | Unknown | Ransomware article or mention records. |
| Darkmon.Ransomware.Page | Unknown | Pagination metadata. |

### dmontip-get-landscape

***
Retrieve cybersecurity landscape news articles or company-specific landscape mentions with title, link, source, author, and matched keywords.

#### Base Command

`dmontip-get-landscape`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 10. | Optional |
| type | Use 'mentions' to retrieve company-specific landscape news mentions, or 'all-topics' to retrieve all landscape news articles. Possible values are: mentions, all-topics. Default is mentions. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.Landscape | Unknown | Landscape article or mention records. |
| Darkmon.Landscape.Page | Unknown | Pagination metadata. |

### dmontip-get-boardprotection

***
Lists the emails currently under board-leak protection (monitored) including request state, owner name, and tokens. Backed by the board-leak/request endpoint.

#### Base Command

`dmontip-get-boardprotection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| term | Optional search term filtering across all available attributes. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.BoardProtection | Unknown | Board protection request records \(monitored emails with state and owner details\). |
| Darkmon.BoardProtection.Page | Unknown | Pagination metadata. |

### dmontip-get-boardemails

***
Retrieves leaked accounts, combo lists, or public breaches associated with a board-protected email. Use dmontip-get-boardprotection first to list monitored emails.

#### Base Command

`dmontip-get-boardemails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Which board-leak data set to retrieve for the given email. Possible values are: accounts, combo-lists, public-breaches. | Required |
| email | The protected email to query (must be an email already under board protection). | Required |
| page | 1-indexed page number. Default is 1. | Optional |
| size | Page size (1-100). Default is 20. | Optional |
| term | Optional search term filtering inside the chosen data set. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darkmon.BoardLeak.Account | Unknown | Leaked account records for the protected email \(when type=accounts\). |
| Darkmon.BoardLeak.ComboList | Unknown | Combo list records for the protected email \(when type=combo-lists\). |
| Darkmon.BoardLeak.PublicBreach | Unknown | Public breach records for the protected email \(when type=public-breaches\). |
| Darkmon.BoardLeak.Page | Unknown | Pagination metadata. |
