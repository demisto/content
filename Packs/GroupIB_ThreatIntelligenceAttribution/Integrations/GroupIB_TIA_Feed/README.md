# Group-IB Threat Intelligence Feed

Use the Group-IB Threat Intelligence Feed integration to fetch IOCs (Indicators of Compromise) from Group-IB collections. The integration supports multiple collections - see the [Data Collections Overview](#data-collections-overview) section below for the complete list with descriptions and recommended date ranges (indicator first fetch).

## Prerequisites

1. **Access the Group-IB Threat Intelligence (TI) portal**
   - Open the Group-IB TI portal at [https://tap.group-ib.com](https://tap.group-ib.com)

2. **Generate API Credentials**
   - In the portal, click your name in the upper right corner
   - Select **Profile** > **Security and Access** tab
   - Click **Personal token** and follow the instructions to generate your API token
   - The API token is the password of the integration instance

3. **Network Configuration**
   - Ask Group-IB support to add the IP address of your Cortex XSOAR server to the allow list
   - If you are using a proxy, provide the public IP address of the proxy server instead
   - Add the Group-IB [API IPs/URLs](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FInitial%20Steps%2FInitial%20Steps) to your firewall or proxy rules.

## Important Notes

### When one collection fails

If a request for one collection fails (for example HTTP 403 or 5xx, or a timeout), the other collections are still fetched and their cursors advance. The failed collection keeps its cursor after the last page it read, is requested again on the next run, and the error is shown in the instance health. A run fails only when every selected collection fails or waits for a start cursor and no record gave an indicator. Every selected collection is requested, whether or not the list of granted collections names it.

### Collections that wait for a start cursor

On a first fetch, and after **Indicator first fetch** changes or **Hunting Rules** is toggled, each collection starts at the Group-IB cursor for the **Indicator first fetch** date (`attacks/ddos` and `attacks/phishing_kit` start from the date itself when no cursor is available). When no cursor is available for that date, any other collection is not read yet: the instance health names it, the cursor is requested again on the next fetch, and the other collections are fetched. If it persists, set a later date; changing it restarts every selected collection. When a collection gets its cursor and the first page is empty or fails, the feed stores that cursor and the next fetch starts there.

### Limit Parameter

The **Limit (items per request)** parameter specifies the number of records requested per API page. This limit applies to all collections configured in the integration instance.

- The limit determines how many records are fetched in a single API request. For example, if "Number of requests per collection" is set to 2 and the limit is 100, the integration reads up to 2 pages per collection, each of up to 100 records, resulting in up to 200 records per collection per fetch cycle (the collections in the last item can read a larger page).
- The [API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) lists the recommended limit per collection.
- Each collection is read in pages no larger than its own page size, whatever the limit (apart from the larger re-read in the next item), except `ioc/common`, which is read in pages of the limit.
- The records of `suspicious_ip/*`, `compromised/spd` and `malware/cnc` can share one cursor position. Each request after the first starts at the last position read, so a few records are read twice and kept once, and a page that one cursor position fills is read again with a larger size, up to 1,000 records; neither counts as a further page against *Number of requests per collection*. The `suspicious_ip/*` collections are read in pages of at most 1,000.

## Data Collections Overview

The feed reads the following collections. For the structure and fields of each collection, see the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

On a trial or POC account, some collections serve only the last 30 days.

| Collection | Description | Recommended Date Range |
|------------|-------------|----------------------|
| `ioc/primary` | The successor of `ioc/common`: IPs, domains, URLs and file hashes from the malware, cybercriminal and nation-state collections, each with its own Group-IB **risk score** (0-100, stored in *GIB Risk Score*; see [Indicator verdicts](#indicator-verdicts)), malware family and threat names. Prefer it over `ioc/common` for new instances and select only one of the two: the API serves the same records under both names (same ids), so selecting both reads every record twice for the same indicators (a value both report is merged into one). | 90 days |
| `compromised/account_group` | The C&C URLs, domains and IPs behind your compromised accounts, each with the malware families, threat actors and source types of every event naming it, the detection date of the first such event and the evaluation of the record. Few events carry a C&C, so the collection yields few indicators. The compromised user's own IP, ASN and geo, and the login page of the service the account belongs to, are never turned into indicators. | 2-4 years |
| `compromised/spd` | Suspicious payment details (supersedes the removed `compromised/mule`). Crypto wallets become *Cryptocurrency Address* indicators, a type the Cryptocurrency pack defines; mobile numbers, bank account numbers, bank cards, IBANs, e-mail addresses, QR payment strings and payment details of type `Unknown` become this pack's *GIB Suspicious Payment Detail* type. A Bitcoin wallet (a valid base58check address starting with 1 or 3, or a `bc1` address) is written `bitcoin:<address>`, the value Cortex XSOAR's extraction gives a base58check wallet. The verdict follows the Group-IB illegal score (see [Indicator verdicts](#indicator-verdicts)), and the record tags become indicator tags. A *Bank Card* value is the full card number, unmasked: it is the card a fraud network collects payments on, and PCI DSS applies to the indicator store that holds it. | 90 days |
| `attacks/ddos` | Distributed Denial of Service (DDoS) attacks: the C&C URL, domain and IP behind the attack become indicators, with the malware family, threat actor, dates and evaluation of the record. The targeted address is the attacked host, not an IOC: it becomes a *GIB Victim IP* indicator only when **Collection filters** names that type, as in `attacks/ddos: kinds = URL, Domain, IP, GIB Victim IP`. A victim gets no verdict, no relationships, no *Malware Family* and no tags of the attack's malware or actors; their names stay in *GIB Malware Name* and *GIB Threat Actor Name*. A target that is also an IP indicator of the same fetch is not sent as *GIB Victim IP*. | 5-10 days |
| `attacks/deface` | Records of defacement attacks. Only the defaced URL becomes an indicator; the defaced site's domain and IP are the victim's and become no indicator. The defacer's handle fills *GIB Threat Actor Name* and *GIB Threat Actor ID* but makes no *Threat Actor* object, relationship or tag: it groups defacements and is not an attribution. | 5-10 days |
| `attacks/phishing_group` | Information on phishing attacks: the phishing URLs become indicators, with the targeted brand and objective (*GIB Phishing Brand* / *GIB Phishing Objectives*, the brand also as a tag), the threat actor and the evaluation. The domain and the hosting IP are often shared infrastructure (a free blog host or a cloud provider's address that also serves legitimate sites) and are not emitted: blocking them would cause false positives. Each phishing URL carries its own objective and detection date; the *Index of* and *Not specified* markers Group-IB writes into the brand field never become a brand or a tag. A group Group-IB flags as a false positive or allow-listed (`falsePositive`, `whitelist`) yields no indicator. | 3-5 days |
| `attacks/phishing_kit` | Collections of phishing website templates, scripts, and configurations used by attackers: the SHA-256 of each kit archive becomes a *File* indicator, its primary indicator, and the operator e-mails *Email* indicators, all Suspicious. | 30 days |
| `apt/threat` | The IOCs of the nation-state threat reports: IPv4 and IPv6 addresses, domains, URLs and files, each file keyed by its SHA-256, else its SHA-1, else its MD5, else its SHA-512, with its own name, hashes and size, every indicator with its own first and last seen dates. From an email-message entry, the address becomes an *Email* indicator and the sender IP an *IP* indicator; the server IP is not read, since the report does not say whose server it is. A defanged value (`hxxps://`, `[.]`) is restored before the indicator is created. | 2-4 years |
| `hi/threat` | The IOCs of the cybercriminal threat reports, built like those of `apt/threat`. | 2-4 years |
| `hi/open_threats` | Public posts about threats from security blogs and social networks: every IP, domain, file, standalone hash, CVE and crypto wallet Group-IB extracted from a post becomes a Suspicious indicator (an e-mail address stays on the record: it can be a researcher's, a victim's or an attacker's) with the post's source and dates, its evaluation and tags, and the malware families and threat actors it names. A parser extracted these values from prose, so they are a watchlist to verify at the post, never a blocklist. Without **Hunting Rules** the collection is the whole public feed, and a blog page can name hundreds of CVEs; **Open threat source types** and **Minimum severity** narrow it. | 7 days |
| `ioc/common` | General Indicators of Compromise (IOCs) from threat reports (Cybercriminals and APT) and Malware sections: file hashes (MD5, SHA-1, SHA-256 on one File indicator), IPs and domains, with the malware family and threat names of the record. It serves the records of `ioc/primary` under the same ids with fewer fields: no URL, evaluation, tags or source, so no URL indicators and no TLP of its own (AMBER). Prefer `ioc/primary` for new instances; do not select both (same records). | 90 days |
| `malware/cnc` | Information on malware Command-and-Control (C&C) servers used for data exfiltration and command distribution: the C&C URL, domain or IP and the addresses it resolves to (IPv4 and IPv6), each with its own ASN, provider and country, related to every malware family and threat actor the record names. Unlike the `ioc/*` collections, it carries the threat actor and the network data of each address. | 90 days |
| `osi/vulnerability` | Information on software vulnerabilities, associated exploits, and available proof-of-concept details. Only a record whose id is a CVE id becomes a *CVE* indicator; advisories under other ids (Nessus, Red Hat, Microsoft) yield none. The CVSS score and vector are Group-IB's merged cross-version CVSS, the legacy CVSS only without it. | 90 days |
| `osi/git_repository` | Public repositories that matched your hunting rules: one URL indicator per leak, the repository address. The revision hashes of the leaked files and the committers' e-mails are not indicators of an attack and are not emitted. | 30 days |
| `suspicious_ip/tor_node` | Tor relays of every role (exit, guard, middle). A relay whose address block lacks a country, region, AS or provider takes the missing values from its most recently seen consensus state. See [Troubleshooting](#tor-node-indicators-show-old-first-seen-dates). | 5 days |
| `suspicious_ip/open_proxy` | Information on publicly available proxy servers, including potentially misconfigured proxies. Group-IB can list an address several times; the feed sends one IP indicator per address, with the port, anonymity flag, source and dates of its latest listing and every port in *GIB Proxy Ports*. | 5 days |
| `suspicious_ip/scanner` | IPv4 or IPv6 addresses identified as scanning or probing corporate networks, with a country code and no provider or ASN; the scan categories become tags (lowercase, with hyphens: `brute-force`), the sources *GIB Source*. | 5 days |
| `suspicious_ip/socks_proxy` | IP addresses of infected hosts configured as SOCKS proxies used for anonymized attacks. | 5 days |
| `suspicious_ip/vpn` | VPN gateways with the product behind them. Most are legitimate commercial or corporate services, and with **Hunting Rules** the collection lists the gateways of your own organization, which then become Suspicious indicators like any other: exclude them, or keep `suspicious_ip/vpn` out of a filtered instance. | 5 days |

`compromised/bank_card_group` and `compromised/masked_card` are not feed collections: the `cnc` block of their records is the shop the card was offered in, not attacker infrastructure, so they carry no indicator. Fetch them as incidents with the **Group-IB Threat Intelligence** integration. The dark web collections `compromised/access`, `compromised/messenger`, `compromised/discord` and `darkweb/forums` are incidents-only too: a listing names your own host and the marketplace, and a post is free text that can quote anything, so none of them carries an indicator.

### Hunting Rules

**Hunting Rules** makes the feed fetch only the records that match the hunting rules configured for your Group-IB account, the same way the incidents integration does. The filter exists on the API side for some collections only, and it takes effect only where your API user has hunting rules enabled. A filtered collection for which none of your rules matches returns no indicators at all while the setting is on (typically the `suspicious_ip/*` collections when your rules target threats or vulnerabilities): keep such collections in a second instance without the setting if you want them unfiltered.

| Filtered when the setting is on | Always filtered by the API | Fetched unfiltered |
| --- | --- | --- |
| `hi/threat`, `apt/threat`, `hi/open_threats`, `osi/vulnerability`, `attacks/phishing_kit`, `attacks/phishing_group`, `suspicious_ip/tor_node`, `suspicious_ip/open_proxy`, `suspicious_ip/socks_proxy`, `suspicious_ip/vpn`, `suspicious_ip/scanner` | `compromised/account_group`, `compromised/spd`, `osi/git_repository`, `attacks/ddos` | `ioc/primary`, `ioc/common`, `malware/cnc`, `attacks/deface` |

The collections of the middle column are filtered by your hunting rules whatever the setting says: the feed sends no hunting-rules parameter for them, and the API then serves them filtered. A collection of the first column without a hunting-rules grant for your user is fetched unfiltered and noted in the debug log, so one instance can mix filtered and unfiltered collections.

Toggling the setting changes which records a collection returns, so every selected collection restarts from **Indicator first fetch** on the next run (the stored cursors are dropped). The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a toggle only after that fetch. Indicators fetched before the toggle stay until they expire.

### Indicator verdicts

Every indicator of compromise carries a verdict; the only indicators without one are the DDoS targets (*GIB Victim IP*, created only when `kinds` names the type; see the table). Group-IB's own evaluation severity (*GIB Severity*: green, orange, red) says how urgent a record is, not how malicious its observables are (a Tor exit node is green), so it is kept as a field and never decides the verdict.

| Collection | Verdict |
| --- | --- |
| `apt/threat`, `hi/threat`, `malware/cnc`, `ioc/common` | Bad: attacker infrastructure and IOCs. |
| `ioc/primary` | Bad when the indicator's own Group-IB risk score is above 0; Suspicious when the score is 0 or missing, as it is for recently listed domains (a listed IOC is never Good). |
| `compromised/spd` | The Group-IB illegal score: 80-100 Bad, below 80 Suspicious. |
| `osi/vulnerability` | Bad: a vulnerability Group-IB tracks, whatever its CVSS. |
| `attacks/ddos` target IPs (*GIB Victim IP*, only when `kinds` names the type) | No verdict (Unknown): a victim, not an IOC. The C&C URL, domain and IP of the attack, when a record names them, are Suspicious. |
| `hi/open_threats` | Suspicious: values extracted from a public post are a watchlist to verify at the post. |
| every other collection | Suspicious: anonymizers, scanners, phishing and defaced sites, leaks and the C&C behind compromised data are worth watching but not proven malicious on their own. |

The *Malware* and *Threat Actor* objects the feed creates for relationships are Bad.

A value several collections report in one fetch is one indicator. It takes the highest verdict and the collection that gave it; on an equal verdict, the collection fetched later in the run supplies the collection and the shared fields. It keeps the tags, relationships, malware families and the malware, actor and threat names of every collection that reports it, and the most restrictive TLP. Only the tie depends on the order of the collections in the instance settings.

**Indicator Reputation** left empty keeps these verdicts. A reputation selected there is applied by Cortex XSOAR to every indicator of the instance instead. An instance created before 4.0.0 keeps `Suspicious`, the former default, which overrides these verdicts; clear the setting to use them.

### Filters

The instance filters the records of a collection, and the observables of a kept record, before they become indicators. The settings carry the filters an analyst changes most: **Minimum severity**, **Skip records older than (days)**, the `osi/vulnerability` types and exploit settings, **Payment detail types to read**, **IOC minimum risk score** and **Open threat source types**. **Collection filters** carries every other filter of every collection, one per line as `collection: filter = value`. The collection is a name or a pattern (`suspicious_ip/*`, `*`); the value is a comma-separated list, a number, `true`, a severity (`Low`, `Medium` or `High`), or addresses or CIDR networks, as **Filters by collection** says for each filter; an empty value removes the filter a setting set for that collection; a line that starts with `#` is a comment. A line the integration cannot apply fails the instance test and every command, naming the line.

```text
ioc/primary: kinds = IP, Domain
ioc/primary: skip_unscored = true
attacks/ddos: kinds = URL, Domain, IP, GIB Victim IP
suspicious_ip/*: max_age_days = 5
suspicious_ip/tor_node: exit_only = true
malware/cnc: excluded_networks = 203.0.113.0/24
```

Every filter decides the same way for its kind:

- A list filter (`types`, `countries`, `malware`, ...) keeps a record that carries at least one of the listed values; a record without the value is skipped. Its `excluded_` counterpart skips a record that carries any listed value and keeps a record without the value. Values are matched whatever their case; a filter whose row in **Filters by collection** says "subdomains included" also matches the subdomains of a listed domain; the scanner categories ignore separators (`Brute-Force` is `brute force`).
- A text filter (`targeted_companies`) keeps a record whose value contains one of the texts, whatever the case; a record without the value is skipped.
- A number filter (`min_cvss`, `min_epss_percentile`, `min_illegal_score`, `min_sources`) compares a number; a record without the number passes, a CVSS score of 0 without a vector counts as none, and `min_sources` counts a listing without sources as 0.
- `max_age_days` keeps the records whose date lies within that many days before the read, by the date named in the collection's table below (the first one the record has; when that date is a placeholder of an unknown date, any date before 1980 such as `0001-01-01` or `1976-01-01`, the record passes and the next date is not read); a record without any of those dates passes.
- `min_severity` and `min_file_severity` take `Low`, `Medium` or `High`; an unrated record counts as `Low`.
- A `true` filter (`has_exploit`, `exit_only`, `secrets_only`, ...) keeps only the records the condition holds for; `false` is no filter.
- `excluded_networks` takes addresses and CIDR networks and skips the records whose address lies in one of them.
- `kinds` names the indicator types a collection creates; the observables of the other types are skipped. Without it a collection creates every type it can, except *GIB Victim IP*, which `attacks/ddos` creates only when `kinds` names it. `min_risk_score` and `skip_unscored` decide per observable on `ioc/primary`, by the observable's own risk score.

A skipped record is not read later: the cursor moves past it. Where the API has the same filter, the request asks for it as well (`osi/vulnerability` types and exploits, one payment detail type) and every record is checked again when it arrives.

#### Filters by collection

##### `ioc/primary`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the date the observables were last seen, else the date they were first seen. |
| `malware` | list | Malware family names a record needs one of. |
| `excluded_malware` | list | Malware family names that skip a record. |
| `threats` | list | Threat names a record needs one of. |
| `tags` | list | Tags a record needs one of. |
| `min_risk_score` | number | The lowest Group-IB risk score (0-100) an observable needs; an unscored one passes. |
| `skip_unscored` | `true` | true skips the observables without a risk score. |
| `kinds` | `URL`, `Domain`, `IP`, `File`, `IPv6` | Indicator types to create; observables of other types are skipped. |

##### `ioc/common`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the date the observables were last seen, else the date they were first seen. |
| `malware` | list | Malware family names a record needs one of. |
| `excluded_malware` | list | Malware family names that skip a record. |
| `threats` | list | Threat names a record needs one of. |
| `kinds` | `Domain`, `IP`, `File`, `IPv6` | Indicator types to create; observables of other types are skipped. |

##### `compromised/account_group`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the account was last compromised, else the date it was first seen. |
| `malware` | list | Malware family names an account needs one of. |
| `excluded_malware` | list | Malware family names that skip an account. |
| `source_types` | list | Source types an account's events need one of. |
| `service_domains` | list | Domains of the service the account belongs to, subdomains included. |
| `login_domains` | list | Domains of the login's e-mail address, subdomains included. |
| `victim_countries` | list | Country codes of the compromised device, from the account's events. |
| `kinds` | `URL`, `Domain`, `IP`, `IPv6` | Indicator types to create; observables of other types are skipped. |

##### `compromised/spd`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the payment detail was last seen. |
| `types` | `Cryptocurrency Wallet`, `Bank Account Number`, `Mobile Number`, `Bank Card`, `IBAN`, `Email`, `QR Payment String`, `Unknown` | Payment detail types a record needs one of. |
| `service_types` | list | Service types a record needs one of. |
| `min_illegal_score` | number | The lowest illegal score a record needs. |
| `countries` | list | Country codes a record needs one of. |
| `malware` | list | Malware family names a record needs one of. |
| `actors` | list | Threat actor names a record needs one of. |
| `kinds` | `Cryptocurrency Address`, `GIB Suspicious Payment Detail` | Indicator types to create; observables of other types are skipped. |

##### `attacks/ddos`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the attack began. |
| `types` | list | Attack types a record needs one of. |
| `protocols` | list | Protocols a record needs one of. |
| `target_countries` | list | Country codes of the attack's target. |
| `target_ports` | list | Target ports a record needs one of. |
| `malware` | list | Malware family names a record needs one of. |
| `actors` | list | Threat actor names a record needs one of. |
| `kinds` | `URL`, `Domain`, `IP`, `GIB Victim IP`, `IPv6` | Indicator types to create; observables of other types are skipped. GIB Victim IP, the attacked host, is created only when listed. |

##### `attacks/deface`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date of the defacement. |
| `target_domains` | list | Domains of the defaced site, subdomains included. |
| `countries` | list | Country codes of the defaced site's address. |
| `actors` | list | Threat actor names a record needs one of. |
| `sources` | list | Source names a record needs one of. |
| `kinds` | `URL` | Indicator types to create; observables of other types are skipped. |

##### `attacks/phishing_kit`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the kit was last seen, else the date it was first seen. |
| `brands` | list | Brands a kit needs to target one of. |
| `sources` | list | Source names a kit needs one of. |
| `kinds` | `File`, `Email` | Indicator types to create; observables of other types are skipped. |

##### `attacks/phishing_group`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the group was detected, else the date it was updated. |
| `brands` | list | Brands a group needs to impersonate one of. |
| `excluded_brands` | list | Brands whose groups are skipped. |
| `objectives` | list | Phishing objectives a group needs one of. |
| `actors` | list | Threat actor names a record needs one of. |
| `sources` | list | Source names a group needs one of. |
| `kinds` | `URL` | Indicator types to create; observables of other types are skipped. |

##### `apt/threat`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the report's publication date, else the date it was created. |
| `report_types` | list | Report types a report needs one of: threat (analyst-authored) or event. |
| `sectors` | list | Sectors a report needs one of. |
| `regions` | list | Regions or country names a report needs one of. |
| `actors` | list | Threat actor names a record needs one of. |
| `excluded_actors` | list | Threat actor names that skip a report. |
| `malware` | list | Malware family names a report needs one of. |
| `excluded_malware` | list | Malware family names that skip a report. |
| `targeted_companies` | list | Text one of the targeted company names must contain. |
| `target_domains` | list | Domains among the report's target domains, subdomains included. |
| `with_iocs_only` | `true` | true keeps only the reports that carry indicators. |
| `kinds` | `IP`, `IPv6`, `Domain`, `URL`, `File`, `Email` | Indicator types to create; observables of other types are skipped. |

##### `hi/threat`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the report's publication date, else the date it was created. |
| `report_types` | list | Report types a report needs one of: threat (analyst-authored) or event. |
| `sectors` | list | Sectors a report needs one of. |
| `regions` | list | Regions or country names a report needs one of. |
| `actors` | list | Threat actor names a record needs one of. |
| `excluded_actors` | list | Threat actor names that skip a report. |
| `malware` | list | Malware family names a report needs one of. |
| `excluded_malware` | list | Malware family names that skip a report. |
| `targeted_companies` | list | Text one of the targeted company names must contain. |
| `target_domains` | list | Domains among the report's target domains, subdomains included. |
| `with_iocs_only` | `true` | true keeps only the reports that carry indicators. |
| `kinds` | `IP`, `IPv6`, `Domain`, `URL`, `File`, `Email` | Indicator types to create; observables of other types are skipped. |

##### `suspicious_ip/tor_node`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the address was last seen listed. |
| `countries` | list | ISO 3166-1 alpha-2 country codes a listing needs one of. |
| `excluded_countries` | list | Country codes that skip a listing. |
| `asns` | list | Autonomous system numbers a listing needs one of, with or without the AS prefix. |
| `excluded_asns` | list | Autonomous system numbers that skip a listing. |
| `sources` | list | Source names a listing needs one of. |
| `excluded_sources` | list | Source names that skip a listing. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |
| `exit_only` | `true` | true keeps only the relays whose newest consensus flags make them a usable exit (Exit without BadExit). |
| `flags` | list | Consensus flags (Exit, Guard, ...) a relay's newest state needs one of. |

##### `suspicious_ip/open_proxy`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the address was last seen listed. |
| `countries` | list | ISO 3166-1 alpha-2 country codes a listing needs one of. |
| `excluded_countries` | list | Country codes that skip a listing. |
| `asns` | list | Autonomous system numbers a listing needs one of, with or without the AS prefix. Group-IB's open proxy listings carry no ASN, so the filter skips them. |
| `excluded_asns` | list | Autonomous system numbers that skip a listing. |
| `sources` | list | Source names a listing needs one of. |
| `excluded_sources` | list | Source names that skip a listing. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |
| `types` | list | Proxy protocols (HTTP, HTTPS, SOCKS4, SOCKS5) a listing needs one of. |
| `ports` | list | Ports a listing needs one of. |
| `min_sources` | number | The lowest number of public lists the address must appear on. |

##### `suspicious_ip/socks_proxy`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the address was last seen listed. |
| `countries` | list | ISO 3166-1 alpha-2 country codes a listing needs one of. |
| `excluded_countries` | list | Country codes that skip a listing. |
| `asns` | list | Autonomous system numbers a listing needs one of, with or without the AS prefix. Group-IB's SOCKS proxy listings carry no ASN, so the filter skips them. |
| `excluded_asns` | list | Autonomous system numbers that skip a listing. |
| `sources` | list | Source names a listing needs one of. |
| `excluded_sources` | list | Source names that skip a listing. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |

##### `suspicious_ip/vpn`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the address was last seen listed. |
| `countries` | list | ISO 3166-1 alpha-2 country codes a listing needs one of. |
| `excluded_countries` | list | Country codes that skip a listing. |
| `asns` | list | Autonomous system numbers a listing needs one of, with or without the AS prefix. |
| `excluded_asns` | list | Autonomous system numbers that skip a listing. |
| `sources` | list | Source names a listing needs one of. |
| `excluded_sources` | list | Source names that skip a listing. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |
| `types` | list | Deployment types (commercial, self-hosted, public, ...) a gateway needs one of. |
| `names` | list | VPN product names a gateway needs one of. |
| `excluded_names` | list | VPN product names that skip a gateway. |

##### `suspicious_ip/scanner`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the address was last seen listed. |
| `countries` | list | ISO 3166-1 alpha-2 country codes a listing needs one of. |
| `excluded_countries` | list | Country codes that skip a listing. |
| `asns` | list | Autonomous system numbers a listing needs one of, with or without the AS prefix. Group-IB's scanner listings carry no ASN, so the filter skips them. |
| `excluded_asns` | list | Autonomous system numbers that skip a listing. |
| `sources` | list | Source names a listing needs one of. |
| `excluded_sources` | list | Source names that skip a listing. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |
| `categories` | list | Activity categories a listing needs one of, whatever their case and separators. |
| `excluded_categories` | list | Activity categories that skip a listing. |
| `kinds` | `IP`, `IPv6` | Indicator types to create; observables of other types are skipped. |

##### `malware/cnc`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the date the C&C was last seen, else the date it was detected. |
| `actors` | list | Threat actor names a record needs one of. |
| `malware` | list | Malware family names a C&C needs one of. |
| `excluded_malware` | list | Malware family names that skip a C&C. |
| `countries` | list | Country codes of the C&C's resolved addresses. |
| `excluded_countries` | list | Country codes that skip a C&C. |
| `platforms` | list | Platforms (Windows, Android, Web) a C&C needs one of. |
| `excluded_networks` | list | Addresses and CIDR networks; a record whose address lies in one is skipped. |
| `kinds` | `URL`, `Domain`, `IP`, `IPv6` | Indicator types to create; observables of other types are skipped. |

##### `osi/vulnerability`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the publication date; an older record updated in the window is skipped. |
| `types` | list | Record types to read (cve, mscve, nessus, redhat, ...); asked of the API as well. |
| `excluded_types` | list | Record types to skip; a single type is asked of the API as well when types is empty. |
| `has_exploit` | `true` | true keeps only the records with a known exploit, asked of the API as well. |
| `seen_in_the_wild` | `true` | true keeps only the vulnerabilities seen exploited in the wild. |
| `min_cvss` | number | The lowest CVSS score a record needs: the merged cross-version score, else the legacy CVSS score. |
| `min_epss_percentile` | number | The lowest EPSS percentile (0-100) a record needs. |
| `vendors` | list | CPE vendors, or vendor:product pairs, a record's CPE table needs one of. |
| `products` | list | CPE products a record's CPE table needs one of. |

##### `osi/git_repository`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity of the repository record; the files carry their own grades. |
| `max_age_days` | days | Days back from the fetch by the date the leak was detected. |
| `min_file_severity` | `Low`, `Medium`, `High` | The lowest grade one of the repository's files needs (gray and yellow count as Low). |
| `secrets_only` | `true` | true keeps only the repositories where a file holds a detected secret. |
| `secret_types` | list | Secret types (password, api_key, ...) a repository's files need one of. |

##### `hi/open_threats`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the post was created, else the date it was detected. |
| `source_types` | `Blog`, `Social Network` | Blog, Social Network or both. |
| `sources` | list | Site or network names a post needs one of. |
| `excluded_sources` | list | Site or network names that skip a post. |
| `actors` | list | Threat actor names a post needs one of. |
| `malware` | list | Malware family names a post needs one of. |
| `tags` | list | Tags a post needs one of. |
| `with_iocs_only` | `true` | true keeps only the posts Group-IB extracted indicators from. |
| `matched_rules_only` | `true` | true keeps only the posts one of your hunting rules matched. |
| `kinds` | `IP`, `Domain`, `File`, `CVE`, `Cryptocurrency Address`, `IPv6` | Indicator types to create; observables of other types are skipped. |

## Troubleshooting

### Tor node indicators show old first-seen dates

The *First Seen By Source* of a Tor node is the day Group-IB first observed it as a Tor node, which can be years ago for an active relay; *Last Seen By Source* shows that a relay is current. An active relay is listed again each time it re-enters the consensus, with its original first-seen date, so a relay first seen years ago keeps reappearing.

- Set **Indicator first fetch** to the last few days (the collection's recommended range is 5 days): the cursors of every selected collection are dropped on the next fetch, and they restart from that date.
- Size the instance for the daily volume, for example a **Limit (items per request)** of 500 with four requests per collection and an hourly fetch.

Not every relay is an exit node: the collection lists relays of every role. `suspicious_ip/tor_node: exit_only = true` in **Collection filters** keeps the usable exits.

## Configure Group-IB Threat Intelligence Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB TI URL | The Group-IB TI API URL (default: `https://tap.group-ib.com/api/v2/`). | True |
| Username | The e-mail address you log in to the Group-IB portal with. Enter your API token (Personal token) as the password. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying the SSL certificate's validity. | False |
| Use system proxy settings | Whether to use Cortex XSOAR system proxy settings to connect to the API. | False |
| Fetch indicators | Enable to fetch indicators from the feed (default: enabled). | False |
| Incremental feed | Hidden. Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation (default: empty). Options: None, Good, Suspicious, Bad. Leave it empty to give every indicator the verdict of its collection (see [Indicator verdicts](#indicator-verdicts)): Bad for threat reports, malware C&C, the IOC collections and vulnerabilities, Suspicious for the others. An `ioc/primary` indicator is Bad when its own Group-IB risk score is above 0 and Suspicious when the score is 0 or missing. A payment detail with an illegal score of 80 or more is Bad, and a DDoS target (*GIB Victim IP*) gets no verdict. A selected reputation is applied to every indicator of the instance instead. An instance created before 4.0.0 keeps `Suspicious`, the former default, which overrides these verdicts; clear the setting to use them. | False |
| Source Reliability | Reliability of the source providing the intelligence data (default: A - Completely reliable). Options: A - Completely reliable, B - Usually reliable, C - Fairly reliable, D - Not usually reliable, E - Unreliable, F - Reliability cannot be judged. | True |
| Feed Fetch Interval | Configure how often to fetch indicators (hours and minutes, default: 1 minute). | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator collections | The collections to fetch indicators from (see the [Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details)). `ioc/primary` and `ioc/common` are the same records under two names, `ioc/common` with fewer fields (no URL, evaluation, tags or source); select one of them. | False |
| Indicator first fetch | Date to start fetching indicators from (default: "3 days"). Each collection starts at the Group-IB cursor for that date (`attacks/ddos` and `attacks/phishing_kit` start from the date itself when no cursor is available). When no cursor is available for that date, any other collection is not read yet and is named in the instance health, and the cursor is requested again on the next fetch (see [Collections that wait for a start cursor](#collections-that-wait-for-a-start-cursor)). Changing the value restarts every selected collection from the new date; the stored cursors are dropped on the next fetch. The value is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch. `gibti-get-indicators` without an id starts from the same date. | False |
| Number of requests per collection | Number of pages read per collection in each fetch iteration (default: 2). Each page asks for up to **Limit (items per request)** records, each with zero or more indicators. On `suspicious_ip/*`, `compromised/spd` and `malware/cnc`, a page that one cursor position fills is read again larger, up to 1,000 records (see [Limit Parameter](#limit-parameter)); each larger read is one more request and does not count as a further page. Lower the value if a fetch does not finish within the interval. | False |
| Limit (items per request) | Number of records requested per API page (default: 100), for every collection of the instance. Larger values reduce API round-trips but may increase response size. The Group-IB [API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) lists the recommended limit per collection. Each collection is read in pages no larger than its own page size (apart from the larger re-read below), except `ioc/common`, which is read in pages of the limit. The `suspicious_ip/*` collections are read in pages of at most 1,000. On `suspicious_ip/*`, `compromised/spd` and `malware/cnc`, a page that one cursor position fills is read again larger, up to 1,000 records; each larger read is one more request and does not count as a further page against **Number of requests per collection** (see [Limit Parameter](#limit-parameter)). | False |
| Tags | Tags added to every indicator of the instance. Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Options: RED, AMBER, GREEN, WHITE. When **Use TLP from source** is disabled, this value is applied to all indicators. When **Use TLP from source** is enabled, this value is used only as a fallback when neither the record nor its collection's default (AMBER on `ioc/primary` and `ioc/common`) gives one. Leave it empty (the default) to give each indicator the TLP of its Group-IB record (see [TLP per indicator](#traffic-light-protocol-tlp-per-indicator)). | False |
| Use TLP from source (per indicator) | When enabled, each indicator takes the TLP of its Group-IB record (see [TLP per indicator](#traffic-light-protocol-tlp-per-indicator) for the list of collections); a record without one takes AMBER on `ioc/primary` and `ioc/common` (an `ioc/common` record carries no evaluation block) and the **Traffic Light Protocol Color** elsewhere. A `malware/cnc` record carries no evaluation block either, so its indicators always take the **Traffic Light Protocol Color**. When disabled, every indicator takes the **Traffic Light Protocol Color**; with no color selected, each indicator keeps the TLP of its record whether the setting is on or off. TLP:CLEAR is stored as WHITE, TLP:AMBER+STRICT as AMBER, an unknown name as RED. | False |
| Hunting Rules | Off by default. Fetch only the records that match your Group-IB hunting rules where the filter is optional and your API user has hunting rules enabled: `hi/threat`, `apt/threat`, `hi/open_threats`, `osi/vulnerability`, `attacks/phishing_kit`, `attacks/phishing_group` and the five `suspicious_ip/*` collections. A filtered collection with no matching rule returns nothing while this is on, and `hi/open_threats` without the setting is the whole public feed. `compromised/account_group`, `compromised/spd`, `osi/git_repository` and `attacks/ddos` are always filtered by the API; `ioc/primary`, `ioc/common`, `malware/cnc` and `attacks/deface` never are. Toggling the setting restarts every selected collection from **Indicator first fetch**. The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a toggle only after that fetch. `gibti-get-indicators` reads with the setting too, except for a record named by `id`. See [Hunting Rules](#hunting-rules). | False |
| Minimum severity | The lowest Group-IB severity a record needs for its observables to become indicators, for every collection whose records carry a severity. `Low` (default) reads every record, and a record without a rating counts as `Low`. A record below the minimum is skipped when it arrives and is not read later. Group-IB rates every record of some collections the same, so `Medium` or `High` keeps all or none of them: `suspicious_ip/*` listings are green, DDoS attacks and defacements orange. `ioc/primary`, `ioc/common` and `malware/cnc` records carry no rating and are not held to it (see [Filters](#filters)). | False |
| Skip records older than (days) | A record older than this many days at the read is skipped and not read later, by the date that matters for its collection: the last sighting of an IOC, a suspicious IP listing or a C&C, the publication date of a vulnerability, the date a phishing group was detected ([Filters by collection](#filters-by-collection) lists every collection's date). Group-IB re-sends old records when it updates them, so a read can bring records years old. Empty or 0 (default) keeps every record. | False |
| Vulnerability types to read | Works only for `osi/vulnerability`. A comma-separated list of record types to read, such as `cve`, `mscve`, `nessus` or `redhat`; case does not matter. The types are asked of the API as well, and every record is checked when it arrives; only a record whose id is a CVE id becomes an indicator. Empty (default) reads every type. | False |
| Vulnerability types to skip | Works only for `osi/vulnerability`. A comma-separated list of record types to skip, such as `nessus`. A single skip type is also excluded in the API request when **Vulnerability types to read** is empty; every record is checked when it arrives. Empty (default) skips none. | False |
| Vulnerabilities with an exploit only | Works only for `osi/vulnerability`. Read only the records with a known exploit: the API is asked for them, and every record is checked when it arrives. | False |
| Payment detail types to read | Works only for `compromised/spd`. The payment detail types to read; empty (default) reads every type. A single selected type is also sent to the API; every record is checked when it arrives. | False |
| IOC minimum risk score | Works only for `ioc/primary`. The lowest Group-IB risk score (0-100) an IP, domain or URL needs to become an indicator; a file takes its record's score. An observable without a score passes; the `skip_unscored` filter in **Collection filters** drops those. Empty (default) reads every observable. | False |
| Open threat source types | Works only for `hi/open_threats`. The kinds of public posts to read indicators from; empty (default) reads both. Blog posts are long articles and carry most of the extracted CVEs; social network posts are short messages, with indicators extracted the same way. | False |
| Collection filters | Every other filter, one per line as `collection: filter = value`, for example `osi/vulnerability: min_cvss = 7` or `suspicious_ip/*: excluded_countries = US, DE`. The collection is a name or a pattern (`suspicious_ip/*`, `*`); the value is a comma-separated list, a number, `true`, a severity (`Low`, `Medium` or `High`), or addresses or CIDR networks, as [Filters by collection](#filters-by-collection) says for each filter; an empty value removes the filter a setting above set for that collection; a line starting with `#` is a comment. A line the integration cannot apply fails the instance test and every command, naming the line. [Filters](#filters) and [Filters by collection](#filters-by-collection) list the filters of each collection. | False |
| Create relationships | Every malware family and threat actor a record names becomes a *Malware* / *Threat Actor* indicator related to the observable (*indicator-of* / *related-to*), apart from a defacer's handle; a *GIB Victim IP* gets no relationship. The feed creates those objects together with the observables. Disable it to keep the feed to plain observables. Enabled by default (see [Indicator enrichment](#indicator-enrichment-fields-tags-and-relationships)). | False |
| Delay between API requests (seconds) | Minimum number of seconds between consecutive requests to the same collection while a fetch or `gibti-get-indicators` pages through it (default 1.2; the first request is never delayed; 0 disables the delay). Raise it if the API answers HTTP 429. | False |
| Indicator Expiration Method | Configure how indicators expire. Options: Never Expire, Time Interval, Indicator Type (the expiration policy of each indicator type). Suspicious IP hosts rotate, so a stale listing can flag an address that is no longer a proxy, Tor node, VPN exit or scanner: with **Time Interval**, fetch the `suspicious_ip/*` collections in an instance whose interval suits them. By default, the incidents integration's ***ip*** command counts a listing at any age (its *Suspicious IP listing recency (days)* setting can set a window). | False |

## Indicator enrichment: fields, tags and relationships

Every indicator the feed creates carries these fields from its Group-IB record:

- **Standard indicator fields**, each where the collection carries it: for IPs, *ASN*, *Geo Country*, *Geo Location* and *Organization* (the hosting provider; not on `attacks/ddos` IPs), each resolved address of a C&C with its own; *First Seen By Source* / *Last Seen By Source* from the record dates, or from the entry's own dates where a list entry has them (a report's indicator, a compromised account's event, a phishing URL), and Group-IB's placeholders of an unknown date, `0001-01-01` and `1976-01-01`, count as no date; *Malware Family* from the malware names of the record; the *Traffic Light Protocol* described below.
- **Group-IB fields**: *GIB ID*, *GIB Collection*, *GIB Malware Name*, *GIB Threat Actor Name* (with id and APT flag where the record has them; a record naming several actors lists all their ids and carries no APT flag), *GIB Threat Name*, *GIB Source* (the sources the record names; on `compromised/account_group`, the source types of the events that name the C&C), the *GIB Severity* / *GIB Reliability* / *GIB Credibility* / *GIB Admiralty Code* evaluation (not on `ioc/common` and `malware/cnc`, whose records carry no evaluation block; `ioc/primary` has no severity), *GIB Risk Score* (`ioc/primary`), *GIB Phishing Brand* and *GIB Phishing Objectives* (`attacks/phishing_group`), *GIB Proxy Port*, *GIB Proxy Ports* and *GIB Proxy Anonymous* (`suspicious_ip/open_proxy`), *GIB File Name* (the files of `apt/threat`, `hi/threat` and `hi/open_threats`), the CVE and payment-detail fields of their collections. A list keeps every value (all the objectives of a phishing URL, all the countries of a payment detail).
- **Tags**: the instance **Tags**, the collection name (for example `malware/cnc` or `suspicious_ip/scanner`), the malware families, the threat actors and the threat names of the record, plus record-specific tags: the targeted brand of a phishing group, the scan categories of a scanner IP (one tag per category whatever case or separator Group-IB sent: `Brute-Force` and `brute-force` both give `brute-force`), the VPN product names of a VPN gateway, the tags of a suspicious payment detail, the tags of an open threat post.
- **Where the fields show**: the pack ships layouts for its own indicator types (*GIB Suspicious Payment Detail*, *GIB Victim IP*) and none for the indicator types of the platform and its content packs (IP, IPv6, Domain, URL, File, CVE, Email, Cryptocurrency Address, Malware, Threat Actor); add a Group-IB field to such a layout where it does not show.
- **Relationships and objects** (**Create relationships**, on by default): each observable is an *indicator-of* a *Malware* indicator for every malware family its record names, and *related-to* a *Threat Actor* indicator for every threat actor. On `compromised/account_group`, a C&C relates only to those of the events that name it. The feed creates those objects itself, once per name and fetch, as *Bad* objects tagged with the instance tags and the collection, with the most restrictive TLP of the records that name them and, for a threat actor named alone by its record, *GIB Threat Actor ID* and the APT flag. A defacer's handle makes no object, relationship or tag, and a *GIB Victim IP* gets no relationship. The malware and actor pages then list every C&C, URL, hash and IP attributed to them across the collections the instance fetches. Disable the setting to keep the feed to plain observables.

## Traffic Light Protocol (TLP) per indicator

An indicator takes its TLP by these rules:

- **A Traffic Light Protocol Color selected, Use TLP from source disabled**: every indicator takes the selected color.
- **Use TLP from source enabled**: each indicator takes the TLP of its Group-IB record when the record has one, in `ioc/primary`, `compromised/account_group`, `compromised/spd` (AMBER or GREEN per record), `attacks/ddos`, `attacks/deface`, `attacks/phishing_kit`, `attacks/phishing_group`, `apt/threat`, `hi/threat`, `osi/vulnerability`, `osi/git_repository`, `hi/open_threats` and the `suspicious_ip/*` collections. `ioc/primary` records without a TLP and every `ioc/common` record (it carries no evaluation block) get AMBER. Any other record without a TLP, and every `malware/cnc` record (no evaluation block either), takes the **Traffic Light Protocol Color**.
- **No color selected** (the default): each indicator takes the TLP of its record whatever **Use TLP from source** says, by the rules above, so a TLP:RED report never yields an indicator without TLP. A `malware/cnc` indicator, and any other indicator whose record has no TLP and no AMBER default, then carries none.
- Group-IB's TLP 2.0 names are folded into the four colors the instance setting offers: TLP:CLEAR as WHITE, TLP:AMBER+STRICT as AMBER. A TLP name outside that set is stored as RED, the most restrictive color.
- A *Malware* or *Threat Actor* object, and a value several records or collections report in one fetch, take the most restrictive TLP of those records.
- `gibti-get-indicators` applies the same rules, and its War Room table shows each indicator's TLP.

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

The configuration steps are in the integration description.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibti-get-indicators

***
Show up to `limit` distinct indicators of a collection, read from the **Indicator first fetch** date on with the instance's **Hunting Rules**, or every indicator of one of its records when `id` is set. The instance's filters apply to both. A collection without a start cursor for that date, other than `attacks/ddos` and `attacks/phishing_kit`, which start from the date itself, fails the command with a message that names it.

#### Base Command

`gibti-get-indicators`

> The legacy name `gibtia-get-indicators` still works but is deprecated: every call adds a War Room warning. Use `gibti-get-indicators` instead.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | GIB Collection to get indicators from. Possible values are: ioc/primary, ioc/common, compromised/account_group, compromised/spd, attacks/ddos, attacks/deface, attacks/phishing_kit, attacks/phishing_group, hi/threat, apt/threat, osi/vulnerability, osi/git_repository, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, suspicious_ip/vpn, suspicious_ip/scanner, malware/cnc, hi/open_threats. | Required |
| id | The id of a record of the collection. When set, the command returns every indicator of that record that the instance filters keep, whatever the limit. | Optional |
| limit | Indicators to show (default 50): pages are read until that many indicators are collected, at most 5 pages. With id, every indicator of that record is shown; the value must still be a number from 1 to 50. Possible values are: 10, 20, 30, 40, 50. Default is 50. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!gibti-get-indicators collection=ioc/primary limit=10```
