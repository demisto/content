# Group-IB Threat Intelligence

This integration fetches Group-IB Threat Intelligence records into Cortex XSOAR as incidents and provides lookup and search commands over the same collections, plus scoring, WHOIS and reputation commands.
The integration fetches compromised accounts, cards and payment details, data breaches, git and public leaks, dark web listings and posts from Telegram, Discord and forums, public posts about threats, vulnerabilities, DDoS, defacement and phishing attacks, phishing kits, threat reports and actor profiles, malware profiles and C&C, and suspicious IPs as incidents. See the [Data Collections Overview](#data-collections-overview) section below for the complete list with descriptions and recommended date ranges.

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
   - Add the Group-IB [API IPs/URLs](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FInitial%20Steps%2FInitial%20Steps) to your firewall or proxy rules

## Important Notes

### Recommended Instance Layout

Run separate integration instances for the following groups:

- Unique accounts (`compromised/account_group` with **Include unique type in data**)
- Combolist accounts (`compromised/account_group` with **Include combolist type in data**)
- Cards (`compromised/bank_card_group`, `compromised/masked_card`)
- Public and git leaks (`osi/public_leak`, `osi/git_repository`)
- Breached records (`compromised/breacheddb`)
- Vulnerabilities
- Threat reports and actor profiles (`hi/threat`, `apt/threat`, `hi/threat_actor`, `apt/threat_actor`) and malware profiles (`malware/malware`)
- Suspicious payment details (`compromised/spd`)
- Suspicious IP
- Malware C&C (`malware/cnc`)
- DDoS, defacement and phishing attacks and phishing kits (`attacks/ddos`, `attacks/deface`, `attacks/phishing_group`, `attacks/phishing_kit`)
- Dark web (`compromised/access`, `compromised/messenger`, `compromised/discord`, `darkweb/forums`)
- Open threats (`hi/open_threats`)

### When one collection fails

If a request for one collection fails (for example HTTP 403 or 5xx, or a timeout), the other collections are still fetched and their cursors advance. The failed collection keeps its cursor after the last page it read, is requested again on the next run, and the error is shown in the instance health. A run fails only when every selected collection fails or waits for a start cursor and no record gave an incident. Every selected collection is requested, whether or not the list of granted collections names it.

### Collections that wait for a start cursor

Each collection starts at the Group-IB cursor for the **Incidents first fetch** date (`attacks/ddos` and `attacks/phishing_kit` start from the date itself when no cursor is available). Any other collection without a cursor for that date is not read yet: the instance health names it, the cursor is requested again on the next fetch, and the other collections are fetched. If a collection keeps waiting, set a later date; changing it restarts every selected collection.

### Limit Parameter

The **Limit (items per request)** parameter specifies the number of records requested per API page. This limit applies to every collection of the instance.

- The limit determines how many records are fetched in one API request. For example, with **Number of requests per collection** set to 2 and the limit at 500, the integration reads up to 2 pages per collection, each of up to 500 records: up to 1,000 records per collection per fetch (`darkweb/forums` reads one page per fetch; the collections in the last item below can read a larger page).
- The [API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) lists the recommended limit per collection.
- Each collection is read in pages no larger than its own page size, whatever the limit, apart from the larger re-read in the next item.
- The records of `suspicious_ip/*`, `compromised/spd`, `malware/cnc`, `osi/public_leak` and `darkweb/forums` can share one cursor position. Each request after the first starts at the last position read, so a few records are read twice and kept once, and a page that one cursor position fills is read again with a larger size, up to 1,000 records (100 on `osi/public_leak`); neither counts as a further page against **Number of requests per collection**. The `suspicious_ip/*` collections are read in pages of at most 1,000.

### API request budget

The integration reads `GET /user/granted_collections` (the list of collections and hunting-rule grants of the API user) for the hunting-rules grant check of `fetch-incidents` (with **Hunting Rules** enabled), for `gibti-get-available-collections` and for the instance test, at most once per command, and keeps the answer in the integration context for five minutes, so fetch runs a minute apart do not repeat it. The instance test always sends the request instead of reading the kept answer. Lookup, search and reputation commands never send the hunting-rules filter and never read the list of granted collections.

### Collection-Specific Filters

**Include unique type in data**, **Include combolist type in data** and **Enable filter "Probable Corporate Access"** apply to `compromised/account_group` only (see [the parameter table](#configure-group-ib-threat-intelligence-in-cortex)). Run separate instances for the account types:

- **Instance 1**: `Include unique type in data` only
- **Instance 2**: `Include combolist type in data` only
- **Instance 3** (optional): `Enable filter "Probable Corporate Access"`, for the accounts Group-IB marks as probable corporate access

### Filters

The instance filters the records of a collection before they become incidents. The settings below carry the filters an analyst changes most; **Collection filters** carries every other filter of every collection, listed in [Filters by collection](#filters-by-collection).

- **Minimum severity**: the lowest Group-IB severity a record needs, for every collection that carries an evaluation; `Low` (default) fetches every record. Group-IB rates every record of some collections the same, so `Medium` or `High` keeps all or none of them: `suspicious_ip/*` listings and breached records are green, DDoS attacks and defacements orange, masked cards red. For `malware/malware` it is the threat level; Telegram, Discord and forum posts, C&C records and actor profiles carry no rating.
- **Skip records older than (days)**: a record older than the window at the fetch is skipped and not fetched later, by the date that matters for its collection (the `max_age_days` row of the collection's table in [Filters by collection](#filters-by-collection) names it): the post date of a dark web post, the publication date of a vulnerability, the last sighting of a suspicious IP listing or C&C, the compromise date of an account, card or access listing. Group-IB re-sends old records when it updates them, so a fetch can bring records years old. `malware/malware` has no such date and is not filtered by it.
- **Vulnerability types to fetch** / **Vulnerability types to skip** (`osi/vulnerability`): comma-separated record types such as `cve`, `mscve`, `nessus` or `redhat`. The types to fetch are asked of the API as one query, and a single type to skip is excluded in the request when no types to fetch are set; every record is checked when it arrives. With **Skip records older than (days)** the fetch keeps the vulnerabilities published in the window; an older record updated in the window is skipped.
- **Vulnerabilities with an exploit only** (`osi/vulnerability`): the API is asked for the records with a known exploit, and every record is checked when it arrives.
- **Breached records to fetch** (`compromised/breacheddb`): `All` (default); `With a password`, asked of the API, which can answer nothing on a recent cursor for a while, since the password-bearing records are older than that cursor; `With a password or a credential column`. The last two check every record when it arrives and keep only the records that carry a password, a credential column or a secret that one of their columns quotes (see *Mask passwords and leaked secrets*), under every password-masking mode.
- **Payment detail types to fetch** (`compromised/spd`): a single selected type is also sent to the API; every record is checked when it arrives.
- **Dark web forum categories to fetch** / **Dark web forum categories to skip** (`darkweb/forums`): comma-separated categories, matched whatever their case. With categories to fetch set, a post without categories is skipped.
- **Open threat source types** (`hi/open_threats`): `Blog`, `Social Network` or both (default).
- **Collection filters**: one filter per line as `collection: filter = value`. The collection is a name or a pattern (`suspicious_ip/*`, `compromised/*`, `*`). The value is a comma-separated list, a number, `true`, a severity (`Low`, `Medium` or `High`), addresses or CIDR networks, a word such as `all`, `password` or `credentials`, or a query text, as **Filters by collection** says for each filter. An empty value removes the filter the settings above set for that collection. A line that starts with `#` is a comment. A line the integration cannot apply fails the instance test and every command, naming the line.

```text
osi/vulnerability: min_cvss = 7
osi/vulnerability: vendors = microsoft, cisco:ios
suspicious_ip/*: excluded_countries = US, DE
suspicious_ip/tor_node: exit_only = true
compromised/account_group: service_domains = example.com
hi/threat: with_iocs_only = true
darkweb/forums: query = forum:"forum.example.com"
```

Every filter decides the same way for its kind:

- A list filter (`types`, `countries`, `malware`, ...) keeps a record that carries at least one of the listed values; a record without the value is skipped. Its `excluded_` counterpart skips a record that carries any listed value and keeps a record without the value. Values are matched whatever their case; a filter whose row in **Filters by collection** says "subdomains included" also matches the subdomains of a listed domain; the scanner categories ignore separators (`Brute-Force` is `brute force`).
- A text filter (`issuers`, `leaks`, `targeted_companies`) keeps a record whose value contains one of the texts, whatever the case; a record without the value is skipped.
- A number filter (`min_cvss`, `min_epss_percentile`, `min_illegal_score`, `min_sources`, `max_price`) compares a number; a record without the number passes, a CVSS score of 0 without a vector counts as none, and `min_sources` counts a listing without sources as 0.
- `max_age_days` keeps the records whose date lies within that many days before the fetch, by the date the collection's table below names (the first one the record has; when that date is a placeholder of an unknown date, any date before 1980 such as `0001-01-01` or `1976-01-01`, the record passes and the next date is not read); a record without any of them passes.
- `min_severity` and `min_file_severity` take `Low`, `Medium` or `High`; an unrated record counts as `Low`.
- A `true` filter (`has_exploit`, `exit_only`, `secrets_only`, ...) keeps only the records the condition holds for; `false` is no filter.
- `excluded_networks` takes addresses and CIDR networks and skips the records whose address lies in one of them.
- `query` is sent to the API as `q` with every request of the collection; it filters nothing itself.

A skipped record is not fetched later: the cursor moves past it. Where the API has the same filter, the request asks for it as well (`osi/vulnerability` types and exploits, breached records with a password, one payment detail type) and every record is checked again when it arrives.

#### Filters by collection

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

##### `compromised/bank_card_group`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the card was last compromised, else the date it was first compromised. |
| `payment_systems` | list | Payment systems a card needs one of. |
| `issuer_countries` | list | Issuer country codes a card needs one of. |
| `issuers` | list | Text the issuer's name must contain. |
| `card_types` | list | Card types a card needs one of. |
| `malware` | list | Malware family names a card needs one of. |
| `excluded_malware` | list | Malware family names that skip a card. |

##### `compromised/masked_card`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the card was compromised, else the date it was detected. |
| `payment_systems` | list | Payment systems a card needs one of. |
| `issuer_countries` | list | Issuer country codes a card needs one of. |
| `issuers` | list | Text the issuer's name must contain. |
| `malware` | list | Malware family names a card needs one of. |
| `excluded_malware` | list | Malware family names that skip a card. |
| `skip_expired` | `true` | true skips the cards past their expiry date. |
| `skip_dumps` | `true` | true skips the records that are card dumps. |

##### `compromised/breacheddb`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the leak was published, else the date it was uploaded. |
| `records` | `all`, `password`, `credentials` | all (every record), password (the records with a password, asked of the API) or credentials (the records with a password, a credential column or a secret a column quotes). |
| `leaks` | list | Text the leak's name must contain. |
| `email_domains` | list | Domains of the leaked e-mail addresses, subdomains included. |

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

##### `compromised/access`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the access was compromised, else the date it was detected. |
| `access_types` | list | Access types a listing needs one of. |
| `malware` | list | Malware family names a listing needs one of. |
| `excluded_malware` | list | Malware family names that skip a listing. |
| `target_domains` | list | Domains of the target host, subdomains included. |
| `shops` | list | Marketplace domains a listing needs one of. |
| `excluded_shops` | list | Marketplace domains that skip a listing. |
| `max_price` | number | The highest price a listing may ask. |

##### `compromised/messenger`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the post date. |
| `channels` | list | Channel names a post needs one of. |
| `excluded_channels` | list | Channel names that skip a post. |
| `authors` | list | Author handles or first names a post needs one of. |
| `excluded_authors` | list | Author handles or first names that skip a post. |
| `with_attachment` | `true` | true keeps only the posts with an attachment. |

##### `compromised/discord`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the post date. |
| `channels` | list | Channel or server names a post needs one of. |
| `excluded_channels` | list | Channel or server names that skip a post. |
| `authors` | list | Author names, without the #discriminator, a post needs one of. |
| `excluded_authors` | list | Author names, without the #discriminator, that skip a post. |
| `with_attachment` | `true` | true keeps only the posts with an attachment. |

##### `darkweb/forums`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the post date. |
| `categories` | list | Group-IB categories a post needs one of; a post without categories is skipped. |
| `excluded_categories` | list | Group-IB categories that skip a post. |
| `forums` | list | Forum hosts a post needs one of. |
| `excluded_forums` | list | Forum hosts that skip a post. |
| `authors` | list | Author handles a post needs one of. |
| `excluded_authors` | list | Author handles that skip a post. |
| `languages` | list | Language names (English, Russian, ...) a post needs one of. |
| `query` | text | Sent to the API as `q` with every request of the collection: bare words, or `id:<id>`, `forum:"<host>"`, `nickname:"<handle>"`, `message:"<term>"` or `ocr_analyser:<term>`; the API rejects other field prefixes. |

##### `osi/git_repository`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity of the repository record; the files carry their own grades. |
| `max_age_days` | days | Days back from the fetch by the date the leak was detected. |
| `min_file_severity` | `Low`, `Medium`, `High` | The lowest grade one of the repository's files needs (gray and yellow count as Low). |
| `secrets_only` | `true` | true keeps only the repositories where a file holds a detected secret. |
| `secret_types` | list | Secret types (password, api_key, ...) a repository's files need one of. |

##### `osi/public_leak`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the leak was created. |
| `sources` | list | Sites a leak needs a link from. |
| `excluded_sources` | list | Sites whose leaks are skipped. |
| `match_types` | list | Match buckets (card, email, commonKeywords, ...) or bucket.category names a leak needs one of. |
| `excluded_match_types` | list | Match buckets or bucket.category names that skip a leak. |

##### `osi/vulnerability`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the publication date; an older record updated in the window is skipped. |
| `types` | list | Record types to fetch (cve, mscve, nessus, redhat, ...); asked of the API as well. |
| `excluded_types` | list | Record types to skip; a single type is asked of the API as well when types is empty. |
| `has_exploit` | `true` | true keeps only the records with a known exploit, asked of the API as well. |
| `seen_in_the_wild` | `true` | true keeps only the vulnerabilities seen exploited in the wild. |
| `min_cvss` | number | The lowest CVSS score a record needs: the merged cross-version score, else the legacy CVSS score. |
| `min_epss_percentile` | number | The lowest EPSS percentile (0-100) a record needs. |
| `vendors` | list | CPE vendors, or vendor:product pairs, a record's CPE table needs one of. |
| `products` | list | CPE products a record's CPE table needs one of. |

##### `attacks/ddos`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the attack began, else the date it was registered. |
| `types` | list | Attack types a record needs one of. |
| `protocols` | list | Protocols a record needs one of. |
| `target_countries` | list | Country codes of the attack's target. |
| `target_ports` | list | Target ports a record needs one of. |
| `malware` | list | Malware family names a record needs one of. |
| `actors` | list | Threat actor names a record needs one of. |

##### `attacks/deface`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date of the defacement. |
| `target_domains` | list | Domains of the defaced site, subdomains included. |
| `countries` | list | Country codes of the defaced site's address. |
| `actors` | list | Threat actor names a record needs one of. |
| `sources` | list | Source names a record needs one of. |

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

##### `attacks/phishing_kit`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest Group-IB severity a record needs. |
| `max_age_days` | days | Days back from the fetch by the date the kit was last seen, else the date it was first seen. |
| `brands` | list | Brands a kit needs to target one of. |
| `sources` | list | Source names a kit needs one of. |

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

##### `malware/malware`

| Filter | Value | What it does |
| --- | --- | --- |
| `min_severity` | `Low`, `Medium`, `High` | The lowest threat level a malware profile needs. |
| `platforms` | list | Platforms a malware profile needs one of. |
| `categories` | list | Categories (Infostealer, RAT, Ransomware, ...) a profile needs one of. |
| `excluded_categories` | list | Categories that skip a profile. |
| `source_countries` | list | Source country codes a profile needs one of. |

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

##### `hi/threat_actor`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the date the actor was last seen active. |
| `with_iocs_only` | `true` | true keeps only the profiles with linked indicators. |
| `sectors` | list | Sectors a profile needs one of. |
| `regions` | list | Regions a profile needs one of. |
| `malware` | list | Malware family names a profile needs one of. |
| `excluded_malware` | list | Malware family names that skip a profile. |
| `query` | text | A name, alias or forum username sent to the API as `q` with every request of the collection, without a field prefix. |

##### `apt/threat_actor`

| Filter | Value | What it does |
| --- | --- | --- |
| `max_age_days` | days | Days back from the fetch by the date the actor was last seen active. |
| `with_iocs_only` | `true` | true keeps only the profiles with linked indicators. |
| `sectors` | list | Sectors a profile needs one of. |
| `regions` | list | Regions a profile needs one of. |
| `malware` | list | Malware family names a profile needs one of. |
| `excluded_malware` | list | Malware family names that skip a profile. |
| `query` | text | A name, alias or country sent to the API as `q` with every request of the collection, without a field prefix. |

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

## Data Collections Overview

The integration fetches the following collections; `gibti-get-available-collections` lists the ones granted to your API user. For the structure and fields of each collection, see the [Collections Overview documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Overview%2FCollections%20Overview).

On a trial or POC account, some collections serve only the last 30 days.

| Collection | Description | Recommended Date Range |
|------------|-------------|----------------------|
| `compromised/account_group` | The collection contains credentials collected from phishing resources, botnets, C&C servers, the dark web and other sources used by attackers. It also includes combolist and corporate accounts. For public breaches, see `compromised/breacheddb`. | 2-4 years |
| `compromised/bank_card_group` | Information about compromised bank cards, sourced from card shops, forums, and public leaks. | 2 years |
| `compromised/masked_card` | Information about compromised masked bank card records returned as individual card entries, including card, owner, malware and source details and the shop the card was offered in. | 2 years |
| `compromised/spd` | Suspicious payment details collected from underground markets, forums, and messaging platforms. Supersedes the removed `compromised/mule` collection (selecting the old name fails with a message naming this one). | 90 days |
| `compromised/breacheddb` | Information about publicly leaked databases containing credentials and personal data. | 90 days |
| `compromised/access` | Dark web marketplace listings of access to your hosts: the target host and device, the stealer family, the shop and the seller, the price and the file list of the offered archive. A listing is a signal to investigate, not the stolen data itself: the target is your own host and the shop is the marketplace, so it yields no indicators. | 30 days |
| `compromised/messenger` | Telegram posts your hunting rules matched, with the channel, the author, the attachment, the earlier versions of the post and the post it replies to. A post is free text that can quote anything, card numbers and credentials included: see [Dark web collections](#dark-web-collections). | 7 days |
| `compromised/discord` | Discord posts your hunting rules matched, handled as Telegram posts are. | 7 days |
| `darkweb/forums` | Forum posts your hunting rules matched, with the forum, the board path, the thread, the author, Group-IB's categories, the languages and the text of the post's images. The integration reads one page of the collection per fetch. A start cursor exists for the last three weeks only, so keep **Incidents first fetch** inside them. | 7 days |
| `attacks/ddos` | Data on Distributed Denial of Service (DDoS) attacks, including targeted resources and attack durations. An incident is dated by the start of the attack and named after the target's IP, else its domain or URL. | 5-10 days |
| `attacks/deface` | Records of defacement attacks, highlighting compromised websites and related actors. | 5-10 days |
| `attacks/phishing_group` | Information on phishing attacks, including URLs of phishing websites. Only the phishing URLs become indicators: the domain and the hosting IP are often shared infrastructure (a free blog host, a cloud provider's address) and stay on the incident. An incident is named after the phishing domain, followed by the impersonated brand in parentheses when the record names one other than the domain. | 3-5 days |
| `attacks/phishing_kit` | Collections of phishing website templates, scripts, and configurations used by attackers. | 30 days |
| `apt/threat` | Reports on nation-state APT activity, including associated indicators (IOCs). | 2-4 years |
| `apt/threat_actor` | Profiles of nation-state groups detailing their characteristics, targets, motivations, and techniques. | 2-4 years |
| `hi/threat` | Reports on financially motivated cybercriminals, including associated indicators (IOCs). | 2-4 years |
| `hi/threat_actor` | Profiles of financially motivated cybercriminals detailing their characteristics, targets, motivations, and techniques. | 2-4 years |
| `hi/open_threats` | Public posts about threats from security blogs and social networks, with the author, the source, the threat actors, malware families, countries, tags and CVE ids Group-IB extracted, and the hunting rules and company tags the post matched. The extracted IPs, domains, files, hashes, CVEs and crypto wallets are Suspicious indicators; an e-mail address stays on the record, since it can be a researcher's, a victim's or an attacker's. Without **Hunting Rules** the collection is the whole public feed. | 7 days |
| `malware/cnc` | Information on malware Command-and-Control (C&C) servers used for data exfiltration and command distribution. Its records carry no Group-IB evaluation; their incidents are created with High severity. | 90 days |
| `malware/malware` | Detailed malware descriptions. | 2-4 years |
| `osi/git_repository` | Publicly available code from repositories. A leak creates no indicators: the revision hashes of the leaked files and the committers' e-mails are not indicators of an attack. The incident takes the worst grade of the repository and its matched files as its severity (red High, orange Medium, yellow and green Low). | 30 days |
| `osi/public_leak` | Public data leaks from paste sites and other public sources, including credentials, database dumps, configuration files, and logs. | 15 days |
| `osi/vulnerability` | Information on software vulnerabilities, associated exploits, and available proof-of-concept details. | 90 days |
| `suspicious_ip/tor_node` | Tor relays, exit nodes and others, used as anonymity infrastructure. When the address block of a relay has no AS and provider, or no country, those come from the relay's newest consensus state, on the incident and on the IP indicator of a lookup. | 5 days |
| `suspicious_ip/open_proxy` | Information on publicly available proxy servers, including potentially misconfigured proxies. Each port of an address is its own incident, named `Suspicious IP Open Proxy: <address>:<port>`. | 5 days |
| `suspicious_ip/scanner` | IPv4 or IPv6 addresses identified as scanning or probing corporate networks. | 5 days |
| `suspicious_ip/socks_proxy` | IP addresses of infected hosts configured as SOCKS proxies used for anonymized attacks. | 5 days |
| `suspicious_ip/vpn` | VPN gateways with the product behind them. Most are legitimate commercial or corporate services, and with **Hunting Rules** the collection lists the gateways of your own organization. | 5 days |

The API serves the `compromised/*` collections, `darkweb/forums`, `osi/git_repository`, `osi/public_leak` and `attacks/ddos` filtered by your hunting rules whatever **Hunting Rules** says (see [Hunting Rules, deduplication and pre-processing](#hunting-rules-deduplication-and-pre-processing)).

**Volume.** `osi/vulnerability`, `hi/open_threats` and the `suspicious_ip/*` collections are global feeds unless **Hunting Rules** filters them, and `attacks/deface` is always global: as incidents they bring every record Group-IB publishes, from about a thousand a day on the proxy collections to well over a hundred thousand a day on `suspicious_ip/scanner`, and on Cortex XSOAR each of them runs through the pre-processing rule. Fetch `osi/vulnerability`, `hi/open_threats` and the `suspicious_ip/*` collections with **Hunting Rules**, or read any of these collections, `attacks/deface` included, as indicators through the **Group-IB Threat Intelligence Feed** integration.

## Configure Group-IB Threat Intelligence in Cortex

| **Parameter**                  | **Description** | **Required** |
|--------------------------------| --- | --- |
| GIB TI URL | The Group-IB TI API URL (default `https://tap.group-ib.com/api/v2/`). | True |
| Username                       | The e-mail address you log in to the Group-IB portal with. Enter your API token (Personal token) as the password. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying the SSL certificate's validity. | False |
| Use system proxy settings      | Whether to use Cortex XSOAR system proxy settings to connect to the API. | False |
| Source Reliability | Reliability of the source providing the intelligence data. Every DBotScore the integration writes carries it, except the reputation results that **Ignore Source Reliability override** gives a computed reliability. Default C - Fairly reliable. | True |
| Ignore Source Reliability override | Give the `ip`, `domain`, `file` and `url` reputation results the reliability of the most reliable matched collection (A for `ioc/primary`, `ioc/common` and `apt/threat`; B for `hi/open_threats` and `attacks/deface`) instead of **Source Reliability**. A result that none of these collections matched, the CVE indicators of `gibti-cve-scoring` and the indicators of the lookup commands keep **Source Reliability**. Disabled by default. | False |
| Collections to fetch | The Group-IB collections to fetch incidents from; none by default. | False |
| Fetch incidents | Enable to fetch incidents from the selected collections. | False |
| Incidents first fetch | Date to start fetching incidents from (default 3 days). Each collection starts at the Group-IB cursor for that date (`attacks/ddos` and `attacks/phishing_kit` start from the date itself when no cursor is available). Any other collection without a cursor for that date is not read yet; the instance health names it, the cursor is requested again on the next fetch, and the other collections are fetched. If a collection keeps waiting, set a later date. Changing this value after the first run restarts every selected collection from the new date (the stored cursors are dropped). The value is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch. | False |
| Incident type | Default incident type for incidents that the classifier does not map (leave empty to use the pack classifier). | False |
| Incidents Fetch Interval | Minutes between two fetch runs (default 1). Advanced. | False |
| Exclude All with Combolist type | Deprecated and ignored; use "**Include combolist type in data**" / "**Include unique type in data**". | False |
| Number of requests per collection | Number of pages read per collection in one fetch iteration (default 3); each page asks for up to "**Limit (items per request)**" records. On `suspicious_ip/*`, `compromised/spd`, `malware/cnc`, `osi/public_leak` and `darkweb/forums`, a page that one cursor position fills is read again larger, up to 1,000 records (100 on `osi/public_leak`); each larger read is one more request and does not count as a further page. Lower the value if fetches time out. `darkweb/forums` reads one page per fetch whatever this value is. | False |
| Skip updated incidents (prevent duplicates) | Disabled by default. Enable it on Cortex XSIAM and the Cortex platform, where the pack does not install the pre-processing rule **GIB Rule All Types**: without that rule, every update Group-IB makes to a record arrives as a new alert. Where **GIB Rule All Types** runs, leave it disabled so that the rule updates the existing incidents, and enable it if you do not use that rule. Enabled, the integration skips Group-IB records it already fetched when they are sent again after an update, so the update does not arrive. The integration remembers a record by its collection and ID, an open proxy by its address and port, and a breached record by its ID, leak name and upload time. | False |
| Deduplication lookback (days) | Days a fetched record stays in the duplicate cache while **Skip updated incidents (prevent duplicates)** is enabled (default and recommended: `365`); an older entry hides nothing. Group-IB can re-send a record long after it was fetched; a shorter window lets it open a new incident. `0` turns the cache off; a negative value fails every fetch, whatever **Skip updated incidents (prevent duplicates)** says. | False |
| Pass flagged phishing groups to the pre-processing rule | Disabled by default: a phishing group that Group-IB flags as a false positive or allow-listed is dropped at fetch and never opens an incident, and an incident opened before Group-IB set the flag never shows it. Enabled, flagged groups go to the pre-processing rule **GIB Rule All Types**, which sets *GIB False Positive* or *GIB Allow Listed* on the open incident of the group and drops the record; a flagged group without an open incident is dropped there too. While **Skip updated incidents (prevent duplicates)** is enabled and **Deduplication lookback (days)** is above 0, only a group the integration already made an incident of is handed on. Enable it only while **GIB Rule All Types** runs; the pack does not install that rule on Cortex XSIAM and the Cortex platform. Without that rule, every flagged group handed on opens an incident of its own, a second one when the group already has an incident. | False |
| Limit (items per request) | Number of items requested per API page, for every collection of the instance (default 100). Larger values reduce API round-trips but may increase response size. A collection with a smaller page size of its own is read in pages of that size whatever this value is. On `suspicious_ip/*`, `compromised/spd`, `malware/cnc`, `osi/public_leak` and `darkweb/forums`, a page that one cursor position fills is read again larger, up to 1,000 records (100 on `osi/public_leak`; see the README's Limit Parameter section). | False |
| Enable reputation commands | Select which reputation commands should be enabled for this integration instance (`ip`, `domain`, `file`, `url`). Default is none enabled. Only the selected commands perform enrichment and return a DBotScore. To keep this instance from answering the generic `!ip`/`!domain`/`!file`/`!url` commands, also select "**Do not use by default**" on the instance and call it explicitly with `using="<instance name>"`. | False |
| Create relationships | Relate the indicators of the lookup commands, and the Suspicious or Bad results of the reputation commands, to the *Malware* and *Threat Actor* objects their records name (indicator-of / related-to). A result made Suspicious only by **Collections that keep an IP at least Suspicious** gets none, and the defacer of an `attacks/deface` record is never related. The objects themselves are created by the feed integration or by the GIBTIEnrichIncidentIndicators automation. Enabled by default; disable it to keep the commands to plain observables. | False |
| Mask passwords and leaked secrets | What happens to passwords and other leaked secrets before they reach Cortex XSOAR (incident fields, the lookup commands and `gibti-local-search`). It covers the passwords of `compromised/account_group` and `compromised/breacheddb` records (*GIB Password*, *GIB Passwords*), and the columns of a breached record's leak (*GIB Breach Record Details*), at any depth, whose name says they hold a password, a secret, a salt, a token, a session ID, a password hash or a secret key such as an API, access, private or SSH key (`user_pass`, `userPw`, `usersalt`, `accessToken`, `sessionId`, `apiKey`, `passwordHash`, `md5`, `senha`, `sshKey`). It also covers the values Group-IB's detectors extracted from an `osi/public_leak` record (*GIB Matches Table*) and the record's raw text (*GIB Leaked Data*). In these records and in dark web posts, it masks a secret written after such a name (`password: ...`, `accessToken=...`, `"clientSecret": "..."`, `<dbPassword>...</dbPassword>`), the password of an e-mail:password pair, a url:login:password line or a `user:password@host` URL, an Authorization header, a Bearer or Basic credential, a crypt hash, the LM and NT hashes of an NTLM dump line, a private key, a GitHub, GitLab, Slack or Stripe token, and every other copy of a password or secret the record names or a text quotes, where it stands apart from other letters and digits (from six characters, or from four in a sentence for a value the record names). A login:password line without an e-mail address or URL is not recognized, and the C&C address of a compromised account keeps its credentials, which are the attacker's. A login, a parsed login domain, a service domain or a breached record's e-mail address or e-mail domain stays as it is when the password is part of its name (`sample@example.com`, the user of `CORP\sample`) or the whole of it, so the incident keeps naming its account: a password equal to the login stays readable there under Partial and Full. In those fields, a `login:password`, a URL, a password in the domain of a `DOMAIN\user` login or a password written beside a login is masked. A hash of anything else (`emailHash`), a passport number (`passportNumber`) and a column that dates a credential, names its type or describes it (`passwordChangedAt`, `hashType`, `passwordLength`) do not count as credentials. A breached record that holds a credential makes the incident High under every setting; a credential column holding only a flag (true/false, 0/1), a placeholder (null, -) or nothing does not count. **Off** (default) keeps everything as Group-IB delivers it. **Partial** keeps the first half of each password or secret followed by `****` (of each part, for a value split by spaces, commas, semicolons or pipes), enough to recognize a reused password. **Full** drops the passwords and credential columns, puts `[withheld]` in place of every other secret and withholds the raw text of a public leak. A change applies to what is fetched or looked up afterward; when Group-IB re-sends the record of an open incident, the incident takes the new value, except that a password or column **Full** drops can stay on an incident that already holds it; clear it yourself. | False |
| Mask card data | Masks the card data of `compromised/bank_card_group` records and the cardholder of `compromised/masked_card` records before they reach Cortex XSOAR (incidents, `gibti-get-compromised-card-group-info`, `gibti-get-compromised-masked-card-info` and `gibti-local-search`). The card number keeps its first six and last four digits, in the incident name too; the CVV is dropped; the cardholder's name and phone read `[redacted]`. The BIN, issuer, expiry and the shop the card was offered in stay. A masked card arrives with its number masked by Group-IB and its owner in plaintext; with the setting on, the owner's name, address, birthday, e-mail, phone, city, ZIP code, passport and tax number read `[redacted]`, while the owner's state and country stay. Disabled (default) keeps the card data as Group-IB delivers it. A change applies to what is fetched or looked up afterward; when Group-IB re-sends the record of an open incident, the incident takes the masked number, while a CVV it already holds stays. | False |
| Mask dark web post text | What happens to the text of `compromised/messenger`, `compromised/discord` and `darkweb/forums` posts before it reaches Cortex XSOAR (*GIB Post Text*, *GIB Post Translation*, *GIB Reply Text*, *GIB Image Text*, GIB Post Edits Table, the lookup commands and `gibti-local-search`). A post is free text that can quote anything its author wrote, card numbers and credentials included. **Off** (default) keeps the text as Group-IB delivers it. **Partial** keeps the last four digits of each card number (13 to 19 digits in one run, or groups of three or more digits on one line that pass the card check digit) outside IPv4 addresses. It clears each CVV code labeled CVV, CVC, CV2 or CID or written on the card's line beside its expiry, and the magnetic stripe data after a card number. Partial covers the text and a forum post's topic and URL. In a URL, a number counts as a card only by the check digit and only apart from other digits, and `cid=` stays as an id. Passwords and other secrets follow the **Mask passwords and leaked secrets** setting. **Full** withholds the text and a forum post's topic, names the incident after the forum, masks its URL as Partial does and keeps the post's metadata (channel, author, dates, attachment, hash). A change applies to what is fetched or looked up afterward. | False |
| Minimum severity | The lowest Group-IB severity a record needs to become an incident, for every collection that carries an evaluation. `Low` (default) fetches every record, and a record without a rating counts as `Low`. A record below the minimum is skipped when it arrives and is not fetched later. Group-IB rates every record of some collections the same, so `Medium` or `High` keeps all or none of them: `suspicious_ip/*` listings and breached records are green, DDoS attacks and defacements orange, masked cards red. For `malware/malware` it is the threat level. Telegram, Discord and forum posts, C&C records and actor profiles carry no rating and are not held to it. | False |
| Skip records older than (days) | A record older than this many days at the fetch is skipped and not fetched later, by the date that matters for its collection: the post date of a dark web post, the publication date of a vulnerability, the last sighting of a suspicious IP listing or C&C, the compromise date of an account, card or access listing (the README lists every collection's date). Group-IB re-sends old records when it updates them, so a fetch can bring records years old. `malware/malware` has no such date and is not filtered by it. Empty or 0 (default) keeps every record. | False |
| Vulnerability types to fetch | Works only for `osi/vulnerability`. A comma-separated list of record types to fetch, such as `cve, mscve`, nessus or redhat; case does not matter. The types are asked of the API as well, and every record is checked when it arrives. Empty (default) fetches every type. | False |
| Vulnerability types to skip | Works only for `osi/vulnerability`. A comma-separated list of record types to skip, such as `nessus`. A single skip type is also excluded in the API request when no types to fetch are set; every record is checked when it arrives. Empty (default) skips none. | False |
| Vulnerabilities with an exploit only | Works only for `osi/vulnerability`. Disabled by default. Enabled, only the records with a known exploit are fetched: the API is asked for them, and every record is checked when it arrives. | False |
| Breached records to fetch | Works only for `compromised/breacheddb`. `All` (default) fetches every record. `With a password` asks the API for the records that carry a password; on a recent cursor that request can return nothing for a while, since the password-bearing records are older than that cursor. Both With a password and `With a password or a credential column` check every record when it arrives and keep only the records that carry a password, a credential column or a secret that one of their columns quotes (see **Mask passwords and leaked secrets**), under every password-masking mode. | False |
| Payment detail types to fetch | Works only for `compromised/spd`. The payment detail types to fetch; empty (default) fetches every type. A single selected type is also sent to the API; every record is checked when it arrives. | False |
| Dark web forum categories to fetch | Works only for `darkweb/forums`. A comma-separated list of the categories Group-IB gives forum posts, such as `Access, Sale, Database`, Exploit, Leak; case does not matter. When set, only a post with at least one of them is fetched, and a post without categories is skipped. Empty (default) fetches every post. The category list is open, and a post's categories can include your organization's monitoring label. | False |
| Dark web forum categories to skip | Works only for `darkweb/forums`. A comma-separated list of categories; a post with any of them is skipped, whatever the categories to fetch say. Empty (default) skips nothing. | False |
| Open threat source types | Works only for `hi/open_threats`. The kinds of public posts to fetch; empty (default) fetches both. Blog posts are long articles and carry most of the extracted CVEs; social network posts are short messages, with indicators extracted the same way. | False |
| Collection filters | Every other filter of this integration, one per line as `collection: filter = value`, for example `osi/vulnerability: min_cvss = 7` or `suspicious_ip/*: excluded_countries = US, DE`. The collection is a name or a pattern (`suspicious_ip/*`, `*`); the value is a comma-separated list, a number, true, a severity (Low, Medium or High), addresses or CIDR networks, a word such as all, password or credentials, or a query text, as the README says for each filter; an empty value removes the filter the settings above set for that collection; a line that starts with # is a comment. A line the integration cannot apply fails the instance test and every command, naming the line. The README lists the filters of each collection and their values. | False |
| Collections that keep an IP at least Suspicious | The ip reputation command returns at least Suspicious for an IP that one of the selected `suspicious_ip/*` collections lists, whatever its Group-IB risk score, and tags it with the collection (without malware or actor names). It applies to ip only; the verdict of a domain comes from its risk score and `ioc/primary`. A listed IP can still score below 40, for example a Tor exit without malicious history. A collection counts only when one of its records is the IP itself, at any age unless **Suspicious IP listing recency (days)** sets a window. Each selected collection is one more request per IP. Every `suspicious_ip/*` collection is selected by default; clear one to leave the verdict to the risk score and `ioc/primary`. Select only the none option so that no listing keeps an IP at least Suspicious; an empty selection uses the default. | False |
| Suspicious IP listing recency (days) | How many days after Group-IB last saw it (`dateLastSeen`) a `suspicious_ip/*` listing still keeps an IP at least Suspicious in the `ip` reputation command and passes its TLP to the result. Empty (default) or 0 counts a listing of any age. A number applies to every `suspicious_ip/*` collection; a listing last seen longer ago, or without a last-seen date, leaves the IP to its risk score and `ioc/primary`. Set a window when an address that served as a proxy, relay or gateway should not stay Suspicious after it stops. Advanced. | False |
| Lookup timeout (seconds) | Longest wait, in seconds, for the Group-IB requests of one value of the `ip`, `domain`, `file` and `url` reputation commands, which run up to **Parallel requests per lookup** at a time. A request that has not answered by then is left out, and the War Room note names it. A verdict is then set only if no missing answer could have raised it. A missing risk score or `ioc/common`, or the `ioc/primary` of a file, could make it Bad, so only a Bad verdict is set; a missing `ioc/primary` of an IP or domain or a missing `suspicious_ip/*` collection could make it Suspicious, so a Suspicious or Bad verdict is set and a lower one is not. Without a verdict, the indicator keeps the one it has. A url sends one request, so a url without an answer gets an error entry. A list of IPs or domains first waits up to the same time for its risk scores. 0 waits without a limit. Default 20. Advanced. | False |
| Parallel requests per lookup | How many Group-IB requests one value of a reputation command sends at once (default 4, at least 1): the collections it reads, the risk score, the WHOIS record and the global search. A higher number answers sooner and sends more requests at the same time; 1 sends them one after another. Advanced. | False |
| Use the Group-IB global search | Disabled by default. Enabled, `ip`, `domain` and `file` also ask the Group-IB global search which other collections mention the value, and list them in `GIBTI.Reputation.collections`; they do not decide the verdict. A result below Suspicious also lists them in its War Room note and, with **Collection tags at every verdict** enabled, in its tags; a Bad result lists them in Malicious.Description. The global search is one more request per value, and a lookup waits for it up to **Lookup timeout (seconds)**. Advanced. | False |
| Collection tags at every verdict | Enabled by default: a reputation result below Suspicious carries as tags the collections in `GIBTI.Reputation.collections`, without their malware or actor names; for an ip result, a collection selected in **Collections that keep an IP at least Suspicious** is never among them. Disabled, such a result carries no tags. Disable it when tags on Good and Unknown indicators would start tag-based playbooks or searches. Advanced. | False |
| Add WHOIS to ip and domain | Enabled by default: `ip` and `domain` also read the Group-IB WHOIS record of the value and write its registry data to the indicator. For an IP: the ASN, the holder organization, the owner of the AS when the registry names it, and the abuse e-mail and phone. For a domain: the registrar and its abuse contact, the registrant's organization and country, the registrant's name and e-mail address unless **WHOIS personal data** is `Drop`, and the dates, statuses and name servers. One more request per value, two for a subdomain; it never decides the verdict. Advanced. | False |
| WHOIS personal data | `Show` (default) keeps a registrant's name and e-mail address as the public WHOIS gives them; `Drop` leaves them out of `gibti-domain-whois` and of the domain indicator. Many registries already hide them. Advanced. | False |
| Look up internal and reserved IP addresses | Disabled by default: the `ip`, `gibti-ip-whois` and `gibti-ip-scoring` commands answer a private, loopback, link-local, shared (100.64.0.0/10) or reserved address, the documentation ranges included, with a note and ask Group-IB nothing, since Group-IB has no intelligence on such an address and its registry data describes another network. Enable it to look such addresses up. Advanced. | False |
| Include combolist type in data | Works only for `compromised/account_group`. Disabled by default. Enabled alone, only combolist records are fetched; with **Include unique type in data** also enabled, or with both disabled, records of both types are fetched. | False |
| Include unique type in data | Works only for `compromised/account_group`. Disabled by default. Enabled alone, only unique records are fetched; with **Include combolist type in data** also enabled, or with both disabled, records of both types are fetched. | False |
| Enable filter "Probable Corporate Access" | Works only for `compromised/account_group`. Disabled by default: every account is fetched. When enabled, the API returns only the accounts it marks as probable corporate access. It combines with the unique and combolist filters. | False |
| Delay between API requests (seconds) | Minimum number of seconds between consecutive requests to the same collection while a fetch or `gibti-local-search` pages through it (default 1.2; the first request is never delayed; 0 disables the delay). Raise it if the API answers HTTP 429. Advanced. | False |
| Hunting Rules | Disabled by default. Enabled, it fetches only the records that match your Group-IB hunting rules from the collections where the filter is optional and your API user has hunting rules enabled (`hi/threat`, `hi/threat_actor`, `apt/threat`, `apt/threat_actor`, `hi/open_threats`, `osi/vulnerability`, `attacks/phishing_kit`, `attacks/phishing_group`, `suspicious_ip/*`). The API always filters the `compromised/*` collections (`compromised/access`, `compromised/messenger` and `compromised/discord` included), `darkweb/forums`, `osi/git_repository`, `osi/public_leak` and `attacks/ddos` by your hunting rules, whatever this setting says; the other collections are fetched unfiltered. A filtered collection with no matching hunting rule returns no records while this is enabled. `hi/open_threats` without this setting is the whole public feed; with it, only the posts your hunting rules matched. Turning the setting on or off restarts the selected collections from **Incidents first fetch** (the stored cursors are dropped). The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch. | False |

## Hunting Rules, deduplication and pre-processing

**Hunting Rules** applies per collection, the same way as in the feed integration: the hunting-rules parameter is sent for the collections whose API supports it and for which your API user has hunting rules enabled (`hi/threat`, `hi/threat_actor`, `apt/threat`, `apt/threat_actor`, `hi/open_threats`, `osi/vulnerability`, `attacks/phishing_kit`, `attacks/phishing_group`, `suspicious_ip/*`, `compromised/messenger`, `darkweb/forums`), and always for `compromised/breacheddb` and `osi/public_leak`. Any other collection, and one without the grant, is fetched without the hunting-rules parameter and noted in the debug log, so one instance can mix both. The API serves the `compromised/*` collections (`account_group`, `bank_card_group`, `masked_card`, `spd`, `breacheddb`, `access`, `messenger`, `discord`), `darkweb/forums`, `osi/git_repository`, `osi/public_leak` and `attacks/ddos` filtered by your hunting rules whatever the setting says, and the integration never asks for their unfiltered view. The hunting-rules grant check runs for fetch-incidents only. Turning the setting on or off restarts the selected collections from **Incidents first fetch**: the filtered and the unfiltered views move through different cursors, so the stored ones are dropped. The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch. A filtered collection for which none of your hunting rules matches returns no records at all while the setting is on (typically the `suspicious_ip/*` collections and `apt/threat` when the rules target other data); disable the setting or move those collections to a second instance if you want them unfiltered. Every fetched incident carries *GIB Fetched With Hunting Rules*: true when the record came through the API filter (always for the collections the API filters), false when its collection was fetched unfiltered.

On Cortex XSIAM and the Cortex platform, enable the built-in deduplication, **Skip updated incidents (prevent duplicates)**. The pack does not install the pre-processing rule **GIB Rule All Types** on Cortex XSIAM and the Cortex platform, so there nothing merges a record Group-IB sends again after an update, and each update arrives as a new alert; for example, every edit Group-IB makes to a threat report would open another alert. With the setting enabled, the integration skips Group-IB records it already fetched, so a report's later updates do not arrive; *GIB Portal Link* on the alert leads to the current version.

Where **GIB Rule All Types** runs, leave **Skip updated incidents (prevent duplicates)** disabled so that the rule updates the existing incidents, and enable it if you do not use that rule.

The built-in deduplication remembers each record by its collection and its id: an open proxy by its address and port, a breached record by its id, leak name and upload time. An address that several `suspicious_ip/*` collections list, or an open proxy listed on several ports, therefore gets one incident per collection and per port. A record that fails to become an incident is not remembered, so it gets its incident when Group-IB serves it again, and an entry older than **Deduplication lookback (days)** hides nothing. The cache of an earlier version keeps working after the upgrade while **Skip updated incidents (prevent duplicates)** is enabled and **Deduplication lookback (days)** is above 0 (a fetch with either one off empties the cache): a remembered record id still hides its record, except a breached record, which the cache keys by its id, leak name and upload time, so it can arrive once more; a remembered IP address is kept only when the instance last fetched exactly one `suspicious_ip/*` collection and that collection is not `suspicious_ip/open_proxy`. Any other remembered address is dropped, so the record it named can arrive once more: where **GIB Rule All Types** runs, the rule merges it into the open incident of the same type, and without the rule it arrives as a new incident or alert.

The shipped pre-processing rule **GIB Rule All Types** runs `GIBTIIncidentUpdateAllTypes` for every incoming incident with a GIB ID: open incidents of the same incident type with the same GIB ID (for an open proxy also the same *GIB Proxy Port*, for a data breach also the same *GIB Leak Name* and *GIB Upload Time*) receive the incoming custom fields, name, occurred time and details (severity, owner, status, type and playbook are never overwritten), and the incoming incident is dropped once at least one of them was updated (or when there was nothing to copy). An incident whose type an analyst changed by hand no longer matches, and the record opens a new incident. Closed incidents are not reopened: a re-sent record whose incident is closed creates a new incident. Two records with the same GIB ID in one fetch batch can both become incidents. The legacy rule **GIB Rule** (`GIBTIIncidentUpdate`, all types except Data Breach) ships disabled; `GIBTIIncidentUpdateIncludingClosed` is the variant that also updates closed incidents, for rules you create yourself. After installing the pack, check that **GIB Rule All Types** shows the script **GIBTIIncidentUpdateAllTypes**; testing an instance (**Test**) fills it in when it is missing. If it still shows none, select it in the rule.

Group-IB marks a phishing group as a false positive (`falsePositive`) or allow-listed (`whitelist`) when it no longer considers it phishing. By default the fetch drops such a record: it never opens an incident, and an incident opened before Group-IB set the flag never shows it. On Cortex XSOAR, with **Pass flagged phishing groups to the pre-processing rule** enabled, the record goes to **GIB Rule All Types**, which writes *GIB False Positive* or *GIB Allow Listed* on the open incident of the group and drops the record, also when no incident matches or the update fails. While **Skip updated incidents (prevent duplicates)** is enabled and **Deduplication lookback (days)** is above 0, only a group the integration already made an incident of is handed on. `gibti-get-phishing-group-info` and **GIBTIEnrichIncidentIndicators** return no indicator for a flagged group, and an incident built from one lists nothing in *GIB Related Indicators Data*.

## Dark web collections

`compromised/access`, `compromised/messenger`, `compromised/discord` and `darkweb/forums` are the dark web collections: marketplace listings of access to your hosts and the Telegram, Discord and forum posts your hunting rules matched. The API serves all four filtered by your hunting rules, so every record already is a match on your organization, and the incident is the place to triage it.

None of them yields indicators. A listing names your own host and the marketplace it is sold on (*GIB Shop Domain*, *GIB Shop URL*, *GIB Shop IP* are the storefront, not attacker infrastructure). A post is free text that can quote anything its author wrote: the victim's own addresses and hosts next to the seller's claims. *GIB Related Indicators Data* stays empty on these incidents, the incident types extract nothing from their fields, and **GIBTIEnrichIncidentIndicators** reports that the record carries no indicators.

The text of a post reaches *GIB Post Text*, *GIB Post Translation*, *GIB Reply Text*, *GIB Image Text*, *GIB Post Edits Table*, the lookup commands and `gibti-local-search` as Group-IB delivers it unless **Mask dark web post text** or **Mask passwords and leaked secrets** says otherwise. With **Mask dark web post text** at `Partial`, the integration keeps the last four digits of each card number and clears each CVV code (labeled CVV, CVC, CV2 or CID, or written on the card's line beside its expiry) and the magnetic stripe data after a card number, in every copy of the text and in a forum post's topic and URL. A card number is 13 to 19 digits as one run, or digits written on one line in groups of three or more that pass the card check digit, outside IPv4 addresses; in a URL, a number counts as a card only by the check digit and only apart from other digits, and `cid=` stays as an id. At `Full`, it withholds the text and a forum post's topic, names the incident after the forum, masks its URL the same way and keeps the post's metadata (channel, author, dates, attachment, hash). **Mask passwords and leaked secrets** masks the passwords and secrets it recognizes in a post. Telegram, Discord and forum posts carry no Group-IB evaluation and are created with **High** severity.

Group-IB collects old posts continuously, so a fetch can bring posts years old: **Skip records older than (days)** drops them by their post date, and **Collection filters** takes the channels, forums and authors to fetch or skip and the languages to fetch (see [Filters by collection](#filters-by-collection)). **Dark web forum categories to fetch** and **Dark web forum categories to skip** keep the forum posts to the topics you want; Group-IB's category list is open, a post can carry none, and the list can include your organization's monitoring label. The integration reads one page of `darkweb/forums` per fetch; `sequence_list` gives it a start cursor for the last three weeks only.

`hi/open_threats` is not a dark web collection: public posts about threats, with the IOCs Group-IB extracted from them as Suspicious indicators, the whole public feed unless **Hunting Rules** is on. **Open threat source types** keeps the fetch to blog articles or social network posts, **Minimum severity** to the posts Group-IB rates Medium or High.

## Postprocessing playbook

Every Group-IB incident type names **Incident Postprocessing - Group-IB Threat Intelligence & Attribution** as its default playbook, and none of them runs it automatically: a fetched incident is created without it. Run the playbook from the incident when you investigate it. To enrich every new incident of a collection, turn on **Run playbook automatically** in the settings of its incident type. Each run costs a few Group-IB API requests: it reads the incident's record again, then the profiles of the actors the record names and the first report each kind of profile lists. Leave the option off for high-volume collections such as `suspicious_ip/*`, and for the dark web collections, whose records carry no indicators to enrich.

## Deprecation notice: `gibtia-` command names

Every `gibtia-` command is available under the `gibti-` prefix. The old `gibtia-` names still work in 4.0.0 for playbooks written against them, but they are marked deprecated in the command list, and every call adds a warning entry to the War Room naming the `gibti-` replacement. `gibtia-get-compromised-mule-info` instead fails with an error naming `gibti-get-compromised-spd-info`, as the deprecated `gibti-get-compromised-mule-info` does. Rename the commands in your playbooks and scripts; the outputs are identical, and so are the arguments, except that `gibti-get-suspicious-ip-vpn-info`, `gibti-get-suspicious-ip-scanner-info` and `gibti-get-malware-malware-info` require *id*. Their `gibtia-` names mark it optional, but they fail without it too.

## Indicator enrichment and relationships

The `gibti-get-*-info` lookup commands and the reputation commands create indicators for the observables of a record (the address of a Tor, proxy, VPN or scanner listing, C&C URLs, domains and IPv4 and IPv6 addresses, phishing URLs, the defaced URL, the hash and operator e-mails of a phishing kit, file hashes, the e-mail address and sender IP of a report's email-message entries, CVEs, crypto wallets, and the IPs, domains, files, hashes, CVEs and wallets Group-IB extracted from a public post) and fill them with what the record knows. The dark web collections yield none (see [Dark web collections](#dark-web-collections)). The `cnc` block of the card collections (`compromised/bank_card_group`, `compromised/masked_card`) is the shop the card was offered in and is not turned into an indicator; an `osi/vulnerability` advisory becomes a CVE indicator only when its id is a CVE id. The indicators get:

- **Standard fields**: *ASN*, *Geo Country* (the ISO code when the record has no country name), *Geo Location* and *Organization* (the hosting provider) for IPs; file name, size and the other hashes for files (each file of a threat report with its own, keyed by its SHA-256, else its SHA-1, else its MD5, else its SHA-512); CVSS, dates and description for CVEs; *Malware Family* from the malware names of the record on IP, domain, URL and file indicators (for a C&C of a compromised account, those of its own event); the record's **TLP** (TLP:CLEAR is stored as WHITE, TLP:AMBER+STRICT as AMBER, and any other marking Cortex XSOAR does not know as RED); a **DBotScore** with the verdict of the record's collection (see [Indicator verdicts](#indicator-verdicts)) and the instance **Source Reliability**.
- **Tags**: the collection name, the malware families, the threat actors and (phishing groups) the targeted brand. A *Cryptocurrency Address* indicator carries no TLP, tags or *Malware Family*, and an *Email* or *CVE* indicator no *Malware Family*, whether a lookup or **GIBTIEnrichIncidentIndicators** creates it.
- **Relationships** (**Create relationships**, on by default): each observable is an *indicator-of* a *Malware* indicator for every malware family its record names, and *related-to* a *Threat Actor* indicator for every threat actor (for a C&C of a compromised account, those of its own event; a reputation result only when it is Suspicious or Bad), so the malware and actor pages list every observable attributed to them. The feed integration and the **GIBTIEnrichIncidentIndicators** automation, which the postprocessing playbook runs first (see [Postprocessing playbook](#postprocessing-playbook)), create the objects the relationships point to. Both create them as Bad. Disable the setting to keep the commands to plain observables.

A defanged value in a record (`hxxps://`, `evil[.]example[.]com`) is restored before the indicator is created, so the indicator matches real traffic. A placeholder (`/contents/{machineId}/`, an e-mail value such as `{email}`) is not an indicator. Of the payment details of `compromised/spd`, only a crypto wallet is an indicator of this integration; the feed creates the others. A Bitcoin wallet (a valid base58check address starting with 1 or 3, or a `bc1` address) becomes the indicator `bitcoin:<address>`, the value Cortex XSOAR's own extraction gives a base58check wallet, so an extracted wallet and an enriched one are the same indicator. The platform's extraction recognizes neither a `bc1` wallet nor a wallet of another chain; **GIBTIEnrichIncidentIndicators** creates both, a wallet of another chain under its bare address.

### Indicator verdicts

Group-IB's evaluation severity of a record (*GIB Severity*: Low, Medium, High; Group-IB's green, orange, red) says how urgent the event is for you, not how malicious its observables are (a Tor exit node is green), so it never decides the verdict of an indicator. The collection does:

| Collection | Verdict of its indicators |
| --- | --- |
| `apt/threat`, `hi/threat`, `malware/cnc` | Bad: attacker infrastructure. |
| `compromised/spd` | The Group-IB illegal score of the payment detail: 80-100 Bad, below 80 Suspicious. |
| `osi/vulnerability` | Bad: a vulnerability Group-IB tracks (the graded rules on exploit evidence, EPSS, CVSS and Group-IB's severity belong to `gibti-cve-scoring`). |
| `hi/open_threats` | Suspicious: values a parser extracted from a public post are a watchlist to verify at the post, never a blocklist. |
| every other collection | Suspicious: anonymizers, scanners, phishing and defaced sites and the C&C behind compromised data are worth watching but not proven malicious on their own. |

Actor profiles (`hi/threat_actor`, `apt/threat_actor`) and malware profiles (`malware/malware`) yield no indicators; their lookups return the record only. The reputation commands decide differently, from Group-IB's risk score and the collections of indicators of compromise (see [Score calculation rules](#score-dbotscore-calculation-rules)).

When you run the commands in the War Room, the platform's indicator extraction creates the indicators and their relationships from the command entries. For an incident, the **GIBTIEnrichIncidentIndicators** task of the postprocessing playbook creates them, whatever the indicator extraction mode of the playbook task. The record entry and its tables are excluded from extraction: the victim's own data is never turned into an indicator (the client IP and the service login page of compromised accounts, the target of DDoS and defacement attacks, and the domain and hosting IP of a phishing page stay on the incident). The indicator entries of `gibti-get-attacks-deface-info` are excluded too, since extraction would add the host of the defaced site as a domain. In the War Room the defaced URL comes from the entry's indicator object; for an incident, **GIBTIEnrichIncidentIndicators** creates it.

Fetched incidents list the same observables in *GIB Related Indicators Data*, apart from a wallet of a chain other than Bitcoin, one value per line with defanged values restored, and Cortex XSOAR extracts the indicators of an incident from that field. Phishing group and defacement incidents extract URLs only: with every type selected, the platform would also extract the host of each URL as a domain, which for a phishing page is often shared hosting and for a defacement is the victim's site. The e-mail addresses of threat reports and phishing kits are listed in *GIB Related Emails* instead and extracted as e-mail addresses only: from *GIB Related Indicators Data*, the platform would also extract each address's domain, often a free-mail provider's. Extraction creates bare values; the **GIBTIEnrichIncidentIndicators** task of the postprocessing playbook reads the record again and gives them the verdict, tags and attributes described above.

## Reputation Commands (ip / domain / file / url)

Every command takes a comma-separated list (`!ip ip=198.51.100.27,203.0.113.54`) and returns one result per value. `file` accepts MD5, SHA-1, SHA-256 and SHA-512 hashes and stores the hash looked up and one hash of each other kind (MD5, SHA-1, SHA-256, SHA-512) found in the `ioc/primary` and `ioc/common` records that list it, each under its own kind.

`ip` writes an IPv6 value to IPv6 context (`IPv6.Address`). An `ip` or `domain` result that the risk score makes **Suspicious** or **Bad** carries as indicator **tags** the collections of the matched `ioc/primary`, `apt/threat`, `hi/open_threats` and `attacks/deface` records, and the threat names and threat actors of those records apart from the defacements; when `ioc/primary` makes the result Suspicious, the tags come from the `ioc/primary` records only. A `suspicious_ip/*` collection selected in **Collections that keep an IP at least Suspicious** that lists the IP within **Suspicious IP listing recency (days)** is a tag as well, and the only one when that listing raised the verdict. The result also carries the attributed malware families as **Malware Family**, the most restrictive **TLP** of the records its tags come from, and, with **Create relationships** enabled, a relationship to every malware family (*indicator-of*) and threat actor (*related-to*) named by the records (see [Indicator enrichment](#indicator-enrichment-and-relationships)). An `ip` or `domain` result that the risk score makes Suspicious or Bad lists the `apt/threat` reports and `hi/open_threats` posts among those records as **Publications**, newest first. A `file` result carries the tags, names and TLP of its `ioc/primary` and `ioc/common` records, and a `url` result those of the `ioc/primary` records that list it. A **Good** or **Unknown** result carries no malware family, TLP or relationship. With **Collection tags at every verdict** enabled (default), its only tags are the collections that list or mention the value, never one selected in **Collections that keep an IP at least Suspicious**. The War Room note names the collections whose records mention the value. That note says *No Group-IB Threat Intelligence data was found* only when no collection lists or mentions the value and Group-IB has no risk score for it. Every result with a verdict carries the earliest `dateFirstSeen` and the latest `dateLastSeen` of the records it read as *FirstSeenBySource* and *LastSeenBySource*, and its *Group-IB records* table gives, per collection, how many records were read and their earliest first and latest last sighting.

### A dedicated instance for reputation

Run the reputation commands from a dedicated integration instance (for example one named *Group-IB TI reputation*), separate from the instances that fetch incidents. Reputation commands are disabled by default: select them (`ip`, `domain`, `file`, `url`) in **Enable reputation commands** on that instance only. An instance where a command is not selected in **Enable reputation commands** answers it with a single note, without an indicator or a DBotScore, so it never changes the merged reputation of the indicator.

Every Group-IB instance answers the generic `!ip` / `!domain` / `!file` / `!url` commands and auto-enrichment. Select **Do not use by default** on the other instances (an instance that fetches incidents, a lookup-only instance, an instance with a restricted license, a test instance) so they stay out of those runs, and call such an instance explicitly with `using=`:

```
!gibti-cve-scoring cve=CVE-2021-44228 using="Group-IB TI lookups"
!gibti-get-malware-cnc-info id=0123456789abcdef0123456789abcdef01234567 using="Group-IB TI lookups"
```

`using=` works for every command of the integration, not only reputation ones. The pack's playbooks and automations do this: the postprocessing playbook passes `using=${incident.sourceInstance}` to its lookups, and **GIBTIEnrichIncidentIndicators** / **GIBTICreateThreatIntelReport** read the record on the instance that fetched the incident, or on the only active one; with several active instances and none of them the one that fetched the incident, the lookup runs on every instance.

### Source Reliability and override behavior

With **Ignore Source Reliability override** disabled (default), every reputation result carries the instance **Source Reliability**. Enabled, a result takes the reliability of the collections that matched (rules below); a result that none of the collections below matched, the CVE indicators of `gibti-cve-scoring` and the indicators of the lookup commands keep **Source Reliability**.

### Score (DBotScore) calculation rules

Score and reliability are calculated independently.

#### `file` score rules

- **BAD**: `ioc/common` lists the hash, or `ioc/primary` lists it with a risk score of 80 or more
- **SUSPICIOUS**: only `ioc/primary` lists the hash, with a risk score below 80 or none
- **UNKNOWN (NONE)**: neither collection lists it
- A value that is not an MD5, SHA-1, SHA-256 or SHA-512 hash is reported in the War Room and not looked up

Only a record of the hash itself counts: an `ioc/common` record whose hashes include it, or an `ioc/primary` file record of it. An `ioc/common` record carries no TLP of its own and counts as AMBER.

#### `ip` and `domain` score rules

Group-IB's own **risk score** (`scoring/ip` for an IPv4 address, `scoring/domain` for a domain, 0-100), `ioc/primary` (Group-IB's collection of indicators of compromise) and, for an IP, the `suspicious_ip/*` collections selected in **Collections that keep an IP at least Suspicious** decide the verdict:

- **BAD**: a risk score of 80-100
- **SUSPICIOUS**: a risk score of 40-79; or `ioc/primary` lists the IP or domain, whatever the risk score of its element there; or a selected `suspicious_ip/*` collection lists the IP itself
- **GOOD**: a risk score of 0-39 without such a listing (public infrastructure such as a DNS resolver scores in this band)
- **UNKNOWN (NONE)**: no risk score and no such listing

Only an `ioc/primary` record of the observable itself counts, one whose IP or domain elements include it: the search for a value also returns records that merely mention it, such as a URL on the domain. An IPv6 address has no risk score, since Group-IB scores IPv4 addresses only, so `ioc/primary` and the `suspicious_ip/*` listings decide its verdict.

A `suspicious_ip/*` collection selected in **Collections that keep an IP at least Suspicious** (by default every one) keeps an IP it lists at least **SUSPICIOUS**, whatever its risk score, and adds the collection as a tag, without malware or actor names. A listed IP can still score below 40, for example a Tor exit without malicious history. A collection counts only when one of its records is the IP itself. A listing counts at any age unless **Suspicious IP listing recency (days)** sets a window after its `dateLastSeen`, and the result carries the most restrictive TLP of the listings that count. The setting does not apply to a domain. Clear a collection to leave the verdict to the risk score and `ioc/primary`.

`apt/threat` reports and `hi/open_threats` posts that the search for the value returns give tags, names, relationships and publications, and `attacks/deface` defacements their tag and TLP; none of them decides the verdict; `hi/threat` reports are not read by the reputation commands. When the risk score makes the verdict Suspicious or Bad, the result takes the malware and actor names of every matched record but the defacements, the most restrictive TLP of the matched records and the publications of the `apt/threat` and `hi/open_threats` records; when `ioc/primary` makes it Suspicious, the names and TLP of the `ioc/primary` records only, and no publications; a `suspicious_ip/*` listing gives only its own tag and its TLP. Actor profiles are not read: the domains a profile lists are the actor's victims. A defacement counts only when it is the defacement of the IP or domain itself (its target domain, the host of the defaced URL or its target IP), and it adds the `attacks/deface` tag and its TLP, never the defacer: the defaced site is a victim.

The reputation commands read their collections directly, at most **Parallel requests per lookup** requests at a time (default 4): for an IP or domain, `ioc/primary`, `apt/threat`, `hi/open_threats` and `attacks/deface` by the value, the risk score and, with **Add WHOIS to ip and domain** enabled, the WHOIS record; for an IP, also the `suspicious_ip/*` collections selected in **Collections that keep an IP at least Suspicious**, by the address; for a file, `ioc/primary` and `ioc/common` by the hash; for a URL, `ioc/primary` by the quoted URL. **Lookup timeout (seconds)** (default 20) limits how long one value waits for them. The risk scores of a list of IPs or domains are asked in requests of up to 100 values; when one of them fails or they do not answer in time, each value asks for its own.

A refused key (HTTP 401) fails the command; a value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry of its own and no verdict, and the other values still return. When a request that decides the verdict (the risk score, `ioc/primary`, `ioc/common` for a file, a selected `suspicious_ip/*` collection for an IP) fails or does not answer in time, *GIBTI.Reputation.partial* is true, and a verdict is set only if no missing answer could have raised it. A missing risk score or `ioc/common`, or the `ioc/primary` of a file, could make it Bad, so only a Bad verdict is set; a missing `ioc/primary` of an IP or domain or a missing `suspicious_ip/*` collection could make it Suspicious, so a Suspicious or Bad verdict is set and a lower one is not. A result without a verdict carries no DBotScore, and the indicator keeps the one it has. A request answered with HTTP 403 (the key has no access) is named in the War Room note; HTTP 403 and HTTP 404 (no record) do not make the result partial, and the verdict comes from the others.

A `url` value whose `ioc/primary` request fails, HTTP 403 and 404 included, or does not answer in time gets an error entry and no verdict. **Use the Group-IB global search** makes `ip`, `domain` and `file` add the other collections that mention the value to `GIBTI.Reputation.collections`; it decides nothing. A result below Suspicious also lists them in its note and, with **Collection tags at every verdict** enabled, in its tags; a Bad result lists them in `Malicious.Description`.

#### `url` score rules

Group-IB scores IPv4 addresses and domains only, so `url` reads `ioc/primary` directly, with a quoted search, and keeps only the records of the URL itself (an `ioc/primary` url element that is the URL); a record that mentions a part of the URL does not count. The query goes out refanged and without a user name or password, and a record's URL matches the value whatever the case of its scheme and host, its defanged form (`hxxp://`, `[.]`) or a trailing slash; the path keeps its case.

- **BAD**: `ioc/primary` lists the URL with a risk score of 80 or more
- **SUSPICIOUS**: `ioc/primary` lists it with a lower risk score or none
- **UNKNOWN (NONE)**: `ioc/primary` does not list it
- A value without a scheme and host is reported in the War Room and not looked up

The `ioc/primary` collection and the threat and actor names of its records become tags; the attributed malware families become **Malware Family**, and the most restrictive TLP of the matched records becomes the indicator's TLP. The highest risk score among the matching `ioc/primary` elements is shown in the War Room table.

### Reliability calculation rules (only when Ignore Source Reliability override is enabled)

#### `file` reliability rules

- **A - Completely reliable**: any match in `ioc/primary` or `ioc/common`
- **Source Reliability** of the instance: no matches

#### `url` reliability rules

- **A - Completely reliable**: any match in `ioc/primary`
- **Source Reliability** of the instance: no matches

#### `domain` and `ip` reliability rules

Reliability is derived from which collections returned matches:

- **A - Completely reliable**:
  - any match in `apt/threat` (nation-state intelligence), or
  - any match in `ioc/primary`

- **B - Usually reliable**:
  - a defacement of the IP or domain itself in `attacks/deface`, or
  - any match in `hi/open_threats`

Final selection logic:

- At least one **A - Completely reliable** source: **A - Completely reliable**
- Otherwise, at least one **B - Usually reliable** source: **B - Usually reliable**
- Otherwise: the instance **Source Reliability**

### Scoring and WHOIS commands

`gibti-ip-scoring` and `gibti-domain-scoring` return the risk score and its verdict band, without the collection lookups, and set no verdict on the indicator.

`gibti-ip-whois` and `gibti-domain-whois` return the registry record of an IP address or a domain from the Group-IB Graph WHOIS, and set no verdict. An IP record gives the address range, the registry, the network name, the holder organization and its country of registration, the ASN that announces the range, the owner of the AS when the registry names it, and the abuse contact, each field from the newest record that has it; a domain record gives the registrar and its abuse contact, the registrant, the statuses, the dates and the name servers, and a subdomain is answered with the record of its registered domain. Texts a registry puts in place of a value (a placeholder phone number, REDACTED FOR PRIVACY) are left out. With **Add WHOIS to ip and domain** enabled (default), `ip` writes the ASN, the holder organization, the owner of the AS and the abuse e-mail and phone to the indicator, and `domain` writes the registrar and its abuse contact, the registrant's organization and country, the registrant's name and e-mail address (unless **WHOIS personal data** is `Drop`), the dates, the statuses and the name servers. The country of an IP record is the country of the organization that holds the range (else of the range), not where the address is, so it does not go to the indicator's geo fields.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Search query syntax

- `gibti-global-search` is a **value** search across all collections: pass the bare value (an actor name, `203.0.113.7`, `evil.example.com`). It answers with the collections that contain matches and their counts; it does not return the records themselves.
- `gibti-local-search` searches **one collection filtered by `query`**: it accepts a bare value in every collection (an actor name or alias, `203.0.113.7`) and `id:<id>` on the collections whose API takes it (threat reports and actor profiles among them). On `hi/threat` and `apt/threat` a bare id finds nothing, so look a report up as `id:<id>`. A value matches the text of the records your account's feed of that collection serves. `gibti-global-search` counts a wider index, so it can report records this command does not return; `gibti-get-threat-actor-info` and `gibti-get-threat-info` read a profile or a report outside the feed by its id. A `date_from` / `date_to` window or a `seq_update` cursor narrows the walk; the cursor takes the place of the window when both are set. The window applies to the first page; a later page follows the cursor and can hold records outside it. `compromised/spd`, `compromised/breacheddb`, `compromised/messenger`, `osi/git_repository` and `darkweb/forums` ignore the window, and `osi/vulnerability` applies it to the record's own date. On a trial or POC account, some collections refuse dates older than 30 days. Without a cursor or a date window, the collection is walked in `seqUpdate` order from its oldest record; `compromised/discord` returns its newest records first, and `darkweb/forums` is read one page per call. With `requests_limit=1` the first page therefore holds the oldest matches, except on `compromised/discord`. Raise `requests_limit` or pass `seq_update` or `date_from` to reach newer ones; on the collections that ignore the window `date_from` does not, and on `darkweb/forums` only `seq_update` does. Follow a hit with the collection's `gibti-get-*-info` command and the returned `id`. A name that `gibti-global-search` does not list under an actor or threat collection has no profile your API user can read.
- The reputation commands (`ip`, `domain`, `file`, `url`) and the `gibti-get-*-info` lookups of the collections whose record is found by a search rather than read by id (the dark web collections, `osi/public_leak`, `attacks/phishing_group`, `hi/open_threats`, Tor nodes, SOCKS and open proxies) use the same per-collection search.

### Available Commands

The following commands are available in this integration:

> Every command except `ip`, `domain`, `file` and `url` uses the `gibti-` prefix; the legacy `gibtia-` names are deprecated (see the deprecation notice above).

- `gibti-get-available-collections` - Returns the collections granted to your API user that the integration's API library knows, sorted
- `gibti-get-compromised-account-info` - Returns the compromised/account_group record with the given ID
- `gibti-get-compromised-card-group-info` - Returns the compromised/bank_card_group record with the given ID
- `gibti-get-compromised-masked-card-info` - Returns the compromised/masked_card record with the given ID
- `gibti-get-compromised-breached-info` - Returns the compromised/breacheddb record with the given ID
- `gibti-get-phishing-group-info` - Returns the attacks/phishing_group record with the given ID
- `gibti-get-phishing-kit-info` - Returns the attacks/phishing_kit record with the given ID
- `gibti-get-osi-git-leak-info` - Returns the osi/git_repository record with the given ID
- `gibti-get-osi-public-leak-info` - Returns the osi/public_leak record with the given ID
- `gibti-get-osi-vulnerability-info` - Returns the osi/vulnerability record with the given ID
- `gibti-get-malware-malware-info` - Returns the malware/malware record with the given ID
- `gibti-get-compromised-spd-info` - Returns the compromised/spd (suspicious payment details) record with the given ID
- `gibti-get-attacks-ddos-info` - Returns the attacks/ddos record with the given ID
- `gibti-get-attacks-deface-info` - Returns the attacks/deface record with the given ID
- `gibti-get-threat-info` - Reads one or more threat reports from hi/threat or apt/threat
- `gibti-get-threat-actor-info` - Reads one or more threat actor profiles from hi/threat_actor or apt/threat_actor
- `gibti-get-suspicious-ip-tor-node-info` - Returns the suspicious_ip/tor_node record with the given ID
- `gibti-get-suspicious-ip-open-proxy-info` - Returns the suspicious_ip/open_proxy records with the given ID
- `gibti-get-suspicious-ip-socks-proxy-info` - Returns the suspicious_ip/socks_proxy record with the given ID
- `gibti-get-suspicious-ip-vpn-info` - Returns the suspicious_ip/vpn record with the given ID
- `gibti-get-suspicious-ip-scanner-info` - Returns the suspicious_ip/scanner record with the given ID
- `gibti-get-malware-cnc-info` - Returns the malware/cnc record with the given ID
- `gibti-get-compromised-access-info` - Returns the compromised/access record with the given ID
- `gibti-get-darkweb-telegram-info` - Returns the compromised/messenger record with the given ID
- `gibti-get-darkweb-discord-info` - Returns the compromised/discord record with the given ID
- `gibti-get-darkweb-forum-info` - Returns the darkweb/forums record with the given ID
- `gibti-get-open-threat-info` - Returns the hi/open_threats record with the given ID
- `gibti-global-search` - Searches Group-IB's collections for a value and returns the matching collections with counts
- `gibti-local-search` - Searches one collection for a value or an `id:<id>` query
- `ip` - Returns the Group-IB reputation of IPs (enable it in **Enable reputation commands**)
- `domain` - Returns the Group-IB reputation of domains (enable it in **Enable reputation commands**)
- `file` - Returns the Group-IB reputation of file hashes (enable it in **Enable reputation commands**)
- `url` - Returns the Group-IB reputation of URLs (enable it in **Enable reputation commands**)
- `gibti-ip-scoring` - Returns the Group-IB risk score of IPv4 addresses and its verdict band in GIBTI.Scoring
- `gibti-domain-scoring` - Returns the Group-IB risk score of domains and its verdict band in GIBTI.Scoring
- `gibti-ip-whois` - Returns the WHOIS record of IP addresses
- `gibti-domain-whois` - Returns the WHOIS record of domains
- `gibti-cve-scoring` - Scores CVEs from osi/vulnerability (exploit evidence, EPSS, CVSS and Group-IB's severity) as a DBotScore

### gibti-get-compromised-account-info

***
Returns the compromised/account_group record with the given ID. The password follows the Mask passwords and leaked secrets setting.

#### Base Command

`gibti-get-compromised-account-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CompromisedAccountGroup.name | String | Record name: the compromised login. |
| GIBTI.CompromisedAccountGroup.id | String | Record id. |
| GIBTI.CompromisedAccountGroup.login | String | Compromised Login. |
| GIBTI.CompromisedAccountGroup.password | String | Password. |
| GIBTI.CompromisedAccountGroup.parsedLogin.domain | String | Parsed Login Domain. |
| GIBTI.CompromisedAccountGroup.parsedLogin.ip | String | Parsed Login IP. |
| GIBTI.CompromisedAccountGroup.service.domain | String | Service Domain. |
| GIBTI.CompromisedAccountGroup.service.ip | String | Service IP. |
| GIBTI.CompromisedAccountGroup.service.url | String | Service URL. |
| GIBTI.CompromisedAccountGroup.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.CompromisedAccountGroup.events_table.cnc | String | Compromised Events Information Table: the C&C of the event as Group-IB lists it. |
| GIBTI.CompromisedAccountGroup.events_table.asn | String | Compromised Events Information Table: ASN of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.city | String | Compromised Events Information Table: city of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.region | String | Compromised Events Information Table: region of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.provider | String | Compromised Events Information Table: provider of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.countryCode | String | Compromised Events Information Table: country code of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.countryName | String | Compromised Events Information Table: country name of the compromised device's IP address. |
| GIBTI.CompromisedAccountGroup.events_table.ip | String | Compromised Events Information Table: IP address of the compromised device. |
| GIBTI.CompromisedAccountGroup.events_table.malware | String | Compromised Events Information Table: malware. |
| GIBTI.CompromisedAccountGroup.events_table.threatActor | String | Compromised Events Information Table: threat actor. |
| GIBTI.CompromisedAccountGroup.events_table.sourceType | String | Compromised Events Information Table: source type. |
| GIBTI.CompromisedAccountGroup.events_table.sourceLink | String | Compromised Events Information Table: id of the event's source. |
| GIBTI.CompromisedAccountGroup.events_table.userName | String | Compromised Events Information Table: user name. |
| GIBTI.CompromisedAccountGroup.events_table.pcName | String | Compromised Events Information Table: name of the compromised device. |
| GIBTI.CompromisedAccountGroup.events_table.os | String | Compromised Events Information Table: operating system of the compromised device. |
| GIBTI.CompromisedAccountGroup.events_table.screen | String | Compromised Events Information Table: screen. |
| GIBTI.CompromisedAccountGroup.events_table.locale | String | Compromised Events Information Table: locale. |
| GIBTI.CompromisedAccountGroup.events_table.malwarePath | String | Compromised Events Information Table: the path of the stealer on the compromised device. |
| GIBTI.CompromisedAccountGroup.events_table.dateDetected | Date | Compromised Events Information Table: date detected. |
| GIBTI.CompromisedAccountGroup.events_table.dateCompromised | Date | Compromised Events Information Table: date compromised. |
| GIBTI.CompromisedAccountGroup.events_table.phone | String | Compromised Events Information Table: phone. |
| GIBTI.CompromisedAccountGroup.events_table.name | String | Compromised Events Information Table: name. |
| GIBTI.CompromisedAccountGroup.events_table.email | String | Compromised Events Information Table: e-mail address. |
| GIBTI.CompromisedAccountGroup.events_table.address | String | Compromised Events Information Table: address. |
| GIBTI.CompromisedAccountGroup.dateFirstCompromised | Date | Date First Compromised. |
| GIBTI.CompromisedAccountGroup.dateLastCompromised | Date | Date Last Compromised. |
| GIBTI.CompromisedAccountGroup.dateFirstSeen | Date | Date First Seen. |
| GIBTI.CompromisedAccountGroup.dateLastSeen | Date | Date Last Seen. |
| GIBTI.CompromisedAccountGroup.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.CompromisedAccountGroup.evaluation.credibility | Number | Credibility. |
| GIBTI.CompromisedAccountGroup.evaluation.reliability | Number | Reliability. |
| GIBTI.CompromisedAccountGroup.evaluation.severity | String | Severity. |
| GIBTI.CompromisedAccountGroup.evaluation.tlp | String | TLP. |
| GIBTI.CompromisedAccountGroup.source_type | String | Source type of each event. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | URL of the C&C. |
| Domain.Name | String | Domain of the C&C. |
| IP.Address | String | IP address of the C&C. |
| IP.Tags | String | The compromised/account_group collection tag and the malware families and threat actors of the event. |
| IP.MalwareFamily | String | Malware families of the event. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| Domain.Tags | String | The compromised/account_group collection tag and the malware families and threat actors of the event. |
| Domain.MalwareFamily | String | Malware families of the event. |
| Domain.TrafficLightProtocol | String | TLP of the record. |
| URL.Tags | String | The compromised/account_group collection tag and the malware families and threat actors of the event. |
| URL.MalwareFamily | String | Malware families of the event. |
| URL.TrafficLightProtocol | String | TLP of the record. |

### gibti-get-compromised-breached-info

***
Returns the compromised/breacheddb record with the given ID. The passwords, the credential columns and a secret that another column quotes follow the Mask passwords and leaked secrets setting. An ID Group-IB does not have is reported as not found. If the request does not complete (HTTP 429, 5xx or a timeout), the command says so; run it again later. This lookup can take longer than the others.

#### Base Command

`gibti-get-compromised-breached-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.DataBreach.name | String | Record name. |
| GIBTI.DataBreach.id | String | Record id. |
| GIBTI.DataBreach.leakName | String | Leak Name. |
| GIBTI.DataBreach.threat_actor_name | String | The leak's publishers (its authors), not an attribution. |
| GIBTI.DataBreach.passwords | String | Passwords. |
| GIBTI.DataBreach.description | String | Description. |
| GIBTI.DataBreach.emails | String | Emails. |
| GIBTI.DataBreach.emailDomains | String | Email Domains. |
| GIBTI.DataBreach.record_details | Unknown | The other columns of the breached record, by column name. |
| GIBTI.DataBreach.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.DataBreach.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.DataBreach.evaluation.credibility | Number | Credibility. |
| GIBTI.DataBreach.evaluation.reliability | Number | Reliability. |
| GIBTI.DataBreach.evaluation.severity | String | Severity. |
| GIBTI.DataBreach.evaluation.tlp | String | TLP. |
| GIBTI.DataBreach.leakPublished | Date | Leak Published. |
| GIBTI.DataBreach.updateTime | Date | Update Time. |
| GIBTI.DataBreach.uploadTime | Date | Upload Time. |
| GIBTI.DataBreach.hasPassword | Boolean | Whether the record carries a password, a credential column or a secret that one of its columns quotes. |

### gibti-get-compromised-spd-info

***
Returns the compromised/spd (suspicious payment details) record with the given ID. The record is a payment identifier used to receive illegal payments (such as a cryptocurrency wallet, a bank account or a card), including type, value, events, sources, malware, and evaluation (severity, TLP, TTL). A Bitcoin wallet (base58check or `bc1`) is returned as the indicator `bitcoin:<address>`, the value Cortex XSOAR's extraction gives a base58check wallet. A *Bank Card* value is the full card number, unmasked: it is the card a fraud network collects payments on.

#### Base Command

`gibti-get-compromised-spd-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CompromisedSPD.name | String | Record name: the payment detail type. |
| GIBTI.CompromisedSPD.id | String | Record id. |
| GIBTI.CompromisedSPD.type | String | SPD Type. |
| GIBTI.CompromisedSPD.serviceType | String | SPD Service Type. |
| GIBTI.CompromisedSPD.ownerName | String | SPD Owner Name. |
| GIBTI.CompromisedSPD.illegalScore | Number | SPD Illegal Score. |
| GIBTI.CompromisedSPD.value | String | SPD Value. |
| GIBTI.CompromisedSPD.createdAt | Date | Date Created At. |
| GIBTI.CompromisedSPD.firstSeenAt | Date | Date First Seen. |
| GIBTI.CompromisedSPD.lastSeenAt | Date | Date Last Seen. |
| GIBTI.CompromisedSPD.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.CompromisedSPD.events.compromisedAt | Date | SPD Events Table: compromised at. |
| GIBTI.CompromisedSPD.events.detectedAt | Date | SPD Events Table: detected at. |
| GIBTI.CompromisedSPD.events.sourceName | String | SPD Events Table: source name. |
| GIBTI.CompromisedSPD.events.sourceType | String | SPD Events Table: source type. |
| GIBTI.CompromisedSPD.events.illegalScore | Number | SPD Events Table: illegal score. |
| GIBTI.CompromisedSPD.events.malwareId | String | SPD Events Table: malware id. |
| GIBTI.CompromisedSPD.events.malwareName | String | SPD Events Table: malware name. |
| GIBTI.CompromisedSPD.events.threatActorId | String | SPD Events Table: threat actor id. |
| GIBTI.CompromisedSPD.events.threatActorName | String | SPD Events Table: threat actor name. |
| GIBTI.CompromisedSPD.sources.name | String | SPD Sources Table: name. |
| GIBTI.CompromisedSPD.sources.type | String | SPD Sources Table: type. |
| GIBTI.CompromisedSPD.source_type | String | The types of the record's sources. |
| GIBTI.CompromisedSPD.malware.id | String | SPD Malware Table: id. |
| GIBTI.CompromisedSPD.malware.name | String | SPD Malware Table: name. |
| GIBTI.CompromisedSPD.threatActor.id | String | SPD Threat Actor Table: id. |
| GIBTI.CompromisedSPD.threatActor.name | String | SPD Threat Actor Table: name. |
| GIBTI.CompromisedSPD.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.CompromisedSPD.evaluation.credibility | Number | Credibility. |
| GIBTI.CompromisedSPD.evaluation.reliability | Number | Reliability. |
| GIBTI.CompromisedSPD.evaluation.severity | String | Severity. |
| GIBTI.CompromisedSPD.evaluation.tlp | String | TLP. |
| GIBTI.CompromisedSPD.evaluation.ttl | Number | TTL. |
| GIBTI.CompromisedSPD.country | String | ISO country codes of the payment detail. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Cryptocurrency.Address | String | Wallet address. |
| Cryptocurrency.AddressType | String | The cryptocurrency of the wallet, such as bitcoin; unknown when Group-IB names none. |
| Cryptocurrency.Malicious.Vendor | String | The vendor that rated the wallet bad. |
| Cryptocurrency.Malicious.Description | String | Empty; the command writes no description. |

### gibti-get-osi-git-leak-info

***
Returns the osi/git_repository record with the given ID.

#### Base Command

`gibti-get-osi-git-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID of the repository (the GIB ID of its incident), not the hash of a file or a revision. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.GitLeak.id | String | Record id. |
| GIBTI.GitLeak.name | String | Record name. |
| GIBTI.GitLeak.leaked_file_name | String | URL of the public repository whose files matched the hunting rules. |
| GIBTI.GitLeak.source | String | Git hosting service of the repository. |
| GIBTI.GitLeak.dateDetected | Date | Date of Detection. |
| GIBTI.GitLeak.dateCreated | Date | Date Created. |
| GIBTI.GitLeak.files.file_id | String | OSI Git Repository Files Table: file id. |
| GIBTI.GitLeak.files.file_name | String | OSI Git Repository Files Table: file name. |
| GIBTI.GitLeak.files.hash | String | OSI Git Repository Files Table: the hashes of the file's revisions. |
| GIBTI.GitLeak.files.dateCreated | Date | OSI Git Repository Files Table: date created. |
| GIBTI.GitLeak.files.dateDetected | Date | OSI Git Repository Files Table: date detected. |
| GIBTI.GitLeak.files.authorName | String | OSI Git Repository Files Table: author name. |
| GIBTI.GitLeak.files.authorEmail | String | OSI Git Repository Files Table: author email. |
| GIBTI.GitLeak.files.url | String | OSI Git Repository Files Table: url. |
| GIBTI.GitLeak.files.dataFound | String | OSI Git Repository Files Table: the types of secrets found in the file. |
| GIBTI.GitLeak.files.severity | String | OSI Git Repository Files Table: the file's own Group-IB severity (gray, yellow, orange or red). |
| GIBTI.GitLeak.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.GitLeak.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.GitLeak.evaluation.credibility | Number | Credibility. |
| GIBTI.GitLeak.evaluation.reliability | Number | Reliability. |
| GIBTI.GitLeak.evaluation.severity | String | Severity. |
| GIBTI.GitLeak.evaluation.tlp | String | TLP. |

### gibti-get-osi-public-leak-info

***
Returns the osi/public_leak record with the given ID. The leaked data and the matches follow the Mask passwords and leaked secrets setting.

#### Base Command

`gibti-get-osi-public-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.PublicLeak.name | String | Record name. |
| GIBTI.PublicLeak.id | String | Record id. |
| GIBTI.PublicLeak.hash | String | Data Hash: Group-IB's SHA-1 hash of the leaked text. |
| GIBTI.PublicLeak.created | Date | Date Created. |
| GIBTI.PublicLeak.data | String | Leaked Data. |
| GIBTI.PublicLeak.linkList.author | String | Link List Table: author. |
| GIBTI.PublicLeak.linkList.hash | String | Link List Table: Group-IB's SHA-1 hash of the leaked text at the link. |
| GIBTI.PublicLeak.linkList.link | String | Link List Table: link. |
| GIBTI.PublicLeak.linkList.title | String | Link List Table: title. |
| GIBTI.PublicLeak.linkList.source | String | Link List Table: source. |
| GIBTI.PublicLeak.linkList.dateDetected | Date | Link List Table: date detected. |
| GIBTI.PublicLeak.linkList.datePublished | Date | Link List Table: date published. |
| GIBTI.PublicLeak.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.PublicLeak.matches | Unknown | Matches of the leak, by bucket and category. |
| GIBTI.PublicLeak.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.PublicLeak.evaluation.credibility | Number | Credibility. |
| GIBTI.PublicLeak.evaluation.reliability | Number | Reliability. |
| GIBTI.PublicLeak.evaluation.severity | String | Severity. |
| GIBTI.PublicLeak.evaluation.tlp | String | TLP. |

### gibti-get-osi-vulnerability-info

***
Returns the osi/vulnerability record with the given ID. The CVE indicator takes its CVSS score and vector from Group-IB's merged cross-version CVSS, or from the legacy CVSS score and vector when the record has no merged score. A CVSS score of 0 without a vector counts as none. The record description is returned as text when it holds HTML block, line-break or text-formatting markup. The CVE indicator description stays as Group-IB sends it.

#### Base Command

`gibti-get-osi-vulnerability-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example CVE-2021-44228. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.OSIVulnerability.name | String | Record name. |
| GIBTI.OSIVulnerability.dateLastSeen | Date | Date Last Seen. |
| GIBTI.OSIVulnerability.dateModified | Date | Date Modified. |
| GIBTI.OSIVulnerability.datePublished | Date | Date Published. |
| GIBTI.OSIVulnerability.id | String | Record id. |
| GIBTI.OSIVulnerability.bulletinFamily | String | Bulletin Family. |
| GIBTI.OSIVulnerability.description | String | Description. |
| GIBTI.OSIVulnerability.extDescription | String | Extended Description. |
| GIBTI.OSIVulnerability.reporter | String | Who reported the vulnerability. |
| GIBTI.OSIVulnerability.hasExploit | Boolean | Has Exploit. |
| GIBTI.OSIVulnerability.exploitCount | Number | Exploit Count. |
| GIBTI.OSIVulnerability.seenInTheWild | Boolean | Seen In The Wild. |
| GIBTI.OSIVulnerability.epssScore | Number | EPSS score: the probability of exploitation, from 0 to 1. |
| GIBTI.OSIVulnerability.epssPercentile | Number | EPSS Percentile. |
| GIBTI.OSIVulnerability.provider | String | Provider. |
| GIBTI.OSIVulnerability.href | String | URL of the vendor advisory. |
| GIBTI.OSIVulnerability.mergedCvss | Number | Merged CVSS score. |
| GIBTI.OSIVulnerability.type | String | Record type: the source of the advisory, such as cve, nessus or redhat. |
| GIBTI.OSIVulnerability.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.OSIVulnerability.cpeTable.product | String | CPE Table: product. |
| GIBTI.OSIVulnerability.cpeTable.string | String | CPE Table: string. |
| GIBTI.OSIVulnerability.cpeTable.string23 | String | CPE Table: string23. |
| GIBTI.OSIVulnerability.cpeTable.type | String | CPE Table: type. |
| GIBTI.OSIVulnerability.cpeTable.vendor | String | CPE Table: vendor. |
| GIBTI.OSIVulnerability.cpeTable.version | String | CPE Table: version. |
| GIBTI.OSIVulnerability.cpeTable.update | String | CPE Table: update (the CPE update component, such as sp1). |
| GIBTI.OSIVulnerability.affectedSoftware.name | String | Affected Software Table: name. |
| GIBTI.OSIVulnerability.affectedSoftware.operator | String | Affected Software Table: operator. |
| GIBTI.OSIVulnerability.affectedSoftware.version | String | Affected Software Table: version. |
| GIBTI.OSIVulnerability.cvss.score | Number | CVSS Score. |
| GIBTI.OSIVulnerability.cvss.vector | String | CVSS Vector. |
| GIBTI.OSIVulnerability.extCvss.base | Number | Extended CVSS Base. |
| GIBTI.OSIVulnerability.extCvss.exploitability | Number | Extended CVSS Exploitability. |
| GIBTI.OSIVulnerability.extCvss.impact | Number | Extended CVSS Impact. |
| GIBTI.OSIVulnerability.extCvss.overall | Number | Extended CVSS Overall. |
| GIBTI.OSIVulnerability.extCvss.temporal | Number | Extended CVSS Temporal. |
| GIBTI.OSIVulnerability.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.OSIVulnerability.evaluation.credibility | Number | Credibility. |
| GIBTI.OSIVulnerability.evaluation.reliability | Number | Reliability. |
| GIBTI.OSIVulnerability.evaluation.severity | String | Severity. |
| GIBTI.OSIVulnerability.evaluation.tlp | String | TLP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| CVE.ID | String | CVE id. |
| CVE.CVSS.Score | Number | CVSS score. |
| CVE.CVSS.Vector | String | CVSS vector. |
| CVE.Published | Date | Publication date. |
| CVE.Modified | Date | Last modification date. |
| CVE.Description | String | Description. |
| CVE.Tags | String | The osi/vulnerability collection tag. |
| CVE.TrafficLightProtocol | String | TLP of the record. |

### gibti-get-attacks-ddos-info

***
Returns the attacks/ddos record with the given ID.

#### Base Command

`gibti-get-attacks-ddos-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.AttacksDDoS.name | String | Record name: the IP address of the DDoS target. |
| GIBTI.AttacksDDoS.id | String | Record id. |
| GIBTI.AttacksDDoS.dateBegin | Date | DDoS Date Begin. |
| GIBTI.AttacksDDoS.dateEnd | Date | DDoS Date End. |
| GIBTI.AttacksDDoS.dateReg | Date | DDoS Date Registration. |
| GIBTI.AttacksDDoS.duration | Number | Duration of the DDoS attack in seconds. |
| GIBTI.AttacksDDoS.protocol | String | DDoS Protocol. |
| GIBTI.AttacksDDoS.source | String | DDoS Source. |
| GIBTI.AttacksDDoS.type | String | DDoS Type. |
| GIBTI.AttacksDDoS.malwareName | String | Malware Name. |
| GIBTI.AttacksDDoS.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.AttacksDDoS.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.AttacksDDoS.evaluation.credibility | Number | Credibility. |
| GIBTI.AttacksDDoS.evaluation.reliability | Number | Reliability. |
| GIBTI.AttacksDDoS.evaluation.severity | String | Severity. |
| GIBTI.AttacksDDoS.evaluation.tlp | String | TLP. |
| GIBTI.AttacksDDoS.cnc.cnc | String | C&C of the attack. |
| GIBTI.AttacksDDoS.cnc.domain | String | Domain of the C&C. |
| GIBTI.AttacksDDoS.cnc.port | Number | Port of the C&C. |
| GIBTI.AttacksDDoS.cnc.url | String | URL of the C&C. |
| GIBTI.AttacksDDoS.threatActor.id | String | Threat Actor ID. |
| GIBTI.AttacksDDoS.threatActor.name | String | Threat Actor Name. |
| GIBTI.AttacksDDoS.threatActor.isAPT | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.AttacksDDoS.target.url | String | DDoS Target URL. |
| GIBTI.AttacksDDoS.target.asn | String | DDoS Target ASN. |
| GIBTI.AttacksDDoS.target.city | String | DDoS Target City. |
| GIBTI.AttacksDDoS.target.region | String | DDoS Target Region. |
| GIBTI.AttacksDDoS.target.provider | String | DDoS Target Provider. |
| GIBTI.AttacksDDoS.target.countryCode | String | DDoS Target Country Code. |
| GIBTI.AttacksDDoS.target.countryName | String | DDoS Target Country Name. |
| GIBTI.AttacksDDoS.target.ip | String | DDoS Target IP. |
| GIBTI.AttacksDDoS.target.port | Number | DDoS Target Port. |
| GIBTI.AttacksDDoS.target.category | String | DDoS Target Category. |
| GIBTI.AttacksDDoS.target.domain | String | DDoS Target Domain. |
| GIBTI.AttacksDDoS.requestData.link | String | DDoS Request Data Link. |
| GIBTI.AttacksDDoS.requestData.headersHash | String | DDoS Request Headers Hash. |
| GIBTI.AttacksDDoS.requestData.body | String | DDoS Request Body. |
| GIBTI.AttacksDDoS.requestData.bodyHash | String | DDoS Request Body Hash. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | URL of the C&C. |
| Domain.Name | String | Domain of the C&C. |
| IP.Address | String | IP address of the C&C. |
| URL.Tags | String | The attacks/ddos collection tag and the malware families and threat actors the record names. |
| URL.MalwareFamily | String | Malware families the record names. |
| URL.TrafficLightProtocol | String | TLP of the record. |
| Domain.Tags | String | The attacks/ddos collection tag and the malware families and threat actors the record names. |
| Domain.MalwareFamily | String | Malware families the record names. |
| Domain.TrafficLightProtocol | String | TLP of the record. |
| IP.ASN | String | ASN of the C&C address. |
| IP.Geo.Country | String | Country of the C&C address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Region of the C&C address. |
| IP.Organization.Name | String | Provider of the C&C address. |
| IP.Tags | String | The attacks/ddos collection tag and the malware families and threat actors the record names. |
| IP.MalwareFamily | String | Malware families the record names. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IPv6.Address | String | IPv6 address of the C&C. |
| IPv6.ASN | String | ASN of the C&C address. |
| IPv6.Geo.Country | String | Country of the C&C address, or its country code when the record has no country name. |
| IPv6.Geo.Description | String | Region of the C&C address. |
| IPv6.Organization.Name | String | Provider of the C&C address. |
| IPv6.Tags | String | The attacks/ddos collection tag and the malware families and threat actors the record names. |
| IPv6.MalwareFamily | String | Malware families the record names. |
| IPv6.TrafficLightProtocol | String | TLP of the record. |

### gibti-get-attacks-deface-info

***
Returns the attacks/deface record with the given ID. The portal link is the record's own portal page. The URL indicator entry is not auto-extracted: extraction would add the defaced site's host, the victim, as a domain.

#### Base Command

`gibti-get-attacks-deface-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.AttacksDeface.name | String | Record name. |
| GIBTI.AttacksDeface.id | String | Record id. |
| GIBTI.AttacksDeface.mirrorLink | String | Mirror Link. |
| GIBTI.AttacksDeface.providerDomain | String | Domain of the source that reported the defacement. |
| GIBTI.AttacksDeface.siteUrl | String | Deface Site URL. |
| GIBTI.AttacksDeface.source | String | Deface Source. |
| GIBTI.AttacksDeface.targetDomain | String | Target Domain. |
| GIBTI.AttacksDeface.targetDomainProvider | String | Target Domain Provider. |
| GIBTI.AttacksDeface.date | Date | Deface Date. |
| GIBTI.AttacksDeface.contacts | String | Contacts of the defaced site, the victim, such as e-mail addresses. |
| GIBTI.AttacksDeface.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.AttacksDeface.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.AttacksDeface.evaluation.credibility | Number | Credibility. |
| GIBTI.AttacksDeface.evaluation.reliability | Number | Reliability. |
| GIBTI.AttacksDeface.evaluation.severity | String | Severity. |
| GIBTI.AttacksDeface.evaluation.tlp | String | TLP. |
| GIBTI.AttacksDeface.targetIp.asn | String | Target ASN. |
| GIBTI.AttacksDeface.targetIp.city | String | Target City. |
| GIBTI.AttacksDeface.targetIp.countryCode | String | Target Country Code. |
| GIBTI.AttacksDeface.targetIp.countryName | String | Target Country Name. |
| GIBTI.AttacksDeface.targetIp.ip | String | Target IP. |
| GIBTI.AttacksDeface.targetIp.provider | String | Target Provider. |
| GIBTI.AttacksDeface.targetIp.region | String | Target Region. |
| GIBTI.AttacksDeface.threatActor.id | String | ID of the defacer's handle, which groups defacements; not an attribution. |
| GIBTI.AttacksDeface.threatActor.name | String | The defacer's handle, which groups defacements; not an attribution. |
| GIBTI.AttacksDeface.threatActor.isAPT | Boolean | Whether the defacer's handle is marked APT. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | URL. |
| URL.Tags | String | The attacks/deface collection tag. |
| URL.TrafficLightProtocol | String | TLP of the record. |

### gibti-get-phishing-kit-info

***
Returns the attacks/phishing_kit record with the given ID. The SHA-256 of the kit archive is a File indicator and the operator e-mails are Email indicators, both Suspicious.

#### Base Command

`gibti-get-phishing-kit-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the SHA-256 of the kit archive (64 hexadecimal characters). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.PhishingKit.name | String | Record name. |
| GIBTI.PhishingKit.id | String | Record id. |
| GIBTI.PhishingKit.hash | String | SHA-256 of the kit archive. |
| GIBTI.PhishingKit.dateDetected | Date | Date of Detection. |
| GIBTI.PhishingKit.dateFirstSeen | Date | Date First Seen. |
| GIBTI.PhishingKit.dateLastSeen | Date | Date Last Seen. |
| GIBTI.PhishingKit.source | String | Phishing Kit Source. |
| GIBTI.PhishingKit.emails | String | Operator e-mail addresses found in the kit. |
| GIBTI.PhishingKit.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.PhishingKit.downloadedFrom.date | Date | Downloaded From Table: date. |
| GIBTI.PhishingKit.downloadedFrom.url | String | Downloaded From Table: url. |
| GIBTI.PhishingKit.downloadedFrom.phishingUrl | String | Downloaded From Table: phishing url. |
| GIBTI.PhishingKit.downloadedFrom.domain | String | Downloaded From Table: domain. |
| GIBTI.PhishingKit.downloadedFrom.fileName | String | Downloaded From Table: file name. |
| GIBTI.PhishingKit.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.PhishingKit.evaluation.credibility | Number | Credibility. |
| GIBTI.PhishingKit.evaluation.reliability | Number | Reliability. |
| GIBTI.PhishingKit.evaluation.severity | String | Severity. |
| GIBTI.PhishingKit.evaluation.tlp | String | TLP. |
| GIBTI.PhishingKit.targetBrand | String | Brands the kit impersonates. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Account.Email.Address | String | E-mail address found in the kit. |
| File.SHA256 | String | SHA-256 hash of the kit archive. |
| Account.Tags | String | The attacks/phishing_kit collection tag. |
| Account.TrafficLightProtocol | String | TLP of the record. |
| File.Hashes.type | String | The kind of the kit archive's hash (SHA256). |
| File.Hashes.value | String | Hash of the kit archive. |
| File.Tags | String | The attacks/phishing_kit collection tag. |
| File.TrafficLightProtocol | String | TLP of the record. |

### gibti-get-threat-info

***
Reads one or more threat reports by id from hi/threat, or from apt/threat when isAPT is true. An id missing from the selected collection is read from the other one, and the ids neither collection publishes are listed in the War Room instead of failing the command. Reports from apt/threat go to `GIBTI.Nation-StateCybercriminalsThreatReport`, reports from hi/threat to `GIBTI.GIBCybercriminalThreatReport`. The description is returned as text, as the incident shows it.

#### Base Command

`gibti-get-threat-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | One or more Group-IB threat report ids, comma-separated, for example 0123456789abcdef0123456789abcdef01234567. | Required |
| isAPT | Whether to read the ids from apt/threat (true) or from hi/threat (false) first. An id the first collection does not have is read from the other one. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.GIBCybercriminalThreatReport.name | String | Record name: the name of the report's threat actor. |
| GIBTI.GIBCybercriminalThreatReport.threatActor.country | String | Threat Actor Country. |
| GIBTI.GIBCybercriminalThreatReport.threatActor.id | String | Threat Actor ID. |
| GIBTI.GIBCybercriminalThreatReport.threatActor.isAPT | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.GIBCybercriminalThreatReport.threatActor.name | String | Threat Actor Name. |
| GIBTI.GIBCybercriminalThreatReport.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.GIBCybercriminalThreatReport.evaluation.credibility | Number | Credibility. |
| GIBTI.GIBCybercriminalThreatReport.evaluation.reliability | Number | Reliability. |
| GIBTI.GIBCybercriminalThreatReport.evaluation.severity | String | Severity. |
| GIBTI.GIBCybercriminalThreatReport.evaluation.tlp | String | TLP. |
| GIBTI.GIBCybercriminalThreatReport.forumsAccounts.nickname | String | Cybercriminal Forums Table: nickname. |
| GIBTI.GIBCybercriminalThreatReport.forumsAccounts.url | String | Cybercriminal Forums Table: url. |
| GIBTI.GIBCybercriminalThreatReport.id | String | Record id. |
| GIBTI.GIBCybercriminalThreatReport.title | String | Cybercriminal Threat Title. |
| GIBTI.GIBCybercriminalThreatReport.description | String | Cybercriminal Threat Description. |
| GIBTI.GIBCybercriminalThreatReport.expertise | String | Cybercriminal Expertise. |
| GIBTI.GIBCybercriminalThreatReport.regions | String | Cybercriminal Regions. |
| GIBTI.GIBCybercriminalThreatReport.labels | String | Cybercriminal Threat Labels. |
| GIBTI.GIBCybercriminalThreatReport.countries | String | Cybercriminal Threat Countries. |
| GIBTI.GIBCybercriminalThreatReport.sectors | String | Cybercriminal Sectors. |
| GIBTI.GIBCybercriminalThreatReport.reportNumber | String | Report Number. |
| GIBTI.GIBCybercriminalThreatReport.report_type | String | Report Type. |
| GIBTI.GIBCybercriminalThreatReport.sources | String | Threat Sources. |
| GIBTI.GIBCybercriminalThreatReport.targeted_companies | String | Targeted Companies. |
| GIBTI.GIBCybercriminalThreatReport.targeted_partners_and_clients | String | Targeted Partners And Clients. |
| GIBTI.GIBCybercriminalThreatReport.target_domains | String | Target Domains. |
| GIBTI.GIBCybercriminalThreatReport.files.name | String | Threat Files Table (files attached to the report): name. |
| GIBTI.GIBCybercriminalThreatReport.files.mime | String | Threat Files Table (files attached to the report): mime. |
| GIBTI.GIBCybercriminalThreatReport.files.size | Number | Threat Files Table (files attached to the report): size. |
| GIBTI.GIBCybercriminalThreatReport.files.hash | String | Threat Files Table (files attached to the report): hash. |
| GIBTI.GIBCybercriminalThreatReport.createdAt | Date | Date Group-IB created the report. |
| GIBTI.GIBCybercriminalThreatReport.datePublished | Date | Date Published. |
| GIBTI.GIBCybercriminalThreatReport.dateFirstSeen | Date | Date First Seen. |
| GIBTI.GIBCybercriminalThreatReport.dateLastSeen | Date | Date Last Seen. |
| GIBTI.GIBCybercriminalThreatReport.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.Nation-StateCybercriminalsThreatReport.name | String | Record name: the name of the report's threat actor. |
| GIBTI.Nation-StateCybercriminalsThreatReport.id | String | Record id. |
| GIBTI.Nation-StateCybercriminalsThreatReport.title | String | Nation-State Cybercriminals Threat Title. |
| GIBTI.Nation-StateCybercriminalsThreatReport.countries | String | Nation-State Cybercriminals Threat Countries. |
| GIBTI.Nation-StateCybercriminalsThreatReport.description | String | Nation-State Cybercriminals Threat Description. |
| GIBTI.Nation-StateCybercriminalsThreatReport.expertise | String | Nation-State Cybercriminals Threat Expertise. |
| GIBTI.Nation-StateCybercriminalsThreatReport.labels | String | Nation-State Cybercriminals Threat Labels. |
| GIBTI.Nation-StateCybercriminalsThreatReport.langs | String | Nation-State Cybercriminals Threat Languages. |
| GIBTI.Nation-StateCybercriminalsThreatReport.regions | String | Nation-State Cybercriminals Threat Regions. |
| GIBTI.Nation-StateCybercriminalsThreatReport.reportNumber | String | Nation-State Cybercriminals Threat Report Number. |
| GIBTI.Nation-StateCybercriminalsThreatReport.sectors | String | Nation-State Cybercriminals Threat Sectors. |
| GIBTI.Nation-StateCybercriminalsThreatReport.report_type | String | Report Type. |
| GIBTI.Nation-StateCybercriminalsThreatReport.sources | String | Threat Sources. |
| GIBTI.Nation-StateCybercriminalsThreatReport.targeted_companies | String | Targeted Companies. |
| GIBTI.Nation-StateCybercriminalsThreatReport.targeted_partners_and_clients | String | Targeted Partners And Clients. |
| GIBTI.Nation-StateCybercriminalsThreatReport.target_domains | String | Target Domains. |
| GIBTI.Nation-StateCybercriminalsThreatReport.files.name | String | Threat Files Table (files attached to the report): name. |
| GIBTI.Nation-StateCybercriminalsThreatReport.files.mime | String | Threat Files Table (files attached to the report): mime. |
| GIBTI.Nation-StateCybercriminalsThreatReport.files.size | Number | Threat Files Table (files attached to the report): size. |
| GIBTI.Nation-StateCybercriminalsThreatReport.files.hash | String | Threat Files Table (files attached to the report): hash. |
| GIBTI.Nation-StateCybercriminalsThreatReport.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.Nation-StateCybercriminalsThreatReport.createdAt | Date | Date Group-IB created the report. |
| GIBTI.Nation-StateCybercriminalsThreatReport.dateFirstSeen | Date | Date First Seen. |
| GIBTI.Nation-StateCybercriminalsThreatReport.dateLastSeen | Date | Date Last Seen. |
| GIBTI.Nation-StateCybercriminalsThreatReport.datePublished | Date | Date Published. |
| GIBTI.Nation-StateCybercriminalsThreatReport.threatActor.country | String | Threat Actor Country. |
| GIBTI.Nation-StateCybercriminalsThreatReport.threatActor.id | String | Threat Actor ID. |
| GIBTI.Nation-StateCybercriminalsThreatReport.threatActor.isAPT | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.Nation-StateCybercriminalsThreatReport.threatActor.name | String | Threat Actor Name. |
| GIBTI.Nation-StateCybercriminalsThreatReport.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.Nation-StateCybercriminalsThreatReport.evaluation.credibility | Number | Credibility. |
| GIBTI.Nation-StateCybercriminalsThreatReport.evaluation.reliability | Number | Reliability. |
| GIBTI.Nation-StateCybercriminalsThreatReport.evaluation.severity | String | Severity. |
| GIBTI.Nation-StateCybercriminalsThreatReport.evaluation.tlp | String | TLP. |
| GIBTI.Nation-StateCybercriminalsThreatReport.forumsAccounts.nickname | String | Nation-State Cybercriminal Forums Table: nickname. |
| GIBTI.Nation-StateCybercriminalsThreatReport.forumsAccounts.url | String | Nation-State Cybercriminal Forums Table: url. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| Domain.Name | String | Domain name. |
| URL.Data | String | URL. |
| File.MD5 | String | MD5 hash of the file. |
| File.SHA1 | String | SHA-1 hash of the file. |
| File.SHA256 | String | SHA-256 hash of the file. |
| File.Name | String | File name. |
| IPv6.Address | String | IPv6 address. |
| File.SHA512 | String | SHA-512 hash of the file. |
| Account.Email.Address | String | E-mail address of an e-mail message listed among the report's indicators. |
| Account.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| Account.TrafficLightProtocol | String | TLP of the record. |
| Domain.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| Domain.MalwareFamily | String | Malware families the record names. |
| Domain.TrafficLightProtocol | String | TLP of the record. |
| Domain.Malicious.Vendor | String | The vendor that rated the domain bad. |
| Domain.Malicious.Description | String | Empty; the command writes no description. |
| File.Hashes.type | String | The kind of each hash of the file: MD5, SHA1, SHA256 or SHA512. |
| File.Hashes.value | String | Each hash of the file. |
| File.Size | Number | Size of the file. |
| File.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| File.MalwareFamily | String | Malware families the record names. |
| File.TrafficLightProtocol | String | TLP of the record. |
| File.Malicious.Vendor | String | The vendor that rated the file bad. |
| File.Malicious.Description | String | Empty; the command writes no description. |
| IP.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| IP.MalwareFamily | String | Malware families the record names. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IP.Malicious.Vendor | String | The vendor that rated the IP bad. |
| IP.Malicious.Description | String | Empty; the command writes no description. |
| IPv6.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| IPv6.MalwareFamily | String | Malware families the record names. |
| IPv6.TrafficLightProtocol | String | TLP of the record. |
| IPv6.Malicious.Vendor | String | The vendor that rated the IPv6 address bad. |
| IPv6.Malicious.Description | String | Empty; the command writes no description. |
| URL.Tags | String | The collection tag, hi/threat or apt/threat, and the malware families and threat actors the record names. |
| URL.MalwareFamily | String | Malware families the record names. |
| URL.TrafficLightProtocol | String | TLP of the record. |
| URL.Malicious.Vendor | String | The vendor that rated the URL bad. |
| URL.Malicious.Description | String | Empty; the command writes no description. |

### gibti-get-threat-actor-info

***
Reads one or more threat actor profiles by id from hi/threat_actor, or from apt/threat_actor when isAPT is true. An id missing from the selected collection is read from the other one, since the actors a malware profile names carry no APT flag. Ids that neither collection publishes, such as a defacer Group-IB tracks only in attacks/deface or an actor profile it has not published, are listed in the War Room and do not fail the command. Profiles from apt/threat_actor go to `GIBTI.Nation-StateCybercriminalsThreatActorProfile`, profiles from hi/threat_actor to `GIBTI.GIBCybercriminalThreatActorProfile`. The description is returned as text. A report Group-IB lists as a bare id fills only the id column of the reports table.

#### Base Command

`gibti-get-threat-actor-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | One or more Group-IB threat actor ids, comma-separated, for example 0123456789abcdef0123456789abcdef01234567. | Required |
| isAPT | Whether to read the ids from apt/threat_actor (true) or from hi/threat_actor (false) first. An id the first collection does not have is read from the other one. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.GIBCybercriminalThreatActorProfile.name | String | Record name. |
| GIBTI.GIBCybercriminalThreatActorProfile.id | String | Record id. |
| GIBTI.GIBCybercriminalThreatActorProfile.aliases | String | Cybercriminal Threat Actor Aliases. |
| GIBTI.GIBCybercriminalThreatActorProfile.description | String | Cybercriminal Threat Actor Description. |
| GIBTI.GIBCybercriminalThreatActorProfile.isAPT | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.GIBCybercriminalThreatActorProfile.threat_actor_name | String | Threat Actor Name. |
| GIBTI.GIBCybercriminalThreatActorProfile.threat_actor_id | String | Threat Actor ID, the id of the profile. |
| GIBTI.GIBCybercriminalThreatActorProfile.expertise | String | Cybercriminal Expertise. |
| GIBTI.GIBCybercriminalThreatActorProfile.regions | String | Cybercriminal Regions. |
| GIBTI.GIBCybercriminalThreatActorProfile.sectors | String | Cybercriminal Sectors. |
| GIBTI.GIBCybercriminalThreatActorProfile.malware | String | Cybercriminal Malware. |
| GIBTI.GIBCybercriminalThreatActorProfile.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.GIBCybercriminalThreatActorProfile.reports.id | String | Cybercriminal Threat Actor Reports Table: id. |
| GIBTI.GIBCybercriminalThreatActorProfile.reports.name | String | Cybercriminal Threat Actor Reports Table: name. |
| GIBTI.GIBCybercriminalThreatActorProfile.reports.datePublished | Date | Cybercriminal Threat Actor Reports Table: date published. |
| GIBTI.GIBCybercriminalThreatActorProfile.createdAt | Date | Date Group-IB created the profile. |
| GIBTI.GIBCybercriminalThreatActorProfile.updatedAt | Date | Date Group-IB last updated the profile. |
| GIBTI.GIBCybercriminalThreatActorProfile.hasIocs | Boolean | Whether the profile has linked indicators. |
| GIBTI.GIBCybercriminalThreatActorProfile.dateFirstSeen | Date | Date First Seen. |
| GIBTI.GIBCybercriminalThreatActorProfile.dateLastSeen | Date | Date Last Seen. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.name | String | Record name. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.id | String | Record id. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.aliases | String | Nation-State Cybercriminals Threat Actor Aliases. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.country | String | Nation-State Cybercriminals Threat Actor Country. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.description | String | Nation-State Cybercriminals Threat Actor Description. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.goals | String | Nation-State Cybercriminals Threat Actor Goals. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.isAPT | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.labels | String | Nation-State Cybercriminals Threat Actor Labels. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.threat_actor_name | String | Threat Actor Name. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.threat_actor_id | String | Threat Actor ID, the id of the profile. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.roles | String | Nation-State Cybercriminals Threat Actor Roles. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.cve | String | Nation-State Cybercriminals Threat Actor CVE. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.expertise | String | Nation-State Cybercriminals Expertise. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.malware | String | Nation-State Cybercriminals Malware. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.regions | String | Nation-State Cybercriminals Regions. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.sectors | String | Nation-State Cybercriminals Sectors. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.reports.id | String | Nation-State Cybercriminals Threat Actor Reports Table: id. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.reports.name | String | Nation-State Cybercriminals Threat Actor Reports Table: name. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.reports.datePublished | Date | Nation-State Cybercriminals Threat Actor Reports Table: date published. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.createdAt | Date | Date Group-IB created the profile. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.dateFirstSeen | Date | Date First Seen. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.dateLastSeen | Date | Date Last Seen. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.updatedAt | Date | Date Group-IB last updated the profile. |
| GIBTI.Nation-StateCybercriminalsThreatActorProfile.hasIocs | Boolean | Whether the profile has linked indicators. |

### gibti-get-suspicious-ip-tor-node-info

***
Returns the suspicious_ip/tor_node record with the given ID.

#### Base Command

`gibti-get-suspicious-ip-tor-node-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the IPv4 address of the relay, for example 198.51.100.46. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.SuspiciousIPTorNode.name | String | Record name. |
| GIBTI.SuspiciousIPTorNode.id | String | Record id. |
| GIBTI.SuspiciousIPTorNode.source | String | How Group-IB detected the relay, such as tor_certs. |
| GIBTI.SuspiciousIPTorNode.countryName | String | Country of the IP address, or its country code when the record has no country name. |
| GIBTI.SuspiciousIPTorNode.countryCode | String | Country Code. |
| GIBTI.SuspiciousIPTorNode.asn | String | ASN. |
| GIBTI.SuspiciousIPTorNode.provider | String | Provider. |
| GIBTI.SuspiciousIPTorNode.dateFirstSeen | Date | Date First Seen. |
| GIBTI.SuspiciousIPTorNode.dateLastSeen | Date | Date Last Seen. |
| GIBTI.SuspiciousIPTorNode.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.SuspiciousIPTorNode.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.SuspiciousIPTorNode.evaluation.credibility | Number | Credibility. |
| GIBTI.SuspiciousIPTorNode.evaluation.reliability | Number | Reliability. |
| GIBTI.SuspiciousIPTorNode.evaluation.severity | String | Severity. |
| GIBTI.SuspiciousIPTorNode.evaluation.tlp | String | TLP. |
| GIBTI.SuspiciousIPTorNode.torFlags | String | Consensus flags of the relay's newest state, such as Exit, Guard or BadExit. |
| GIBTI.SuspiciousIPTorNode.torExit | Boolean | Whether the relay's newest consensus state makes it a usable exit: its flags include Exit and not BadExit. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.Tags | String | The suspicious_ip/tor_node collection. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IP.ASN | String | ASN of the IP address. |
| IP.Geo.Country | String | Country of the IP address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Region of the IP address. |
| IP.Organization.Name | String | Provider of the IP address. |

### gibti-get-suspicious-ip-open-proxy-info

***
Returns the suspicious_ip/open_proxy records with the given ID. Every listing of the address is returned, one `GIBTI.SuspiciousIPOpenProxy` record per port, keyed by its `listing` (`<address>:<port>`), so a repeated lookup updates each listing, port 0 included.

#### Base Command

`gibti-get-suspicious-ip-open-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the IPv4 address of the proxy, for example 203.0.113.5; every port it is listed on is returned. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.SuspiciousIPOpenProxy.name | String | Record name. |
| GIBTI.SuspiciousIPOpenProxy.id | String | Record id. |
| GIBTI.SuspiciousIPOpenProxy.countryName | String | Country of the IP address, or its country code when the record has no country name. |
| GIBTI.SuspiciousIPOpenProxy.countryCode | String | Country Code. |
| GIBTI.SuspiciousIPOpenProxy.asn | String | ASN of the address; Group-IB's open proxy listings carry none. |
| GIBTI.SuspiciousIPOpenProxy.provider | String | Provider of the address; Group-IB's open proxy listings carry none. |
| GIBTI.SuspiciousIPOpenProxy.dateFirstSeen | Date | Date First Seen. |
| GIBTI.SuspiciousIPOpenProxy.dateLastSeen | Date | Date Last Seen. |
| GIBTI.SuspiciousIPOpenProxy.dateDetected | Date | Date of Detection. |
| GIBTI.SuspiciousIPOpenProxy.port | Number | Proxy Port. |
| GIBTI.SuspiciousIPOpenProxy.listing | String | The address and port of the listing, `<address>:<port>`, the key of its context entry. |
| GIBTI.SuspiciousIPOpenProxy.source | String | Primary public list the listing comes from. |
| GIBTI.SuspiciousIPOpenProxy.sources | String | Public lists that carry the listing. |
| GIBTI.SuspiciousIPOpenProxy.type | String | Proxy Type. |
| GIBTI.SuspiciousIPOpenProxy.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.SuspiciousIPOpenProxy.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.SuspiciousIPOpenProxy.evaluation.credibility | Number | Credibility. |
| GIBTI.SuspiciousIPOpenProxy.evaluation.reliability | Number | Reliability. |
| GIBTI.SuspiciousIPOpenProxy.evaluation.severity | String | Severity. |
| GIBTI.SuspiciousIPOpenProxy.evaluation.tlp | String | TLP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.Tags | String | The suspicious_ip/open_proxy collection. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IP.ASN | String | Empty; Group-IB's open proxy listings carry no ASN. |
| IP.Geo.Country | String | Country of the IP address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Empty; Group-IB's open proxy listings carry no region. |
| IP.Organization.Name | String | Empty; Group-IB's open proxy listings carry no provider. |

### gibti-get-suspicious-ip-socks-proxy-info

***
Returns the suspicious_ip/socks_proxy record with the given ID.

#### Base Command

`gibti-get-suspicious-ip-socks-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the IPv4 address of the proxy, for example 192.0.2.80. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.SuspiciousIPSocksProxy.name | String | Record name. |
| GIBTI.SuspiciousIPSocksProxy.id | String | Record id. |
| GIBTI.SuspiciousIPSocksProxy.countryName | String | Country of the IP address, or its country code when the record has no country name. |
| GIBTI.SuspiciousIPSocksProxy.countryCode | String | Country Code. |
| GIBTI.SuspiciousIPSocksProxy.asn | String | ASN of the address; Group-IB's SOCKS proxy listings carry none. |
| GIBTI.SuspiciousIPSocksProxy.provider | String | Provider of the address; Group-IB's SOCKS proxy listings carry none. |
| GIBTI.SuspiciousIPSocksProxy.dateFirstSeen | Date | Date First Seen. |
| GIBTI.SuspiciousIPSocksProxy.dateLastSeen | Date | Date Last Seen. |
| GIBTI.SuspiciousIPSocksProxy.dateDetected | Date | Date of Detection. |
| GIBTI.SuspiciousIPSocksProxy.source | String | Source of the SOCKS proxy listing. |
| GIBTI.SuspiciousIPSocksProxy.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.SuspiciousIPSocksProxy.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.SuspiciousIPSocksProxy.evaluation.credibility | Number | Credibility. |
| GIBTI.SuspiciousIPSocksProxy.evaluation.reliability | Number | Reliability. |
| GIBTI.SuspiciousIPSocksProxy.evaluation.severity | String | Severity. |
| GIBTI.SuspiciousIPSocksProxy.evaluation.tlp | String | TLP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.Tags | String | The suspicious_ip/socks_proxy collection. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IP.ASN | String | Empty; Group-IB's SOCKS proxy listings carry no ASN. |
| IP.Geo.Country | String | Country of the IP address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Empty; Group-IB's SOCKS proxy listings carry no region. |
| IP.Organization.Name | String | Empty; Group-IB's SOCKS proxy listings carry no provider. |

### gibti-get-malware-cnc-info

***
Returns the malware/cnc record with the given ID.

#### Base Command

`gibti-get-malware-cnc-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.MalwareCNC.name | String | Record name. |
| GIBTI.MalwareCNC.id | String | Record id. |
| GIBTI.MalwareCNC.cnc | String | The C&C as Group-IB lists it: a URL, a domain, or an IP address. |
| GIBTI.MalwareCNC.dateFirstSeen | Date | Date First Seen. |
| GIBTI.MalwareCNC.dateLastSeen | Date | Date Last Seen. |
| GIBTI.MalwareCNC.dateDetected | Date | Date of Detection. |
| GIBTI.MalwareCNC.domain | String | Domain of the C&C. |
| GIBTI.MalwareCNC.malwareList.id | String | Malware Table: id. |
| GIBTI.MalwareCNC.malwareList.name | String | Malware Table: name. |
| GIBTI.MalwareCNC.threatActor.id | String | Threat Actors Table: id. |
| GIBTI.MalwareCNC.threatActor.name | String | Threat Actors Table: name. |
| GIBTI.MalwareCNC.platform | String | Platforms the malware runs on. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | URL. |
| Domain.Name | String | Domain name. |
| IP.Address | String | IP address. |
| IPv6.Address | String | IPv6 address. |
| IP.Tags | String | The malware/cnc collection tag and the malware families and threat actors the record names. |
| IP.MalwareFamily | String | Malware families the record names. |
| IP.TrafficLightProtocol | String | Empty; malware/cnc records carry no TLP. |
| IP.ASN | String | ASN of the C&C address. |
| IP.Geo.Country | String | Country of the C&C address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Region of the C&C address. |
| IP.Organization.Name | String | Provider of the C&C address. |
| IP.Malicious.Vendor | String | The vendor that rated the IP address bad. |
| IP.Malicious.Description | String | Empty; the command writes no description. |
| IPv6.Tags | String | The malware/cnc collection tag and the malware families and threat actors the record names. |
| IPv6.MalwareFamily | String | Malware families the record names. |
| IPv6.TrafficLightProtocol | String | Empty; malware/cnc records carry no TLP. |
| IPv6.ASN | String | ASN of the C&C address. |
| IPv6.Geo.Country | String | Country of the C&C address, or its country code when the record has no country name. |
| IPv6.Geo.Description | String | Region of the C&C address. |
| IPv6.Organization.Name | String | Provider of the C&C address. |
| IPv6.Malicious.Vendor | String | The vendor that rated the IPv6 address bad. |
| IPv6.Malicious.Description | String | Empty; the command writes no description. |
| Domain.Tags | String | The malware/cnc collection tag and the malware families and threat actors the record names. |
| Domain.MalwareFamily | String | Malware families the record names. |
| Domain.TrafficLightProtocol | String | Empty; malware/cnc records carry no TLP. |
| Domain.Malicious.Vendor | String | The vendor that rated the domain bad. |
| Domain.Malicious.Description | String | Empty; the command writes no description. |
| URL.Tags | String | The malware/cnc collection tag and the malware families and threat actors the record names. |
| URL.MalwareFamily | String | Malware families the record names. |
| URL.TrafficLightProtocol | String | Empty; malware/cnc records carry no TLP. |
| URL.Malicious.Vendor | String | The vendor that rated the URL bad. |
| URL.Malicious.Description | String | Empty; the command writes no description. |

### gibti-get-available-collections

***
Returns the collections granted to your API user that the integration's API library knows, sorted.

#### Base Command

`gibti-get-available-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.OtherInfo.collections | String | Collections granted to your API user that the integration's API library knows. |

#### Command Example

```!gibti-get-available-collections```

#### Human Readable Output

>### Available collections
>
>|collections|
>|---|
>| apt/threat,<br>apt/threat_actor,<br>attacks/ddos,<br>attacks/deface,<br>attacks/phishing_group,<br>attacks/phishing_kit,<br>compromised/account_group,<br>compromised/bank_card_group,<br>compromised/breacheddb,<br>compromised/masked_card,<br>compromised/spd,<br>hi/threat,<br>hi/threat_actor,<br>malware/cnc,<br>malware/malware,<br>osi/git_repository,<br>osi/public_leak,<br>osi/vulnerability,<br>suspicious_ip/open_proxy,<br>suspicious_ip/scanner,<br>suspicious_ip/socks_proxy,<br>suspicious_ip/tor_node,<br>suspicious_ip/vpn |

### gibti-get-compromised-access-info

***
Returns the compromised/access record with the given ID. The record is a dark web marketplace listing of access to one of your hosts and carries no indicators.

#### Base Command

`gibti-get-compromised-access-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CompromisedAccess.name | String | Record name: the target host, with the stealer family. |
| GIBTI.CompromisedAccess.id | String | Record id. |
| GIBTI.CompromisedAccess.accessType | String | Access Type: the category of access sold, such as Logs. |
| GIBTI.CompromisedAccess.dateCompromised | Date | Date Compromised: when the data was stolen. |
| GIBTI.CompromisedAccess.dateDetected | Date | Date of Detection: when Group-IB saw the listing. |
| GIBTI.CompromisedAccess.priceValue | Number | Price Value: the asking price. |
| GIBTI.CompromisedAccess.priceCurrency | String | Price Currency. |
| GIBTI.CompromisedAccess.malware_name | String | Malware Name: the stealer family. |
| GIBTI.CompromisedAccess.malware_id | String | Malware ID. |
| GIBTI.CompromisedAccess.sourceType | String | Source: the marketplace. |
| GIBTI.CompromisedAccess.seller | String | Seller: the vendor on the marketplace. |
| GIBTI.CompromisedAccess.sourceExternalId | String | The listing's id on the marketplace. |
| GIBTI.CompromisedAccess.sourceDbId | String | Source database id. |
| GIBTI.CompromisedAccess.sourceLink | String | Source link. |
| GIBTI.CompromisedAccess.shop.domain | String | Shop Domain: the marketplace's own domain, not attacker infrastructure. |
| GIBTI.CompromisedAccess.shop.url | String | Shop URL. |
| GIBTI.CompromisedAccess.shop.ip | String | Shop IP. |
| GIBTI.CompromisedAccess.shop.port | Number | Shop port. |
| GIBTI.CompromisedAccess.shop.protocol | String | Shop protocol. |
| GIBTI.CompromisedAccess.shop.asn | String | ASN of the shop IP. |
| GIBTI.CompromisedAccess.shop.provider | String | Provider of the shop IP. |
| GIBTI.CompromisedAccess.shop.countryCode | String | Country code of the shop IP. |
| GIBTI.CompromisedAccess.shop.region | String | Region of the shop IP. |
| GIBTI.CompromisedAccess.shop.city | String | City of the shop IP. |
| GIBTI.CompromisedAccess.target.host | String | Target Host: your host the listing offers access to. |
| GIBTI.CompromisedAccess.target.domain | String | Target Domain. |
| GIBTI.CompromisedAccess.target.ip | String | Target IP, when the record gives one. |
| GIBTI.CompromisedAccess.target.provider | String | Target provider. |
| GIBTI.CompromisedAccess.target.os | String | Device OS. |
| GIBTI.CompromisedAccess.target.browser | String | Device Browser. |
| GIBTI.CompromisedAccess.target.userAgent | String | Device user agent. |
| GIBTI.CompromisedAccess.target.systemName | String | Device Name. |
| GIBTI.CompromisedAccess.target.country | String | Device country. |
| GIBTI.CompromisedAccess.target.region | String | Device region. |
| GIBTI.CompromisedAccess.target.state | String | Device state. |
| GIBTI.CompromisedAccess.target.city | String | Device city. |
| GIBTI.CompromisedAccess.archiveFiles | String | Archive File List: the list of files in the offered archive, as text. |
| GIBTI.CompromisedAccess.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.CompromisedAccess.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.CompromisedAccess.evaluation.credibility | Number | Credibility. |
| GIBTI.CompromisedAccess.evaluation.reliability | Number | Reliability. |
| GIBTI.CompromisedAccess.evaluation.severity | String | Severity. |
| GIBTI.CompromisedAccess.evaluation.tlp | String | TLP. |

### gibti-get-darkweb-telegram-info

***
Returns the compromised/messenger record with the given ID. The record is a Telegram post your hunting rules matched; its text follows the **Mask dark web post text** and **Mask passwords and leaked secrets** settings, and it carries no indicators.

#### Base Command

`gibti-get-darkweb-telegram-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.DarkwebTelegram.name | String | Record name: the channel's title. |
| GIBTI.DarkwebTelegram.id | String | Record id. |
| GIBTI.DarkwebTelegram.messageId | String | Telegram message id. |
| GIBTI.DarkwebTelegram.text | String | Post Text. |
| GIBTI.DarkwebTelegram.translation | String | Post Translation. |
| GIBTI.DarkwebTelegram.postDate | Date | Post Date. |
| GIBTI.DarkwebTelegram.editDate | Date | Post Edit Date. |
| GIBTI.DarkwebTelegram.deletedDate | Date | Post Deleted Date: when the post was deleted; empty while it is up. |
| GIBTI.DarkwebTelegram.isReply | Boolean | Whether the post replies to another. |
| GIBTI.DarkwebTelegram.highlight | String | The portal's highlighted copy of the matched text. |
| GIBTI.DarkwebTelegram.author.id | String | Author ID. |
| GIBTI.DarkwebTelegram.author.handle | String | Author Handle: the Telegram user name. |
| GIBTI.DarkwebTelegram.author.firstName | String | Author's first name. |
| GIBTI.DarkwebTelegram.author.lastName | String | Author's last name. |
| GIBTI.DarkwebTelegram.author.name | String | Author's first and last name, joined. |
| GIBTI.DarkwebTelegram.author.type | String | Author type. |
| GIBTI.DarkwebTelegram.channel.id | String | Channel ID. |
| GIBTI.DarkwebTelegram.channel.name | String | Channel Name: the handle. |
| GIBTI.DarkwebTelegram.channel.title | String | Channel Title. |
| GIBTI.DarkwebTelegram.channel.description | String | Channel Description. |
| GIBTI.DarkwebTelegram.channel.type | String | Channel type. |
| GIBTI.DarkwebTelegram.channel.messages | Number | Channel Messages. |
| GIBTI.DarkwebTelegram.channel.subscribers | Number | Channel Subscribers. |
| GIBTI.DarkwebTelegram.channel.firstMessageDate | Date | First message date of the channel. |
| GIBTI.DarkwebTelegram.channel.lastMessageDate | Date | Last message date of the channel. |
| GIBTI.DarkwebTelegram.attachment.name | String | Attachment Name. |
| GIBTI.DarkwebTelegram.attachment.type | String | Attachment Type. |
| GIBTI.DarkwebTelegram.attachment.size | Number | Attachment Size. |
| GIBTI.DarkwebTelegram.edits.dateDetected | Date | Post Edits Table: date detected. |
| GIBTI.DarkwebTelegram.edits.text | String | Post Edits Table: text. |
| GIBTI.DarkwebTelegram.edits.translation | String | Post Edits Table: translation. |
| GIBTI.DarkwebTelegram.reply.id | String | Record id of the post replied to. |
| GIBTI.DarkwebTelegram.reply.messageId | String | Telegram message id of the post replied to. |
| GIBTI.DarkwebTelegram.reply.postDate | Date | Post date of the post replied to. |
| GIBTI.DarkwebTelegram.reply.text | String | Reply Text: the text of the post replied to. |
| GIBTI.DarkwebTelegram.reply.translation | String | Translation of the post replied to. |
| GIBTI.DarkwebTelegram.reply.authorId | String | Author ID of the post replied to. |
| GIBTI.DarkwebTelegram.portalLink | String | Link to the record in the Group-IB portal. |

### gibti-get-darkweb-discord-info

***
Returns the compromised/discord record with the given ID. The record is a Discord post your hunting rules matched; its text follows the **Mask dark web post text** and **Mask passwords and leaked secrets** settings, and it carries no indicators.

#### Base Command

`gibti-get-darkweb-discord-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 1290000000000000001. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.DarkwebDiscord.name | String | Record name: the server and the channel. |
| GIBTI.DarkwebDiscord.id | String | Record id: the Discord message id. |
| GIBTI.DarkwebDiscord.text | String | Post Text. |
| GIBTI.DarkwebDiscord.translation | String | Post Translation. |
| GIBTI.DarkwebDiscord.postDate | Date | Post Date. |
| GIBTI.DarkwebDiscord.deletedDate | Date | Post Deleted Date: when the post was deleted; empty while it is up. |
| GIBTI.DarkwebDiscord.highlight | String | The portal's highlighted copy of the matched text. |
| GIBTI.DarkwebDiscord.ruleIds | Number | Rule ids Group-IB attaches to the post. |
| GIBTI.DarkwebDiscord.author.id | String | Author ID. |
| GIBTI.DarkwebDiscord.author.name | String | Author's Discord name. |
| GIBTI.DarkwebDiscord.author.discriminator | String | Author's Discord discriminator. |
| GIBTI.DarkwebDiscord.author.handle | String | Author Handle: the Discord tag. |
| GIBTI.DarkwebDiscord.channel.id | String | Channel ID. |
| GIBTI.DarkwebDiscord.channel.name | String | Channel Name. |
| GIBTI.DarkwebDiscord.channel.server | String | Server Name. |
| GIBTI.DarkwebDiscord.channel.messages | Number | Channel Messages. |
| GIBTI.DarkwebDiscord.channel.subscribers | Number | Channel Subscribers. |
| GIBTI.DarkwebDiscord.channel.firstMessageDate | Date | First message date of the channel. |
| GIBTI.DarkwebDiscord.channel.lastMessageDate | Date | Last message date of the channel. |
| GIBTI.DarkwebDiscord.attachment.name | String | Attachment Name. |
| GIBTI.DarkwebDiscord.attachment.type | String | Attachment Type. |
| GIBTI.DarkwebDiscord.attachment.size | Number | Attachment Size. |
| GIBTI.DarkwebDiscord.edits.date | Date | Post Edits Table: date. |
| GIBTI.DarkwebDiscord.edits.dateDetected | Date | Post Edits Table: date detected. |
| GIBTI.DarkwebDiscord.edits.text | String | Post Edits Table: text. |
| GIBTI.DarkwebDiscord.edits.translation | String | Post Edits Table: translation. |
| GIBTI.DarkwebDiscord.reply.id | String | Record id of the post replied to. |
| GIBTI.DarkwebDiscord.reply.text | String | Reply Text: the text of the post replied to. |
| GIBTI.DarkwebDiscord.reply.translation | String | Translation of the post replied to. |
| GIBTI.DarkwebDiscord.reply.authorName | String | Author of the post replied to. |
| GIBTI.DarkwebDiscord.portalLink | String | Link to the record in the Group-IB portal. |

#### Command Example

```!gibti-get-darkweb-discord-info id=1290000000000000001```

### gibti-get-darkweb-forum-info

***
Returns the darkweb/forums record with the given ID. The record is a forum post your hunting rules matched; its text follows the **Mask dark web post text** and **Mask passwords and leaked secrets** settings, and it carries no indicators.

#### Base Command

`gibti-get-darkweb-forum-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.DarkwebForum.name | String | Record name: the thread title, or the forum when the thread has no title or Mask dark web post text is Full. |
| GIBTI.DarkwebForum.id | String | Record id. |
| GIBTI.DarkwebForum.text | String | Post Text. |
| GIBTI.DarkwebForum.clearText | String | The cleaned copy of the post Group-IB keeps. |
| GIBTI.DarkwebForum.imageText | String | Image Text: the text read from the post's images. |
| GIBTI.DarkwebForum.messageHash | String | Data Hash: Group-IB's hash of the post text. |
| GIBTI.DarkwebForum.messageLength | Number | Length of the post in characters. |
| GIBTI.DarkwebForum.languages | String | Languages of the post, as Group-IB lists them, joined. |
| GIBTI.DarkwebForum.messageLanguages | String | Languages detected in the post text. |
| GIBTI.DarkwebForum.topic | String | Title: the thread title. |
| GIBTI.DarkwebForum.topicHash | String | Hash of the thread title. |
| GIBTI.DarkwebForum.threadId | String | Thread ID. |
| GIBTI.DarkwebForum.firstPost | Boolean | Whether the post opens its thread. |
| GIBTI.DarkwebForum.forum | String | Forum. |
| GIBTI.DarkwebForum.forumSection | String | Forum Section. |
| GIBTI.DarkwebForum.domain | String | Domain of the forum. |
| GIBTI.DarkwebForum.url | String | Post URL. |
| GIBTI.DarkwebForum.author.handle | String | Author Handle: the forum nickname. |
| GIBTI.DarkwebForum.categories | String | Categories. |
| GIBTI.DarkwebForum.postDate | Date | Post Date. |
| GIBTI.DarkwebForum.uploadTime | Date | Upload Time: when Group-IB collected the post. |
| GIBTI.DarkwebForum.alertUpdateDate | Date | When Group-IB last updated its alert on the post. |
| GIBTI.DarkwebForum.portalLink | String | Link to the record in the Group-IB portal. |

#### Command Example

```!gibti-get-darkweb-forum-info id=0123456789abcdef0123456789abcdef```

### gibti-get-open-threat-info

***
Returns the hi/open_threats record with the given ID. The record is a public post about a threat with the IOCs Group-IB extracted from it. A post text that holds HTML block, line-break or text-formatting markup is returned as text.

#### Base Command

`gibti-get-open-threat-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.OpenThreat.name | String | Record name: the author and the title or the start of the post. |
| GIBTI.OpenThreat.id | String | Record id. |
| GIBTI.OpenThreat.title | String | Title. |
| GIBTI.OpenThreat.text | String | Post Text. |
| GIBTI.OpenThreat.url | String | Post URL. |
| GIBTI.OpenThreat.sourceName | String | Source Name: the site or network. |
| GIBTI.OpenThreat.sourceType | String | Source: the kind of site, such as Blog or Social Network. |
| GIBTI.OpenThreat.author.id | String | Author ID. |
| GIBTI.OpenThreat.author.handle | String | Author Handle. |
| GIBTI.OpenThreat.author.name | String | Author Name. |
| GIBTI.OpenThreat.author.profileUrl | String | Author Profile URL. |
| GIBTI.OpenThreat.author.reposted | Boolean | Whether the post is a repost. |
| GIBTI.OpenThreat.createdAt | Date | Date Created At: when the post was published. |
| GIBTI.OpenThreat.dateDetected | Date | Date of Detection: when Group-IB collected it. |
| GIBTI.OpenThreat.updatedAt | Date | Date Updated At. |
| GIBTI.OpenThreat.threat_actor_name | String | Threat Actor Name. |
| GIBTI.OpenThreat.threat_actor_id | String | Threat Actor ID. |
| GIBTI.OpenThreat.malware_name | String | Malware Name. |
| GIBTI.OpenThreat.countryName | String | Country Name. |
| GIBTI.OpenThreat.tags | String | Tags. |
| GIBTI.OpenThreat.cveIds | String | CVE IDs. |
| GIBTI.OpenThreat.huntingRuleIds | String | Hunting Rule IDs. |
| GIBTI.OpenThreat.companyTags | String | Company Tags. |
| GIBTI.OpenThreat.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.OpenThreat.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.OpenThreat.evaluation.credibility | Number | Credibility. |
| GIBTI.OpenThreat.evaluation.reliability | Number | Reliability. |
| GIBTI.OpenThreat.evaluation.severity | String | Severity. |
| GIBTI.OpenThreat.evaluation.tlp | String | TLP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.Tags | String | The hi/open_threats collection, with the malware families and threat actors the post names. |
| IP.MalwareFamily | String | Malware families the post names. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IPv6.Address | String | IPv6 address. |
| IPv6.Tags | String | The hi/open_threats collection, with the malware families and threat actors the post names. |
| IPv6.MalwareFamily | String | Malware families the post names. |
| IPv6.TrafficLightProtocol | String | TLP of the record. |
| Domain.Name | String | Domain name. |
| Domain.Tags | String | The hi/open_threats collection, with the malware families and threat actors the post names. |
| Domain.MalwareFamily | String | Malware families the post names. |
| Domain.TrafficLightProtocol | String | TLP of the record. |
| File.MD5 | String | MD5 hash. |
| File.SHA1 | String | SHA-1 hash. |
| File.SHA256 | String | SHA-256 hash. |
| File.SHA512 | String | SHA-512 hash. |
| File.Name | String | File name. |
| File.Size | Number | File size. |
| File.Hashes.type | String | The kind of each hash of the file: MD5, SHA1, SHA256 or SHA512. |
| File.Hashes.value | String | Each hash of the file. |
| File.Tags | String | The hi/open_threats collection, with the malware families and threat actors the post names. |
| File.MalwareFamily | String | Malware families the post names. |
| File.TrafficLightProtocol | String | TLP of the record. |
| CVE.ID | String | CVE id. |
| CVE.Tags | String | The hi/open_threats collection, with the malware families and threat actors the post names. |
| CVE.TrafficLightProtocol | String | TLP of the record. |
| Cryptocurrency.Address | String | Wallet address. |
| Cryptocurrency.AddressType | String | The cryptocurrency of the wallet, such as bitcoin; unknown when Group-IB names none. |

#### Command Example

```!gibti-get-open-threat-info id=0123456789abcdef0123456789abcdef01234567```

### gibti-global-search

***
Searches Group-IB's collections for a value (IP, domain, URL, hash, e-mail, name) and returns the matching collections with counts. Every collection the API reports is listed, including the ones this pack has no lookup command for (`supportedByPack` tells them apart). Use bare values here; `gibti-local-search` reads the matching records of one collection.

#### Base Command

`gibti-global-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query you want to search, for example 203.0.113.7. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.search.global.apiPath | String | Collection in which matches were found. |
| GIBTI.search.global.label | String | Display name of the collection. |
| GIBTI.search.global.count | Number | Number of records matching the query. |
| GIBTI.search.global.supportedByPack | Boolean | Whether the pack has a lookup command for the collection. |
| GIBTI.search.global.GIBLink | String | Link to the matches in the Group-IB portal or API. |
| GIBTI.search.global.query | String | The collection's search path for the value (its apiPath followed by ?q= and the query); unique per row. |

#### Command Example

```!gibti-global-search query=evil.example.com```

### gibti-local-search

***
Searches one collection by a bare value, or by `id:<id>` on the collections whose API takes it (threat reports and actor profiles among them). A value matches the text of the records your account's feed of that collection serves; `gibti-get-threat-actor-info` and `gibti-get-threat-info` read a profile or a report outside the feed by its id. An optional date window or a seqUpdate cursor, which takes the place of the window when both are set, narrows the walk; without a cursor or a date window, the collection is walked from its oldest record. On `darkweb/forums` the command reads one page per call (pass the highest `seqUpdate` of its rows as `seq_update` for the next one), and `compromised/discord` without a cursor or a date window returns its newest records.

#### Base Command

`gibti-local-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_name | Collection you want to search. Possible values are: compromised/account_group, compromised/bank_card_group, compromised/masked_card, compromised/breacheddb, compromised/spd, osi/git_repository, osi/public_leak, osi/vulnerability, attacks/ddos, attacks/deface, attacks/phishing_group, attacks/phishing_kit, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, suspicious_ip/vpn, suspicious_ip/scanner, malware/cnc, malware/malware, hi/threat, hi/threat_actor, apt/threat_actor, apt/threat, compromised/access, compromised/messenger, compromised/discord, darkweb/forums, hi/open_threats. | Required |
| query | Value or field query to filter the collection by, e.g. 203.0.113.7. Without it the command returns the records it reads in update order: from the oldest record, from date_from or from seq_update; compromised/discord without seq_update or date_from returns its newest records first. | Optional |
| date_from | Start of the search window (e.g. 2024-01-01 or "30 days"); on a trial or POC account, some collections serve only the last 30 days. It does not narrow compromised/spd, compromised/breacheddb, compromised/messenger, osi/git_repository or darkweb/forums, and on osi/vulnerability it filters on the record's own date. The window applies to the first page; a later page follows the cursor and can hold records outside it. | Optional |
| date_to | End of the search window (e.g. 2024-06-30); requires date_from. | Optional |
| seq_update | seqUpdate cursor to resume the collection's update feed from (for example the highest seqUpdate among the rows of a previous call). | Optional |
| requests_limit | Maximum number of API requests (pages) sent to the collection; darkweb/forums reads one page whatever the value. Default is 1. | Optional |
| page_size_limit | Maximum number of entries per API response (page size). A collection with a smaller page size of its own is read in pages of that size. Default is 100. | Optional |
| include_raw_feed | If set to true, each row also carries its parsed record, masked as the instance settings say, as 'raw_feed'. Use with caution: can increase context size. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.search.local.id | String | Id of a matching record. |
| GIBTI.search.local.additional_info | String | The record's name, as `Name: <name>`. |
| GIBTI.search.local.seqUpdate | Number | The record's own seqUpdate (a cursor to resume from with seq_update). |
| GIBTI.search.local.raw_feed | String | The matching record as a one-line JSON string, masked as the instance settings say (only when include_raw_feed=true). |

#### Command Example

```!gibti-local-search collection_name=attacks/phishing_group query=203.0.113.7```

#### Human Readable Output

>### Search results
>
>|id|additional_info|seqUpdate|raw_feed|
>|---|---|---|---|
>| 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | Name: login-portal.example.com | 1779676701720185 |  |

### gibti-ip-whois

***
Returns the registry (WHOIS) record of one or more IP addresses from the Group-IB Graph WHOIS: the address range and its CIDR, the regional registry, the network name, the holder organization and its country of registration, the ASN that announces the range, the owner of the AS when the registry names it, and the abuse e-mail addresses and phones. Each field comes from the newest record that has it, and texts a registry puts in place of a value, such as a placeholder phone number, are left out. Unless Look up internal and reserved IP addresses is enabled, a private, shared or reserved address gets a note and no request. The value is refanged first. A refused key (HTTP 401 or 403) fails the command; any other failed request is the error entry of its value, and the other values still return. history=true adds up to history_limit earlier records. The command sets no verdict.

#### Base Command

`gibti-ip-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses. | Required |
| history | true adds up to history_limit earlier WHOIS records. Possible values are: true, false. Default is false. | Optional |
| history_limit | How many earlier records history=true adds, the newest first; 1 or more. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.IPWhois.ip | String | The IP address. |
| GIBTI.IPWhois.rangeStart | String | First address of the registered range. |
| GIBTI.IPWhois.rangeEnd | String | Last address of the registered range. |
| GIBTI.IPWhois.cidr | String | CIDR of the registered range. |
| GIBTI.IPWhois.registry | String | Regional registry of the range (ARIN, RIPE, APNIC, LACNIC or AFRINIC). |
| GIBTI.IPWhois.netname | String | Network name of the range. |
| GIBTI.IPWhois.organization | String | Organization that holds the range. |
| GIBTI.IPWhois.country | String | Country of the organization that holds the range (else of the range), as an ISO code; not the location of the address. |
| GIBTI.IPWhois.asn | String | ASN that announces the range. |
| GIBTI.IPWhois.asOwner | String | Owner of the AS, when the registry names it. |
| GIBTI.IPWhois.abuseEmails | String | Abuse e-mail addresses of the range. |
| GIBTI.IPWhois.abusePhones | String | Phones of the abuse contact of the range. |
| GIBTI.IPWhois.status | String | Registration status of the range. |
| GIBTI.IPWhois.firstSeen | Date | When Group-IB first saw the newest record. |
| GIBTI.IPWhois.lastSeen | Date | When Group-IB last saw the newest record. |
| GIBTI.IPWhois.history.firstSeen | Date | With history=true, when Group-IB first saw an earlier record. |
| GIBTI.IPWhois.history.lastSeen | Date | With history=true, when Group-IB last saw an earlier record. |
| GIBTI.IPWhois.history.organization | String | With history=true, the holder organization of an earlier record. |
| GIBTI.IPWhois.history.netname | String | With history=true, the network name of an earlier record. |
| GIBTI.IPWhois.history.asn | String | With history=true, the ASN of an earlier record. |
| GIBTI.IPWhois.history.cidr | String | With history=true, the CIDR of an earlier record. |

#### Command Example

```!gibti-ip-whois ip=198.51.100.27```

### gibti-domain-whois

***
Returns the registration (WHOIS) record of one or more domains from the Group-IB Graph WHOIS: the registrar with its IANA ID and abuse contact, the registrant's organization and country, the registrant's name and e-mail address unless WHOIS personal data is Drop, the statuses, the creation, update and expiration dates and the name servers. A subdomain is answered with the record of the registered domain under its zone, and an internationalized domain is looked up in its ASCII form. The registrar, the registrant's organization and country, the statuses, the dates and the name servers come from the newest record that has them; the IANA ID, the abuse contact and the registrant's name and e-mail address come from the current record only. Texts a registry puts in place of a value, such as REDACTED FOR PRIVACY, are left out. The value is refanged, lowercased and stripped of a final dot first. A refused key (HTTP 401 or 403) fails the command; any other failed request is the error entry of its value, and the other values still return. history=true adds up to history_limit earlier records. The command sets no verdict.

#### Base Command

`gibti-domain-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains. | Required |
| history | true adds up to history_limit earlier WHOIS records. Possible values are: true, false. Default is false. | Optional |
| history_limit | How many earlier records history=true adds, the newest first; 1 or more. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.DomainWhois.domain | String | The domain. |
| GIBTI.DomainWhois.zone | String | Zone of the domain, such as com or net. |
| GIBTI.DomainWhois.registeredDomain | Boolean | Whether the record is that of a registered domain; a subdomain is answered with its registered domain's record. |
| GIBTI.DomainWhois.registrar | String | Registrar of the domain. |
| GIBTI.DomainWhois.registrarIanaId | String | IANA ID of the registrar. |
| GIBTI.DomainWhois.registrarAbuseEmail | String | Abuse e-mail address of the registrar. |
| GIBTI.DomainWhois.registrarAbusePhone | String | Abuse phone of the registrar. |
| GIBTI.DomainWhois.whoisServer | String | WHOIS server of the registrar. |
| GIBTI.DomainWhois.registrantOrganization | String | Organization of the registrant. |
| GIBTI.DomainWhois.registrantCountry | String | Country of the registrant. |
| GIBTI.DomainWhois.registrantName | String | Name of the registrant, unless WHOIS personal data is Drop. |
| GIBTI.DomainWhois.registrantEmail | String | E-mail address of the registrant, unless WHOIS personal data is Drop. |
| GIBTI.DomainWhois.statuses | String | Statuses of the domain. |
| GIBTI.DomainWhois.creationDate | Date | Creation date of the domain. |
| GIBTI.DomainWhois.updatedDate | Date | Date of the last update of the registration. |
| GIBTI.DomainWhois.expirationDate | Date | Expiration date of the registration. |
| GIBTI.DomainWhois.nameServers | String | Name servers of the domain. |
| GIBTI.DomainWhois.checkedAt | Date | When Group-IB read the WHOIS record. |
| GIBTI.DomainWhois.history.firstSeen | Date | With history=true, when Group-IB first saw an earlier record. |
| GIBTI.DomainWhois.history.lastSeen | Date | With history=true, when Group-IB last saw an earlier record. |
| GIBTI.DomainWhois.history.registrar | String | With history=true, the registrar of an earlier record. |
| GIBTI.DomainWhois.history.nameServers | String | With history=true, the name servers of an earlier record. |

#### Command Example

```!gibti-domain-whois domain=example.com history=true```

### ip

***
Returns the Group-IB reputation of one or more IPs. The Group-IB risk score (scoring/ip), ioc/primary and the `suspicious_ip/*` collections selected in Collections that keep an IP at least Suspicious decide the verdict. Bad for a risk score of 80-100. Suspicious for a risk score of 40-79, or when ioc/primary lists the IP, whatever its risk score there, or a selected `suspicious_ip/*` collection lists the IP itself, at any age unless Suspicious IP listing recency (days) sets a window. Good for a risk score of 0-39 without such a listing. Unknown without a risk score or a listing. Records of apt/threat and hi/open_threats give tags, names, relationships and publications, and a defacement of the value in attacks/deface gives its collection tag and TLP; they never decide. When the risk score makes the verdict Suspicious or Bad, the collections of the matched records become tags, the threat and actor names of every matched record but the defacements become tags too, the malware names of those records become Malware Family, the most restrictive TLP of the matched records becomes the TLP, and the apt/threat and hi/open_threats records become publications; when ioc/primary makes it Suspicious, the tags, Malware Family and TLP come from the ioc/primary records only, and there are no publications; a `suspicious_ip/*` listing adds only its collection as a tag, and its TLP. With Create relationships enabled, the malware families and actors also become relationships. The value is refanged first. Unless Look up internal and reserved IP addresses is enabled, a private, shared or reserved address, the documentation ranges included, gets a note and no request. An IPv6 address gets no risk score, since Group-IB scores IPv4 addresses only. A refused key (HTTP 401) fails the command; a value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry of its own, and the other values still return. When the risk score, ioc/primary or a selected `suspicious_ip/*` collection fails or does not answer within Lookup timeout (seconds), GIBTI.Reputation.partial is true, and a verdict is set only if no missing answer could have raised it. A missing risk score could make it Bad, so only a Bad verdict is set; a missing ioc/primary or `suspicious_ip/*` collection could make it Suspicious, so a Suspicious or Bad verdict is set and a lower one is not. Without a verdict, the indicator keeps the one it has. A request answered with HTTP 403 (the key has no access) is named in the War Room note; HTTP 403 and HTTP 404 (no record) do not make the result partial, and the verdict comes from the others. With Add WHOIS to ip and domain enabled, the indicator also carries the ASN, the holder organization, the owner of the AS when the registry names it, and the abuse e-mail and phone from the WHOIS record.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.ASN | String | ASN that announces the address range (WHOIS). |
| IP.ASOwner | String | Owner of the autonomous system, when the registry names it (WHOIS). |
| IP.Organization.Name | String | Organization that holds the address range (WHOIS). |
| IP.Registrar.Abuse.Phone | String | Phones of the abuse contact of the address range, comma-separated (WHOIS). |
| IP.Registrar.Abuse.Email | String | Abuse e-mail addresses of the address range, comma-separated (WHOIS). |
| IP.Tags | String | Collections of the matched ioc/primary, apt/threat, hi/open_threats and attacks/deface records, with the threat names and actors of all but the defacements, when the risk score makes the IP Suspicious or Bad; when ioc/primary makes it Suspicious, those of the ioc/primary records only. A `suspicious_ip/*` collection selected in Collections that keep an IP at least Suspicious adds its name when it lists the IP within Suspicious IP listing recency (days), and is the only tag when it raised the verdict. Below Suspicious, with Collection tags at every verdict enabled, the collections in GIBTI.Reputation.collections, without names, and never a collection selected in Collections that keep an IP at least Suspicious. |
| IP.MalwareFamily | String | Malware families of the records the tags come from; empty below Suspicious. |
| IP.TrafficLightProtocol | String | Most restrictive TLP of the records the tags come from; empty below Suspicious. |
| IP.FirstSeenBySource | Date | Earliest first sighting (dateFirstSeen) of the Group-IB records that list or mention the IP. |
| IP.LastSeenBySource | Date | Latest last sighting (dateLastSeen) of the Group-IB records that list or mention the IP. |
| IP.Publications.source | String | Publisher of a Group-IB threat report (Group-IB Threat Intelligence) or a public post that names the IP, on a result the risk score makes Suspicious or Bad. |
| IP.Publications.title | String | Title of the report or post. |
| IP.Publications.link | String | Link to the public post; empty for a Group-IB threat report. |
| IP.Publications.timestamp | Date | When the report or post was published. |
| IP.Malicious.Vendor | String | The vendor that rated the IP bad. |
| IP.Malicious.Description | String | The Group-IB risk score and the collections in GIBTI.Reputation.collections, when Group-IB rates the IP bad. |
| IPv6.Address | String | IPv6 address. |
| IPv6.ASN | String | ASN that announces the address range (WHOIS). |
| IPv6.ASOwner | String | Owner of the autonomous system, when the registry names it (WHOIS). |
| IPv6.Organization.Name | String | Organization that holds the address range (WHOIS). |
| IPv6.Registrar.Abuse.Phone | String | Phones of the abuse contact of the address range, comma-separated (WHOIS). |
| IPv6.Registrar.Abuse.Email | String | Abuse e-mail addresses of the address range, comma-separated (WHOIS). |
| IPv6.Tags | String | The tags of the IPv6 address, as for IP.Tags. |
| IPv6.MalwareFamily | String | The malware families of the IPv6 address, as for IP.MalwareFamily. |
| IPv6.TrafficLightProtocol | String | The TLP of the IPv6 address, as for IP.TrafficLightProtocol. |
| IPv6.FirstSeenBySource | Date | The first sighting of the IPv6 address, as for IP.FirstSeenBySource. |
| IPv6.LastSeenBySource | Date | The last sighting of the IPv6 address, as for IP.LastSeenBySource. |
| IPv6.Publications.source | String | Always empty, since an IPv6 address has no Group-IB risk score and only a result the risk score makes Suspicious or Bad carries publications. |
| IPv6.Publications.title | String | Always empty, as for IPv6.Publications.source. |
| IPv6.Publications.link | String | Always empty, as for IPv6.Publications.source. |
| IPv6.Publications.timestamp | Date | Always empty, as for IPv6.Publications.source. |
| IPv6.Malicious.Vendor | String | Always empty, since an IPv6 address has no Group-IB risk score and the command never rates it bad. |
| IPv6.Malicious.Description | String | Always empty, since an IPv6 address has no Group-IB risk score and the command never rates it bad. |
| GIBTI.Reputation.indicator | String | The value looked up: refanged, a domain also in lower case without a final dot, a hash only trimmed. |
| GIBTI.Reputation.type | String | The reputation command that answered: ip, domain, file or url. |
| GIBTI.Reputation.score | Number | The verdict the command set (0 unknown, 1 good, 2 suspicious, 3 bad); empty when the lookup was incomplete and no verdict was set. |
| GIBTI.Reputation.riskScore | Number | The Group-IB risk score (0-100) of an IPv4 address or a domain, the highest risk score of the matching ioc/primary records of a file hash, or the highest risk score with which ioc/primary lists a URL; empty without one. |
| GIBTI.Reputation.collections | String | The Group-IB collections whose records list or mention the value, and with Use the Group-IB global search enabled the other collections the search reports. |
| GIBTI.Reputation.sources.collection | String | A Group-IB collection with records of the value. |
| GIBTI.Reputation.sources.count | Number | How many records of the collection list or mention the value, counted on the one page the lookup reads (up to 100 records, 10 on apt/threat). |
| GIBTI.Reputation.sources.firstSeen | Date | Earliest dateFirstSeen of those records; empty when they carry none. |
| GIBTI.Reputation.sources.lastSeen | Date | Latest dateLastSeen of those records; empty when they carry none. |
| GIBTI.Reputation.partial | Boolean | True when a request that decides the verdict failed or did not answer within Lookup timeout (seconds); HTTP 403 (the key has no access) and HTTP 404 (no record) do not make it true. A verdict is then set only if no missing answer could have raised it. |
| GIBTI.Reputation.failedSources | String | The requests that failed or did not answer in time, as the War Room note names them. |

#### Command Example

```!ip ip=198.51.100.27```

### domain

***
Returns the Group-IB reputation of one or more domains. The Group-IB risk score (scoring/domain) and ioc/primary decide the verdict. Bad for a risk score of 80-100. Suspicious for a risk score of 40-79, or when ioc/primary lists the domain, whatever its risk score there. Good for a risk score of 0-39 when ioc/primary does not list it. Unknown without a risk score or a listing. The setting Collections that keep an IP at least Suspicious does not apply to a domain. Records of apt/threat and hi/open_threats give tags, names, relationships and publications, and a defacement of the value in attacks/deface gives its collection tag and TLP; they never decide. When the risk score makes the verdict Suspicious or Bad, the collections of the matched records become tags, the threat and actor names of every matched record but the defacements become tags too, the malware names of those records become Malware Family, the most restrictive TLP of the matched records becomes the TLP, and the apt/threat and hi/open_threats records become publications; when ioc/primary makes it Suspicious, the tags, Malware Family and TLP come from the ioc/primary records only, and there are no publications. With Create relationships enabled, the malware families and actors also become relationships. The value is refanged, lowercased and stripped of a final dot first. A refused key (HTTP 401) fails the command; a value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry of its own, and the other values still return. When the risk score or ioc/primary fails or does not answer within Lookup timeout (seconds), GIBTI.Reputation.partial is true, and a verdict is set only if no missing answer could have raised it. A missing risk score could make it Bad, so only a Bad verdict is set; a missing ioc/primary could make it Suspicious, so a Suspicious or Bad verdict is set and a lower one is not. Without a verdict, the indicator keeps the one it has. A request answered with HTTP 403 (the key has no access) is named in the War Room note; HTTP 403 and HTTP 404 (no record) do not make the result partial, and the verdict comes from the others. With Add WHOIS to ip and domain enabled, the indicator also carries the registrar and its abuse contact, the registrant's organization and country, the registrant's name and e-mail address unless WHOIS personal data is Drop, and the dates, statuses and name servers from the WHOIS record.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Domain.Name | String | Domain name. |
| Domain.Organization | String | Organization of the registrant (WHOIS). |
| Domain.Registrar.Name | String | Registrar of the domain (WHOIS). |
| Domain.Registrar.AbuseEmail | String | Abuse e-mail address of the registrar (WHOIS). |
| Domain.Registrar.AbusePhone | String | Abuse phone of the registrar (WHOIS). |
| Domain.Registrant.Name | String | Name of the registrant, unless WHOIS personal data is Drop (WHOIS). |
| Domain.Registrant.Email | String | E-mail address of the registrant, unless WHOIS personal data is Drop (WHOIS). |
| Domain.Registrant.Country | String | Country of the registrant (WHOIS). |
| Domain.DomainStatus | String | Statuses of the domain (WHOIS). |
| Domain.CreationDate | Date | Creation date of the domain, written as 03 Feb 2001 04:05:06 UTC, the form the Domain indicator type reads into Creation Date (WHOIS). |
| Domain.UpdatedDate | Date | Date of the last update of the registration, in the same form as Domain.CreationDate (WHOIS). |
| Domain.ExpirationDate | Date | Expiration date of the registration (WHOIS). |
| Domain.NameServers | String | Name servers of the domain (WHOIS). |
| Domain.WHOIS.Registrar.Name | String | Registrar of the domain (WHOIS). |
| Domain.WHOIS.Registrar.AbuseEmail | String | Abuse e-mail address of the registrar (WHOIS). |
| Domain.WHOIS.Registrar.AbusePhone | String | Abuse phone of the registrar (WHOIS). |
| Domain.WHOIS.Registrant.Name | String | Name of the registrant, unless WHOIS personal data is Drop (WHOIS). |
| Domain.WHOIS.Registrant.Email | String | E-mail address of the registrant, unless WHOIS personal data is Drop (WHOIS). |
| Domain.WHOIS.Registrant.Country | String | Country of the registrant (WHOIS). |
| Domain.Whois.Registrar.Name | String | Registrar of the domain, where the Domain indicator type reads Registrar Name (WHOIS). |
| Domain.Whois.Registrar.AbuseEmail | String | Abuse e-mail address of the registrar, where the Domain indicator type reads Registrar Abuse Email (WHOIS). |
| Domain.Registrant.name | String | Name of the registrant, where the Domain indicator type reads Registrant Name, unless WHOIS personal data is Drop (WHOIS). |
| Domain.Registrant.email | String | E-mail address of the registrant, where the Domain indicator type reads Registrant Email, unless WHOIS personal data is Drop (WHOIS). |
| Domain.Registrant.country | String | Country of the registrant, where the Domain indicator type reads Registrant Country (WHOIS). |
| Domain.Admin.Organization | String | Organization of the registrant, where the Domain indicator type reads Organization (WHOIS). |
| Domain.WHOIS.DomainStatus | String | Statuses of the domain (WHOIS). |
| Domain.WHOIS.CreationDate | Date | Creation date of the domain (WHOIS). |
| Domain.WHOIS.UpdatedDate | Date | Date of the last update of the registration (WHOIS). |
| Domain.WHOIS.ExpirationDate | Date | Expiration date of the registration (WHOIS). |
| Domain.WHOIS.NameServers | String | Name servers of the domain (WHOIS). |
| Domain.Tags | String | Collections of the matched ioc/primary, apt/threat, hi/open_threats and attacks/deface records, with the threat names and actors of all but the defacements, when the risk score makes the domain Suspicious or Bad; when ioc/primary makes it Suspicious, those of the ioc/primary records only. Below Suspicious, with Collection tags at every verdict enabled, the collections in GIBTI.Reputation.collections, without names. |
| Domain.MalwareFamily | String | Malware families of the records the tags come from; empty below Suspicious. |
| Domain.TrafficLightProtocol | String | Most restrictive TLP of the records the tags come from; empty below Suspicious. |
| Domain.FirstSeenBySource | Date | Earliest first sighting (dateFirstSeen) of the Group-IB records that list or mention the domain. |
| Domain.LastSeenBySource | Date | Latest last sighting (dateLastSeen) of the Group-IB records that list or mention the domain. |
| Domain.Publications.source | String | Publisher of a Group-IB threat report (Group-IB Threat Intelligence) or a public post that names the domain, on a result the risk score makes Suspicious or Bad. |
| Domain.Publications.title | String | Title of the report or post. |
| Domain.Publications.link | String | Link to the public post; empty for a Group-IB threat report. |
| Domain.Publications.timestamp | Date | When the report or post was published. |
| Domain.Malicious.Vendor | String | The vendor that rated the domain bad. |
| Domain.Malicious.Description | String | The Group-IB risk score and the collections in GIBTI.Reputation.collections, when Group-IB rates the domain bad. |
| GIBTI.Reputation.indicator | String | The value looked up: refanged, a domain also in lower case without a final dot, a hash only trimmed. |
| GIBTI.Reputation.type | String | The reputation command that answered: ip, domain, file or url. |
| GIBTI.Reputation.score | Number | The verdict the command set (0 unknown, 1 good, 2 suspicious, 3 bad); empty when the lookup was incomplete and no verdict was set. |
| GIBTI.Reputation.riskScore | Number | The Group-IB risk score (0-100) of an IPv4 address or a domain, the highest risk score of the matching ioc/primary records of a file hash, or the highest risk score with which ioc/primary lists a URL; empty without one. |
| GIBTI.Reputation.collections | String | The Group-IB collections whose records list or mention the value, and with Use the Group-IB global search enabled the other collections the search reports. |
| GIBTI.Reputation.sources.collection | String | A Group-IB collection with records of the value. |
| GIBTI.Reputation.sources.count | Number | How many records of the collection list or mention the value, counted on the one page the lookup reads (up to 100 records, 10 on apt/threat). |
| GIBTI.Reputation.sources.firstSeen | Date | Earliest dateFirstSeen of those records; empty when they carry none. |
| GIBTI.Reputation.sources.lastSeen | Date | Latest dateLastSeen of those records; empty when they carry none. |
| GIBTI.Reputation.partial | Boolean | True when a request that decides the verdict failed or did not answer within Lookup timeout (seconds); HTTP 403 (the key has no access) and HTTP 404 (no record) do not make it true. A verdict is then set only if no missing answer could have raised it. |
| GIBTI.Reputation.failedSources | String | The requests that failed or did not answer in time, as the War Room note names them. |

#### Command Example

```!domain domain=evil.example.com```

### file

***
Returns the Group-IB reputation of one or more file hashes (MD5, SHA-1, SHA-256 or SHA-512). The verdict comes from ioc/common and ioc/primary, from a record of the hash itself. Bad when ioc/common lists the hash or ioc/primary lists it with a risk score of 80 or more; Suspicious when only ioc/primary lists it, with a lower risk score or none; otherwise Unknown. An ioc/common record carries no TLP of its own and counts as AMBER. The indicator carries the hash looked up and one hash of each other kind found in the records of both collections, each under its own kind. The collections and the threat and actor names of the matched records become tags and their malware names Malware Family; with Create relationships enabled, the malware families and actors also become relationships. A refused key (HTTP 401) fails the command; a value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry of its own, and the other values still return. When ioc/primary or ioc/common fails or does not answer within Lookup timeout (seconds), GIBTI.Reputation.partial is true, and a verdict is set only if no missing answer could have raised it. A missing ioc/common or ioc/primary could make it Bad, so only a Bad verdict is set. Without a verdict, the indicator keeps the one it has. A request answered with HTTP 403 (the key has no access) is named in the War Room note; HTTP 403 and HTTP 404 (no record) do not make the result partial, and the verdict comes from the others.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes (MD5, SHA-1, SHA-256 or SHA-512). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| File.MD5 | String | File MD5 hash. |
| File.SHA1 | String | File SHA-1 hash. |
| File.SHA256 | String | File SHA-256 hash. |
| File.SHA512 | String | File SHA-512 hash. |
| File.Hashes.type | String | The kind of each hash of the file: MD5, SHA1, SHA256 or SHA512. |
| File.Hashes.value | String | Each hash of the file. |
| File.Tags | String | Collections, threat names and actors of the matched ioc/primary and ioc/common records. Below Suspicious, with Collection tags at every verdict enabled, the collections in GIBTI.Reputation.collections, without names. |
| File.MalwareFamily | String | Malware families attributed to the file. |
| File.TrafficLightProtocol | String | Most restrictive TLP of the matched ioc/primary and ioc/common records; an ioc/common record counts as AMBER. |
| File.FirstSeenBySource | Date | Earliest first sighting (dateFirstSeen) of the Group-IB records that list the hash. |
| File.LastSeenBySource | Date | Latest last sighting (dateLastSeen) of the Group-IB records that list the hash. |
| File.Malicious.Vendor | String | The vendor that rated the file bad. |
| File.Malicious.Description | String | The Group-IB risk score and the collections in GIBTI.Reputation.collections, when Group-IB rates the file bad. |
| GIBTI.Reputation.indicator | String | The value looked up: refanged, a domain also in lower case without a final dot, a hash only trimmed. |
| GIBTI.Reputation.type | String | The reputation command that answered: ip, domain, file or url. |
| GIBTI.Reputation.score | Number | The verdict the command set (0 unknown, 1 good, 2 suspicious, 3 bad); empty when the lookup was incomplete and no verdict was set. |
| GIBTI.Reputation.riskScore | Number | The Group-IB risk score (0-100) of an IPv4 address or a domain, the highest risk score of the matching ioc/primary records of a file hash, or the highest risk score with which ioc/primary lists a URL; empty without one. |
| GIBTI.Reputation.collections | String | The Group-IB collections whose records list or mention the value, and with Use the Group-IB global search enabled the other collections the search reports. |
| GIBTI.Reputation.sources.collection | String | A Group-IB collection with records of the value. |
| GIBTI.Reputation.sources.count | Number | How many records of the collection list the hash, counted on the one page the lookup reads (up to 100 records). |
| GIBTI.Reputation.sources.firstSeen | Date | Earliest dateFirstSeen of those records; empty when they carry none. |
| GIBTI.Reputation.sources.lastSeen | Date | Latest dateLastSeen of those records; empty when they carry none. |
| GIBTI.Reputation.partial | Boolean | True when a request that decides the verdict failed or did not answer within Lookup timeout (seconds); HTTP 403 (the key has no access) and HTTP 404 (no record) do not make it true. A verdict is then set only if no missing answer could have raised it. |
| GIBTI.Reputation.failedSources | String | The requests that failed or did not answer in time, as the War Room note names them. |

#### Command Example

```!file file=0123456789abcdef0123456789abcdef```

### url

***
Returns the Group-IB reputation of one or more URLs. Group-IB scores IPv4 addresses and domains only, so the verdict comes from ioc/primary, read directly; only a record that lists the URL itself counts. Bad when ioc/primary lists the URL with a risk score of 80 or more; Suspicious when it lists the URL with a lower risk score or none; otherwise Unknown. The collection and the threat and actor names of its records become tags, and, with Create relationships enabled, the malware families and actors become relationships. The result carries the attributed malware families as Malware Family and the most restrictive TLP of the matched records. The value is refanged first, and the indicator carries the refanged URL. A refused key (HTTP 401) fails the command. When ioc/primary fails, HTTP 403 (the key has no access) and HTTP 404 (no record) included, or does not answer within Lookup timeout (seconds), the value gets an error entry of its own and no verdict, so the indicator keeps the verdict it has, and the other values still return.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs; defanged forms (hxxp://, [.]) are accepted, and a user name and password in a URL are not sent. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | The URL. |
| URL.Tags | String | The ioc/primary collection and the threat and actor names of its records that list the URL. |
| URL.MalwareFamily | String | Malware families attributed to the URL. |
| URL.TrafficLightProtocol | String | Most restrictive TLP of the ioc/primary records that list the URL. |
| URL.FirstSeenBySource | Date | Earliest first sighting (dateFirstSeen) of the Group-IB records that list the URL. |
| URL.LastSeenBySource | Date | Latest last sighting (dateLastSeen) of the Group-IB records that list the URL. |
| URL.Malicious.Vendor | String | The vendor that rated the URL bad. |
| URL.Malicious.Description | String | The Group-IB risk score and the collections whose records list the URL, when Group-IB rates it bad. |
| GIBTI.Reputation.indicator | String | The value looked up: refanged, a domain also in lower case without a final dot, a hash only trimmed. |
| GIBTI.Reputation.type | String | The reputation command that answered: ip, domain, file or url. |
| GIBTI.Reputation.score | Number | The verdict the command set (0 unknown, 1 good, 2 suspicious, 3 bad). |
| GIBTI.Reputation.riskScore | Number | The Group-IB risk score (0-100) of an IPv4 address or a domain, the highest risk score of the matching ioc/primary records of a file hash, or the highest risk score with which ioc/primary lists a URL; empty without one. |
| GIBTI.Reputation.collections | String | The Group-IB collections whose records list the URL. |
| GIBTI.Reputation.sources.collection | String | A Group-IB collection with records of the value. |
| GIBTI.Reputation.sources.count | Number | How many records of the collection list the URL, counted on the one page the lookup reads (up to 100 records). |
| GIBTI.Reputation.sources.firstSeen | Date | Earliest dateFirstSeen of those records; empty when they carry none. |
| GIBTI.Reputation.sources.lastSeen | Date | Latest dateLastSeen of those records; empty when they carry none. |
| GIBTI.Reputation.partial | Boolean | Always false for url: when ioc/primary fails, HTTP 403 and 404 included, or does not answer within Lookup timeout (seconds), the value gets an error entry instead. |
| GIBTI.Reputation.failedSources | String | Always empty for url, since a failed or late ioc/primary request gives the value an error entry instead. |

#### Command Example

```!url url=http://evil.example.com/login```

### gibti-ip-scoring

***
Returns the Group-IB risk score (0-100) of one or more IPv4 addresses from `scoring/ip`, with its verdict band in *GIBTI.Scoring.score*: 0-39 good, 40-79 suspicious, 80-100 bad, unknown when Group-IB has no score. The command sets no verdict on the indicator: the `ip` and `domain` reputation commands set it. A list is scored in requests of up to 100 values; when one of these requests fails, every value is asked alone. A refused key (HTTP 401 or 403) fails the command; any other failed request is the error entry of its value, and the other values still return. Group-IB scores IPv4 addresses only: a host name, a CIDR or an IPv6 address gets a War Room note and no request. Unless **Look up internal and reserved IP addresses** is enabled, a private, shared or reserved address gets a note and no request. Use `gibti-domain-scoring` for domains.

#### Base Command

`gibti-ip-scoring`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPv4 addresses to score (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.Scoring.indicator | String | The scored value. |
| GIBTI.Scoring.type | String | The kind of the scored value: ip. |
| GIBTI.Scoring.riskScore | Number | Group-IB risk score (0-100); 0 when Group-IB has no data on the value, empty when it returns no score. A value the command does not send to Group-IB gets a War Room note and no GIBTI.Scoring entry. |
| GIBTI.Scoring.score | Number | The verdict band of the risk score (0 unknown, 1 good, 2 suspicious, 3 bad). A risk score of 0-39 is good, 40-79 suspicious and 80-100 bad; without a score it is unknown. The command sets no verdict on the indicator. |

#### Command Example

```!gibti-ip-scoring ip=203.0.113.7,203.0.113.8```

### gibti-domain-scoring

***
Returns the Group-IB risk score (0-100) of one or more domains from `scoring/domain`, with its verdict band in *GIBTI.Scoring.score*: 0-39 good, 40-79 suspicious, 80-100 bad, unknown when Group-IB has no score. The command sets no verdict on the indicator: the `ip` and `domain` reputation commands set it. A list is scored in requests of up to 100 values; when one of these requests fails, every value is asked alone. A refused key (HTTP 401 or 403) fails the command; any other failed request is the error entry of its value, and the other values still return. An IP address gets a War Room note and no request; score an IPv4 address with `gibti-ip-scoring`.

#### Base Command

`gibti-domain-scoring`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains to score (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.Scoring.indicator | String | The scored value. |
| GIBTI.Scoring.type | String | The kind of the scored value: domain. |
| GIBTI.Scoring.riskScore | Number | Group-IB risk score (0-100); 0 when Group-IB has no data on the value, empty when it returns no score. A value the command does not send to Group-IB gets a War Room note and no GIBTI.Scoring entry. |
| GIBTI.Scoring.score | Number | The verdict band of the risk score (0 unknown, 1 good, 2 suspicious, 3 bad). A risk score of 0-39 is good, 40-79 suspicious and 80-100 bad; without a score it is unknown. The command sets no verdict on the indicator. |

#### Command Example

```!gibti-domain-scoring domain=evil.example.com```

### gibti-cve-scoring

***
Scores CVEs from the `osi/vulnerability` collection. The DBotScore combines exploit evidence, EPSS and CVSS with Group-IB's own severity. Bad for an exploit available (or a non-zero exploit count), seen in the wild, EPSS >= 0.5, EPSS percentile >= 0.95, CVSS >= 9.0 (Group-IB's merged cross-version CVSS, the legacy CVSS score only without it) or Group-IB severity red; Suspicious for every other CVE Group-IB has a record of, whatever its CVSS; Unknown when Group-IB has no record of the CVE. The CVE indicator is returned with its CVSS score and vector, publication and modification dates, description, TLP and the `osi/vulnerability` tag; the full scoring detail is written to `GIBTI.CVEScoring`.

#### Base Command

`gibti-cve-scoring`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVE identifiers to score (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CVEScoring.id | String | CVE identifier. |
| GIBTI.CVEScoring.found | Boolean | Whether Group-IB has a record for the CVE. |
| GIBTI.CVEScoring.title | String | Vulnerability title. |
| GIBTI.CVEScoring.cvssScore | Number | CVSS score, the merged cross-version CVSS when the record has one, else the legacy CVSS score. |
| GIBTI.CVEScoring.cvssVector | String | CVSS vector of that score. |
| GIBTI.CVEScoring.mergedCvss | Number | Merged CVSS score. |
| GIBTI.CVEScoring.epss | Number | EPSS exploitation probability (0-1). |
| GIBTI.CVEScoring.epssPercentile | Number | EPSS percentile (0-1). |
| GIBTI.CVEScoring.hasExploit | Boolean | Whether a public exploit is known. |
| GIBTI.CVEScoring.exploitCount | Number | Number of known exploits. |
| GIBTI.CVEScoring.seenInTheWild | Boolean | Whether exploitation in the wild was observed. |
| GIBTI.CVEScoring.severity | String | Group-IB severity (green/orange/red). |
| GIBTI.CVEScoring.tlp | String | TLP of the record. |
| GIBTI.CVEScoring.datePublished | Date | Date published. |
| GIBTI.CVEScoring.dateModified | Date | Date modified. |
| GIBTI.CVEScoring.score | Number | DBot score (0 unknown, 1 good, 2 suspicious, 3 bad). |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | DBot score (0 unknown, 1 good, 2 suspicious, 3 bad). |
| DBotScore.Reliability | String | Reliability of the source (always the instance Source Reliability). |
| CVE.ID | String | CVE identifier. |
| CVE.Published | Date | Date published. |
| CVE.Modified | Date | Date modified. |
| CVE.Description | String | Vulnerability description. |
| CVE.CVSS.Score | Number | CVSS score. |
| CVE.CVSS.Vector | String | CVSS vector. |
| CVE.Tags | String | The osi/vulnerability collection tag (only when Group-IB has a record of the CVE). |
| CVE.TrafficLightProtocol | String | TLP of the record. |

#### Command Example

```!gibti-cve-scoring cve=CVE-2021-44228```

### gibti-get-suspicious-ip-vpn-info

***
Returns the suspicious_ip/vpn record with the given ID.

#### Base Command

`gibti-get-suspicious-ip-vpn-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the IPv4 address of the gateway, for example 192.0.2.10. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.SuspiciousIPVPN.name | String | Record name. |
| GIBTI.SuspiciousIPVPN.id | String | Record id. |
| GIBTI.SuspiciousIPVPN.countryName | String | Country of the IP address, or its country code when the record has no country name. |
| GIBTI.SuspiciousIPVPN.countryCode | String | Country Code. |
| GIBTI.SuspiciousIPVPN.asn | String | ASN. |
| GIBTI.SuspiciousIPVPN.provider | String | Provider of the address; Group-IB's VPN listings carry none. |
| GIBTI.SuspiciousIPVPN.dateFirstSeen | Date | Date First Seen. |
| GIBTI.SuspiciousIPVPN.dateLastSeen | Date | Date Last Seen. |
| GIBTI.SuspiciousIPVPN.sources | String | VPN Sources. |
| GIBTI.SuspiciousIPVPN.names | String | VPN Names. |
| GIBTI.SuspiciousIPVPN.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.SuspiciousIPVPN.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.SuspiciousIPVPN.evaluation.credibility | Number | Credibility. |
| GIBTI.SuspiciousIPVPN.evaluation.reliability | Number | Reliability. |
| GIBTI.SuspiciousIPVPN.evaluation.severity | String | Severity. |
| GIBTI.SuspiciousIPVPN.evaluation.tlp | String | TLP. |
| GIBTI.SuspiciousIPVPN.types | String | Deployment types of the VPN gateway, such as commercial, self-hosted or public. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.ASN | String | ASN of the IP address. |
| IP.Geo.Country | String | Country of the IP address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Empty; Group-IB's VPN listings carry no region. |
| IP.Organization.Name | String | Empty; Group-IB's VPN listings carry no provider. |
| IP.Tags | String | The suspicious_ip/vpn collection. |
| IP.TrafficLightProtocol | String | TLP of the record. |

#### Command Example

```!gibti-get-suspicious-ip-vpn-info id=192.0.2.10```

### gibti-get-suspicious-ip-scanner-info

***
Returns the suspicious_ip/scanner record with the given ID.

#### Base Command

`gibti-get-suspicious-ip-scanner-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID: the IPv4 or IPv6 address of the scanner, for example 192.0.2.20. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.SuspiciousIPScanner.name | String | Record name. |
| GIBTI.SuspiciousIPScanner.id | String | Record id. |
| GIBTI.SuspiciousIPScanner.countryName | String | Country of the IP address, or its country code when the record has no country name. |
| GIBTI.SuspiciousIPScanner.countryCode | String | Country Code. |
| GIBTI.SuspiciousIPScanner.asn | String | ASN of the address; Group-IB's scanner listings carry none. |
| GIBTI.SuspiciousIPScanner.provider | String | Provider of the address; Group-IB's scanner listings carry none. |
| GIBTI.SuspiciousIPScanner.dateFirstSeen | Date | Date First Seen. |
| GIBTI.SuspiciousIPScanner.dateLastSeen | Date | Date Last Seen. |
| GIBTI.SuspiciousIPScanner.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.SuspiciousIPScanner.categories | String | Scanner Categories. |
| GIBTI.SuspiciousIPScanner.sources | String | Scanner Sources. |
| GIBTI.SuspiciousIPScanner.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.SuspiciousIPScanner.evaluation.credibility | Number | Credibility. |
| GIBTI.SuspiciousIPScanner.evaluation.reliability | Number | Reliability. |
| GIBTI.SuspiciousIPScanner.evaluation.severity | String | Severity. |
| GIBTI.SuspiciousIPScanner.evaluation.tlp | String | TLP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| IP.Address | String | IP address. |
| IP.ASN | String | Empty; Group-IB's scanner listings carry no ASN. |
| IP.Geo.Country | String | Country of the IP address, or its country code when the record has no country name. |
| IP.Geo.Description | String | Empty; Group-IB's scanner listings carry no region. |
| IP.Organization.Name | String | Empty; Group-IB's scanner listings carry no provider. |
| IP.Tags | String | The suspicious_ip/scanner collection. |
| IP.TrafficLightProtocol | String | TLP of the record. |
| IPv6.Address | String | IPv6 address. |
| IPv6.ASN | String | Empty; Group-IB's scanner listings carry no ASN. |
| IPv6.Geo.Country | String | Country of the IPv6 address, or its country code when the record has no country name. |
| IPv6.Geo.Description | String | Empty; Group-IB's scanner listings carry no region. |
| IPv6.Organization.Name | String | Empty; Group-IB's scanner listings carry no provider. |
| IPv6.Tags | String | The suspicious_ip/scanner collection. |
| IPv6.TrafficLightProtocol | String | TLP of the record. |

#### Command Example

```!gibti-get-suspicious-ip-scanner-info id=192.0.2.20```

### gibti-get-malware-malware-info

***
Returns the malware/malware record with the given ID. The descriptions are returned as text, as the incident shows them.

#### Base Command

`gibti-get-malware-malware-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.Malware.id | String | Record id. |
| GIBTI.Malware.name | String | Record name. |
| GIBTI.Malware.malware_name | String | Malware Name. |
| GIBTI.Malware.updatedAt | Date | Date Updated At. |
| GIBTI.Malware.aliases | String | Malware Aliases. |
| GIBTI.Malware.category | String | Malware Categories. |
| GIBTI.Malware.description | String | Malware Description. |
| GIBTI.Malware.shortDescription | String | Malware Short Description. |
| GIBTI.Malware.geoRegion | String | Malware Regions. |
| GIBTI.Malware.langs | String | Languages of the Group-IB malware report, such as en. |
| GIBTI.Malware.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.Malware.sourceCountry | String | Malware Source Countries. |
| GIBTI.Malware.platform | String | Malware Platforms. |
| GIBTI.Malware.threatLevel | String | Threat Level. |
| GIBTI.Malware.taList.id | String | Threat Actors Table: id. |
| GIBTI.Malware.taList.name | String | Threat Actors Table: name. |

#### Command Example

```!gibti-get-malware-malware-info id=0123456789abcdef0123456789abcdef01234567```

### gibti-get-compromised-card-group-info

***
Returns the compromised/bank_card_group record with the given ID. The `cnc` block of a card record is the shop the card was offered in, so the command returns no indicator.

#### Base Command

`gibti-get-compromised-card-group-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CompromisedCardGroup.name | String | Record name: the card number; Mask card data keeps its first six and last four digits. |
| GIBTI.CompromisedCardGroup.issuer | String | Card Issuer. |
| GIBTI.CompromisedCardGroup.issuer_country_code | String | Card Issuer Country Code. |
| GIBTI.CompromisedCardGroup.number | String | Card number; Mask card data keeps its first six and last four digits. |
| GIBTI.CompromisedCardGroup.type | String | Card Type. |
| GIBTI.CompromisedCardGroup.card_category | String | Card Category. |
| GIBTI.CompromisedCardGroup.payment_system | String | Payment System. |
| GIBTI.CompromisedCardGroup.id | String | Record id. |
| GIBTI.CompromisedCardGroup.sourceType | String | Types of the sources the card came from, such as Telegram or Card shop. |
| GIBTI.CompromisedCardGroup.cvv | String | CVV; empty with Mask card data. |
| GIBTI.CompromisedCardGroup.validThru | String | Card Valid Thru. |
| GIBTI.CompromisedCardGroup.compromised_events.cvv | String | Compromised Events Table: cvv; empty with Mask card data. |
| GIBTI.CompromisedCardGroup.compromised_events.valid_thru_date | Date | Compromised Events Table: valid thru date. |
| GIBTI.CompromisedCardGroup.compromised_events.valid_thru | String | Compromised Events Table: valid thru. |
| GIBTI.CompromisedCardGroup.compromised_events.client_ip | String | Compromised Events Table: client ip. |
| GIBTI.CompromisedCardGroup.compromised_events.cnc | String | Compromised Events Table: address of the shop the card was offered in. |
| GIBTI.CompromisedCardGroup.compromised_events.cnc_ip | String | Compromised Events Table: IP address of the shop the card was offered in. |
| GIBTI.CompromisedCardGroup.compromised_events.threat_actor_name | String | Compromised Events Table: threat actor name. |
| GIBTI.CompromisedCardGroup.compromised_events.source_type | String | Compromised Events Table: source type. |
| GIBTI.CompromisedCardGroup.compromised_events.source_link | String | Compromised Events Table: id of the event's source. |
| GIBTI.CompromisedCardGroup.compromised_events.date_detected | Date | Compromised Events Table: date detected. |
| GIBTI.CompromisedCardGroup.compromised_events.date_compromised | Date | Compromised Events Table: date compromised. |
| GIBTI.CompromisedCardGroup.compromised_events.victim_phone | String | Compromised Events Table: victim phone; [redacted] with Mask card data. |
| GIBTI.CompromisedCardGroup.compromised_events.victim_name | String | Compromised Events Table: victim name; [redacted] with Mask card data. |
| GIBTI.CompromisedCardGroup.compromised_events.malware | String | Compromised Events Table: malware. |
| GIBTI.CompromisedCardGroup.malware.id | String | Malware Table: id. |
| GIBTI.CompromisedCardGroup.malware.name | String | Malware Table: name. |
| GIBTI.CompromisedCardGroup.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.CompromisedCardGroup.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.CompromisedCardGroup.evaluation.credibility | Number | Credibility. |
| GIBTI.CompromisedCardGroup.evaluation.reliability | Number | Reliability. |
| GIBTI.CompromisedCardGroup.evaluation.severity | String | Severity. |
| GIBTI.CompromisedCardGroup.evaluation.tlp | String | TLP. |
| GIBTI.CompromisedCardGroup.dateFirstSeen | Date | Date First Seen. |
| GIBTI.CompromisedCardGroup.dateLastSeen | Date | Date Last Seen. |
| GIBTI.CompromisedCardGroup.dateFirstCompromised | Date | Date First Compromised. |
| GIBTI.CompromisedCardGroup.dateLastCompromised | Date | Date Last Compromised. |
| GIBTI.CompromisedCardGroup.threatActor.id | String | Threat Actors Table: id. |
| GIBTI.CompromisedCardGroup.threatActor.name | String | Threat Actors Table: name. |

#### Command Example

```!gibti-get-compromised-card-group-info id=0123456789abcdef0123456789abcdef01234567```

### gibti-get-compromised-masked-card-info

***
Returns the compromised/masked_card record with the given ID. The `cnc` block of a card record is the shop the card was offered in, so the command returns no indicator.

#### Base Command

`gibti-get-compromised-masked-card-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef01234567. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.CompromisedMaskedCard.name | String | Record name. |
| GIBTI.CompromisedMaskedCard.id | String | Record id. |
| GIBTI.CompromisedMaskedCard.baseName | String | Base Name: the name of the dump batch the card came from. |
| GIBTI.CompromisedMaskedCard.card_bin | String | Card BIN. |
| GIBTI.CompromisedMaskedCard.cvv | String | CVV. |
| GIBTI.CompromisedMaskedCard.card_dump | String | Card Dump. |
| GIBTI.CompromisedMaskedCard.issuer_country_code | String | Card Issuer Country Code. |
| GIBTI.CompromisedMaskedCard.issuer_country_name | String | Card Issuer Country Name. |
| GIBTI.CompromisedMaskedCard.issuer | String | Card Issuer. |
| GIBTI.CompromisedMaskedCard.number | String | Card Number. |
| GIBTI.CompromisedMaskedCard.card_pin | String | Card PIN. |
| GIBTI.CompromisedMaskedCard.payment_system | String | Payment System. |
| GIBTI.CompromisedMaskedCard.card_category | String | Card Category. |
| GIBTI.CompromisedMaskedCard.type | String | Card Type. |
| GIBTI.CompromisedMaskedCard.validThru | String | Card Valid Thru. |
| GIBTI.CompromisedMaskedCard.validThruDate | Date | Card Valid Thru Date. |
| GIBTI.CompromisedMaskedCard.client_asn | String | Client ASN. |
| GIBTI.CompromisedMaskedCard.client_city | String | Client City. |
| GIBTI.CompromisedMaskedCard.client_region | String | Client Region. |
| GIBTI.CompromisedMaskedCard.client_provider | String | Client Provider. |
| GIBTI.CompromisedMaskedCard.client_country_code | String | Client Country Code. |
| GIBTI.CompromisedMaskedCard.client_country_name | String | Client Country Name. |
| GIBTI.CompromisedMaskedCard.client_ip | String | Client IP. |
| GIBTI.CompromisedMaskedCard.cnc | String | Address of the shop the card was offered in. |
| GIBTI.CompromisedMaskedCard.cnc_domain | String | Shop Domain. |
| GIBTI.CompromisedMaskedCard.cnc_ip | String | Shop IP. |
| GIBTI.CompromisedMaskedCard.cnc_asn | String | Shop ASN. |
| GIBTI.CompromisedMaskedCard.cnc_city | String | Shop City. |
| GIBTI.CompromisedMaskedCard.cnc_region | String | Shop Region. |
| GIBTI.CompromisedMaskedCard.cnc_provider | String | Shop Provider. |
| GIBTI.CompromisedMaskedCard.cnc_country_code | String | Shop Country Code. |
| GIBTI.CompromisedMaskedCard.cnc_country_name | String | Shop Country Name. |
| GIBTI.CompromisedMaskedCard.cnc_url | String | Shop URL. |
| GIBTI.CompromisedMaskedCard.dateDetected | Date | Date of Detection. |
| GIBTI.CompromisedMaskedCard.dateCompromised | Date | Date Compromised. |
| GIBTI.CompromisedMaskedCard.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.CompromisedMaskedCard.evaluation.credibility | Number | Credibility. |
| GIBTI.CompromisedMaskedCard.evaluation.reliability | Number | Reliability. |
| GIBTI.CompromisedMaskedCard.evaluation.severity | String | Severity. |
| GIBTI.CompromisedMaskedCard.evaluation.tlp | String | TLP. |
| GIBTI.CompromisedMaskedCard.evaluation.ttl | Number | TTL. |
| GIBTI.CompromisedMaskedCard.isDump | Boolean | Is Dump. |
| GIBTI.CompromisedMaskedCard.isExpired | Boolean | Is Expired. |
| GIBTI.CompromisedMaskedCard.isMasked | Boolean | Is Masked. |
| GIBTI.CompromisedMaskedCard.malware_name | String | Malware Name. |
| GIBTI.CompromisedMaskedCard.malware_id | String | Malware ID. |
| GIBTI.CompromisedMaskedCard.malware_stix_guid | String | Malware STIX GUID. |
| GIBTI.CompromisedMaskedCard.address | String | Owner Address; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_birthday | String | Owner Birthday; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_country_code | String | Owner Country Code. |
| GIBTI.CompromisedMaskedCard.email | String | Owner Email; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_name | String | Owner Name; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_passport | String | Owner Passport; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.phone | String | Owner Phone; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_state | String | Owner State. |
| GIBTI.CompromisedMaskedCard.owner_tax_number | String | Owner Tax Number; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_zip | String | Owner ZIP; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.owner_city | String | Owner City; [redacted] with Mask card data. |
| GIBTI.CompromisedMaskedCard.price_currency | String | Price Currency. |
| GIBTI.CompromisedMaskedCard.price_value | Number | Price Value. |
| GIBTI.CompromisedMaskedCard.sourceLink | String | Source Link. |
| GIBTI.CompromisedMaskedCard.sourceType | String | Source. |
| GIBTI.CompromisedMaskedCard.threat_actor_name | String | Threat Actor Name. |
| GIBTI.CompromisedMaskedCard.threat_actor_id | String | Threat Actor ID. |
| GIBTI.CompromisedMaskedCard.threat_actor_stix_guid | String | Threat Actor STIX GUID. |
| GIBTI.CompromisedMaskedCard.threat_actor_is_apt | Boolean | Whether Group-IB marks the threat actor as APT. |
| GIBTI.CompromisedMaskedCard.threat_actor_country | String | Threat Actor Country. |
| GIBTI.CompromisedMaskedCard.track | String | Track: the magnetic stripe track data of the card. |
| GIBTI.CompromisedMaskedCard.portalLink | String | Link to the record in the Group-IB portal. |

#### Command Example

```!gibti-get-compromised-masked-card-info id=0123456789abcdef0123456789abcdef01234567```

### gibti-get-phishing-group-info

***
Returns the attacks/phishing_group record with the given ID. The record name (`GIBTI.PhishingGroup.name`) is the phishing domain. A group that Group-IB flags as a false positive or as allow-listed returns no indicator, and the War Room entry says which flag withdrew it.

#### Base Command

`gibti-get-phishing-group-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Group-IB record ID, for example 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTI.PhishingGroup.name | String | Record name. |
| GIBTI.PhishingGroup.id | String | Record id. |
| GIBTI.PhishingGroup.brand | String | Phishing Brand. |
| GIBTI.PhishingGroup.phishing_urls | String | Phishing URLs. |
| GIBTI.PhishingGroup.objective | String | Phishing Objectives. |
| GIBTI.PhishingGroup.source | String | Phishing Sources. |
| GIBTI.PhishingGroup.portalLink | String | Link to the record in the Group-IB portal. |
| GIBTI.PhishingGroup.blocked | Date | Phishing Date Blocked. |
| GIBTI.PhishingGroup.added | Date | Phishing Date Added. |
| GIBTI.PhishingGroup.detected | Date | Phishing Date Detected. |
| GIBTI.PhishingGroup.updated | Date | Phishing Date Updated. |
| GIBTI.PhishingGroup.domainInfo.domain | String | Phishing Domain. |
| GIBTI.PhishingGroup.domainInfo.domainPuny | String | Punycode form of the phishing domain. |
| GIBTI.PhishingGroup.domainInfo.expirationDate | Date | Phishing Domain Expiration Date. |
| GIBTI.PhishingGroup.domainInfo.registrar | String | Phishing Registrar. |
| GIBTI.PhishingGroup.evaluation.admiraltyCode | String | Admiralty Code. |
| GIBTI.PhishingGroup.evaluation.credibility | Number | Credibility. |
| GIBTI.PhishingGroup.evaluation.reliability | Number | Reliability. |
| GIBTI.PhishingGroup.evaluation.severity | String | Severity. |
| GIBTI.PhishingGroup.evaluation.tlp | String | TLP. |
| GIBTI.PhishingGroup.phishing_ip.ip | String | Phishing IP Table: ip. |
| GIBTI.PhishingGroup.phishing_ip.countryCode | String | Phishing IP Table: country code. |
| GIBTI.PhishingGroup.phishing_ip.countryName | String | Phishing IP Table: country name. |
| GIBTI.PhishingGroup.phishing_ip.provider | String | Phishing IP Table: provider. |
| GIBTI.PhishingGroup.threatActor.id | String | Threat Actor ID. |
| GIBTI.PhishingGroup.threatActor.name | String | Threat Actor Name. |
| GIBTI.PhishingGroup.phishing_kit_table.name | String | Phishing Kit Table: name. |
| GIBTI.PhishingGroup.phishing_kit_table.email | String | Phishing Kit Table: email. |
| GIBTI.PhishingGroup.falsePositive | Boolean | Whether Group-IB marks the phishing group as a false positive. |
| GIBTI.PhishingGroup.whitelist | Boolean | Whether Group-IB has allow-listed the phishing group. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| URL.Data | String | URL. |
| URL.Tags | String | The attacks/phishing_group collection, the phishing brand and the threat actor names of the record. |
| URL.TrafficLightProtocol | String | TLP of the record. |

#### Command Example

```!gibti-get-phishing-group-info id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef```
