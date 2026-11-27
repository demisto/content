# Group-IB Threat Intelligence

How to configure a Group-IB Threat Intelligence instance in Cortex XSOAR.

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

## Configuration Steps

1. **Configure Connection Settings**
   - **GIB TI URL**: The Group-IB TI API URL (default: `https://tap.group-ib.com/api/v2/`)
   - **Username**: Enter the e-mail address you use to log in to the Group-IB portal.
   - **Password**: Enter your API token (Personal token) generated in step 2 of Prerequisites.
   - **Trust any certificate (not secure)**: Whether to allow connections without verifying the SSL certificate's validity.
   - **Use system proxy settings**: Whether to use Cortex XSOAR system proxy settings to connect to the API.
2. **Configure Collection Parameters**
   - **Collections to fetch**: Select the collections you want to fetch incidents from. See the [Collections Overview documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Overview%2FCollections%20Overview).
   - **Fetch incidents**: Enable to fetch incidents from the selected collections.
   - **Incident type**: Default incident type for incidents the classifier does not map (leave empty to use the pack classifier).
   - **Incidents first fetch**: Date to start fetching incidents from (default 3 days). Each collection starts at the Group-IB cursor for that date (`attacks/ddos` and `attacks/phishing_kit` start from the date itself when no cursor is available). Any other collection without a cursor for that date is not read yet; the instance health names it, the cursor is requested again on the next fetch, and the other collections are fetched. If a collection keeps waiting, set a later date. Changing this value after the first run restarts every selected collection from the new date (the stored cursors are dropped). The value is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch.
   - **Number of requests per collection**: Number of pages read per collection in each fetch iteration (default: 3).
   - **Skip updated incidents (prevent duplicates)**: Disabled by default. Enable it on Cortex XSIAM and the Cortex platform, where the pack does not install the pre-processing rule **GIB Rule All Types**: without that rule, every update Group-IB makes to a record arrives as a new alert. Where **GIB Rule All Types** runs, leave it disabled so that the rule updates the existing incidents, and enable it if you do not use that rule. Enabled, the integration skips Group-IB records it already fetched when they are sent again after an update, so the update does not arrive. It remembers a record by its collection and ID, an open proxy by its address and port, and a breached record by its ID, leak name and upload time.
   - **Deduplication lookback (days)**: How many days a fetched record stays in the duplicate cache while **Skip updated incidents (prevent duplicates)** is enabled. Group-IB can re-send a record long after it was fetched; a shorter window lets it open a new incident. 0 turns the cache off. Default and recommended value: `365` days.
   - **Pass flagged phishing groups to the pre-processing rule**: Disabled by default: a phishing group that Group-IB flags as a false positive or allow-listed is dropped at fetch and never opens an incident, and an incident opened before Group-IB set the flag never shows it. Enabled, flagged groups go to the pre-processing rule **GIB Rule All Types**, which sets *GIB False Positive* or *GIB Allow Listed* on the open incident of the group and drops the record; a flagged group without an open incident is dropped there too. While **Skip updated incidents (prevent duplicates)** is enabled and **Deduplication lookback (days)** is above 0, only a group the integration already made an incident of is handed on. Enable it only while **GIB Rule All Types** runs; the pack does not install that rule on Cortex XSIAM and the Cortex platform. Without that rule, every flagged group handed on opens an incident of its own, a second one when the group already has an incident.
   - **Limit (items per request)**: Number of records the fetch asks for per API page (default: 100).
     - This limit applies to all collections configured in the integration instance
     - The [API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) lists the recommended limit per collection
     - Each collection is read in pages no larger than its own page size, whatever the limit is, apart from the larger re-read below
     - On `suspicious_ip/*`, `compromised/spd`, `malware/cnc`, `osi/public_leak` and `darkweb/forums`, a page that one cursor position fills is read again larger, up to 1,000 records (100 on `osi/public_leak`); each larger read is one more request and does not count as a further page against **Number of requests per collection**
   - **Example**: If "Number of requests per collection" is set to 2 and the limit is 500, the integration asks for up to 1,000 records per collection per fetch (2 pages x 500 records each; `darkweb/forums` reads one page per fetch, and the collections in the item above can read a larger page).
   - **Delay between API requests (seconds)**: Minimum number of seconds between consecutive requests to the same collection while a fetch or `gibti-local-search` pages through it (default 1.2; the first request is never delayed; 0 disables the delay). Raise it if the API answers HTTP 429.
   - **Hunting Rules**: Fetch only the records matching your Group-IB hunting rules, for the collections whose API supports the filter and for which your API user has hunting rules enabled (hi/*, apt/*, osi/vulnerability, attacks/phishing_kit, attacks/phishing_group, suspicious_ip/*). The API serves the compromised/* collections, darkweb/forums, osi/git_repository, osi/public_leak and attacks/ddos filtered by your hunting rules whatever the setting says; the other collections are fetched unfiltered. A filtered collection with no matching hunting rule returns nothing while the setting is on. Only fetch-incidents applies the setting; the lookup, search and reputation commands never send the hunting-rules filter. Turning it on or off restarts the selected collections from **Incidents first fetch**. The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch.
   - **Source Reliability**: Reliability of the source providing the intelligence data. Every DBotScore the integration writes carries it, except the reputation results that **Ignore Source Reliability override** gives a computed reliability. Default C - Fairly reliable.
   - **Ignore Source Reliability override**: When enabled, the `ip`, `domain`, `file` and `url` results carry the reliability computed from the matched collections (A for `ioc/primary`, `ioc/common` and `apt/threat`; B for `hi/open_threats` and `attacks/deface`); a result that none of these collections matched, the CVE indicators of `gibti-cve-scoring` and the indicators of the lookup commands keep **Source Reliability**.
   - **Create relationships**: Relate the indicators of the lookup commands, and the Suspicious or Bad results of the reputation commands, to the *Malware* and *Threat Actor* objects their records name (enabled by default). A result made Suspicious only by **Collections that keep an IP at least Suspicious** gets none, and the defacer of an `attacks/deface` record is never related.
   - **Incidents Fetch Interval**: Minutes between two fetch runs (advanced, default 1).
   - **Enable reputation commands**: Optional multi-select list of reputation commands to enable for this integration instance (supported: ip, domain, file, url). Default: none enabled. Only selected commands perform enrichment and return DBotScore.
   - **Mask passwords and leaked secrets**: Off (default) keeps passwords and secrets as Group-IB delivers them; Partial keeps the first half of each followed by `****`; Full drops the passwords and credential columns, puts `[withheld]` in place of other secrets and withholds the raw text of a public leak. It covers the passwords of `compromised/account_group` and `compromised/breacheddb` records, the credential columns of a breached record's leak at any depth, and the extracted values and raw text of an `osi/public_leak` record. In these records and in dark web posts, it also masks secrets written after a credential name (`password: ...`, `accessToken=...`), the passwords of e-mail:password pairs, url:login:password lines and URLs, Authorization headers, Bearer and Basic credentials, crypt hashes, the LM and NT hashes of NTLM dump lines, private keys and GitHub, GitLab, Slack and Stripe tokens. It also masks every other copy of a password or secret the record names or a text quotes, where the copy stands apart from other letters and digits (from six characters, or from four in a sentence for a value the record names). A login:password line without an e-mail address or URL is not recognized, and the C&C address of a compromised account keeps its credentials, which are the attacker's. It applies to incidents, the lookup commands and `gibti-local-search`. A change applies to what is fetched or looked up afterward; a password or column that Full drops can stay on an incident that already holds it; clear it yourself. A login, a parsed login domain, a service domain or a breached record's e-mail address or e-mail domain stays as it is when the password is part of its name (`sample@example.com`, the user of `CORP\sample`) or the whole of it, so the incident keeps naming its account: a password equal to the login stays readable there under Partial and Full. In those fields, a `login:password`, a URL, a password in the domain of a `DOMAIN\user` login or a password written beside a login is masked. Columns named like a password, a secret, a salt, a token, a session ID, a password hash or a secret key (`user_pass`, `userPw`, `accessToken`, `sessionId`, `apiKey`, `sshKey`, `passwordHash`, `md5`, `senha`) count; a hash of anything else (`emailHash`), a passport number and a column that dates, types or describes a credential (`passwordChangedAt`, `hashType`, `passwordLength`) do not. A breached record with a credential makes the incident High under every setting; a credential column holding only a flag (true/false, 0/1), a placeholder (null, -) or nothing does not count.
   - **Mask card data**: Off by default. On, a `compromised/bank_card_group` record keeps the first six and last four digits of its card number (in the incident name too), loses its CVV and shows `[redacted]` for the cardholder's name and phone, in incidents, `gibti-get-compromised-card-group-info` and `gibti-local-search`. A `compromised/masked_card` record, whose card number arrives masked, shows `[redacted]` for its owner's name, address, birthday, e-mail, phone, city, ZIP code, passport and tax number in incidents, `gibti-get-compromised-masked-card-info` and `gibti-local-search`; the owner's state and country stay. A change applies to what is fetched or looked up afterward; a CVV an incident already holds stays.
   - **Mask dark web post text**: Off (default) keeps the text of `compromised/messenger`, `compromised/discord` and `darkweb/forums` posts as Group-IB delivers it; Partial keeps the last four digits of each card number (13 to 19 digits as one run, or written on one line in groups of three or more digits and passing the card check digit, outside IPv4 addresses) and clears each CVV code labeled CVV, CVC, CV2 or CID or written on the card's line beside its expiry, and the magnetic stripe data after a card number. Partial covers the text and a forum post's topic and URL (in a URL, a number counts as a card only by the check digit and only apart from other digits, and `cid=` stays as an id). Full withholds the text and a forum post's topic, names the incident after the forum, masks its URL as Partial does and keeps the post's metadata (channel, author, dates, attachment, hash); passwords and other secrets follow **Mask passwords and leaked secrets**. Applies to incidents, the lookup commands and `gibti-local-search`.
   - **Collections that keep an IP at least Suspicious**: The `ip` reputation command returns at least Suspicious for an IP that one of the selected `suspicious_ip/*` collections lists, whatever its risk score, tagged with the collection (default: every `suspicious_ip/*` collection). It applies to `ip` only. Each selected collection is one more request per IP. A collection counts only when one of its records is the IP itself, at any age unless **Suspicious IP listing recency (days)** sets a window. Clear a collection to leave the verdict to the risk score and `ioc/primary`; select only `none` so that no listing keeps an IP at least Suspicious, since an empty selection uses the default.
   - **Suspicious IP listing recency (days)**: How many days after Group-IB last saw it a `suspicious_ip/*` listing still keeps an IP at least Suspicious in `ip` and passes its TLP to the result (advanced). Empty (default) or 0 counts a listing of any age; a number applies to every `suspicious_ip/*` collection.
   - **Lookup timeout (seconds)**: Longest wait for the Group-IB requests of one value of `ip`, `domain`, `file` and `url` (advanced, default 20; 0 waits without a limit); a request that has not answered by then is left out, and a verdict is set only if no missing answer could have raised it. `url` sends one request, so a `url` value without an answer gets an error entry. A list of IPs or domains first waits up to the same time for its risk scores.
   - **Parallel requests per lookup**: How many Group-IB requests one value of `ip`, `domain`, `file` or `url` sends at once (advanced, default 4, at least 1).
   - **Use the Group-IB global search**: Advanced, disabled by default; enabled, `ip`, `domain` and `file` also list the other collections that mention the value in GIBTI.Reputation.collections; those collections do not decide the verdict. A result below Suspicious also lists them in its War Room note and, with **Collection tags at every verdict** enabled, in its tags; a Bad result lists them in Malicious.Description.
   - **Collection tags at every verdict**: Advanced, enabled by default; a reputation result below Suspicious carries as tags the collections that list or mention the value, without their malware or actor names, and, for an `ip` result, never a collection selected in **Collections that keep an IP at least Suspicious**. Disable it when tags on Good and Unknown indicators would start tag-based playbooks or searches.
   - **Add WHOIS to ip and domain**: Advanced, enabled by default; `ip` and `domain` also write the WHOIS data of the value to the indicator, one more request per value, two for a subdomain.
   - **WHOIS personal data**: Advanced; `Show` (default) keeps a registrant's name and e-mail address; `Drop` leaves them out.
   - **Look up internal and reserved IP addresses**: Advanced, disabled by default. Disabled, `ip`, `gibti-ip-whois` and `gibti-ip-scoring` answer a private, loopback, link-local, shared or reserved address, the documentation ranges included, with a note and ask Group-IB nothing; enabled, they look such addresses up.
   - **Minimum severity**: The lowest Group-IB severity a record needs to become an incident, for every collection with an evaluation, and the lowest threat level for malware/malware; Low (default) fetches every record. Group-IB rates every record of some collections the same (suspicious_ip/* listings and breached records green, DDoS attacks and defacements orange, masked cards red), so Medium or High keeps all or none of them.
   - **Skip records older than (days)**: A record older than the window at the fetch is skipped and not fetched later, by the date that matters for its collection (the post date of a dark web post, the publication date of a vulnerability, the last sighting of a suspicious IP listing or C&C, the compromise date of an account, card or access listing); empty or 0 (default) keeps every record. `malware/malware` has no such date and is not filtered by it.
   - **Vulnerability types to fetch** / **Vulnerability types to skip** / **Vulnerabilities with an exploit only**: The `osi/vulnerability` record types (cve, mscve, nessus, ...) and exploit flag; the types to fetch, a single type to skip when no types to fetch are set, and the exploit flag are sent to the API, and every record is checked when it arrives.
   - **Breached records to fetch**: All (default), With a password (asked of the API) or With a password or a credential column.
   - **Payment detail types to fetch**: The `compromised/spd` types; a single selected type is also sent to the API.
   - **Dark web forum categories to fetch** / **Dark web forum categories to skip**: The Group-IB categories of `darkweb/forums` posts. When categories to fetch are set, only a post with one of them is fetched and a post without categories is skipped; a post with a category to skip is skipped, whatever the categories to fetch say.
   - **Open threat source types**: Blog, Social Network or both (default) for `hi/open_threats`.
   - **Collection filters**: Every other filter of every collection, one per line as `collection: filter = value` (`osi/vulnerability: min_cvss = 7`, `suspicious_ip/*: excluded_countries = US`, `suspicious_ip/tor_node: exit_only = true`); the README lists the filters of each collection. A line the integration cannot apply fails the instance test and every command.

   **Filters of `compromised/account_group`** (no effect on other collections):
   - **Include unique type in data**: Enabled alone, only unique records are fetched; with **Include combolist type in data** also enabled, or with both disabled, records of both types are fetched.
   - **Include combolist type in data**: Enabled alone, only combolist records are fetched; with **Include unique type in data** also enabled, or with both disabled, records of both types are fetched.
   - **Enable filter "Probable Corporate Access"**: Disabled by default: every account is fetched. When enabled, the API returns only the accounts it marks as probable corporate access. It combines with the unique and combolist filters.
   - Run separate instances for the account types: one with **Include unique type in data**, one with **Include combolist type in data**, and, for the accounts Group-IB marks as probable corporate access, one with **Enable filter "Probable Corporate Access"**.

3. **Configure Classifier and Mapper**
   - A new instance preselects the *Group-IB Threat Intelligence* classifier and mapper; replace them with your own if you map the incidents differently

4. **Built-In Deduplication and Pre-Processing Rules**
   - If you use a pre-processing rule to update existing incidents, enable it and check that it shows its script
<~XSOAR>

   - Pre-processing rule workflow (Cortex XSOAR):
     - Keep **Skip updated incidents (prevent duplicates)** disabled so that updated Group-IB records are fetched again
     - Open **Pre-Process Rules** (Cortex XSOAR 8: **Settings & Info** > **Settings** > **Object Setup** > **Incidents** > **Pre-Process Rules**; Cortex XSOAR 6: **Settings** > **Integrations** > **Pre-Process Rules**)
     - Enable or create a rule with the following configuration:
       - **Conditions**:
         - `gibid Is not empty (General)`
       - **Action**: Run a script
       - **Script**: Select `GIBTIIncidentUpdateAllTypes`

</~XSOAR>

   - The integration keeps the duplicate cache in its fetch state. The cache survives a change of **Incidents first fetch**: records re-read after the restart that were already fetched within the lookback are still skipped
   - While **Skip updated incidents (prevent duplicates)** is disabled, **Deduplication lookback (days)** is not used, but a negative value still fails the fetch
<~XSOAR>

   - What a rule that runs `GIBTIIncidentUpdateAllTypes` does with a re-sent record:
     - finds the open incidents of the same incident type with the same *GIB ID*, for an open proxy also with the same *GIB Proxy Port* and for a data breach with the same *GIB Leak Name* and *GIB Upload Time* (closed ones are left alone, so a re-sent record whose incident is closed creates a new incident; an incident whose type an analyst changed by hand no longer matches) and copies the incoming custom fields plus the name, occurred time and details onto each of them; severity, owner, status, type and the playbook of the existing incident are never touched
     - drops the incoming incident once at least one existing incident was updated, or when there was nothing to copy; if every update fails, the incoming incident is kept so nothing is lost
     - never keeps a phishing group that Group-IB flags as a false positive or allow-listed: it writes *GIB False Positive* or *GIB Allow Listed* on the open incident of the group and drops the record
     - two records with the same GIB ID arriving in one fetch batch can both become incidents
   - After installing the pack, check that **GIB Rule All Types** shows the script **GIBTIIncidentUpdateAllTypes**; testing an instance (**Test**) fills it in when it is missing. If it still shows none, select it in the rule

</~XSOAR>


## Postprocessing playbook

Every Group-IB incident type names **Incident Postprocessing - Group-IB Threat Intelligence & Attribution** as its default playbook, and none of them runs it automatically: a fetched incident is created without it. Run the playbook from the incident when you investigate it. To enrich every new incident of a collection, turn on **Run playbook automatically** in the settings of its incident type. Each run costs a few Group-IB API requests: it reads the incident's record again, then the profiles of the actors the record names and the first report each kind of profile lists. Leave the option off for high-volume collections such as `suspicious_ip/*`, and for the dark web collections, whose records carry no indicators to enrich.

## Recommended Instance Layout

Use separate integration instances for the following groups:

- Accounts unique (`compromised/account_group`)
- Accounts combolist (`compromised/account_group`)
- Cards (`compromised/bank_card_group`, `compromised/masked_card`)
- Public and git leaks (`osi/public_leak`, `osi/git_repository`)
- Breached records (`compromised/breacheddb`)
- Vulnerabilities (`osi/vulnerability`)
- Threat reports and actor profiles (`hi/threat`, `apt/threat`, `hi/threat_actor`, `apt/threat_actor`) and malware profiles (`malware/malware`)
- Suspicious payment details (`compromised/spd`)
- Suspicious IP (`suspicious_ip/*`)
- Malware C&C (`malware/cnc`)
- Attacks (`attacks/ddos`, `attacks/deface`, `attacks/phishing_group`, `attacks/phishing_kit`)
- Dark web (`compromised/access`, `compromised/messenger`, `compromised/discord`, `darkweb/forums`)
- Open threats (`hi/open_threats`)

## Deprecation notice: `gibtia-` command names

Every `gibtia-` command is available under the `gibti-` prefix. The old `gibtia-` names still work in 4.0.0 for playbooks written against them, but they are marked deprecated in the command list, and every call adds a warning entry to the War Room naming the `gibti-` replacement. `gibtia-get-compromised-mule-info` instead fails with an error naming `gibti-get-compromised-spd-info`, as the deprecated `gibti-get-compromised-mule-info` does. Rename the commands in your playbooks and scripts; the outputs are identical, and so are the arguments, except that `gibti-get-suspicious-ip-vpn-info`, `gibti-get-suspicious-ip-scanner-info` and `gibti-get-malware-malware-info` require *id*. Their `gibtia-` names mark it optional, but they fail without it too.

## Search commands

- `gibti-global-search` takes a bare value (an actor name, `203.0.113.7`) and lists the collections that contain matches; records themselves come from `gibti-local-search` or the `gibti-get-*-info` commands.
- `gibti-local-search` searches one collection filtered by a bare value (every collection; an actor name or alias on the actor collections) or `id:<id>` on the collections whose API takes it (threat reports and actor profiles among them), with an optional `date_from` / `date_to` window (`date_to` needs `date_from`) or a `seq_update` cursor, which takes the place of the window when both are set; without a cursor or a date window, the collection is walked from its oldest record. `darkweb/forums` is read one page per call, and `compromised/discord` without a cursor or a date window returns its newest records.

## Reputation Commands (ip / domain / file / url)

Every reputation command takes a comma-separated list and returns one result per value; `file` accepts MD5, SHA-1, SHA-256 and SHA-512 and stores the hash looked up and one hash of each other kind found in the matched `ioc/primary` and `ioc/common` records, each under its own kind. An `ip` or `domain` result that the risk score makes Suspicious or Bad carries as indicator tags the collections of the matched `ioc/primary`, `apt/threat`, `hi/open_threats` and `attacks/deface` records and the threat names and actors of all but the defacements; when `ioc/primary` makes the result Suspicious, the tags come from the `ioc/primary` records only. A `suspicious_ip/*` collection selected in **Collections that keep an IP at least Suspicious** that lists the IP within **Suspicious IP listing recency (days)** is a tag as well (the only tag when that listing raised the verdict). A `file` result carries those of its `ioc/primary` and `ioc/common` records, and a `url` result those of the `ioc/primary` records that list it. A Suspicious or Bad result also carries the attributed malware families as Malware Family and the most restrictive TLP of the records its tags come from. An `ip` or `domain` result that the risk score makes Suspicious or Bad lists the `apt/threat` reports and `hi/open_threats` posts among those records as Publications, newest first. A Good or Unknown result carries no malware family, TLP or relationship, and with **Collection tags at every verdict** enabled (default) the collections that list or mention the value as its only tags, never a collection selected in **Collections that keep an IP at least Suspicious**; the War Room note names the collections whose records mention the value. A refused key (HTTP 401) fails the command; a value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry of its own, and the other values still return; any other failed request, such as a collection the key cannot read, is named in the War Room note. `ip` writes an IPv6 value to IPv6 context.

### A dedicated instance for reputation

Run the reputation commands from a dedicated integration instance (for example one named *Group-IB TI reputation*), separate from the instances that fetch incidents. Reputation commands are disabled by default: select them (`ip`, `domain`, `file`, `url`) in **Enable reputation commands** on that instance only, and select **Do not use by default** on the other instances so they stay out of the generic `!ip`, `!domain`, `!file` and `!url` runs.

### Calling a specific instance (`using=`)

Every Group-IB instance answers the generic `!ip` / `!domain` / `!file` / `!url` commands and auto-enrichment. To keep an instance out of those generic commands (a lookup-only instance, an instance with a restricted license, a test instance) select **Do not use by default** on the instance and call it explicitly:

```
!gibti-cve-scoring cve=CVE-2021-44228 using="Group-IB TI lookups"
!gibti-get-malware-cnc-info id=0123456789abcdef0123456789abcdef01234567 using="Group-IB TI lookups"
```

`using=` works for every command of the integration, not only reputation ones. An instance where a reputation command is not selected in **Enable reputation commands** answers it with a single note, without an indicator or a DBotScore, so it never changes the merged reputation of the indicator.

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

Group-IB's own **risk score** (`scoring/ip` for an IPv4 address, `scoring/domain` for a domain, 0-100), `ioc/primary` (Group-IB's indicators of compromise) and, for an IP, the `suspicious_ip/*` collections selected in **Collections that keep an IP at least Suspicious** decide the verdict:

- **BAD**: a risk score of 80-100
- **SUSPICIOUS**: a risk score of 40-79; or `ioc/primary` lists the IP or domain, whatever the risk score of its element there; or a selected `suspicious_ip/*` collection lists the IP itself
- **GOOD**: a risk score of 0-39 without such a listing (public infrastructure such as a DNS resolver scores in this band)
- **UNKNOWN (NONE)**: no risk score and no such listing

Only an `ioc/primary` record of the observable itself counts, one whose IP or domain elements include it: the search for a value also returns records that merely mention it, such as a URL on the domain. An IPv6 address has no risk score, since Group-IB scores IPv4 addresses only, so `ioc/primary` and the `suspicious_ip/*` listings decide its verdict.

A `suspicious_ip/*` collection selected in **Collections that keep an IP at least Suspicious** (by default every one) keeps an IP it lists at least **SUSPICIOUS**, whatever its risk score, and adds the collection as a tag, without malware or actor names. A listed IP can still score below 40, for example a Tor exit without malicious history. A collection counts only when one of its records is the IP itself. A listing counts at any age unless **Suspicious IP listing recency (days)** sets a window after its `dateLastSeen`, and the result carries the most restrictive TLP of the listings that count. The setting does not apply to a domain. Clear a collection to leave the verdict to the risk score and `ioc/primary`.

`apt/threat` reports and `hi/open_threats` posts that the search for the value returns give tags, names, relationships and publications, and `attacks/deface` defacements only their tag and TLP; none decides the verdict. `hi/threat` reports are not read by the reputation commands. When the risk score makes the verdict Suspicious or Bad, the result takes the malware and actor names of every matched record but the defacements, the most restrictive TLP of the matched records and the publications of the `apt/threat` and `hi/open_threats` records; when `ioc/primary` makes it Suspicious, the names and TLP of the `ioc/primary` records only, and no publications; a `suspicious_ip/*` listing gives only its own tag and its TLP. Actor profiles are not read: the domains a profile lists are the actor's victims. A defacement counts only when it is the defacement of the IP or domain itself, and it never names the defacer.

The reputation commands read their collections directly, at most **Parallel requests per lookup** requests at a time (default 4): for an IP or domain, `ioc/primary`, `apt/threat`, `hi/open_threats` and `attacks/deface` by the value, the risk score and, with **Add WHOIS to ip and domain** enabled, the WHOIS record; for an IP, also the `suspicious_ip/*` collections selected in **Collections that keep an IP at least Suspicious**, by the address; for a file, `ioc/primary` and `ioc/common` by the hash; for a URL, `ioc/primary` by the quoted URL. **Lookup timeout (seconds)** (default 20) limits how long one value waits for them. The risk scores of a list of IPs or domains are asked in requests of up to 100 values; when one of them fails or they do not answer in time, each value asks for its own. When a request that decides the verdict (the risk score, `ioc/primary`, `ioc/common` for a file, a selected `suspicious_ip/*` collection for an IP) fails or does not answer in time, *GIBTI.Reputation.partial* is true, and a verdict is set only if no missing answer could have raised it. A missing risk score or `ioc/common`, or the `ioc/primary` of a file, could make it Bad, so only a Bad verdict is set; a missing `ioc/primary` of an IP or domain or a missing `suspicious_ip/*` collection could make it Suspicious, so a Suspicious or Bad verdict is set and a lower one is not. A result without a verdict carries no DBotScore, and the indicator keeps the one it has. A request refused with HTTP 403 (a collection the key cannot read) or answered with HTTP 404 (no record) does not make *GIBTI.Reputation.partial* true; the verdict is set as if the collection had no record. An `ip`, `domain` or `file` value whose requests all fail, HTTP 403 and 404 included, or do not answer in time gets an error entry and no verdict. A `url` value whose `ioc/primary` request fails, HTTP 403 and 404 included, or does not answer in time gets an error entry and no verdict. **Use the Group-IB global search** makes `ip`, `domain` and `file` add the other collections that mention the value to GIBTI.Reputation.collections; it decides nothing. A result below Suspicious also lists them in its note and, with **Collection tags at every verdict** enabled, in its tags; a Bad result lists them in Malicious.Description.

`gibti-ip-scoring` and `gibti-domain-scoring` return the risk score and its verdict band, without the collection lookups, and set no verdict on the indicator.

`gibti-ip-whois` and `gibti-domain-whois` return the registry record of an IP address or a domain from the Group-IB Graph WHOIS, and set no verdict. An IP record gives the address range, the registry, the network name, the holder organization and its country of registration, the ASN that announces the range, the owner of the AS when the registry names it, and the abuse contact, each field from the newest record that has it; a domain record gives the registrar and its abuse contact, the registrant, the statuses, the dates and the name servers, and a subdomain is answered with the record of its registered domain. Texts a registry puts in place of a value (a placeholder phone number, REDACTED FOR PRIVACY) are left out. With **Add WHOIS to ip and domain** enabled (default), `domain` writes the same data to the indicator, and `ip` writes the ASN, the holder organization, the owner of the AS and the abuse contact. The country of an IP record is the country of the organization that holds the range (else of the range), not where the address is, so it does not go to the indicator's geo fields.

`url` reads `ioc/primary` directly, with a quoted search, and counts only a record of the URL itself: Bad when `ioc/primary` lists the URL with a risk score of 80 or more, Suspicious when it lists it with a lower risk score or none, otherwise Unknown.

### Reliability calculation rules (only when Ignore Source Reliability override is enabled)

#### `file` reliability rules

- **A - Completely reliable**: at least one match in `ioc/primary` or `ioc/common`
- **Source Reliability** of the instance: no matches

#### `domain` and `ip` reliability rules

Reliability is derived from which collections returned matches:

- **A - Completely reliable**:
  - any match in `apt/threat`, or
  - any match in `ioc/primary`

- **B - Usually reliable**:
  - a defacement of the IP or domain itself in `attacks/deface`, or
  - any match in `hi/open_threats`

Final selection logic:

- At least one **A - Completely reliable** source: **A - Completely reliable**
- Otherwise, at least one **B - Usually reliable** source: **B - Usually reliable**
- Otherwise: the instance **Source Reliability**

#### `url` reliability rules

- **A - Completely reliable**: a match in `ioc/primary`
- **Source Reliability** of the instance: no matches

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [Collections Overview](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Overview%2FCollections%20Overview).