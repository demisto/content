# Group-IB Threat Intelligence Feed

How to configure a Group-IB Threat Intelligence Feed instance in Cortex XSOAR.

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
   - **Username**: Enter the e-mail address you use to log in to the Group-IB portal
   - **Password**: Enter your API token (Personal token) generated in step 2 of Prerequisites
   - **Trust any certificate (not secure)**: Whether to allow connections without verifying the SSL certificate's validity
   - **Use system proxy settings**: Whether to use Cortex XSOAR system proxy settings to connect to the API

2. **Configure Collection Parameters**

   - **Fetch indicators**: Enable to fetch indicators from the feed (default: enabled)
   - **Indicator collections**: The collections to fetch indicators from (see the [Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details)). `ioc/primary` and `ioc/common` are the same records under two names, `ioc/common` with fewer fields (no URL, evaluation, tags or source); select one of them
   - **Indicator first fetch**: Date to start fetching indicators from (default: "3 days"). Each collection starts at the Group-IB cursor for that date (attacks/ddos and attacks/phishing_kit start from the date itself when no cursor is available). When no cursor is available for that date, any other collection is not read yet and is named in the instance health, and the cursor is requested again on the next fetch. Changing the value restarts every selected collection from the new date; the stored cursors are dropped on the next fetch. The value is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a change only after that fetch. `gibti-get-indicators` without an id starts from the same date.
   - **Number of requests per collection**: Number of pages read per collection in each fetch iteration (default: 2). Each page asks for up to **Limit (items per request)** records, each with zero or more indicators. On `suspicious_ip/*`, `compromised/spd` and `malware/cnc`, a page that one cursor position fills is read again larger, up to 1,000 records; each larger read is one more request and does not count as a further page. Lower the value if a fetch does not finish within the interval.
   - **Limit (items per request)**: Number of records requested per API page (default: 100). Larger values reduce API round-trips but may increase response size
     - This limit applies to all collections configured in the integration instance
     - The [API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) lists the recommended limit per collection
     - Each collection is read in pages no larger than its own page size, whatever the limit is (apart from the larger re-read below), except `ioc/common`, which is read in pages of the limit. The `suspicious_ip/*` collections are read in pages of at most 1,000
     - On `suspicious_ip/*`, `compromised/spd` and `malware/cnc`, a page that one cursor position fills is read again larger, up to 1,000 records; each larger read is one more request and does not count as a further page against **Number of requests per collection**
   - **Example**: If "Number of requests per collection" is set to 2 and the limit is 100, the integration asks for up to 200 records per collection per fetch (2 pages x 100 records each; the collections in the item above can read a larger page)

   **Configure Feed Behavior Settings**:
   - **Indicator Reputation**: Indicators from this integration instance will be marked with this reputation (options: None, Good, Suspicious, Bad; default: empty). Leave it empty to give every indicator the verdict of its collection: Bad for threat reports, malware C&C, the IOC collections and vulnerabilities (osi/vulnerability CVEs are always Bad, whatever their CVSS), Suspicious for the others; an ioc/primary indicator is Bad when its own Group-IB risk score is above 0 and Suspicious when the score is 0 or missing; a compromised/spd payment detail is Bad from an illegal score of 80 and Suspicious below; the DDoS target IPs (GIB Victim IP) carry no verdict. A selected reputation is applied to every indicator of the instance instead. An instance created before 4.0.0 keeps `Suspicious`, the former default, which overrides these verdicts; clear the setting to use them
   - **Source Reliability**: Reliability of the source providing the intelligence data (required; default: A - Completely reliable). Options: A - Completely reliable, B - Usually reliable, C - Fairly reliable, D - Not usually reliable, E - Unreliable, F - Reliability cannot be judged
   - **Feed Fetch Interval**: Configure how often to fetch indicators (hours and minutes, default: 1 minute)
   - **Bypass exclusion list**: When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system.
   - **Tags**: Tags added to every indicator of the instance. Supports CSV values
   - **Use TLP from source (per indicator)**: When enabled, each indicator takes the TLP of its Group-IB record; a record without one takes AMBER on ioc/primary and ioc/common (an ioc/common record carries no evaluation block) and the **Traffic Light Protocol Color** elsewhere. A malware/cnc record carries no evaluation block either, so its indicators always take the **Traffic Light Protocol Color**. When disabled, every indicator takes the **Traffic Light Protocol Color**; with no color selected, each indicator keeps the TLP of its record whether the setting is on or off. TLP:CLEAR is stored as WHITE, TLP:AMBER+STRICT as AMBER, an unknown name as RED
   - **Hunting Rules**: Off by default. Fetch only the records that match your Group-IB hunting rules where the filter is optional and your API user has hunting rules enabled: hi/threat, apt/threat, hi/open_threats, osi/vulnerability, attacks/phishing_kit, attacks/phishing_group and the five suspicious_ip/* collections. A filtered collection with no matching rule returns nothing while this is on, and hi/open_threats without the setting is the whole public feed. compromised/account_group, compromised/spd, osi/git_repository and attacks/ddos are always filtered by the API; ioc/primary, ioc/common, malware/cnc and attacks/deface never are. Toggling the setting restarts every selected collection from **Indicator first fetch**. The setting is recorded from the first fetch on 4.0.0, so an instance upgraded from an older version detects a toggle only after that fetch. `gibti-get-indicators` reads with the setting too, except for a record named by id
   - **Minimum severity**: The lowest Group-IB severity a record needs for its observables to become indicators, for every collection whose records carry a severity. Low (default) reads every record, and a record without a rating counts as Low. A record below the minimum is skipped when it arrives and is not read later. Group-IB rates every record of some collections the same, so Medium or High keeps all or none of them: suspicious_ip/* listings are green, DDoS attacks and defacements orange. ioc/primary, ioc/common and malware/cnc records carry no rating and are not held to it
   - **Skip records older than (days)**: A record older than this many days at the read is skipped and not read later, by the date that matters for its collection: the last sighting of an IOC, a suspicious IP listing or a C&C, the publication date of a vulnerability, the date a phishing group was detected (the README lists every collection's date). Group-IB re-sends old records when it updates them, so a read can bring records years old. Empty or 0 (default) keeps every record
   - **Vulnerability types to read** / **Vulnerability types to skip** / **Vulnerabilities with an exploit only**: The `osi/vulnerability` record types (cve, mscve, nessus, ...) and exploit flag; the types to read, a single type to skip when no types to read are set, and the exploit flag are sent to the API, and every record is checked when it arrives. Only a record whose id is a CVE id becomes an indicator
   - **Payment detail types to read**: Works only for `compromised/spd`. The payment detail types to read; empty (default) reads every type. A single selected type is also sent to the API; every record is checked when it arrives
   - **IOC minimum risk score**: Works only for `ioc/primary`. The lowest Group-IB risk score (0-100) an IP, domain or URL needs to become an indicator; a file takes its record's score. An observable without a score passes; the `skip_unscored` filter in **Collection filters** drops those. Empty (default) reads every observable
   - **Open threat source types**: The kinds of `hi/open_threats` posts to read indicators from, Blog, Social Network or both (default)
   - **Collection filters**: Every other filter of every collection, one per line as `collection: filter = value` (`ioc/primary: kinds = IP, Domain`, `suspicious_ip/*: max_age_days = 5`, `attacks/ddos: kinds = URL, Domain, IP, GIB Victim IP`); the README lists the filters of each collection. A line the integration cannot apply fails the instance test and every command, naming the line
   - **Create relationships**: Every malware family and threat actor a record names becomes a *Malware* / *Threat Actor* indicator related to the observable (indicator-of / related-to), apart from a defacer's handle; a GIB Victim IP gets no relationship. The feed creates those objects together with the observables. Disable it to keep the feed to plain observables (enabled by default)
   - **Delay between API requests (seconds)**: Minimum number of seconds between consecutive requests to the same collection while a fetch or `gibti-get-indicators` pages through it (default 1.2; the first request is never delayed; 0 disables the delay). Raise it if the API answers HTTP 429
   - **Traffic Light Protocol Color**: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Options: RED, AMBER, GREEN, WHITE. When **Use TLP from source** is disabled, this value is applied to all indicators. When **Use TLP from source** is enabled, this value is used only as a fallback when neither the record nor its collection's default (AMBER on ioc/primary and ioc/common) gives one. Leave it empty (the default) to give each indicator the TLP of its Group-IB record
   - **Indicator Expiration Method**: Configure how indicators expire. Options: Never Expire, Time Interval, Indicator Type (the expiration policy of each indicator type). Suspicious IP hosts rotate, so a stale listing can flag an address that is no longer a proxy, Tor node, VPN exit or scanner: with Time Interval, fetch the suspicious_ip/* collections in an instance whose interval suits them. By default, the incidents integration's `ip` command counts a listing at any age (its *Suspicious IP listing recency (days)* setting can set a window)

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).