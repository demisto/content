The Silent Push Platform uses first-party data and a proprietary scanning engine to enrich global DNS data with risk and reputation scoring, giving security teams the ability to join the dots across the entire IPv4 and IPv6 range, and identify adversary infrastructure before an attack is launched. The content pack integrates with the Silent Push system to gain insights into domain/IP information, reputations, enrichment, and infratag-related details. It also provides functionality to live-scan URLs and take screenshots of them. Additionally, it allows fetching future attack feeds from the Silent Push system.
This integration was integrated and tested with version xx of SilentPush_v2.

## Configure SilentPush in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| API Key | False |
| Password | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### silentpush-add-feed

***
This command add the new feed

#### Base Command

`silentpush-add-feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the feed. | Required | 
| type | Feed Type. | Required | 
| category | Feed Category. | Optional | 
| vendor | Vendor. | Optional | 
| feed_description | Detailed info about the feed. | Optional | 
| tags | Tags that should be attached with the feed. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Feed.name | String | The name of the feed. | 
| SilentPush.Feed.type | String | The type of the feed. | 
| SilentPush.Feed.vendor | String | The vendor of the feed. | 
| SilentPush.Feed.feed_description | String | A description of the feed. | 
| SilentPush.Feed.category | String | The category of the feed. | 
| SilentPush.Feed.tags | Unknown | Tags associated with the feed. | 

#### Command example
```!silentpush-add-feed name=myFeed type=silenpush.com```
#### Human Readable Output



### silentpush-add-feed-tags

***
This command add indicators to the feed

#### Base Command

`silentpush-add-feed-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Optional | 
| tags | Comma separated tags to be updated to the feed. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddFeedTags.created_or_updated | Unknown | List of indicator names that were created or updated in the feed. | 
| SilentPush.AddFeedTags.invalid_indicators | Unknown | List of indicators that were considered invalid and not added to the feed. | 

#### Command example
```!silentpush-add-feed-tags feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e tags=Tag1,Tag2```
#### Human Readable Output



### silentpush-add-indicators

***
This command add indicators to the feed

#### Base Command

`silentpush-add-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Required | 
| indicators | Indicators for the feed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddIndicators.created_or_updated | Unknown | List of indicator names that were created or updated in the feed. | 
| SilentPush.AddIndicators.invalid_indicators | Unknown | List of indicators that were considered invalid and not added to the feed. | 

#### Command example
```!silentpush-add-indicators feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e indicators=silenpush.com,173.245.58.236```
#### Human Readable Output



### silentpush-add-indicator-tags

***
This command updates tags to the indicators

#### Base Command

`silentpush-add-indicator-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Required | 
| indicator_name | The name of the indicator to tag. | Required | 
| tags | Tags to be added to the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddIndicatorTags.uuid | String | The UUID of the indicator. | 
| SilentPush.AddIndicatorTags.name | String | The name of the indicator. | 
| SilentPush.AddIndicatorTags.tags | String | The tags assigned to the indicator. | 

#### Command example
```!silentpush-add-indicator-tags feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e indicator_name=silenpush.com tags=Tag3,Tag4```
#### Human Readable Output



### silentpush-bulk-enrich

***
This command enriches IPs or Domains in a bulk

#### Base Command

`silentpush-bulk-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | Type of resource for which information needs to be retrieved {e.g. domain}. | Required | 
| value | Value corresponding to the selected "resource" for which information needs to be retrieved {e.g. silentpush.com}. | Required | 
| explain | Include explanation of data calculations. | Optional | 
| scan_data | Include scan data (IPv4 only). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Bulk.Enrich.value | String | Queried value. | 
| SilentPush.Bulk.Enrich.domain_string_frequency_probability.avg_probability | Number | Average probability score of the domain string. | 
| SilentPush.Bulk.Enrich.domain_string_frequency_probability.dga_probability_score | Number | Probability score indicating likelihood of being a DGA domain. | 
| SilentPush.Bulk.Enrich.domain_string_frequency_probability.domain | String | Domain name analyzed. | 
| SilentPush.Bulk.Enrich.domain_string_frequency_probability.domain_string_freq_probabilities | Unknown | List of frequency probabilities for different domain string components. | 
| SilentPush.Bulk.Enrich.domain_string_frequency_probability.query | String | Domain name queried. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.alexa_rank | Number | Alexa rank of the domain. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.alexa_top10k | Boolean | Indicates if the domain is in the Alexa top 10k. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.alexa_top10k_score | Number | Score indicating domain's Alexa top 10k ranking. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.dynamic_domain_score | Number | Score indicating likelihood of domain being dynamically generated. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.is_dynamic_domain | Boolean | Indicates if the domain is dynamic. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.is_url_shortener | Boolean | Indicates if the domain is a known URL shortener. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.results | Number | Number of results found for the domain. | 
| SilentPush.Bulk.Enrich.domain_urls.results_summary.url_shortner_score | Number | Score of the shortned URL. | 
| SilentPush.Bulk.Enrich.domaininfo.domain | String | Domain name analyzed. | 
| SilentPush.Bulk.Enrich.domaininfo.error | String | Error message if no data is available for the domain. | 
| SilentPush.Bulk.Enrich.domaininfo.zone | String | TLD zone of the domain. | 
| SilentPush.Bulk.Enrich.domaininfo.registrar | String | registrar of the domain. | 
| SilentPush.Bulk.Enrich.domaininfo.whois_age | String | The age of the domain based on WHOIS records. | 
| SilentPush.Bulk.Enrich.domaininfo.whois_created_date | String | The created date on WHOIS records. | 
| SilentPush.Bulk.Enrich.domaininfo.query | String | The domain name that was queried in the system. | 
| SilentPush.Bulk.Enrich.domaininfo.last_seen | Number | The first recorded observation of the domain in the database. | 
| SilentPush.Bulk.Enrich.domaininfo.first_seen | Number | The last recorded observation of the domain in the database. | 
| SilentPush.Bulk.Enrich.domaininfo.is_new | Boolean | Indicates whether the domain is considered "new.". | 
| SilentPush.Bulk.Enrich.domaininfo.is_new_score | Number | A scoring metric indicating how "new" the domain is. | 
| SilentPush.Bulk.Enrich.domaininfo.age | Number | Represents the age of the domain in days. | 
| SilentPush.Bulk.Enrich.domaininfo.age_score | Number | A scoring metric indicating the trustworthiness of the domain based on its age. | 
| SilentPush.Bulk.Enrich.ip_diversity.asn_diversity | String | Number of different ASNs associated with the domain. | 
| SilentPush.Bulk.Enrich.ip_diversity.ip_diversity_all | String | Total number of unique IPs observed for the domain. | 
| SilentPush.Bulk.Enrich.ip_diversity.host | String | The hostname being analyzed. | 
| SilentPush.Bulk.Enrich.ip_diversity.ip_diversity_groups | String | The number of distinct IP groups \(e.g., IPs belonging to different ranges or providers\). | 
| SilentPush.Bulk.Enrich.ns_reputation.is_expired | Boolean | Indicates if the domain\`s nameserver is expired. | 
| SilentPush.Bulk.Enrich.ns_reputation.is_parked | Boolean |  The domain is not parked \(a parked domain is one without active content\). | 
| SilentPush.Bulk.Enrich.ns_reputation.is_sinkholed | Boolean | The domain is not sinkholed \(not forcibly redirected to a security researcher\`s trap\). | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_reputation_max | Number | Maximum reputation score for nameservers. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_reputation_score | Number | Reputation score of the domain\`s nameservers. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_srv_reputation.domain | String | The nameservers of domain. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_srv_reputation.ns_server | String | Provided nameserver. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_srv_reputation.ns_server_domain_density | Number | Number of domains sharing this NS. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_srv_reputation.ns_server_domains_listed | Number | Number of listed domains using this NS. | 
| SilentPush.Bulk.Enrich.ns_reputation.ns_srv_reputation.ns_server_reputation | Number | Reputation score for this NS. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.domain | String | Domain for which the SSL certificate was issued. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.domains | Unknown | Other Domains for which the SSL certificate was issued. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.issuer_organization | String | Issuer organization of the SSL certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.fingerprint_sha1 | String | A unique identifier for the certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.hostname | String | The hostname associated with the certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.ip | String | The IP address of the server using this certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.is_expired | String | Indicates whether the certificate has expired. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.issuer_common_name | String | he Common Name \(CN\) of the Certificate Authority \(CA\) that issued this certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.not_after | String | Expiry date of the certificate. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.not_before | String | Start date of the certificate validity. | 
| SilentPush.Bulk.Enrich.scan_data.certificates.scan_date | String | The date when this certificate data was last scanned. | 
| SilentPush.Bulk.Enrich.scan_data.headers.response | String | HTTP response code for the domain scan. | 
| SilentPush.Bulk.Enrich.scan_data.headers.hostname | String | The hostname that sent this response. | 
| SilentPush.Bulk.Enrich.scan_data.headers.ip | String | The IP address responding to the request. | 
| SilentPush.Bulk.Enrich.scan_data.headers.scan_date | String | The date when the headers were scanned. | 
| SilentPush.Bulk.Enrich.scan_data.headers.headers.cache-control | String | HTTP cache-control. | 
| SilentPush.Bulk.Enrich.scan_data.headers.headers.content-length" | String | Content length of the HTTP response. | 
| SilentPush.Bulk.Enrich.scan_data.headers.headers.date | String | The date/time of the response. | 
| SilentPush.Bulk.Enrich.scan_data.headers.headers.expires | String | Indicates an already expired response. | 
| SilentPush.Bulk.Enrich.scan_data.headers.headers.server | String | The web server handling the request \(Cloudflare proxy\). | 
| SilentPush.Bulk.Enrich.scan_data.html.hostname | String | HTTP response code for the domain scan. | 
| SilentPush.Bulk.Enrich.scan_data.html.html_body_murmur3 | String | hash of the page content. | 
| SilentPush.Bulk.Enrich.scan_data.html.html_body_ssdeep | String | SSDEEP hash \(used for fuzzy matching similar HTML content\). | 
| SilentPush.Bulk.Enrich.scan_data.html.html_title | String | The page title \(suggests a Cloudflare challenge page, likely due to bot protection\). | 
| SilentPush.Bulk.Enrich.scan_data.html.ip | String | The IP address responding to the request. | 
| SilentPush.Bulk.Enrich.scan_data.html.scan_date | String | The date when the headers were scanned. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.favicon2_md5 | String | MD5 hash of a secondary favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.favicon2_mmh3 | String | Murmur3 hash of a secondary favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.favicon2_path | String | The file path of the secondary favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.favicon_md5 | String | MD5 hash of the primary favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.favicon_mmh3 | String | Murmur3 hash of the primary favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.hostname | String | The hostname where this favicon was found. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.ip | String | The IP address associated with the favicon. | 
| SilentPush.Bulk.Enrich.scan_data.favicon.scan_date | String | Date when this favicon was last scanned. | 
| SilentPush.Bulk.Enrich.scan_data.jarm.hostname | String | The hostname where this jarm was found. | 
| SilentPush.Bulk.Enrich.scan_data.jarm.ip | String | The IP address responding to the request. | 
| SilentPush.Bulk.Enrich.scan_data.jarm.jarm_hash | String | Unique identifier for the TLS configuration of the server. | 
| SilentPush.Bulk.Enrich.scan_data.jarm.scan_date | String | Date when this jarm was last scanned. | 
| SilentPush.Bulk.Enrich.sp_risk_score | Number | Overall risk score for the domain. | 
| SilentPush.Bulk.Enrich.sp_risk_score_explain.sp_risk_score_decider | String | Factor that determined the final risk score. | 
| SilentPush.Bulk.Enrich.ip2asn.asn | Number | Autonomous System Number \(ASN\) associated with the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_allocation_age | Number | Age of ASN allocation in days. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_allocation_date | Number | Date of ASN allocation. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_rank | Number | Rank of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_rank_score | Number | Rank score of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_reputation | Number | Reputation score of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_reputation_explain.ips_in_asn | Number | Total number of IPs in the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_reputation_explain.ips_num_active | Number | Number of active IPs in the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_reputation_explain.ips_num_listed | Number | Number of listed IPs in the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_reputation_score | Number | Reputation score of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation | Number | Takedown reputation score of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation_explain.ips_in_asn | Number | Total number of IPs in the ASN with takedown reputation. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation_explain.ips_num_listed | Number | Number of listed IPs in the ASN with takedown reputation. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation_explain.items_num_listed | Number | Number of flagged items in the ASN with takedown reputation. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation_explain.listings_max_age | Number | Maximum age of listings for the ASN with takedown reputation. | 
| SilentPush.Bulk.Enrich.ip2asn.asn_takedown_reputation_score | Number | Takedown reputation score of the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.asname | String | Name of the Autonomous System \(AS\). | 
| SilentPush.Bulk.Enrich.ip2asn.benign_info.actor | String | This field is usually used to indicate a known organization or individual associated with the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.benign_info.known_benign | Boolean | Indicates whether this IP/ASN is explicitly known to be safe \(e.g., a reputable cloud provider or public service\). | 
| SilentPush.Bulk.Enrich.ip2asn.benign_info.tags | Unknown | Contains descriptive tags if the IP/ASN has a known role \(e.g., "Google Bot", "Cloudflare Proxy"\). | 
| SilentPush.Bulk.Enrich.ip2asn.date | Number | Date of the scan data \(YYYYMMDD format\). | 
| SilentPush.Bulk.Enrich.ip2asn.density | Number | The density value associated with the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.ip | String | IP address associated with the ASN. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_has_expired_certificate | Boolean | Indicates whether the IP has an expired SSL/TLS certificate. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_has_open_directory | Boolean | Indicates whether the IP hosts an open directory listing. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_is_dsl_dynamic | Boolean | the IP is from a dynamic DSL pool. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_is_dsl_dynamic_score | Number | A score indicating how likely this IP is dynamic. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_is_ipfs_node | Boolean | the InterPlanetary File System \(IPFS\), a decentralized file storage system. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_is_tor_exit_node | Boolean | Tor exit node \(used for anonymous internet browsing\). | 
| SilentPush.Bulk.Enrich.ip2asn.ip_location.continent_code | String | abbreviation for the continent where the IP is located. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_location.continent_name | String | The full name of the continent. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_location.country_code | String | The ISO 3166-1 alpha-2 country code representing the country. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_location.country_is_in_european_union | Boolean | A Boolean value \(true/false\) indicating if the country is part of the European Union \(EU\). | 
| SilentPush.Bulk.Enrich.ip2asn.ip_location.country_name | String | The full name of the country where the IP is registered. | 
| SilentPush.Bulk.Enrich.ip2asn.ip_ptr | String | The reverse DNS \(PTR\) record for the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.listing_score | Number | Measures how frequently the IP appears in threat intelligence or blacklist databases. | 
| SilentPush.Bulk.Enrich.ip2asn.listing_score_explain | Unknown | A breakdown of why the listing score is assigned. | 
| SilentPush.Bulk.Enrich.ip2asn.malscore | Number | Malicious activity score for the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.hostname | String | Hostname associated with the SSL certificate. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.domain | String | Domain for which the SSL certificate was issued. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.fingerprint_sha1 | String | SHA-1 fingerprint of the SSL certificate. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.issuer_common_name | String | Common name of the certificate issuer. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.issuer_organization | String | Organization that issued the SSL certificate. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.not_before | String | Start date of SSL certificate validity. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.not_after | String | Expiration date of SSL certificate validity. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.domains | Unknown | Other domains for which the SSL certificate was issued. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.is_expired | Boolean | Is certificate expired. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.certificates.scan_date | String | Scan date of the certificate. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.favicon2_md5 | String | MD5 hash of the second favicon. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.favicon2_mmh3 | Number | MurmurHash3 value of the second favicon. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.favicon_md5 | String | MD5 hash of the favicon. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.favicon_mmh3 | Number | MurmurHash3 value of the favicon. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.favicon2_path | String | Path to the second favicon file. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.favicon.scan_date | String | Scan date of favicon file. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.response | String | HTTP response code from the scan. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.headers.server | String | Server header from the HTTP response. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.headers.content-type | String | Content-Type header from the HTTP response. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.headers.content-length | String | Content-Length header from the HTTP response. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.headers.cache-control | String | Cache-control header from the HTTP response. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.headers.headers.date | String | Date header from the HTTP response. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.html.html_title | String | Title of the scanned HTML page. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.html.html_body_murmur3 | String | MurmurHash3 of the HTML body content. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.html.html_body_ssdeep | String | SSDEEP fuzzy hash of the HTML body content. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.html.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.jarm.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Bulk.Enrich.ip2asn.scan_data.jarm.jarm_hash | String | JARM fingerprint hash for TLS analysis. | 
| SilentPush.Bulk.Enrich.ip2asn.sp_risk_score | Number | Security risk score for the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.sp_risk_score_explain.sp_risk_score_decider | String | Factor that determined the final risk score. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet | String | Subnet associated with the IP. | 
| SilentPush.Bulk.Enrich.ip2asn.sinkhole_info.known_sinkhole_ip | Boolean | Indicates whether the IP is part of a sinkhole \(a controlled system that captures malicious traffic\). | 
| SilentPush.Bulk.Enrich.ip2asn.sinkhole_info.tags | Unknown | If the IP were a known sinkhole, this field would contain tags describing its purpose. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet_allocation_age | Number | Represents the age \(in days\) since the subnet was allocated. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet_allocation_date | Number | The date when the subnet was assigned to an organization or ISP. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet_reputation | Number | A measure of how frequently IPs from this subnet appear in threat intelligence databases. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet_reputation_explain | Unknown | A breakdown of why the subnet received its reputation score. | 
| SilentPush.Bulk.Enrich.ip2asn.subnet_reputation_score | Number | A numerical risk score \(typically 0-100, with higher values indicating higher risk\). | 

#### Command example
```!silentpush-bulk-enrich resource=ipv4 value=173.245.58.236S explain=1 scan_data=1```
#### Human Readable Output



### silentpush-density-lookup

***
This command queries granular DNS/IP parameters (e.g., NS servers, MX servers, IPaddresses, ASNs) for density information.

#### Base Command

`silentpush-density-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qtype | Query type. | Required | 
| query | Value to query. | Required | 
| scope | Match level (optional). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.DensityLookup.qtype | String | The following qtypes are supported: nssrv, mxsrv. | 
| SilentPush.DensityLookup.query | String | The query value to lookup, which can be the name of an NS or MX server. | 
| SilentPush.DensityLookup.records.density | Number | The density value associated with the query result. | 
| SilentPush.DensityLookup.records.nssrv | String | The name server \(NS\) for the query result. | 

#### Command example
```!silentpush-density-lookup qtype=nssrv query=silenpush.com```
#### Human Readable Output



### silentpush-forward-padns-lookup

***
This command performs a forward PADNS lookup using various filtering parameters.

#### Base Command

`silentpush-forward-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| last_seen_after | Filter results to include only records last seen after this date. | Optional | 
| last_seen_before | Filter results to include only records last seen before this date. | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| qtype | DNS record type. | Required | 
| query | The DNS record name to lookup. | Required | 
| netmask | The netmask to filter the lookup results. | Optional | 
| match | Type of match for the query (e.g., exact, partial). | Optional | 
| as_of | Date or time to get the DNS records as of a specific point in time. | Optional | 
| sort | Sort the results by the specified field (e.g., date, score). | Optional | 
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.PADNSLookup.qname | String | The DNS record name that was looked up. | 
| SilentPush.PADNSLookup.qtype | String | The DNS record type queried \(e.g., NS\). | 
| SilentPush.PADNSLookup.records.answer | String | The answer \(e.g., name server\) for the DNS record. | 
| SilentPush.PADNSLookup.records.count | Number | The number of occurrences for this DNS record. | 
| SilentPush.PADNSLookup.records.first_seen | String | The timestamp when this DNS record was first seen. | 
| SilentPush.PADNSLookup.records.last_seen | String | The timestamp when this DNS record was last seen. | 
| SilentPush.PADNSLookup.records.nshash | String | Unique hash for the DNS record. | 
| SilentPush.PADNSLookup.records.query | String | The DNS record query name \(e.g., silentpush.com\). | 
| SilentPush.PADNSLookup.records.ttl | Number | Time to live \(TTL\) value for the DNS record. | 
| SilentPush.PADNSLookup.records.type | String | The type of the DNS record \(e.g., NS\). | 

#### Command example
```!silentpush-forward-padns-lookup qtype=a query=silenpush.com```
#### Human Readable Output



### silentpush-get-asns-for-domain

***
This command retrieves Autonomous System Numbers (ASNs) associated with a domain.

#### Base Command

`silentpush-get-asns-for-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to search. | Required | 
| result_format | format of returned results: compact (default) = return ASN and AS Name only, full = return details of domain hosts in each ASN. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.DomainASNs.domain | String | The domain name for which ASNs are retrieved. | 
| SilentPush.DomainASNs.asns | Unknown | Dictionary of Autonomous System Numbers \(ASNs\) associated with the domain. | 

#### Command example
```!silentpush-get-asns-for-domain domain=silenpush.com```
#### Human Readable Output



### silentpush-get-data-exports

***
This command runs the threat check on the specified 

#### Base Command

`silentpush-get-data-exports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| export_type | Which export type (iofa, organisation, etc). | Required | 
| file_name | The name of the file to be exported. | Required | 
| file_type | The file type (csv, json, txt, etc). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.GetDataExports.EntryID | Unknown | The EntryID of the report file. | 
| SilentPush.GetDataExports.Extension | String | The extension of the report file. | 
| SilentPush.GetDataExports.Name | String | The name of the report file. | 
| SilentPush.GetDataExports.Info | String | The info of the report file. | 
| SilentPush.GetDataExports.Size | Number | The size of the report file. | 
| SilentPush.GetDataExports.Type | String | The type of the report file. | 

#### Command example
```!silentpush-get-data-exports export_type=organisation file_name=filename file_type=csv```
#### Human Readable Output



### silentpush-get-domain-certificates

***
This command get certificate data collected from domain scanning.

#### Base Command

`silentpush-get-domain-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| domain | The domain to query certificates for. | Required | 
| domain_regex | Regular expression to match domains. | Optional | 
| certificate_issuer | Filter by certificate issuer. | Optional | 
| date_min | Filter certificates issued on or after this date. | Optional | 
| date_max | Filter certificates issued on or before this date. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Certificate.domain | String | Queried domain. | 
| SilentPush.Certificate.metadata | String | Metadata of the response. | 
| SilentPush.Certificate.certificates.cert_index | Number | Index of the certificate. | 
| SilentPush.Certificate.certificates.chain | Unknown | Certificate chain. | 
| SilentPush.Certificate.certificates.date | Number | Certificate issue date. | 
| SilentPush.Certificate.certificates.domain | String | Primary domain of the certificate. | 
| SilentPush.Certificate.certificates.domains | Unknown | List of domains covered by the certificate. | 
| SilentPush.Certificate.certificates.fingerprint | String | SHA-1 fingerprint of the certificate. | 
| SilentPush.Certificate.certificates.fingerprint_md5 | String | MD5 fingerprint of the certificate. | 
| SilentPush.Certificate.certificates.fingerprint_sha1 | String | SHA-1 fingerprint of the certificate. | 
| SilentPush.Certificate.certificates.fingerprint_sha256 | String | SHA-256 fingerprint of the certificate. | 
| SilentPush.Certificate.certificates.host | String | Host associated with the certificate. | 
| SilentPush.Certificate.certificates.issuer | String | Issuer of the certificate. | 
| SilentPush.Certificate.certificates.not_after | String | Expiration date of the certificate. | 
| SilentPush.Certificate.certificates.not_before | String | Start date of the certificate validity. | 
| SilentPush.Certificate.certificates.serial_dec | String | Decimal representation of the serial number. | 
| SilentPush.Certificate.certificates.serial_hex | String | Hexadecimal representation of the serial number. | 
| SilentPush.Certificate.certificates.serial_number | String | Serial number of the certificate. | 
| SilentPush.Certificate.certificates.source_name | String | Source log name of the certificate. | 
| SilentPush.Certificate.certificates.source_url | String | URL of the certificate log source. | 
| SilentPush.Certificate.certificates.subject | String | Subject details of the certificate. | 
| SilentPush.Certificate.certificates.wildcard | Number | Indicates if the certificate is a wildcard certificate. | 
| SilentPush.Certificate.job_details.get | String | URL to get the data of the job or its status. | 
| SilentPush.Certificate.job_details.job_id | String | ID of the job. | 
| SilentPush.Certificate.job_details.status | String | Status of the job. | 

### silentpush-get-enrichment-data

***
This command retrieves comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).

#### Base Command

`silentpush-get-enrichment-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | Type of resource for which information needs to be retrieved {e.g. domain}. | Required | 
| value | Value corresponding to the selected "resource" for which information needs to be retrieved {e.g. silentpush.com}. | Required | 
| explain | Include explanation of data calculations. | Optional | 
| scan_data | Include scan data (IPv4 only). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Enrichment.value | String | Queried value. | 
| SilentPush.Enrichment.domain_string_frequency_probability.avg_probability | Number | Average probability score of the domain string. | 
| SilentPush.Enrichment.domain_string_frequency_probability.dga_probability_score | Number | Probability score indicating likelihood of being a DGA domain. | 
| SilentPush.Enrichment.domain_string_frequency_probability.domain | String | Domain name analyzed. | 
| SilentPush.Enrichment.domain_string_frequency_probability.domain_string_freq_probabilities | Unknown | List of frequency probabilities for different domain string components. | 
| SilentPush.Enrichment.domain_string_frequency_probability.query | String | Domain name queried. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_rank | Number | Alexa rank of the domain. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_top10k | Boolean | Indicates if the domain is in the Alexa top 10k. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_top10k_score | Number | Score indicating domain's Alexa top 10k ranking. | 
| SilentPush.Enrichment.domain_urls.results_summary.dynamic_domain_score | Number | Score indicating likelihood of domain being dynamically generated. | 
| SilentPush.Enrichment.domain_urls.results_summary.is_dynamic_domain | Boolean | Indicates if the domain is dynamic. | 
| SilentPush.Enrichment.domain_urls.results_summary.is_url_shortener | Boolean | Indicates if the domain is a known URL shortener. | 
| SilentPush.Enrichment.domain_urls.results_summary.results | Number | Number of results found for the domain. | 
| SilentPush.Enrichment.domain_urls.results_summary.url_shortner_score | Number | Score of the shortned URL. | 
| SilentPush.Enrichment.domaininfo.domain | String | Domain name analyzed. | 
| SilentPush.Enrichment.domaininfo.error | String | Error message if no data is available for the domain. | 
| SilentPush.Enrichment.domaininfo.zone | String | TLD zone of the domain. | 
| SilentPush.Enrichment.domaininfo.registrar | String | registrar of the domain. | 
| SilentPush.Enrichment.domaininfo.whois_age | String | The age of the domain based on WHOIS records. | 
| SilentPush.Enrichment.domaininfo.whois_created_date | String | The created date on WHOIS records. | 
| SilentPush.Enrichment.domaininfo.query | String | The domain name that was queried in the system. | 
| SilentPush.Enrichment.domaininfo.last_seen | Number | The first recorded observation of the domain in the database. | 
| SilentPush.Enrichment.domaininfo.first_seen | Number | The last recorded observation of the domain in the database. | 
| SilentPush.Enrichment.domaininfo.is_new | Boolean | Indicates whether the domain is considered "new.". | 
| SilentPush.Enrichment.domaininfo.is_new_score | Number | A scoring metric indicating how "new" the domain is. | 
| SilentPush.Enrichment.domaininfo.age | Number | Represents the age of the domain in days. | 
| SilentPush.Enrichment.domaininfo.age_score | Number | A scoring metric indicating the trustworthiness of the domain based on its age. | 
| SilentPush.Enrichment.ip_diversity.asn_diversity | String | Number of different ASNs associated with the domain. | 
| SilentPush.Enrichment.ip_diversity.ip_diversity_all | String | Total number of unique IPs observed for the domain. | 
| SilentPush.Enrichment.ip_diversity.host | String | The hostname being analyzed. | 
| SilentPush.Enrichment.ip_diversity.ip_diversity_groups | String | The number of distinct IP groups \(e.g., IPs belonging to different ranges or providers\). | 
| SilentPush.Enrichment.ns_reputation.is_expired | Boolean | Indicates if the domain\`s nameserver is expired. | 
| SilentPush.Enrichment.ns_reputation.is_parked | Boolean |  The domain is not parked \(a parked domain is one without active content\). | 
| SilentPush.Enrichment.ns_reputation.is_sinkholed | Boolean | The domain is not sinkholed \(not forcibly redirected to a security researcher\`s trap\). | 
| SilentPush.Enrichment.ns_reputation.ns_reputation_max | Number | Maximum reputation score for nameservers. | 
| SilentPush.Enrichment.ns_reputation.ns_reputation_score | Number | Reputation score of the domain\`s nameservers. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.domain | String | The nameservers of domain. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server | String | Provided nameserver. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_domain_density | Number | Number of domains sharing this NS. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_domains_listed | Number | Number of listed domains using this NS. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_reputation | Number | Reputation score for this NS. | 
| SilentPush.Enrichment.scan_data.certificates.domain | String | Domain for which the SSL certificate was issued. | 
| SilentPush.Enrichment.scan_data.certificates.domains | Unknown | Other Domains for which the SSL certificate was issued. | 
| SilentPush.Enrichment.scan_data.certificates.issuer_organization | String | Issuer organization of the SSL certificate. | 
| SilentPush.Enrichment.scan_data.certificates.fingerprint_sha1 | String | A unique identifier for the certificate. | 
| SilentPush.Enrichment.scan_data.certificates.hostname | String | The hostname associated with the certificate. | 
| SilentPush.Enrichment.scan_data.certificates.ip | String | The IP address of the server using this certificate. | 
| SilentPush.Enrichment.scan_data.certificates.is_expired | String | Indicates whether the certificate has expired. | 
| SilentPush.Enrichment.scan_data.certificates.issuer_common_name | String | he Common Name \(CN\) of the Certificate Authority \(CA\) that issued this certificate. | 
| SilentPush.Enrichment.scan_data.certificates.not_after | String | Expiry date of the certificate. | 
| SilentPush.Enrichment.scan_data.certificates.not_before | String | Start date of the certificate validity. | 
| SilentPush.Enrichment.scan_data.certificates.scan_date | String | The date when this certificate data was last scanned. | 
| SilentPush.Enrichment.scan_data.headers.response | String | HTTP response code for the domain scan. | 
| SilentPush.Enrichment.scan_data.headers.hostname | String | The hostname that sent this response. | 
| SilentPush.Enrichment.scan_data.headers.ip | String | The IP address responding to the request. | 
| SilentPush.Enrichment.scan_data.headers.scan_date | String | The date when the headers were scanned. | 
| SilentPush.Enrichment.scan_data.headers.headers.cache-control | String | HTTP cache-control. | 
| SilentPush.Enrichment.scan_data.headers.headers.content-length" | String | Content length of the HTTP response. | 
| SilentPush.Enrichment.scan_data.headers.headers.date | String | The date/time of the response. | 
| SilentPush.Enrichment.scan_data.headers.headers.expires | String | Indicates an already expired response. | 
| SilentPush.Enrichment.scan_data.headers.headers.server | String | The web server handling the request \(Cloudflare proxy\). | 
| SilentPush.Enrichment.scan_data.html.hostname | String | HTTP response code for the domain scan. | 
| SilentPush.Enrichment.scan_data.html.html_body_murmur3 | String | hash of the page content. | 
| SilentPush.Enrichment.scan_data.html.html_body_ssdeep | String | SSDEEP hash \(used for fuzzy matching similar HTML content\). | 
| SilentPush.Enrichment.scan_data.html.html_title | String | The page title \(suggests a Cloudflare challenge page, likely due to bot protection\). | 
| SilentPush.Enrichment.scan_data.html.ip | String | The IP address responding to the request. | 
| SilentPush.Enrichment.scan_data.html.scan_date | String | The date when the headers were scanned. | 
| SilentPush.Enrichment.scan_data.favicon.favicon2_md5 | String | MD5 hash of a secondary favicon. | 
| SilentPush.Enrichment.scan_data.favicon.favicon2_mmh3 | String | Murmur3 hash of a secondary favicon. | 
| SilentPush.Enrichment.scan_data.favicon.favicon2_path | String | The file path of the secondary favicon. | 
| SilentPush.Enrichment.scan_data.favicon.favicon_md5 | String | MD5 hash of the primary favicon. | 
| SilentPush.Enrichment.scan_data.favicon.favicon_mmh3 | String | Murmur3 hash of the primary favicon. | 
| SilentPush.Enrichment.scan_data.favicon.hostname | String | The hostname where this favicon was found. | 
| SilentPush.Enrichment.scan_data.favicon.ip | String | The IP address associated with the favicon. | 
| SilentPush.Enrichment.scan_data.favicon.scan_date | String | Date when this favicon was last scanned. | 
| SilentPush.Enrichment.scan_data.jarm.hostname | String | The hostname where this jarm was found. | 
| SilentPush.Enrichment.scan_data.jarm.ip | String | The IP address responding to the request. | 
| SilentPush.Enrichment.scan_data.jarm.jarm_hash | String | Unique identifier for the TLS configuration of the server. | 
| SilentPush.Enrichment.scan_data.jarm.scan_date | String | Date when this jarm was last scanned. | 
| SilentPush.Enrichment.sp_risk_score | Number | Overall risk score for the domain. | 
| SilentPush.Enrichment.sp_risk_score_explain.sp_risk_score_decider | String | Factor that determined the final risk score. | 
| SilentPush.Enrichment.ip2asn.asn | Number | Autonomous System Number \(ASN\) associated with the IP. | 
| SilentPush.Enrichment.ip2asn.asn_allocation_age | Number | Age of ASN allocation in days. | 
| SilentPush.Enrichment.ip2asn.asn_allocation_date | Number | Date of ASN allocation. | 
| SilentPush.Enrichment.ip2asn.asn_rank | Number | Rank of the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_rank_score | Number | Rank score of the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_reputation | Number | Reputation score of the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_reputation_explain.ips_in_asn | Number | Total number of IPs in the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_reputation_explain.ips_num_active | Number | Number of active IPs in the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_reputation_explain.ips_num_listed | Number | Number of listed IPs in the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_reputation_score | Number | Reputation score of the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation | Number | Takedown reputation score of the ASN. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation_explain.ips_in_asn | Number | Total number of IPs in the ASN with takedown reputation. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation_explain.ips_num_listed | Number | Number of listed IPs in the ASN with takedown reputation. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation_explain.items_num_listed | Number | Number of flagged items in the ASN with takedown reputation. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation_explain.listings_max_age | Number | Maximum age of listings for the ASN with takedown reputation. | 
| SilentPush.Enrichment.ip2asn.asn_takedown_reputation_score | Number | Takedown reputation score of the ASN. | 
| SilentPush.Enrichment.ip2asn.asname | String | Name of the Autonomous System \(AS\). | 
| SilentPush.Enrichment.ip2asn.benign_info.actor | String | This field is usually used to indicate a known organization or individual associated with the IP. | 
| SilentPush.Enrichment.ip2asn.benign_info.known_benign | Boolean | Indicates whether this IP/ASN is explicitly known to be safe \(e.g., a reputable cloud provider or public service\). | 
| SilentPush.Enrichment.ip2asn.benign_info.tags | Unknown | Contains descriptive tags if the IP/ASN has a known role \(e.g., "Google Bot", "Cloudflare Proxy"\). | 
| SilentPush.Enrichment.ip2asn.date | Number | Date of the scan data \(YYYYMMDD format\). | 
| SilentPush.Enrichment.ip2asn.density | Number | The density value associated with the IP. | 
| SilentPush.Enrichment.ip2asn.ip | String | IP address associated with the ASN. | 
| SilentPush.Enrichment.ip2asn.ip_has_expired_certificate | Boolean | Indicates whether the IP has an expired SSL/TLS certificate. | 
| SilentPush.Enrichment.ip2asn.ip_has_open_directory | Boolean | Indicates whether the IP hosts an open directory listing. | 
| SilentPush.Enrichment.ip2asn.ip_is_dsl_dynamic | Boolean | the IP is from a dynamic DSL pool. | 
| SilentPush.Enrichment.ip2asn.ip_is_dsl_dynamic_score | Number | A score indicating how likely this IP is dynamic. | 
| SilentPush.Enrichment.ip2asn.ip_is_ipfs_node | Boolean | the InterPlanetary File System \(IPFS\), a decentralized file storage system. | 
| SilentPush.Enrichment.ip2asn.ip_is_tor_exit_node | Boolean | Tor exit node \(used for anonymous internet browsing\). | 
| SilentPush.Enrichment.ip2asn.ip_location.continent_code | String | abbreviation for the continent where the IP is located. | 
| SilentPush.Enrichment.ip2asn.ip_location.continent_name | String | The full name of the continent. | 
| SilentPush.Enrichment.ip2asn.ip_location.country_code | String | The ISO 3166-1 alpha-2 country code representing the country. | 
| SilentPush.Enrichment.ip2asn.ip_location.country_is_in_european_union | Boolean | A Boolean value \(true/false\) indicating if the country is part of the European Union \(EU\). | 
| SilentPush.Enrichment.ip2asn.ip_location.country_name | String | The full name of the country where the IP is registered. | 
| SilentPush.Enrichment.ip2asn.ip_ptr | String | The reverse DNS \(PTR\) record for the IP. | 
| SilentPush.Enrichment.ip2asn.listing_score | Number | Measures how frequently the IP appears in threat intelligence or blacklist databases. | 
| SilentPush.Enrichment.ip2asn.listing_score_explain | Unknown | A breakdown of why the listing score is assigned. | 
| SilentPush.Enrichment.ip2asn.malscore | Number | Malicious activity score for the IP. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.hostname | String | Hostname associated with the SSL certificate. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.domain | String | Domain for which the SSL certificate was issued. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.fingerprint_sha1 | String | SHA-1 fingerprint of the SSL certificate. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.issuer_common_name | String | Common name of the certificate issuer. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.issuer_organization | String | Organization that issued the SSL certificate. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.not_before | String | Start date of SSL certificate validity. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.not_after | String | Expiration date of SSL certificate validity. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.domains | Unknown | Other domains for which the SSL certificate was issued. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.is_expired | Boolean | Is certificate expired. | 
| SilentPush.Enrichment.ip2asn.scan_data.certificates.scan_date | String | Scan date of the certificate. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.favicon2_md5 | String | MD5 hash of the second favicon. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.favicon2_mmh3 | Number | MurmurHash3 value of the second favicon. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.favicon_md5 | String | MD5 hash of the favicon. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.favicon_mmh3 | Number | MurmurHash3 value of the favicon. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.favicon2_path | String | Path to the second favicon file. | 
| SilentPush.Enrichment.ip2asn.scan_data.favicon.scan_date | String | Scan date of favicon file. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.response | String | HTTP response code from the scan. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.headers.server | String | Server header from the HTTP response. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.headers.content-type | String | Content-Type header from the HTTP response. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.headers.content-length | String | Content-Length header from the HTTP response. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.headers.cache-control | String | Cache-control header from the HTTP response. | 
| SilentPush.Enrichment.ip2asn.scan_data.headers.headers.date | String | Date header from the HTTP response. | 
| SilentPush.Enrichment.ip2asn.scan_data.html.html_title | String | Title of the scanned HTML page. | 
| SilentPush.Enrichment.ip2asn.scan_data.html.html_body_murmur3 | String | MurmurHash3 of the HTML body content. | 
| SilentPush.Enrichment.ip2asn.scan_data.html.html_body_ssdeep | String | SSDEEP fuzzy hash of the HTML body content. | 
| SilentPush.Enrichment.ip2asn.scan_data.html.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Enrichment.ip2asn.scan_data.jarm.scan_date | String | The date and time when the scan was performed. | 
| SilentPush.Enrichment.ip2asn.scan_data.jarm.jarm_hash | String | JARM fingerprint hash for TLS analysis. | 
| SilentPush.Enrichment.ip2asn.sp_risk_score | Number | Security risk score for the IP. | 
| SilentPush.Enrichment.ip2asn.sp_risk_score_explain.sp_risk_score_decider | String | Factor that determined the final risk score. | 
| SilentPush.Enrichment.ip2asn.subnet | String | Subnet associated with the IP. | 
| SilentPush.Enrichment.ip2asn.sinkhole_info.known_sinkhole_ip | Boolean | Indicates whether the IP is part of a sinkhole \(a controlled system that captures malicious traffic\). | 
| SilentPush.Enrichment.ip2asn.sinkhole_info.tags | Unknown | If the IP were a known sinkhole, this field would contain tags describing its purpose. | 
| SilentPush.Enrichment.ip2asn.subnet_allocation_age | Number | Represents the age \(in days\) since the subnet was allocated. | 
| SilentPush.Enrichment.ip2asn.subnet_allocation_date | Number | The date when the subnet was assigned to an organization or ISP. | 
| SilentPush.Enrichment.ip2asn.subnet_reputation | Number | A measure of how frequently IPs from this subnet appear in threat intelligence databases. | 
| SilentPush.Enrichment.ip2asn.subnet_reputation_explain | Unknown | A breakdown of why the subnet received its reputation score. | 
| SilentPush.Enrichment.ip2asn.subnet_reputation_score | Number | A numerical risk score \(typically 0-100, with higher values indicating higher risk\). | 

#### Command example
```!silentpush-get-enrichment-data resource=ipv6 value=2a02:4780:37:b262:f807:71a8:e3ee:9b64```
#### Human Readable Output



### silentpush-get-ipv4-reputation

***
This command retrieves the reputation information for an IPv4.

#### Base Command

`silentpush-get-ipv4-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipv4 | IPv4 address for which information needs to be retrieved. | Required | 
| explain | Show the information used to calculate the reputation score. | Optional | 
| limit | The maximum number of reputation history to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPv4Reputation.date | Number | Date when the reputation information was retrieved. | 
| SilentPush.IPv4Reputation.ip | String | IPv4 address for which the reputation is calculated. | 
| SilentPush.IPv4Reputation.reputation_score | Number | Reputation score for the given IP address. | 
| SilentPush.IPv4Reputation.ip_reputation_explain.ip_density | Number | The number of domain names or services associated with this IP. A higher value may indicate shared hosting or potential abuse. | 
| SilentPush.IPv4Reputation.ip_reputation_explain.names_num_listed | Number | The number of domain names linked to this IP that are flagged or listed in security threat databases. | 

#### Command example
```!silentpush-get-ipv4-reputation ipv4=173.245.58.236```
#### Human Readable Output



### silentpush-get-nameserver-reputation

***
This command retrieves historical reputation data for a specified nameserver,including reputation scores and optional detailed calculation information.

#### Base Command

`silentpush-get-nameserver-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameserver | Nameserver name for which information needs to be retrieved. | Required | 
| explain | Show the information used to calculate the reputation score. | Optional | 
| limit | The maximum number of reputation history to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.NameserverReputation.nameserver | Number | The nameserver associated with the reputation history entry. | 
| SilentPush.NameserverReputation.reputation_data.date | Number | Date of the reputation history entry \(in YYYYMMDD format\). | 
| SilentPush.NameserverReputation.reputation_data.ns_server | String | Name of the nameserver associated with the reputation history entry. | 
| SilentPush.NameserverReputation.reputation_data.ns_server_reputation | Number | Reputation score of the nameserver on the specified date. | 
| SilentPush.NameserverReputation.reputation_data.ns_server_reputation_explain.ns_server_domain_density | Number | Number of domains associated with the nameserver. | 
| SilentPush.NameserverReputation.reputation_data.ns_server_reputation_explain.ns_server_domains_listed | Number | Number of domains listed in reputation databases. | 

#### Command example
```!silentpush-get-nameserver-reputation nameserver=a.dns-servers.net.ru```
#### Human Readable Output



### silentpush-get-subnet-reputation

***
This command retrieves the reputation history for a specific subnet.

#### Base Command

`silentpush-get-subnet-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | IPv4 subnet in the format IP/NETMASK for which reputation information needs to be retrieved, i.e.: 192.35.168.0/23. | Required | 
| explain | Show the detailed information used to calculate the reputation score. | Optional | 
| limit | Maximum number of reputation history entries to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.SubnetReputation.subnet | String | The subnet associated with the reputation history. | 
| SilentPush.SubnetReputation.reputation_history.date | Number | The date of the subnet reputation record. | 
| SilentPush.SubnetReputation.reputation_history.subnet | String | The subnet associated with the reputation record. | 
| SilentPush.SubnetReputation.reputation_history.subnet_reputation | Number | The reputation score of the subnet. | 
| SilentPush.SubnetReputation.reputation_history.subnet_reputation_explain.ips_in_subnet | Number | Total number of IPs in the subnet. | 
| SilentPush.SubnetReputation.reputation_history.subnet_reputation_explain.ips_num_active | Number | Number of active IPs in the subnet. | 
| SilentPush.SubnetReputation.reputation_history.subnet_reputation_explain.ips_num_listed | Number | Number of listed IPs in the subnet. | 

#### Command example
```!silentpush-get-subnet-reputation subnet=192.35.168.0/23```
#### Human Readable Output



### silentpush-ip-diversity-lookup

***
Get IP diversity (number of IP addresses pointed to over time) for the query to qtype.

#### Base Command

`silentpush-ip-diversity-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qtype | Query type. | Required | 
| query | Value to query. | Required | 
| window | use records with a last_seen more recently than days ago, default = 30. | Optional | 
| asn | include asn diversity, 0 = do not include, 1 (default) = include asn diversity. | Optional | 
| timeline | include timeline of {ip, first_seen, last_seen} (+asn if asn=1), 0 (default) = do not include, 1 = include timeline. | Optional | 
| verbose | return ips, dates, timeline, (and asns if asn=1), 0 (default) = do not include, 1 = include all data. | Optional | 
| scope | exact or near match results by qtype, *scope=live is automatically set when timeline=1 or verbose=1. *for qtype = a: host - exact match (default when qtype=a), domain - match all hosts in this domain (domain extracted from {query}), subdomain - match all hosts at this subdomain level (i.e. *.{query}), live - calculate values from live data instead of pre-aggregated values - also switches to exact match only. *for qtype = aaaa, live - only this mode is supported for qtype=aaaa. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPdiversityLookup.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. | 
| SilentPush.IPdiversityLookup.host | String | The domain name \(host\) associated with the record. | 
| SilentPush.IPdiversityLookup.ip_diversity_all | Number | The total number of unique IPs associated with the domain. | 
| SilentPush.IPdiversityLookup.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. | 
| SilentPush.IPdiversityLookup.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. | 

#### Command example
```!silentpush-ip-diversity-lookup qtype=a query=silenpush.com```
#### Human Readable Output



### silentpush-ip-diversity-patterns

***
Search for IP Diversity patterns, with optional name server and domain name pattern matching.

#### Base Command

`silentpush-ip-diversity-patterns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| domain | Name or wildcard pattern of domain names to search for. | Optional | 
| domain_regex | A valid RE2 regex pattern to match domains. Overrides the domain argument. | Optional | 
| nsname | Name server name or wildcard pattern of the name server used by domains. | Optional | 
| mxname | mx server name or wildcard pattern of mx server used by domains, use mxname=self to find domains hosting their own mailservers. | Optional | 
| first_seen_min | only domains that have A records seen for the first time after the given date. | Optional | 
| first_seen_max | only domains that have A records seen for the first time before the given date. | Optional | 
| first_seen_min_mode | match mode for first_seen_min parameter, strict (default) - select A records that do not have any timestamps before first_seen_min, any - select A records that have at least one timestamp after first_seen_min. | Optional | 
| first_seen_max_mode | match mode for first_seen_max parameter, strict (default) - select A records that do not have any timestamps after first_seen_max, any - select A records that have at least one timestamp before first_seen_max. | Optional | 
| last_seen_min | only domains that have A records last seen more recently than the given date. | Optional | 
| last_seen_max | only domains that have A records last seen earlier than the given date. | Optional | 
| last_seen_min_mode | match mode for last_seen_min parameter, strict - select A records that do not have any timestamps before last_seen_min, any (default) - select A records that have at least one timestamp after first_seen_min. | Optional | 
| last_seen_max_mode | match mode for last_seen_max parameter, strict (default) - select A records that do not have any timestamps after last_seen_max, any - select A records that have at least one timestamp before last_seen_max. | Optional | 
| asnum | Autonomous System (AS) number to filter domains. | Optional | 
| asname | Search for all AS numbers where the AS Name begins with the specified value. | Optional | 
| network | additional network and net mask, give option as 1.1.1.1/24, network parameter may be given multiple times and the search will be performed as an ‘or’ condition. | Optional | 
| timeline | include details of IPs, ASNs, first_seen and last_seen for each domain, 0 (default) = do not include, 1 = include timeline. | Optional | 
| ip_diversity_all_min | Minimum IP diversity limit to filter domains. | Optional | 
| registrar | Name or partial name of the registrar used to register domains. | Optional | 
| email | email used to register domains - no wildcards, the given string is used in exact match - this is a slow search option and should only be used in combination with the domain match option. | Optional | 
| nschange_from_ns | domain has changed name server from nsname, exact match, wildcards and ‘self’ options supported. | Optional | 
| nschange_to_ns | domain has changed name server to nsname, exact match, wildcards and ‘self’ options supported. | Optional | 
| nschange_date_after | only domains with name server changes that occurred after the given date, if nschange_date_after is not given, the default is to find name server changes in the last 30 days, if nschange_date_before is not given. | Optional | 
| nschange_date_before | only domains with name server changes that occurred before the given date. | Optional | 
| cert_date_min | only domains that have had ssl certificates issued on or after the given date. | Optional | 
| cert_date_max | only domains that have had ssl certificates issued on or before the given date. | Optional | 
| cert_issuer | Filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported. | Optional | 
| infratag | search by infratag, infratag must include mx part, ns part, asname part, or registrar part, overrides mxname, nsname and registrar parameters, if infratag contains these parts, can be combined with all other parameters. | Optional | 
| asn_diversity_min | Minimum ASN diversity limit to filter domains. | Optional | 
| ip_diversity_all_min | minimum diversity limit, default = 1. | Optional | 
| ip_diversity_groups_min | minimum diversity limit. | Optional | 
| whois_date_after | Filter domains with a WHOIS creation date after this date (YYYY-MM-DD). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPDiversityPatterns.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. | 
| SilentPush.IPDiversityPatterns.host | String | The domain name \(host\) associated with the record. | 
| SilentPush.IPDiversityPatterns.ip_diversity_all | Number | The total number of unique IPs associated with the domain. | 
| SilentPush.IPDiversityPatterns.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. | 
| SilentPush.IPDiversityPatterns.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. | 

#### Command example
```!silentpush-ip-diversity-patterns nsname=a.dns-servers.net.ru asn_diversity_min=2```
#### Human Readable Output



### silentpush-list-domain-information

***
This command get domain information along with Silent Push risk score and live whois information for multiple domains.

#### Base Command

`silentpush-list-domain-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domains to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Domain.host_flags | Unknown | The domain name queried. | 
| SilentPush.Domain.domain_urls | Unknown | The last seen date of the domain in YYYYMMDD format. | 
| SilentPush.Domain.domaininfo | Unknown | The domain name used for the query. | 
| SilentPush.Domain.ns_reputation | Unknown | The age of the domain in days based on WHOIS creation date. | 
| SilentPush.Domain.nschanges | Unknown | The first seen date of the domain in YYYYMMDD format. | 
| SilentPush.Domain.domain_string_frequency_probability | Unknown | Indicates whether the domain is newly observed. | 
| SilentPush.Domain.is_private_suffix | Boolean | The top-level domain \(TLD\) or zone of the queried domain. | 
| SilentPush.Domain.private_suffix_info | Unknown | The registrar responsible for the domain registration. | 
| SilentPush.Domain.ip_diversity | Unknown | A risk score based on the domain's age. | 
| SilentPush.Domain.listing_score | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. | 
| SilentPush.Domain.listing_score_explain | Unknown | A risk score indicating how new the domain is. | 
| SilentPush.Domain.listing_score_feeds_explain | Unknown | The age of the domain in days. | 
| SilentPush.Domain.sp_risk_score | Number | The age of the domain in days. | 
| SilentPush.Domain.sp_risk_score_explain | Unknown | The age of the domain in days. | 

#### Command example
```!silentpush-list-domain-information domains=silentpush.com,docs.silentpush.com```
#### Human Readable Output



### silentpush-list-ip4-information

***
This command get IP4 information along with Silent Push risk score 

#### Base Command

`silentpush-list-ip4-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Comma-separated list of IPs to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IP4.ip | String | The domain name queried. | 
| SilentPush.IP4.asn | Number | The last seen date of the domain in YYYYMMDD format. | 
| SilentPush.IP4.asname | String | The domain name used for the query. | 
| SilentPush.IP4.asn_allocation_date | Number | The age of the domain in days based on WHOIS creation date. | 
| SilentPush.IP4.asn_allocation_age | Number | The first seen date of the domain in YYYYMMDD format. | 
| SilentPush.IP4.asn_rank | Number | Indicates whether the domain is newly observed. | 
| SilentPush.IP4.asn_rank_score | Number | The top-level domain \(TLD\) or zone of the queried domain. | 
| SilentPush.IP4.asn_reputation | Number | The registrar responsible for the domain registration. | 
| SilentPush.IP4.asn_reputation_explain | Unknown | A risk score based on the domain's age. | 
| SilentPush.IP4.malscore | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. | 
| SilentPush.IP4.asn_takedown_reputation | Number | A risk score indicating how new the domain is. | 
| SilentPush.IP4.asn_takedown_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP4.asn_takedown_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP4.date | Number | The age of the domain in days. | 
| SilentPush.IP4.subnet | String | The age of the domain in days. | 
| SilentPush.IP4.subnet_allocation_date | Number | The age of the domain in days. | 
| SilentPush.IP4.subnet_allocation_age | Number | The age of the domain in days. | 
| SilentPush.IP4.subnet_reputation | Number | The age of the domain in days. | 
| SilentPush.IP4.subnet_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP4.subnet_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP4.ip_reputation | Number | The age of the domain in days. | 
| SilentPush.IP4.ip_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP4.ip_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP4.ip_location | Unknown | The age of the domain in days. | 
| SilentPush.IP4.ip_is_dsl_dynamic | Boolean | The age of the domain in days. | 
| SilentPush.IP4.ip_is_dsl_dynamic_score | Number | The age of the domain in days. | 
| SilentPush.IP4.ip_ptr | String | The age of the domain in days. | 
| SilentPush.IP4.benign_info | Unknown | The age of the domain in days. | 
| SilentPush.IP4.sinkhole_info | Unknown | The age of the domain in days. | 
| SilentPush.IP4.ip_is_tor_exit_node | Boolean | The age of the domain in days. | 
| SilentPush.IP4.ip_is_ipfs_node | Boolean | The age of the domain in days. | 
| SilentPush.IP4.ip_has_open_directory | Boolean | The age of the domain in days. | 
| SilentPush.IP4.ip_has_expired_certificate | Boolean | The age of the domain in days. | 
| SilentPush.IP4.ip_flags | Unknown | The age of the domain in days. | 
| SilentPush.IP4.density | Number | The age of the domain in days. | 
| SilentPush.IP4.listing_score | Number | The age of the domain in days. | 
| SilentPush.IP4.listing_score_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP4.listing_score_feeds_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP4.sp_risk_score | Number | The age of the domain in days. | 
| SilentPush.IP4.sp_risk_score_explain | Unknown | The age of the domain in days. | 

#### Command example
```!silentpush-list-ip4-information ips=173.245.58.236,173.245.58.237```
#### Human Readable Output



### silentpush-list-ip6-information

***
This command get IP6 information along with Silent Push risk score 

#### Base Command

`silentpush-list-ip6-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Comma-separated list of IPs to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IP6.ip | String | The domain name queried. | 
| SilentPush.IP6.asn | Number | The last seen date of the domain in YYYYMMDD format. | 
| SilentPush.IP6.asname | String | The domain name used for the query. | 
| SilentPush.IP6.asn_allocation_date | Number | The age of the domain in days based on WHOIS creation date. | 
| SilentPush.IP6.asn_allocation_age | Number | The first seen date of the domain in YYYYMMDD format. | 
| SilentPush.IP6.asn_rank | Number | Indicates whether the domain is newly observed. | 
| SilentPush.IP6.asn_rank_score | Number | The top-level domain \(TLD\) or zone of the queried domain. | 
| SilentPush.IP6.asn_reputation | Number | The registrar responsible for the domain registration. | 
| SilentPush.IP6.asn_reputation_explain | Unknown | A risk score based on the domain's age. | 
| SilentPush.IP6.malscore | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. | 
| SilentPush.IP6.asn_takedown_reputation | Number | A risk score indicating how new the domain is. | 
| SilentPush.IP6.asn_takedown_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP6.asn_takedown_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP6.date | Number | The age of the domain in days. | 
| SilentPush.IP6.subnet | String | The age of the domain in days. | 
| SilentPush.IP6.subnet_allocation_date | Number | The age of the domain in days. | 
| SilentPush.IP6.subnet_allocation_age | Number | The age of the domain in days. | 
| SilentPush.IP6.subnet_reputation | Number | The age of the domain in days. | 
| SilentPush.IP6.subnet_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP6.subnet_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP6.ip_reputation | Number | The age of the domain in days. | 
| SilentPush.IP6.ip_reputation_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP6.ip_reputation_score | Number | The age of the domain in days. | 
| SilentPush.IP6.ip_location | Unknown | The age of the domain in days. | 
| SilentPush.IP6.ip_is_dsl_dynamic | Boolean | The age of the domain in days. | 
| SilentPush.IP6.ip_is_dsl_dynamic_score | Number | The age of the domain in days. | 
| SilentPush.IP6.ip_ptr | String | The age of the domain in days. | 
| SilentPush.IP6.benign_info | Unknown | The age of the domain in days. | 
| SilentPush.IP6.sinkhole_info | Unknown | The age of the domain in days. | 
| SilentPush.IP6.ip_is_tor_exit_node | Boolean | The age of the domain in days. | 
| SilentPush.IP6.ip_is_ipfs_node | Boolean | The age of the domain in days. | 
| SilentPush.IP6.ip_has_open_directory | Boolean | The age of the domain in days. | 
| SilentPush.IP6.ip_has_expired_certificate | Boolean | The age of the domain in days. | 
| SilentPush.IP6.ip_flags | Unknown | The age of the domain in days. | 
| SilentPush.IP6.density | Number | The age of the domain in days. | 
| SilentPush.IP6.listing_score | Number | The age of the domain in days. | 
| SilentPush.IP6.listing_score_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP6.listing_score_feeds_explain | Unknown | The age of the domain in days. | 
| SilentPush.IP6.sp_risk_score | Number | The age of the domain in days. | 
| SilentPush.IP6.sp_risk_score_explain | Unknown | The age of the domain in days. | 

#### Command example
```!silentpush-list-ip6-information ips=2606:4700:4700::1111,2a02:4780:37:b262:f807:71a8:e3ee:9b64```
#### Human Readable Output



### silentpush-live-url-scan

***
This command scan a URL to retrieve hosting metadata.

#### Base Command

`silentpush-live-url-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to scan. | Required | 
| platform | Platform to scan the URL on. | Optional | 
| os | Operating system to scan the URL on. | Optional | 
| browser | Browser to scan the URL on. | Optional | 
| region | Region to scan the URL in. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.URLScan.HHV | String | Unique identifier for HHV. | 
| SilentPush.URLScan.adtech.ads_txt | Boolean | Indicates if ads_txt is present. | 
| SilentPush.URLScan.adtech.app_ads_txt | Boolean | Indicates if app_ads_txt is present. | 
| SilentPush.URLScan.adtech.sellers_json | Boolean | Indicates if sellers_json is present. | 
| SilentPush.URLScan.datahash | String | Hash value of the data. | 
| SilentPush.URLScan.domain | String | The domain name. | 
| SilentPush.URLScan.favicon2_avg | String | Hash value for favicon2 average. | 
| SilentPush.URLScan.favicon2_md5 | String | MD5 hash for favicon2. | 
| SilentPush.URLScan.favicon2_murmur3 | Number | Murmur3 hash for favicon2. | 
| SilentPush.URLScan.favicon2_path | String | Path to favicon2 image. | 
| SilentPush.URLScan.favicon_avg | String | Hash value for favicon average. | 
| SilentPush.URLScan.favicon_md5 | String | MD5 hash for favicon. | 
| SilentPush.URLScan.favicon_murmur3 | String | Murmur3 hash for favicon. | 
| SilentPush.URLScan.favicon_path | String | Path to favicon image. | 
| SilentPush.URLScan.favicon_urls | Unknown | List of favicon URLs. | 
| SilentPush.URLScan.header.cache-control | String | Cache control header value. | 
| SilentPush.URLScan.header.content-encoding | String | Content encoding header value. | 
| SilentPush.URLScan.header.content-type | String | Content type header value. | 
| SilentPush.URLScan.header.server | String | Server header value. | 
| SilentPush.URLScan.header.x-powered-by | String | X-Powered-By header value. | 
| SilentPush.URLScan.hostname | String | The hostname of the server. | 
| SilentPush.URLScan.html_body_length | Number | Length of the HTML body. | 
| SilentPush.URLScan.html_body_murmur3 | Number | Murmur3 hash for the HTML body. | 
| SilentPush.URLScan.html_body_sha256 | String | SHA256 hash for the HTML body. | 
| SilentPush.URLScan.html_body_similarity | Number | Similarity score of the HTML body. | 
| SilentPush.URLScan.html_body_ssdeep | String | ssdeep hash for the HTML body. | 
| SilentPush.URLScan.htmltitle | String | The HTML title of the page. | 
| SilentPush.URLScan.ip | String | IP address associated with the domain. | 
| SilentPush.URLScan.jarm | String | JARM \(TLS fingerprint\) value. | 
| SilentPush.URLScan.mobile_enabled | Boolean | Indicates if the mobile version is enabled. | 
| SilentPush.URLScan.opendirectory | Boolean | Indicates if open directory is enabled. | 
| SilentPush.URLScan.origin_domain | String | Origin domain of the server. | 
| SilentPush.URLScan.origin_hostname | String | Origin hostname of the server. | 
| SilentPush.URLScan.origin_ip | String | Origin IP address of the server. | 
| SilentPush.URLScan.origin_jarm | String | JARM \(TLS fingerprint\) value for the origin. | 
| SilentPush.URLScan.origin_path | String | Origin path for the URL. | 
| SilentPush.URLScan.origin_port | Number | Port used for the origin server. | 
| SilentPush.URLScan.origin_ssl.CHV | String | SSL Certificate Chain Value \(CHV\). | 
| SilentPush.URLScan.origin_ssl.SHA1 | String | SHA1 hash of the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.SHA256 | String | SHA256 hash of the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.authority_key_id | String | Authority Key Identifier for SSL certificate. | 
| SilentPush.URLScan.origin_ssl.expired | Boolean | Indicates if the SSL certificate is expired. | 
| SilentPush.URLScan.origin_ssl.issuer.common_name | String | Issuer common name for SSL certificate. | 
| SilentPush.URLScan.origin_ssl.issuer.country | String | Issuer country for SSL certificate. | 
| SilentPush.URLScan.origin_ssl.issuer.organization | String | Issuer organization for SSL certificate. | 
| SilentPush.URLScan.origin_ssl.not_after | String | Expiration date of the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.not_before | String | Start date of the SSL certificate validity. | 
| SilentPush.URLScan.origin_ssl.sans | Unknown | List of Subject Alternative Names \(SANs\) for the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.sans_count | Number | Count of SANs for the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.serial_number | String | Serial number of the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.sigalg | String | Signature algorithm used for the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.subject.common_name | String | Subject common name for the SSL certificate. | 
| SilentPush.URLScan.origin_ssl.subject_key_id | String | Subject Key Identifier for SSL certificate. | 
| SilentPush.URLScan.origin_ssl.valid | Boolean | Indicates if the SSL certificate is valid. | 
| SilentPush.URLScan.origin_ssl.wildcard | Boolean | Indicates if the SSL certificate is a wildcard. | 
| SilentPush.URLScan.origin_subdomain | String | Subdomain of the origin. | 
| SilentPush.URLScan.origin_tld | String | Top-level domain of the origin. | 
| SilentPush.URLScan.origin_url | String | Complete URL of the origin. | 
| SilentPush.URLScan.path | String | Path for the URL. | 
| SilentPush.URLScan.port | Number | Port for the URL. | 
| SilentPush.URLScan.proxy_enabled | Boolean | Indicates if the proxy is enabled. | 
| SilentPush.URLScan.redirect | Boolean | Indicates if a redirect occurs. | 
| SilentPush.URLScan.redirect_count | Number | Count of redirects. | 
| SilentPush.URLScan.redirect_list | Unknown | List of redirect URLs. | 
| SilentPush.URLScan.resolves_to | Unknown | List of IPs the domain resolves to. | 
| SilentPush.URLScan.response | Number | HTTP response code. | 
| SilentPush.URLScan.scheme | String | URL scheme \(e.g., https\). | 
| SilentPush.URLScan.screenshot | String | URL for the domain screenshot. | 
| SilentPush.URLScan.ssl.CHV | String | SSL Certificate Chain Value \(CHV\). | 
| SilentPush.URLScan.ssl.SHA1 | String | SHA1 hash of the SSL certificate. | 
| SilentPush.URLScan.ssl.SHA256 | String | SHA256 hash of the SSL certificate. | 
| SilentPush.URLScan.ssl.authority_key_id | String | Authority Key Identifier for SSL certificate. | 
| SilentPush.URLScan.ssl.expired | Boolean | Indicates if the SSL certificate is expired. | 
| SilentPush.URLScan.ssl.issuer.common_name | String | Issuer common name for SSL certificate. | 
| SilentPush.URLScan.ssl.issuer.country | String | Issuer country for SSL certificate. | 
| SilentPush.URLScan.ssl.issuer.organization | String | Issuer organization for SSL certificate. | 
| SilentPush.URLScan.ssl.not_after | String | Expiration date of the SSL certificate. | 
| SilentPush.URLScan.ssl.not_before | String | Start date of the SSL certificate validity. | 
| SilentPush.URLScan.ssl.sans | Unknown | List of Subject Alternative Names \(SANs\) for the SSL certificate. | 
| SilentPush.URLScan.ssl.sans_count | Number | Count of SANs for the SSL certificate. | 
| SilentPush.URLScan.ssl.serial_number | String | Serial number of the SSL certificate. | 
| SilentPush.URLScan.ssl.sigalg | String | Signature algorithm used for the SSL certificate. | 
| SilentPush.URLScan.ssl.subject.common_name | String | Subject common name for the SSL certificate. | 
| SilentPush.URLScan.ssl.subject_key_id | String | Subject Key Identifier for SSL certificate. | 
| SilentPush.URLScan.ssl.valid | Boolean | Indicates if the SSL certificate is valid. | 
| SilentPush.URLScan.ssl.wildcard | Boolean | Indicates if the SSL certificate is a wildcard. | 
| SilentPush.URLScan.body_analysis.SHV | String | Unique identifier for body analysis. | 
| SilentPush.URLScan.body_analysis.body_sha256 | String | SHA-256 hash of the body content. | 
| SilentPush.URLScan.body_analysis.google-GA4 | Unknown | List of Google GA4 tracking IDs. | 
| SilentPush.URLScan.body_analysis.google-UA | Unknown | List of Google Universal Analytics tracking IDs. | 
| SilentPush.URLScan.body_analysis.google-adstag | Unknown | List of Google Adstag tracking IDs. | 
| SilentPush.URLScan.body_analysis.js_sha256 | Unknown | List of SHA-256 hashes of JavaScript files. | 
| SilentPush.URLScan.body_analysis.js_ssdeep | Unknown | List of ssdeep fuzzy hashes of JavaScript files. | 

#### Command example
```!silentpush-live-url-scan url=URL region=EU proxy=mu platform=Mobile```
#### Human Readable Output



### silentpush-multi-conditional-padns-lookup

***
This command searches passive DNS data for records matching both query and answer.

#### Base Command

`silentpush-multi-conditional-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| last_seen_after | Filter results to include only records last seen after this date. | Optional | 
| last_seen_before | Filter results to include only records last seen before this date. | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| qtype | DNS record type. | Required | 
| query | The DNS record name to lookup. | Required | 
| netmask | The netmask to filter the lookup results. | Optional | 
| match | Type of match for the query (e.g., exact, partial). | Optional | 
| as_of | Date or time to get the DNS records as of a specific point in time. | Optional | 
| sort | Sort the results by the specified field (e.g., date, score). | Optional | 
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| answer | DNS record answer to lookup. | Required | 
| name | additional name to match qanswer, up to 5. | Optional | 
| net | find ptr4 or a records where ipv4 in or not in subnet defined by netmask. in (default) - find records in subnet, notin - find records not in subnet. | Optional | 
| network | additional network and net mask in the format 1.1.1.1/24, up to 5. | Optional | 
| asnum | Autonomous System (AS) number to filter domains. | Optional | 
| asn | include asn diversity, 0 = do not include, 1 (default) = include asn diversity. | Optional | 
| asname | Search for all AS numbers where the AS Name begins with the specified value. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.MultiConditionalPADNSLookup.qname | String | The DNS record name that was looked up. | 
| SilentPush.MultiConditionalPADNSLookup.qtype | String | The DNS record type queried \(e.g., NS\). | 
| SilentPush.MultiConditionalPADNSLookup.records.answer | String | The answer \(e.g., name server\) for the DNS record. | 
| SilentPush.MultiConditionalPADNSLookup.records.count | Number | The number of occurrences for this DNS record. | 
| SilentPush.MultiConditionalPADNSLookup.records.first_seen | String | The timestamp when this DNS record was first seen. | 
| SilentPush.MultiConditionalPADNSLookup.records.last_seen | String | The timestamp when this DNS record was last seen. | 
| SilentPush.MultiConditionalPADNSLookup.records.nshash | String | Unique hash for the DNS record. | 
| SilentPush.MultiConditionalPADNSLookup.records.query | String | The DNS record query name \(e.g., silentpush.com\). | 
| SilentPush.MultiConditionalPADNSLookup.records.ttl | Number | Time to live \(TTL\) value for the DNS record. | 
| SilentPush.MultiConditionalPADNSLookup.records.type | String | The type of the DNS record \(e.g., NS\). | 

#### Command example
```!silentpush-multi-conditional-padns-lookup qtype=ns query=silenpush.com answer=a.dns-servers.net.ru last_seen_after=2021-07-01```
#### Human Readable Output



### silentpush-retry-job

***
This command retry another command which returned a Job ID

#### Base Command

`silentpush-retry-job`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The Job ID to retry. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!silentpush-retry-job job_id=c20664f4-6516-40d9-bd4a-e089ef67684e```
#### Human Readable Output



### silentpush-reverse-padns-lookup

***
This command retrieve reverse Passive DNS data for specific DNS record types.

#### Base Command

`silentpush-reverse-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| last_seen_after | Filter results to include only records last seen after this date. | Optional | 
| last_seen_before | Filter results to include only records last seen before this date. | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| qtype | DNS record type. | Required | 
| query | The DNS record name to lookup. | Required | 
| netmask | The netmask to filter the lookup results. | Optional | 
| match | Type of match for the query (e.g., exact, partial). | Optional | 
| as_of | Date or time to get the DNS records as of a specific point in time. | Optional | 
| sort | Sort the results by the specified field (e.g., date, score). | Optional | 
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ReversePADNSLookup.qname | String | The DNS record name that was looked up. | 
| SilentPush.ReversePADNSLookup.qtype | String | The DNS record type queried \(e.g., NS\). | 
| SilentPush.ReversePADNSLookup.records.answer | String | The answer \(e.g., name server\) for the DNS record. | 
| SilentPush.ReversePADNSLookup.records.count | Number | The number of occurrences for this DNS record. | 
| SilentPush.ReversePADNSLookup.records.first_seen | String | The timestamp when this DNS record was first seen. | 
| SilentPush.ReversePADNSLookup.records.last_seen | String | The timestamp when this DNS record was last seen. | 
| SilentPush.ReversePADNSLookup.records.nshash | String | Unique hash for the DNS record. | 
| SilentPush.ReversePADNSLookup.records.query | String | The DNS record query name \(e.g., silentpush.com\). | 
| SilentPush.ReversePADNSLookup.records.ttl | Number | Time to live \(TTL\) value for the DNS record. | 
| SilentPush.ReversePADNSLookup.records.type | String | The type of the DNS record \(e.g., NS\). | 

#### Command example
```!silentpush-reverse-padns-lookup qtype=a query=173.245.58.236```
#### Human Readable Output



### silentpush-run-threat-check

***
This command runs the threat check on the specified 

#### Base Command

`silentpush-run-threat-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The name of the data source to query. | Required | 
| query | The value to check for threats (e.g., IP or domain). | Required | 
| type | The type of the value being queried (e.g., ip, domain). | Required | 
| user_identifier | A unique identifier for the user making the request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.RunThreatCheck.is_listed | Boolean | Indicates whether the queried value is listed as a threat. | 
| SilentPush.RunThreatCheck.listed_txt | String | Textual description of the listing status. | 
| SilentPush.RunThreatCheck.query | String | The original value that was checked. | 

#### Command example
```!silentpush-run-threat-check data=iofa query=173.245.58.236 type=ip user_identifier=c20664f4-6516-40d9-bd4a-e089ef67684e```
#### Human Readable Output



### silentpush-search-domains

***
This command search for domains with optional filters.

#### Base Command

`silentpush-search-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| domain | Name or wildcard pattern of domain names to search for. | Optional | 
| domain_regex | A valid RE2 regex pattern to match domains. Overrides the domain argument. | Optional | 
| nsname | Name server name or wildcard pattern of the name server used by domains. | Optional | 
| mxname | mx server name or wildcard pattern of mx server used by domains, use mxname=self to find domains hosting their own mailservers. | Optional | 
| first_seen_min | only domains that have A records seen for the first time after the given date. | Optional | 
| first_seen_max | only domains that have A records seen for the first time before the given date. | Optional | 
| first_seen_min_mode | match mode for first_seen_min parameter, strict (default) - select A records that do not have any timestamps before first_seen_min, any - select A records that have at least one timestamp after first_seen_min. | Optional | 
| first_seen_max_mode | match mode for first_seen_max parameter, strict (default) - select A records that do not have any timestamps after first_seen_max, any - select A records that have at least one timestamp before first_seen_max. | Optional | 
| last_seen_min | only domains that have A records last seen more recently than the given date. | Optional | 
| last_seen_max | only domains that have A records last seen earlier than the given date. | Optional | 
| last_seen_min_mode | match mode for last_seen_min parameter, strict - select A records that do not have any timestamps before last_seen_min, any (default) - select A records that have at least one timestamp after first_seen_min. | Optional | 
| last_seen_max_mode | match mode for last_seen_max parameter, strict (default) - select A records that do not have any timestamps after last_seen_max, any - select A records that have at least one timestamp before last_seen_max. | Optional | 
| asnum | Autonomous System (AS) number to filter domains. | Optional | 
| asname | Search for all AS numbers where the AS Name begins with the specified value. | Optional | 
| network | additional network and net mask, give option as 1.1.1.1/24, network parameter may be given multiple times and the search will be performed as an ‘or’ condition. | Optional | 
| timeline | include details of IPs, ASNs, first_seen and last_seen for each domain, 0 (default) = do not include, 1 = include timeline. | Optional | 
| ip_diversity_all_min | Minimum IP diversity limit to filter domains. | Optional | 
| registrar | Name or partial name of the registrar used to register domains. | Optional | 
| email | email used to register domains - no wildcards, the given string is used in exact match - this is a slow search option and should only be used in combination with the domain match option. | Optional | 
| nschange_from_ns | domain has changed name server from nsname, exact match, wildcards and ‘self’ options supported. | Optional | 
| nschange_to_ns | domain has changed name server to nsname, exact match, wildcards and ‘self’ options supported. | Optional | 
| nschange_date_after | only domains with name server changes that occurred after the given date, if nschange_date_after is not given, the default is to find name server changes in the last 30 days, if nschange_date_before is not given. | Optional | 
| nschange_date_before | only domains with name server changes that occurred before the given date. | Optional | 
| cert_date_min | only domains that have had ssl certificates issued on or after the given date. | Optional | 
| cert_date_max | only domains that have had ssl certificates issued on or before the given date. | Optional | 
| cert_issuer | Filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported. | Optional | 
| infratag | search by infratag, infratag must include mx part, ns part, asname part, or registrar part, overrides mxname, nsname and registrar parameters, if infratag contains these parts, can be combined with all other parameters. | Optional | 
| asn_diversity_min | Minimum ASN diversity limit to filter domains. | Optional | 
| ip_diversity_all_min | minimum diversity limit, default = 1. | Optional | 
| ip_diversity_groups_min | minimum diversity limit. | Optional | 
| whois_date_after | Filter domains with a WHOIS creation date after this date (YYYY-MM-DD). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPDiversityPatterns.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. | 
| SilentPush.IPDiversityPatterns.host | String | The domain name \(host\) associated with the record. | 
| SilentPush.IPDiversityPatterns.ip_diversity_all | Number | The total number of unique IPs associated with the domain. | 
| SilentPush.IPDiversityPatterns.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. | 
| SilentPush.IPDiversityPatterns.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. | 

#### Command example
```!silentpush-search-domains name_server=a.dns-servers.net.ru min_asn_diversity=2 limit=3 timeline=1```
#### Human Readable Output



### silentpush-search-scan-data

***
This command search Silent Push scan data repositories using SPQL queries.

#### Base Command

`silentpush-search-scan-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | SPQL query string. | Required | 
| fields | Fields to return in the response. | Optional | 
| sort | Sorting criteria for results. | Optional | 
| skip | Number of records to skip in the response. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| with_metadata | Whether to include metadata in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ScanData.HHV | String | Unique identifier for the scan data entry. | 
| SilentPush.ScanData.adtech | Unknown | Adtech information for the scan data entry. | 
| SilentPush.ScanData.adtech.ads_txt | Boolean | Indicates if ads.txt is used. | 
| SilentPush.ScanData.adtech.app_ads_txt | Boolean | Indicates if app_ads.txt is used. | 
| SilentPush.ScanData.adtech.sellers_json | Boolean | Indicates if sellers.json is used. | 
| SilentPush.ScanData.body_analysis | Unknown | Body analysis for the scan data entry. | 
| SilentPush.ScanData.body_analysis.body_sha256 | String | SHA256 hash of the body. | 
| SilentPush.ScanData.body_analysis.language | Unknown | Languages detected in the body. | 
| SilentPush.ScanData.body_analysis.ICP_license | String | ICP License information. | 
| SilentPush.ScanData.body_analysis.SHV | String | Server Hash Verification value. | 
| SilentPush.ScanData.body_analysis.adsense | Unknown | List of AdSense data. | 
| SilentPush.ScanData.body_analysis.footer_sha256 | String | SHA-256 hash of the footer content. | 
| SilentPush.ScanData.body_analysis.google-GA4 | Unknown | List of Google GA4 identifiers. | 
| SilentPush.ScanData.body_analysis.google-UA | Unknown | List of Google Universal Analytics identifiers. | 
| SilentPush.ScanData.body_analysis.google-adstag | Unknown | List of Google adstag identifiers. | 
| SilentPush.ScanData.body_analysis.header_sha256 | Unknown | SHA-256 hash of the header content. | 
| SilentPush.ScanData.body_analysis.js_sha256 | Unknown | List of JavaScript files with SHA-256 hash values. | 
| SilentPush.ScanData.body_analysis.js_ssdeep | Unknown | List of JavaScript files with SSDEEP hash values. | 
| SilentPush.ScanData.body_analysis.onion | Unknown | List of Onion URLs detected. | 
| SilentPush.ScanData.body_analysis.telegram | Unknown | List of Telegram-related information. | 
| SilentPush.ScanData.datahash | String | Hash of the data. | 
| SilentPush.ScanData.datasource | String | Source of the scan data. | 
| SilentPush.ScanData.domain | String | Domain associated with the scan data. | 
| SilentPush.ScanData.geoip | Unknown | GeoIP information related to the scan. | 
| SilentPush.ScanData.geoip.city_name | String | City where the scan data was retrieved. | 
| SilentPush.ScanData.geoip.country_name | String | Country name from GeoIP information. | 
| SilentPush.ScanData.geoip.location | Unknown | Geo-location coordinates. | 
| SilentPush.ScanData.geoip.location.lat | Number | Latitude from GeoIP location. | 
| SilentPush.ScanData.geoip.location.lon | Number | Longitude from GeoIP location. | 
| SilentPush.ScanData.header | Unknown | HTTP header information for the scan. | 
| SilentPush.ScanData.header.content-length | String | Content length from HTTP response header. | 
| SilentPush.ScanData.header.location | String | Location from HTTP response header. | 
| SilentPush.ScanData.header.connection | String | Connection type used, e.g., keep-alive. | 
| SilentPush.ScanData.header.server | String | Server software used to serve the content, e.g., openresty. | 
| SilentPush.ScanData.hostname | String | Hostname associated with the scan data. | 
| SilentPush.ScanData.html_body_sha256 | String | SHA256 hash of the HTML body. | 
| SilentPush.ScanData.htmltitle | String | Title of the HTML page scanned. | 
| SilentPush.ScanData.ip | String | IP address associated with the scan. | 
| SilentPush.ScanData.jarm | String | JARM hash value. | 
| SilentPush.ScanData.mobile_enabled | Boolean | Indicates if the page is mobile-enabled. | 
| SilentPush.ScanData.origin_domain | String | Origin domain associated with the scan. | 
| SilentPush.ScanData.origin_geoip | Unknown | GeoIP information of the origin domain. | 
| SilentPush.ScanData.origin_geoip.city_name | String | City of the origin domain from GeoIP information. | 
| SilentPush.ScanData.origin_hostname | String | Origin hostname associated with the scan data. | 
| SilentPush.ScanData.origin_ip | String | Origin IP address of the scan. | 
| SilentPush.ScanData.origin_jarm | String | JARM hash value of the origin domain. | 
| SilentPush.ScanData.origin_ssl | Unknown | SSL certificate information for the origin domain. | 
| SilentPush.ScanData.origin_ssl.SHA256 | String | SHA256 of the SSL certificate. | 
| SilentPush.ScanData.origin_ssl.subject | Unknown | Subject of the SSL certificate. | 
| SilentPush.ScanData.origin_ssl.subject.common_name | String | Common name in the SSL certificate. | 
| SilentPush.ScanData.port | Number | Port used during the scan. | 
| SilentPush.ScanData.redirect | Boolean | Indicates if a redirect occurred during the scan. | 
| SilentPush.ScanData.redirect_count | Number | Count of redirects encountered. | 
| SilentPush.ScanData.redirect_list | Unknown | List of redirect URLs encountered during the scan. | 
| SilentPush.ScanData.response | Number | HTTP response code received during the scan. | 
| SilentPush.ScanData.scan_date | String | Timestamp of the scan date. | 
| SilentPush.ScanData.scheme | String | URL scheme used in the scan. | 
| SilentPush.ScanData.ssl | Unknown | SSL certificate details for the scan. | 
| SilentPush.ScanData.ssl.SHA256 | String | SHA256 of the SSL certificate. | 
| SilentPush.ScanData.ssl.subject | Unknown | Subject of the SSL certificate. | 
| SilentPush.ScanData.ssl.subject.common_name | String | Common name in the SSL certificate. | 
| SilentPush.ScanData.subdomain | String | Subdomain associated with the scan data. | 
| SilentPush.ScanData.tld | String | Top-level domain \(TLD\) of the scanned URL. | 
| SilentPush.ScanData.url | String | The URL scanned. | 

#### Command example
```!silentpush-search-scan-data query=domain=silenpush.com fields=scan_date,a.dns-servers.net.runame,silenpush.com,ip,user-agent sort=scan_date/desc,silenpush.com/asc limit=10```
#### Human Readable Output



### silentpush-whois

***
This command get Whois information

#### Base Command

`silentpush-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.whois.whois.registrar | String | Name or partial name of the registrar used to register domains. | 
| SilentPush.whois.whois.name | String | The registrant name | 
| SilentPush.whois.whois.whois_server | String | The server queried | 
| SilentPush.whois.whois.org | String | Organization | 
| SilentPush.whois.whois.address | String | Address | 
| SilentPush.whois.whois.city | Number | City | 
| SilentPush.whois.whois.country | String | Country | 
| SilentPush.whois.whois.created | String | Date created | 
| SilentPush.whois.whois.date | String | Date | 
| SilentPush.whois.whois.domain | String | Domain | 
| SilentPush.whois.whois.emails | Number | Emails | 
| SilentPush.whois.whois.expires | String | Expires | 
| SilentPush.whois.whois.nameservers | String | Nameservers | 
| SilentPush.whois.whois.state | String | State | 
| SilentPush.whois.whois.updated | String | Date updated | 
| SilentPush.whois.whois.zipcode | String | Zip code | 

#### Command example
```!silentpush-whois domain=silenpush.com```
#### Human Readable Output


