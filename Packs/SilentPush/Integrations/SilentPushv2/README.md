The Silent Push Platform uses first-party data and a proprietary scanning engine to enrich global DNS data with risk and reputation scoring, giving security teams the ability to join the dots across the entire IPv4 and IPv6 range, and identify adversary infrastructure before an attack is launched. The content pack integrates with the Silent Push system to gain insights into domain/IP information, reputations, enrichment, and infratag-related details. It also provides functionality to live-scan URLs and take screenshots of them. Additionally, it allows fetching future attack feeds from the Silent Push system.
This integration was integrated and tested with version xx of SilentPush_v2.

## Configure SilentPush in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| API Key | False |
| Password | False |
| The Threat Check key | False |
| Password | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### silentpush-add-feed

***
add the new feed

#### Base Command

`silentpush-add-feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the feed. | Required |
| type | The Feed Type. | Required |
| category | The Feed Category. | Optional |
| vendor | The Vendor. | Optional |
| feed_description | The detailed info about the feed. | Optional |
| tags | The Tags that should be attached with the feed. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Feed.SilentPush.Feed.name | String | The name of the feed. |
| SilentPush.Feed.SilentPush.Feed.type | String | The type of the feed. |
| SilentPush.Feed.SilentPush.Feed.vendor | String | The vendor of the feed. |
| SilentPush.Feed.SilentPush.Feed.feed_description | String | A description of the feed. |
| SilentPush.Feed.SilentPush.Feed.category | String | The category of the feed. |
| SilentPush.Feed.SilentPush.Feed.tags | Unknown | Tags associated with the feed. |

#### Command example

```!silentpush-add-feed name=myFeed type=domain```

#### Human Readable Output

### silentpush-add-feed-tags

***
add indicators to the feed

#### Base Command

`silentpush-add-feed-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Optional |
| tags | A comma separated tags to be updated to the feed. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddFeedTags.SilentPush.Feed.created_or_updated | Unknown | List of indicator names that were created or updated in the feed. |
| SilentPush.AddFeedTags.SilentPush.Feed.invalid_indicators | Unknown | List of indicators that were considered invalid and not added to the feed. |

#### Command example

```!silentpush-add-feed-tags feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e tags=Tag1,Tag2```

#### Human Readable Output

### silentpush-add-indicators

***
add indicators to the feed

#### Base Command

`silentpush-add-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Required |
| indicators | The Indicators for the feed. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddIndicators.SilentPush.Feed.created_or_updated | Unknown | List of indicator names that were created or updated in the feed. |
| SilentPush.AddIndicators.SilentPush.Feed.invalid_indicators | Unknown | List of indicators that were considered invalid and not added to the feed. |

#### Command example

```!silentpush-add-indicators feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e indicators=example.com,198.51.100.1```

#### Human Readable Output

### silentpush-add-indicator-tags

***
updates tags to the indicators

#### Base Command

`silentpush-add-indicator-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | The feed uuid that is returned when creating it. | Required |
| indicator_name | The name of the indicator to tag. | Required |
| tags | The Tags to be added to the indicator. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.AddIndicatorTags.SilentPush.Feed.uuid | String | The UUID of the indicator. |
| SilentPush.AddIndicatorTags.SilentPush.Feed.name | String | The name of the indicator. |
| SilentPush.AddIndicatorTags.SilentPush.Feed.tags | String | The tags assigned to the indicator. |

#### Command example

```!silentpush-add-indicator-tags feed_uuid=c20664f4-6516-40d9-bd4a-e089ef67684e indicator_name=example.com tags=Tag3,Tag4```

#### Human Readable Output

### silentpush-bulk-enrich

***
enriches IPs or Domains in a bulk

#### Base Command

`silentpush-bulk-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The type of resource for which information needs to be retrieved {e.g. domain}. | Required |
| value | The value corresponding to the selected "resource" for which information needs to be retrieved {e.g. silentpush.com}. | Required |
| explain | Whether include explanation of data calculations. | Optional |
| scan_data | Whether include scan data (IPv4 only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.value | String | Queried value. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.avg_probability | Number | Average probability score of the domain string. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.dga_probability_score | Number | Probability score indicating likelihood of being a DGA domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain | String | Domain name analyzed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain_string_freq_probabilities | Unknown | List of frequency probabilities for different domain string components. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.query | String | Domain name queried. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.alexa_rank | Number | Alexa rank of the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.alexa_top10k | Boolean | Indicates if the domain is in the Alexa top 10k. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.alexa_top10k_score | Number | Score indicating domain's Alexa top 10k ranking. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.dynamic_domain_score | Number | Score indicating likelihood of domain being dynamically generated. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_dynamic_domain | Boolean | Indicates if the domain is dynamic. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_url_shortener | Boolean | Indicates if the domain is a known URL shortener. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.results | Number | Number of results found for the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.url_shortner_score | Number | Score of the shortened URL. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain | String | Domain name analyzed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.error | String | Error message if no data is available for the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.zone | String | TLD zone of the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.registrar | String | registrar of the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.whois_age | String | The age of the domain based on WHOIS records. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.whois_created_date | String | The created date on WHOIS records. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.query | String | The domain name that was queried in the system. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.last_seen | Number | The first recorded observation of the domain in the database. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.first_seen | Number | The last recorded observation of the domain in the database. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_new | Boolean | Indicates whether the domain is considered "new.". |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_new_score | Number | A scoring metric indicating how "new" the domain is. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.age | Number | Represents the age of the domain in days. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.age_score | Number | A scoring metric indicating the trustworthiness of the domain based on its age. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_diversity | String | Number of different ASNs associated with the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_diversity_all | String | Total number of unique IPs observed for the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.host | String | The hostname being analyzed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_diversity_groups | String | The number of distinct IP groups \(e.g., IPs belonging to different ranges or providers\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_expired | Boolean | Indicates if the domain\`s nameserver is expired. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_parked | Boolean | Whether the domain is not parked \(a parked domain is one without active content\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_sinkholed | Boolean | Whether the domain is not sinkholed \(not forcibly redirected to a security researcher\`s trap\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_reputation_max | Number | Maximum reputation score for nameservers. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_reputation_score | Number | Reputation score of the domain\`s nameservers. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain | String | The nameservers of domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_server | String | Provided nameserver. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_server_domain_density | Number | Number of domains sharing this NS. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_server_domains_listed | Number | Number of listed domains using this NS. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ns_server_reputation | Number | Reputation score for this NS. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain | String | Domain for which the SSL certificate was issued. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domains | Unknown | Other Domains for which the SSL certificate was issued. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.issuer_organization | String | Issuer organization of the SSL certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.fingerprint_sha1 | String | A unique identifier for the certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.hostname | String | The hostname associated with the certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip | String | The IP address of the server using this certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_expired | String | Indicates whether the certificate has expired. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.issuer_common_name | String | The Common Name \(CN\) of the Certificate Authority \(CA\) that issued this certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.not_after | String | Expiry date of the certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.not_before | String | Start date of the certificate validity. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | The date when this certificate data was last scanned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.response | String | HTTP response code for the domain scan. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.hostname | String | The hostname that sent this response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip | String | The IP address responding to the request. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | The date when the headers were scanned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.cache-control | String | HTTP cache-control. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.content-length | String | Content length of the HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.date | String | The date/time of the response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.expires | String | Indicates an already expired response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.server | String | The web server handling the request \(Cloudflare proxy\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.hostname | String | HTTP response code for the domain scan. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_body_murmur3 | String | hash of the page content. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_body_ssdeep | String | SSDEEP hash \(used for fuzzy matching similar HTML content\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_title | String | The page title \(suggests a Cloudflare challenge page, likely due to bot protection\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip | String | The IP address responding to the request. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | The date when the headers were scanned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_md5 | String | MD5 hash of a secondary favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_mmh3 | String | Murmur3 hash of a secondary favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_path | String | The file path of the secondary favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon_md5 | String | MD5 hash of the primary favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon_mmh3 | String | Murmur3 hash of the primary favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.hostname | String | The hostname where this favicon was found. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip | String | The IP address associated with the favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | Date when this favicon was last scanned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_hostname | String | The hostname where this jarm was found. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_ip | String | The IP address responding to the request. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_jarm_hash | String | Unique identifier for the TLS configuration of the server. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_scan_date | String | Date when this jarm was last scanned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.sp_risk_score | Number | Overall risk score for the domain. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.sp_risk_score_decider | String | Factor that determined the final risk score. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn | Number | Autonomous System Number \(ASN\) associated with the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_allocation_age | Number | Age of ASN allocation in days. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_allocation_date | Number | Date of ASN allocation. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_rank | Number | Rank of the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_rank_score | Number | Rank score of the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_reputation | Number | Reputation score of the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ips_in_asn | Number | Total number of IPs in the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ips_num_active | Number | Number of active IPs in the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ips_num_listed | Number | Number of listed IPs in the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_reputation_score | Number | Reputation score of the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_takedown_reputation | Number | Takedown reputation score the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ips_in_asn | Number | Total number of IPs in the ASN with takedown reputation. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ips_num_listed | Number | Number of listed IPs in the ASN with takedown reputation. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.items_num_listed | Number | Number of flagged items in the ASN with takedown reputation. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.listings_max_age | Number | Maximum age of listings for the ASN with takedown reputation. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asn_takedown_reputation_score | Number | Takedown reputation score of the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.asname | String | Name of the Autonomous System \(AS\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.actor | String | This field is usually used to indicate a known organization or individual associated with the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.known_benign | Boolean | Indicates whether this IP/ASN is explicitly known to be safe \(e.g., a reputable cloud provider or public service\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.tags | Unknown | Contains descriptive tags if the IP/ASN has a known role \(e.g., "Google Bot", "Cloudflare Proxy"\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.date | Number | Date of the scan data \(YYYYMMDD format\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.density | Number | The density value associated with the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip | String | IP address associated with the ASN. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_has_expired_certificate | Boolean | Indicates whether the IP has an expired SSL/TLS certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_has_open_directory | Boolean | Indicates whether the IP hosts an open directory listing. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_is_dsl_dynamic | Boolean | Whether the IP is from dynamic DSL pool. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_is_dsl_dynamic_score | Number | A score indicating how likely this IP is dynamic. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_is_ipfs_node | Boolean | the InterPlanetary File System \(IPFS\), a decentralized file storage system. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_is_tor_exit_node | Boolean | Tor exit node \(used for anonymous internet browsing\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.continent_code | String | abbreviation for the continent where the IP is located. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.continent_name | String | The full name of the continent. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.country_code | String | The ISO 3166-1 alpha-2 country code representing the country. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.country_is_in_european_union | Boolean | A Boolean value \(true/false\) indicating if the country is part of the European Union \(EU\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.country_name | String | The full name of the country where the IP is registered. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.ip_ptr | String | The reverse DNS \(PTR\) record for the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.listing_score | Number | Measures how frequently the IP appears in threat intelligence or blacklist databases. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.listing_score_explain | Unknown | A breakdown of why the listing score is assigned. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.malscore | Number | Malicious activity score for the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.hostname | String | Hostname associated with the SSL certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domain | String | Domain for which the SSL certificate was issued. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.fingerprint_sha1 | String | SHA-1 fingerprint of the SSL certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.issuer_common_name | String | Common name of the certificate issuer. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.issuer_organization | String | Organization that issued the SSL certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.not_before | String | Start date of SSL certificate validity. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.not_after | String | Expiration date of SSL certificate validity. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.domains | Unknown | Other domains for which the SSL certificate was issued. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.is_expired | Boolean | Is certificate expired. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | Scan date of the certificate. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_md5 | String | MD5 hash of the second favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_mmh3 | Number | MurmurHash3 value of the second favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon_md5 | String | MD5 hash of the favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon_mmh3 | Number | MurmurHash3 value of the favicon. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.favicon2_path | String | Path to the second favicon file. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | Scan date of favicon file. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.response | String | HTTP response code from the scan. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | The date and time when the scan was performed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.headers_server | String | Server header from the HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.headers_content-type | String | Content-Type header from the HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.headers_content-length | String | Content-Length header from the HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.headers_cache-control | String | Cache-control header from the HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.headers_date | String | Date header from HTTP response. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_title | String | Title of the scanned HTML page. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_body_murmur3 | String | MurmurHash3 of the HTML body content. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.html_body_ssdeep | String | SSDEEP fuzzy hash of the HTML body content. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_date | String | The date and time when the scan was performed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_scan_date | String | The date and time when the scan was performed. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.scan_data_jarm_jarm_hash | String | JARM fingerprint hash for TLS analysis. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.sp_risk_score | Number | Security risk score for the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.sp_risk_score_decider | String | Factor that determined the final risk score. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet | String | Subnet associated with the IP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.known_sinkhole_ip | Boolean | Indicates whether the IP is part of a sinkhole \(a controlled system that captures malicious traffic\). |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.tags | Unknown | If the IP were a known sinkhole, this field would contain tags describing its purpose. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet_allocation_age | Number | Represents the age \(in days\) since the subnet was allocated. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet_allocation_date | Number | The date when the subnet was assigned to an organization or ISP. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet_reputation | Number | A measure of how frequently IPs from this subnet appear in threat intelligence databases. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet_reputation_explain | Unknown | A breakdown of why the subnet received its reputation score. |
| SilentPush.Bulk.Enrich.SilentPush.Enrichment.subnet_reputation_score | Number | A numerical risk score \(typically 0-100, with higher values indicating higher risk\). |

#### Command example

```!silentpush-bulk-enrich resource=ipv4 value=198.51.100.1 explain=1 scan_data=1```

#### Human Readable Output

### silentpush-density-lookup

***
queries granular DNS/IP parameters (e.g., NS servers, MX servers, IPaddresses, ASNs) for density information.

#### Base Command

`silentpush-density-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qtype | The query type. | Required |
| query | The value to query. | Required |
| scope | The match level (optional). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.DensityLookup.SilentPush.Lookup.qtype | String | The following qtypes are supported: nssrv, mxsrv. |
| SilentPush.DensityLookup.SilentPush.Lookup.query | String | The query value to lookup, which can be the name of an NS or MX server. |
| SilentPush.DensityLookup.SilentPush.Lookup.density | Number | The density value associated with the query result. |
| SilentPush.DensityLookup.SilentPush.Lookup.nssrv | String | The name server \(NS\) for the query result. |

#### Command example

```!silentpush-density-lookup qtype=nssrv query=example.com```

#### Human Readable Output

### silentpush-forward-padns-lookup

***
performs a forward PADNS lookup using various filtering parameters.

#### Base Command

`silentpush-forward-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | The filter results to include only records first seen after this date. | Optional |
| first_seen_before | The filter results to include only records first seen before this date. | Optional |
| last_seen_after | The filter results to include only records last seen after this date. | Optional |
| last_seen_before | The filter results to include only records last seen before this date. | Optional |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| qtype | The DNS record type. | Required |
| query | The DNS record name to lookup. | Required |
| netmask | The netmask to filter the lookup results. | Optional |
| match | The type of match for the query (e.g., exact, partial). | Optional |
| as_of | The date or time to get the DNS records as of a specific point in time. | Optional |
| sort | The sort the results by the specified field (e.g., date, score). | Optional |
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.PADNSLookup.SilentPush.PADNS.qname | String | The DNS record name that was looked up. |
| SilentPush.PADNSLookup.SilentPush.PADNS.qtype | String | The DNS record type queried \(e.g., NS\). |
| SilentPush.PADNSLookup.SilentPush.PADNS.answer | String | The answer \(e.g., name server\) for the DNS record. |
| SilentPush.PADNSLookup.SilentPush.PADNS.count | Number | The number of occurrences for this DNS record. |
| SilentPush.PADNSLookup.SilentPush.PADNS.first_seen | String | The timestamp when this DNS record was first seen. |
| SilentPush.PADNSLookup.SilentPush.PADNS.last_seen | String | The timestamp when this DNS record was last seen. |
| SilentPush.PADNSLookup.SilentPush.PADNS.nshash | String | Unique hash for the DNS record. |
| SilentPush.PADNSLookup.SilentPush.PADNS.query | String | The DNS record query name \(e.g., silentpush.com\). |
| SilentPush.PADNSLookup.SilentPush.PADNS.ttl | Number | Time to live \(TTL\) value for the DNS record. |
| SilentPush.PADNSLookup.SilentPush.PADNS.type | String | The type of the DNS record \(e.g., NS\). |

#### Command example

```!silentpush-forward-padns-lookup qtype=a query=example.com```

#### Human Readable Output

### silentpush-get-asns-for-domain

***
retrieves Autonomous System Numbers (ASNs) associated with a domain.

#### Base Command

`silentpush-get-asns-for-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to search. | Required |
| result_format | The format of returned results: compact (default) = return ASN and AS Name only, full = return details of domain hosts in each ASN. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.DomainASNs.SilentPush.ASN.domain | String | The domain name for which ASNs are retrieved. |
| SilentPush.DomainASNs.SilentPush.ASN.asns | Unknown | Dictionary of Autonomous System Numbers \(ASNs\) associated with the domain. |

#### Command example

```!silentpush-get-asns-for-domain domain=example.com```

#### Human Readable Output

### silentpush-get-data-exports

***
runs the threat check on the specified

#### Base Command

`silentpush-get-data-exports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| export_type | The export type (iofa, organisation, etc). | Required |
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
get certificate data collected from domain scanning.

#### Base Command

`silentpush-get-domain-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| domain | The domain to query certificates for. | Required |
| domain_regex | The regular expression to match domains. | Optional |
| certificate_issuer | The filter by certificate issuer. | Optional |
| date_min | The filter certificates issued on or after this date. | Optional |
| date_max | The filter certificates issued on or before this date. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Certificate.SilentPush.Enrichment.domain | String | Queried domain. |
| SilentPush.Certificate.SilentPush.Enrichment.metadata | String | Metadata of the response. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_cert_index | Number | Index of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_chain | Unknown | Certificate chain. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_date | Number | Certificate issue date. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_domain | String | Primary domain of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_domains | Unknown | List of domains covered by the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_fingerprint | String | SHA-1 fingerprint of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_fingerprint_md5 | String | MD5 fingerprint of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_fingerprint_sha1 | String | SHA-1 fingerprint of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_fingerprint_sha256 | String | SHA-256 fingerprint of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_host | String | Host associated with the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_issuer | String | Issuer of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_not_after | String | Expiration date of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_not_before | String | Start date of the certificate validity. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_serial_dec | String | Decimal representation of the serial number. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_serial_hex | String | Hexadecimal representation of the serial number. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_serial_number | String | Serial number of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_source_name | String | Source log name of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_source_url | String | URL of the certificate log source. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_subject | String | Subject details of the certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.certificates_wildcard | Number | Indicates if the certificate is a wildcard certificate. |
| SilentPush.Certificate.SilentPush.Enrichment.job_url | String | URL to get the data of the job or its status. |
| SilentPush.Certificate.SilentPush.Enrichment.job_id | String | ID of the job. |
| SilentPush.Certificate.SilentPush.Enrichment.job_status | String | Status of the job. |

#### Command example

```!silentpush-get-domain-certificates domain=example.com```

#### Human Readable Output

### silentpush-get-enrichment-data

***
retrieves comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).

#### Base Command

`silentpush-get-enrichment-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The type of resource for which information needs to be retrieved {e.g. domain}. | Required |
| value | The value corresponding to the selected "resource" for which information needs to be retrieved {e.g. silentpush.com}. | Required |
| explain | Whether include explanation of data calculations. | Optional |
| scan_data | Whether include scan data (IPv4 only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Enrichment.SilentPush.Enrichment.value | String | Queried value. |
| SilentPush.Enrichment.SilentPush.Enrichment.avg_probability | Number | Average probability score of the domain string. |
| SilentPush.Enrichment.SilentPush.Enrichment.dga_probability_score | Number | Probability score indicating likelihood of being a DGA domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain | String | Domain name analyzed. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain_string_freq_probabilities | Unknown | List of frequency probabilities for different domain string components. |
| SilentPush.Enrichment.SilentPush.Enrichment.query | String | Domain name queried. |
| SilentPush.Enrichment.SilentPush.Enrichment.alexa_rank | Number | Alexa rank of the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.alexa_top10k | Boolean | Indicates if the domain is in the Alexa top 10k. |
| SilentPush.Enrichment.SilentPush.Enrichment.alexa_top10k_score | Number | Score indicating domain's Alexa top 10k ranking. |
| SilentPush.Enrichment.SilentPush.Enrichment.dynamic_domain_score | Number | Score indicating likelihood of domain being dynamically generated. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_dynamic_domain | Boolean | Indicates if the domain is dynamic. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_url_shortener | Boolean | Indicates if the domain is a known URL shortener. |
| SilentPush.Enrichment.SilentPush.Enrichment.results | Number | Number of results found for the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.url_shortner_score | Number | Score of the shortened URL. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain | String | Domain name analyzed. |
| SilentPush.Enrichment.SilentPush.Enrichment.error | String | Error message if no data is available for the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.zone | String | TLD zone of the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.registrar | String | registrar of the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.whois_age | String | The age of the domain based on WHOIS records. |
| SilentPush.Enrichment.SilentPush.Enrichment.whois_created_date | String | The created date on WHOIS records. |
| SilentPush.Enrichment.SilentPush.Enrichment.query | String | The domain name that was queried in the system. |
| SilentPush.Enrichment.SilentPush.Enrichment.last_seen | Number | The first recorded observation of the domain in the database. |
| SilentPush.Enrichment.SilentPush.Enrichment.first_seen | Number | The last recorded observation of the domain in the database. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_new | Boolean | Indicates whether the domain is considered "new.". |
| SilentPush.Enrichment.SilentPush.Enrichment.is_new_score | Number | A scoring metric indicating how "new" the domain is. |
| SilentPush.Enrichment.SilentPush.Enrichment.age | Number | Represents the age of the domain in days. |
| SilentPush.Enrichment.SilentPush.Enrichment.age_score | Number | A scoring metric indicating the trustworthiness of the domain based on its age. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_diversity | String | Number of different ASNs associated with the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_diversity_all | String | Total number of unique IPs observed for the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.host | String | The hostname being analyzed. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_diversity_groups | String | The number of distinct IP groups \(e.g., IPs belonging to different ranges or providers\). |
| SilentPush.Enrichment.SilentPush.Enrichment.is_expired | Boolean | Indicates if the domain\`s nameserver is expired. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_parked | Boolean | Whether the domain is not parked \(a parked domain is one without active content\). |
| SilentPush.Enrichment.SilentPush.Enrichment.is_sinkholed | Boolean | Whether the domain is not sinkholed \(not forcibly redirected to a security researcher\`s trap\). |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_reputation_max | Number | Maximum reputation score for nameservers. |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_reputation_score | Number | Reputation score of the domain\`s nameservers. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain | String | The nameservers of domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_server | String | Provided nameserver. |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_server_domain_density | Number | Number of domains sharing this NS. |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_server_domains_listed | Number | Number of listed domains using this NS. |
| SilentPush.Enrichment.SilentPush.Enrichment.ns_server_reputation | Number | Reputation score for this NS. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain | String | Domain for which the SSL certificate was issued. |
| SilentPush.Enrichment.SilentPush.Enrichment.domains | Unknown | Other Domains for which the SSL certificate was issued. |
| SilentPush.Enrichment.SilentPush.Enrichment.issuer_organization | String | Issuer organization of the SSL certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.fingerprint_sha1 | String | A unique identifier for the certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.hostname | String | The hostname associated with the certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip | String | The IP address of the server using this certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_expired | String | Indicates whether the certificate has expired. |
| SilentPush.Enrichment.SilentPush.Enrichment.issuer_common_name | String | The Common Name \(CN\) of the Certificate Authority \(CA\) that issued this certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.not_after | String | Expiry date of the certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.not_before | String | Start date of the certificate validity. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | The date when this certificate data was last scanned. |
| SilentPush.Enrichment.SilentPush.Enrichment.response | String | HTTP response code for the domain scan. |
| SilentPush.Enrichment.SilentPush.Enrichment.hostname | String | The hostname that sent this response. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip | String | The IP address responding to the request. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | The date when the headers were scanned. |
| SilentPush.Enrichment.SilentPush.Enrichment.cache-control | String | HTTP cache-control. |
| SilentPush.Enrichment.SilentPush.Enrichment.content-length | String | Content length of the HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.date | String | The date/time of the response. |
| SilentPush.Enrichment.SilentPush.Enrichment.expires | String | Indicates an already expired response. |
| SilentPush.Enrichment.SilentPush.Enrichment.server | String | The web server handling the request \(Cloudflare proxy\). |
| SilentPush.Enrichment.SilentPush.Enrichment.hostname | String | HTTP response code for the domain scan. |
| SilentPush.Enrichment.SilentPush.Enrichment.html_body_murmur3 | String | hash of the page content. |
| SilentPush.Enrichment.SilentPush.Enrichment.html_body_ssdeep | String | SSDEEP hash \(used for fuzzy matching similar HTML content\). |
| SilentPush.Enrichment.SilentPush.Enrichment.html_title | String | The page title \(suggests a Cloudflare challenge page, likely due to bot protection\). |
| SilentPush.Enrichment.SilentPush.Enrichment.ip | String | The IP address responding to the request. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | The date when the headers were scanned. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_md5 | String | MD5 hash of a secondary favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_mmh3 | String | Murmur3 hash of a secondary favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_path | String | The file path of the secondary favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon_md5 | String | MD5 hash of the primary favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon_mmh3 | String | Murmur3 hash of the primary favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.hostname | String | The hostname where this favicon was found. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip | String | The IP address associated with the favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | Date when this favicon was last scanned. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_hostname | String | The hostname where this jarm was found. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_ip | String | The IP address responding to the request. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_jarm_hash | String | Unique identifier for the TLS configuration of the server. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_scan_date | String | Date when this jarm was last scanned. |
| SilentPush.Enrichment.SilentPush.Enrichment.sp_risk_score | Number | Overall risk score for the domain. |
| SilentPush.Enrichment.SilentPush.Enrichment.sp_risk_score_decider | String | Factor that determined the final risk score. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn | Number | Autonomous System Number \(ASN\) associated with the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_allocation_age | Number | Age of ASN allocation in days. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_allocation_date | Number | Date of ASN allocation. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_rank | Number | Rank of the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_rank_score | Number | Rank score of the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_reputation | Number | Reputation score of the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.ips_in_asn | Number | Total number of IPs in the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.ips_num_active | Number | Number of active IPs in the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.ips_num_listed | Number | Number of listed IPs in the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_reputation_score | Number | Reputation score of the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_takedown_reputation | Number | Takedown reputation score the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.ips_in_asn | Number | Total number of IPs in the ASN with takedown reputation. |
| SilentPush.Enrichment.SilentPush.Enrichment.ips_num_listed | Number | Number of listed IPs in the ASN with takedown reputation. |
| SilentPush.Enrichment.SilentPush.Enrichment.items_num_listed | Number | Number of flagged items in the ASN with takedown reputation. |
| SilentPush.Enrichment.SilentPush.Enrichment.listings_max_age | Number | Maximum age of listings for the ASN with takedown reputation. |
| SilentPush.Enrichment.SilentPush.Enrichment.asn_takedown_reputation_score | Number | Takedown reputation score of the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.asname | String | Name of the Autonomous System \(AS\). |
| SilentPush.Enrichment.SilentPush.Enrichment.actor | String | This field is usually used to indicate a known organization or individual associated with the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.known_benign | Boolean | Indicates whether this IP/ASN is explicitly known to be safe \(e.g., a reputable cloud provider or public service\). |
| SilentPush.Enrichment.SilentPush.Enrichment.tags | Unknown | Contains descriptive tags if the IP/ASN has a known role \(e.g., "Google Bot", "Cloudflare Proxy"\). |
| SilentPush.Enrichment.SilentPush.Enrichment.date | Number | Date of the scan data \(YYYYMMDD format\). |
| SilentPush.Enrichment.SilentPush.Enrichment.density | Number | The density value associated with the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip | String | IP address associated with the ASN. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_has_expired_certificate | Boolean | Indicates whether the IP has an expired SSL/TLS certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_has_open_directory | Boolean | Indicates whether the IP hosts an open directory listing. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_is_dsl_dynamic | Boolean | Whether the IP is from dynamic DSL pool. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_is_dsl_dynamic_score | Number | A score indicating how likely this IP is dynamic. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_is_ipfs_node | Boolean | the InterPlanetary File System \(IPFS\), a decentralized file storage system. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_is_tor_exit_node | Boolean | Tor exit node \(used for anonymous internet browsing\). |
| SilentPush.Enrichment.SilentPush.Enrichment.continent_code | String | abbreviation for the continent where the IP is located. |
| SilentPush.Enrichment.SilentPush.Enrichment.continent_name | String | The full name of the continent. |
| SilentPush.Enrichment.SilentPush.Enrichment.country_code | String | The ISO 3166-1 alpha-2 country code representing the country. |
| SilentPush.Enrichment.SilentPush.Enrichment.country_is_in_european_union | Boolean | A Boolean value \(true/false\) indicating if the country is part of the European Union \(EU\). |
| SilentPush.Enrichment.SilentPush.Enrichment.country_name | String | The full name of the country where the IP is registered. |
| SilentPush.Enrichment.SilentPush.Enrichment.ip_ptr | String | The reverse DNS \(PTR\) record for the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.listing_score | Number | Measures how frequently the IP appears in threat intelligence or blacklist databases. |
| SilentPush.Enrichment.SilentPush.Enrichment.listing_score_explain | Unknown | A breakdown of why the listing score is assigned. |
| SilentPush.Enrichment.SilentPush.Enrichment.malscore | Number | Malicious activity score for the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.hostname | String | Hostname associated with the SSL certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.domain | String | Domain for which the SSL certificate was issued. |
| SilentPush.Enrichment.SilentPush.Enrichment.fingerprint_sha1 | String | SHA-1 fingerprint of the SSL certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.issuer_common_name | String | Common name of the certificate issuer. |
| SilentPush.Enrichment.SilentPush.Enrichment.issuer_organization | String | Organization that issued the SSL certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.not_before | String | Start date of SSL certificate validity. |
| SilentPush.Enrichment.SilentPush.Enrichment.not_after | String | Expiration date of SSL certificate validity. |
| SilentPush.Enrichment.SilentPush.Enrichment.domains | Unknown | Other domains for which the SSL certificate was issued. |
| SilentPush.Enrichment.SilentPush.Enrichment.is_expired | Boolean | Is certificate expired. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | Scan date of the certificate. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_md5 | String | MD5 hash of the second favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_mmh3 | Number | MurmurHash3 value of the second favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon_md5 | String | MD5 hash of the favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon_mmh3 | Number | MurmurHash3 value of the favicon. |
| SilentPush.Enrichment.SilentPush.Enrichment.favicon2_path | String | Path to the second favicon file. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | Scan date of favicon file. |
| SilentPush.Enrichment.SilentPush.Enrichment.response | String | HTTP response code from the scan. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | The date and time when the scan was performed. |
| SilentPush.Enrichment.SilentPush.Enrichment.headers_server | String | Server header from the HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.headers_content-type | String | Content-Type header from the HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.headers_content-length | String | Content-Length header from the HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.headers_cache-control | String | Cache-control header from the HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.headers_date | String | Date header from HTTP response. |
| SilentPush.Enrichment.SilentPush.Enrichment.html_title | String | Title of the scanned HTML page. |
| SilentPush.Enrichment.SilentPush.Enrichment.html_body_murmur3 | String | MurmurHash3 of the HTML body content. |
| SilentPush.Enrichment.SilentPush.Enrichment.html_body_ssdeep | String | SSDEEP fuzzy hash of the HTML body content. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_date | String | The date and time when the scan was performed. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_scan_date | String | The date and time when the scan was performed. |
| SilentPush.Enrichment.SilentPush.Enrichment.scan_data_jarm_jarm_hash | String | JARM fingerprint hash for TLS analysis. |
| SilentPush.Enrichment.SilentPush.Enrichment.sp_risk_score | Number | Security risk score for the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.sp_risk_score_decider | String | Factor that determined the final risk score. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet | String | Subnet associated with the IP. |
| SilentPush.Enrichment.SilentPush.Enrichment.known_sinkhole_ip | Boolean | Indicates whether the IP is part of a sinkhole \(a controlled system that captures malicious traffic\). |
| SilentPush.Enrichment.SilentPush.Enrichment.tags | Unknown | If the IP were a known sinkhole, this field would contain tags describing its purpose. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet_allocation_age | Number | Represents the age \(in days\) since the subnet was allocated. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet_allocation_date | Number | The date when the subnet was assigned to an organization or ISP. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet_reputation | Number | A measure of how frequently IPs from this subnet appear in threat intelligence databases. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet_reputation_explain | Unknown | A breakdown of why the subnet received its reputation score. |
| SilentPush.Enrichment.SilentPush.Enrichment.subnet_reputation_score | Number | A numerical risk score \(typically 0-100, with higher values indicating higher risk\). |

#### Command example

```!silentpush-get-enrichment-data resource=ipv6 value=2a02:4780:37:b262:f807:71a8:e3ee:9b64```

#### Human Readable Output

### silentpush-get-ipv4-reputation

***
retrieves the reputation information for an IPv4.

#### Base Command

`silentpush-get-ipv4-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipv4 | The IPv4 address for which information needs to be retrieved. | Required |
| explain | Whether show the information used to calculate the reputation score. | Optional |
| limit | The maximum number of reputation history to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPv4Reputation.SilentPush.Reputation.date | Number | Date when the reputation information was retrieved. |
| SilentPush.IPv4Reputation.SilentPush.Reputation.ip | String | IPv4 address for which the reputation is calculated. |
| SilentPush.IPv4Reputation.SilentPush.Reputation.reputation_score | Number | Reputation score for the given IP address. |
| SilentPush.IPv4Reputation.SilentPush.Reputation.ip_density | Number | The number of domain names or services associated with this IP. A higher value may indicate shared hosting or potential abuse. |
| SilentPush.IPv4Reputation.SilentPush.Reputation.names_num_listed | Number | The number of domain names linked to this IP that are flagged or listed in security threat databases. |

#### Command example

```!silentpush-get-ipv4-reputation ipv4=198.51.100.1```

#### Human Readable Output

### silentpush-get-nameserver-reputation

***
retrieves historical reputation data for a specified nameserver,including reputation scores and optional detailed calculation information.

#### Base Command

`silentpush-get-nameserver-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameserver | The Nameserver name for which information needs to be retrieved. | Required |
| explain | Whether to show the information used to calculate the reputation score. | Optional |
| limit | The maximum number of reputation history to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.NameserverReputation.SilentPush.Reputation.nameserver | Number | The nameserver associated with the reputation history entry. |
| SilentPush.NameserverReputation.SilentPush.Reputation.date | Number | Date of the reputation history entry \(in YYYYMMDD format\). |
| SilentPush.NameserverReputation.SilentPush.Reputation.ns_server | String | Name of the nameserver associated with the reputation history entry. |
| SilentPush.NameserverReputation.SilentPush.Reputation.ns_server_reputation | Number | Reputation score of the nameserver on the specified date. |
| SilentPush.NameserverReputation.SilentPush.Reputation.ns_server_domain_density | Number | Number of domains associated with the nameserver. |
| SilentPush.NameserverReputation.SilentPush.Reputation.ns_server_domains_listed | Number | Number of domains listed in reputation databases. |

#### Command example

```!silentpush-get-nameserver-reputation nameserver=ns1.example.com```

#### Human Readable Output

### silentpush-get-subnet-reputation

***
retrieves the reputation history for a specific subnet.

#### Base Command

`silentpush-get-subnet-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | The IPv4 subnet in the format IP/NETMASK for which reputation information needs to be retrieved, i.e.: 192.35.168.0/23. | Required |
| explain | Whether to show the detailed information used to calculate the reputation score. | Optional |
| limit | The maximum number of reputation history entries to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.SubnetReputation.SilentPush.Reputation.subnet | String | The subnet associated with the reputation history. |
| SilentPush.SubnetReputation.SilentPush.Reputation.date | Number | The date of the subnet reputation record. |
| SilentPush.SubnetReputation.SilentPush.Reputation.subnet | String | The subnet associated with the reputation record. |
| SilentPush.SubnetReputation.SilentPush.Reputation.subnet_reputation | Number | The reputation score of the subnet. |
| SilentPush.SubnetReputation.SilentPush.Reputation.ips_in_subnet | Number | Total number of IPs in the subnet. |
| SilentPush.SubnetReputation.SilentPush.Reputation.ips_num_active | Number | Number of active IPs in the subnet. |
| SilentPush.SubnetReputation.SilentPush.Reputation.ips_num_listed | Number | Number of listed IPs in the subnet. |

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
| qtype | The query type. | Required |
| query | The value to query. | Required |
| window | The use records with a last_seen more recently than days ago, default = 30. | Optional |
| asn | Whether to include asn diversity, 0 = do not include, 1 (default) = include asn diversity. | Optional |
| timeline | Whether include timeline of {ip, first_seen, last_seen} (+asn if asn=1), 0 (default) = do not include, 1 = include timeline. | Optional |
| verbose | Whether return ips, dates, timeline, (and asns if asn=1), 0 (default) = do not include, 1 = include all data. | Optional |
| scope | The exact or near match results by qtype, *scope=live is automatically set when timeline=1 or verbose=1.*for qtype = a: host - exact match (default when qtype=a), domain - match all hosts in this domain (domain extracted from {query}), subdomain - match all hosts at this subdomain level (i.e. *.{query}), live - calculate values from live data instead of pre-aggregated values - also switches to exact match only.*for qtype = aaaa, live - only this mode is supported for qtype=aaaa. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPdiversityLookup.SilentPush.Diversity.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. |
| SilentPush.IPdiversityLookup.SilentPush.Diversity.host | String | The domain name \(host\) associated with the record. |
| SilentPush.IPdiversityLookup.SilentPush.Diversity.ip_diversity_all | Number | The total number of unique IPs associated with the domain. |
| SilentPush.IPdiversityLookup.SilentPush.Diversity.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. |
| SilentPush.IPdiversityLookup.SilentPush.Diversity.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. |

#### Command example

```!silentpush-ip-diversity-lookup qtype=a query=example.com```

#### Human Readable Output

### silentpush-ip-diversity-patterns

***
Search for IP Diversity patterns, with optional name server and domain name pattern matching.

#### Base Command

`silentpush-ip-diversity-patterns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | The filter results to include only records first seen after this date. | Optional |
| first_seen_before | The filter results to include only records first seen before this date. | Optional |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| domain | The name or wildcard pattern of domain names to search for. | Optional |
| domain_regex | The valid RE2 regex pattern to match domains. Overrides the domain argument. | Optional |
| nsname | The server name or wildcard pattern of the name server used by domains. | Optional |
| mxname | The mx server name or wildcard pattern of mx server used by domains, use mxname=self to find domains hosting their own mailservers. | Optional |
| first_seen_min | The only domains that have A records seen for the first time after the given date. | Optional |
| first_seen_max | The only domains that have A records seen for the first time before the given date. | Optional |
| first_seen_min_mode | The match mode for first_seen_min parameter, strict (default) - select A records that do not have any timestamps before first_seen_min, any - select A records that have at least one timestamp after first_seen_min. | Optional |
| first_seen_max_mode | The match mode for first_seen_max parameter, strict (default) - select A records that do not have any timestamps after first_seen_max, any - select A records that have at least one timestamp before first_seen_max. | Optional |
| last_seen_min | The only domains that have A records last seen more recently than the given date. | Optional |
| last_seen_max | The only domains that have A records last seen earlier than the given date. | Optional |
| last_seen_min_mode | The match mode for last_seen_min parameter, strict - select A records that do not have any timestamps before last_seen_min, any (default) - select A records that have at least one timestamp after first_seen_min. | Optional |
| last_seen_max_mode | The match mode for last_seen_max parameter, strict (default) - select A records that do not have any timestamps after last_seen_max, any - select A records that have at least one timestamp before last_seen_max. | Optional |
| asnum | The Autonomous System (AS) number to filter domains. | Optional |
| asname | The search for all AS numbers where the AS Name begins with the specified value. | Optional |
| network | The additional network and net mask, give option as 1.1.1.1/24, network parameter may be given multiple times and the search will be performed as an 'or' condition. | Optional |
| timeline | Whether to include details of IPs, ASNs, first_seen and last_seen for each domain, 0 (default) = do not include, 1 = include timeline. | Optional |
| ip_diversity_all_min | The Minimum IP diversity limit to filter domains. | Optional |
| registrar | The name or partial name of the registrar used to register domains. | Optional |
| email | The email used to register domains - no wildcards, the given string is used in exact match - this is a slow search option and should only be used in combination with the domain match option. | Optional |
| nschange_from_ns | The domain has changed name server from nsname, exact match, wildcards and 'self' options supported. | Optional |
| nschange_to_ns | The domain has changed name server to nsname, exact match, wildcards and 'self' options supported. | Optional |
| nschange_date_after | The only domains with name server changes that occurred after the given date, if nschange_date_after is not given, the default is to find name server changes in the last 30 days, if nschange_date_before is not given. | Optional |
| nschange_date_before | The only domains with name server changes that occurred before the given date. | Optional |
| cert_date_min | The only domains that have had ssl certificates issued on or after the given date. | Optional |
| cert_date_max | The only domains that have had ssl certificates issued on or before the given date. | Optional |
| cert_issuer | The filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported. | Optional |
| infratag | The search by infratag, infratag must include mx part, ns part, asname part, or registrar part, overrides mxname, nsname and registrar parameters, if infratag contains these parts, can be combined with all other parameters. | Optional |
| asn_diversity_min | The minimum ASN diversity limit to filter domains. | Optional |
| ip_diversity_all_min | The minimum diversity limit, default = 1. | Optional |
| ip_diversity_groups_min | The minimum diversity limit. | Optional |
| whois_date_after | The filter domains with a WHOIS creation date after this date (YYYY-MM-DD). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.host | String | The domain name \(host\) associated with the record. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.ip_diversity_all | Number | The total number of unique IPs associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. |

#### Command example

```!silentpush-ip-diversity-patterns nsname=ns1.example.com asn_diversity_min=2```

#### Human Readable Output

### silentpush-list-domain-information

***
get domain information along with Silent Push risk score and live whois information for multiple domains.

#### Base Command

`silentpush-list-domain-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | A comma-separated list of domains to query. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Domain.SilentPush.Enrichment.host_flags | Unknown | The domain name queried. |
| SilentPush.Domain.SilentPush.Enrichment.domain_urls | Unknown | The last seen date of the domain in YYYYMMDD format. |
| SilentPush.Domain.SilentPush.Enrichment.domaininfo | Unknown | The domain name used for the query. |
| SilentPush.Domain.SilentPush.Enrichment.ns_reputation | Unknown | The age of the domain in days based on WHOIS creation date. |
| SilentPush.Domain.SilentPush.Enrichment.nschanges | Unknown | The first seen date of the domain in YYYYMMDD format. |
| SilentPush.Domain.SilentPush.Enrichment.domain_string_frequency_probability | Unknown | Indicates whether the domain is newly observed. |
| SilentPush.Domain.SilentPush.Enrichment.is_private_suffix | Boolean | The top-level domain \(TLD\) or zone of the queried domain. |
| SilentPush.Domain.SilentPush.Enrichment.private_suffix_info | Unknown | The registrar responsible for the domain registration. |
| SilentPush.Domain.SilentPush.Enrichment.ip_diversity | Unknown | A risk score based on the domain's age. |
| SilentPush.Domain.SilentPush.Enrichment.listing_score | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. |
| SilentPush.Domain.SilentPush.Enrichment.listing_score_explain | Unknown | A risk score indicating how new the domain is. |
| SilentPush.Domain.SilentPush.Enrichment.listing_score_feeds_explain | Unknown | The age of the domain in days. |
| SilentPush.Domain.SilentPush.Enrichment.sp_risk_score | Number | The age of the domain in days. |
| SilentPush.Domain.SilentPush.Enrichment.sp_risk_score_explain | Unknown | The age of the domain in days. |

#### Command example

```!silentpush-list-domain-information domains=example.com,docs.example.com```

#### Human Readable Output

### silentpush-list-ip4-information

***
get IP4 information along with Silent Push risk score

#### Base Command

`silentpush-list-ip4-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | A comma-separated list of IPs to query. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IP4.SilentPush.Enrichment.ip | String | The domain name queried. |
| SilentPush.IP4.SilentPush.Enrichment.asn | Number | The last seen date of the domain in YYYYMMDD format. |
| SilentPush.IP4.SilentPush.Enrichment.asname | String | The domain name used for the query. |
| SilentPush.IP4.SilentPush.Enrichment.asn_allocation_date | Number | The age of the domain in days based on WHOIS creation date. |
| SilentPush.IP4.SilentPush.Enrichment.asn_allocation_age | Number | The first seen date of the domain in YYYYMMDD format. |
| SilentPush.IP4.SilentPush.Enrichment.asn_rank | Number | Indicates whether the domain is newly observed. |
| SilentPush.IP4.SilentPush.Enrichment.asn_rank_score | Number | The top-level domain \(TLD\) or zone of the queried domain. |
| SilentPush.IP4.SilentPush.Enrichment.asn_reputation | Number | The registrar responsible for the domain registration. |
| SilentPush.IP4.SilentPush.Enrichment.asn_reputation_explain | Unknown | A risk score based on the domain's age. |
| SilentPush.IP4.SilentPush.Enrichment.malscore | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. |
| SilentPush.IP4.SilentPush.Enrichment.asn_takedown_reputation | Number | A risk score indicating how new the domain is. |
| SilentPush.IP4.SilentPush.Enrichment.asn_takedown_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.asn_takedown_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.date | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet | String | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet_allocation_date | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet_allocation_age | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet_reputation | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.subnet_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_reputation | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_location | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_is_dsl_dynamic | Boolean | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_is_dsl_dynamic_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_ptr | String | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.benign_info | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.sinkhole_info | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_is_tor_exit_node | Boolean | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_is_ipfs_node | Boolean | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_has_open_directory | Boolean | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_has_expired_certificate | Boolean | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.ip_flags | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.density | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.listing_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.listing_score_explain | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.listing_score_feeds_explain | Unknown | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.sp_risk_score | Number | The age of the domain in days. |
| SilentPush.IP4.SilentPush.Enrichment.sp_risk_score_explain | Unknown | The age of the domain in days. |

#### Command example

```!silentpush-list-ip4-information ips=198.51.100.1,198.51.100.2```

#### Human Readable Output

### silentpush-list-ip6-information

***
get IP6 information along with Silent Push risk score

#### Base Command

`silentpush-list-ip6-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | A comma-separated list of IPs to query. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IP6.SilentPush.Enrichment.ip | String | The domain name queried. |
| SilentPush.IP6.SilentPush.Enrichment.asn | Number | The last seen date of the domain in YYYYMMDD format. |
| SilentPush.IP6.SilentPush.Enrichment.asname | String | The domain name used for the query. |
| SilentPush.IP6.SilentPush.Enrichment.asn_allocation_date | Number | The age of the domain in days based on WHOIS creation date. |
| SilentPush.IP6.SilentPush.Enrichment.asn_allocation_age | Number | The first seen date of the domain in YYYYMMDD format. |
| SilentPush.IP6.SilentPush.Enrichment.asn_rank | Number | Indicates whether the domain is newly observed. |
| SilentPush.IP6.SilentPush.Enrichment.asn_rank_score | Number | The top-level domain \(TLD\) or zone of the queried domain. |
| SilentPush.IP6.SilentPush.Enrichment.asn_reputation | Number | The registrar responsible for the domain registration. |
| SilentPush.IP6.SilentPush.Enrichment.asn_reputation_explain | Unknown | A risk score based on the domain's age. |
| SilentPush.IP6.SilentPush.Enrichment.malscore | Number | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. |
| SilentPush.IP6.SilentPush.Enrichment.asn_takedown_reputation | Number | A risk score indicating how new the domain is. |
| SilentPush.IP6.SilentPush.Enrichment.asn_takedown_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.asn_takedown_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.date | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet | String | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet_allocation_date | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet_allocation_age | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet_reputation | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.subnet_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_reputation | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_reputation_explain | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_reputation_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_location | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_is_dsl_dynamic | Boolean | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_is_dsl_dynamic_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_ptr | String | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.benign_info | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.sinkhole_info | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_is_tor_exit_node | Boolean | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_is_ipfs_node | Boolean | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_has_open_directory | Boolean | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_has_expired_certificate | Boolean | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.ip_flags | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.density | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.listing_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.listing_score_explain | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.listing_score_feeds_explain | Unknown | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.sp_risk_score | Number | The age of the domain in days. |
| SilentPush.IP6.SilentPush.Enrichment.sp_risk_score_explain | Unknown | The age of the domain in days. |

#### Command example

```!silentpush-list-ip6-information ips=2606:4700:4700::1111,2a02:4780:37:b262:f807:71a8:e3ee:9b64```

#### Human Readable Output

### silentpush-live-url-scan

***
scan a URL to retrieve hosting metadata.

#### Base Command

`silentpush-live-url-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to scan. | Required |
| platform | The platform to scan the URL on. | Optional |
| os | The operating system to scan the URL on. | Optional |
| browser | The browser to scan the URL on. | Optional |
| region | The region to scan the URL in. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.URLScan.SilentPush.Web.HHV | String | Unique identifier for HHV. |
| SilentPush.URLScan.SilentPush.Web.adtech_ads_txt | Boolean | Indicates if ads_txt is present. |
| SilentPush.URLScan.SilentPush.Web.adtech_app_ads_txt | Boolean | Indicates if app_ads_txt is present. |
| SilentPush.URLScan.SilentPush.Web.adtech_sellers_json | Boolean | Indicates if sellers_json is present. |
| SilentPush.URLScan.SilentPush.Web.datahash | String | Hash value of the data. |
| SilentPush.URLScan.SilentPush.Web.domain | String | The domain name. |
| SilentPush.URLScan.SilentPush.Web.favicon2_avg | String | Hash value for favicon2 average. |
| SilentPush.URLScan.SilentPush.Web.favicon2_md5 | String | MD5 hash for favicon2. |
| SilentPush.URLScan.SilentPush.Web.favicon2_murmur3 | Number | Murmur3 hash for favicon2. |
| SilentPush.URLScan.SilentPush.Web.favicon2_path | String | Path to favicon2 image. |
| SilentPush.URLScan.SilentPush.Web.favicon_avg | String | Hash value for favicon average. |
| SilentPush.URLScan.SilentPush.Web.favicon_md5 | String | MD5 hash for favicon. |
| SilentPush.URLScan.SilentPush.Web.favicon_murmur3 | String | Murmur3 hash for favicon. |
| SilentPush.URLScan.SilentPush.Web.favicon_path | String | Path to favicon image. |
| SilentPush.URLScan.SilentPush.Web.favicon_urls | Unknown | List of favicon URLs. |
| SilentPush.URLScan.SilentPush.Web.header_cache-control | String | Cache control header value. |
| SilentPush.URLScan.SilentPush.Web.header_content-encoding | String | Content encoding header value. |
| SilentPush.URLScan.SilentPush.Web.header_content-type | String | Content type header value. |
| SilentPush.URLScan.SilentPush.Web.header_server | String | Server header value. |
| SilentPush.URLScan.SilentPush.Web.header_x-powered-by | String | X-Powered-By header value. |
| SilentPush.URLScan.SilentPush.Web.hostname | String | The hostname of the server. |
| SilentPush.URLScan.SilentPush.Web.html_body_length | Number | Length of the HTML body. |
| SilentPush.URLScan.SilentPush.Web.html_body_murmur3 | Number | Murmur3 hash for the HTML body. |
| SilentPush.URLScan.SilentPush.Web.html_body_sha256 | String | SHA256 hash for the HTML body. |
| SilentPush.URLScan.SilentPush.Web.html_body_similarity | Number | Similarity score of HTML body. |
| SilentPush.URLScan.SilentPush.Web.html_body_ssdeep | String | ssdeep hash for the HTML body. |
| SilentPush.URLScan.SilentPush.Web.htmltitle | String | The HTML title of the page. |
| SilentPush.URLScan.SilentPush.Web.ip | String | IP address associated with the domain. |
| SilentPush.URLScan.SilentPush.Web.jarm | String | JARM \(TLS fingerprint\) value. |
| SilentPush.URLScan.SilentPush.Web.mobile_enabled | Boolean | Indicates if the mobile version is enabled. |
| SilentPush.URLScan.SilentPush.Web.opendirectory | Boolean | Indicates if open directory is enabled. |
| SilentPush.URLScan.SilentPush.Web.origin_domain | String | Origin domain of the server. |
| SilentPush.URLScan.SilentPush.Web.origin_hostname | String | Origin hostname of the server. |
| SilentPush.URLScan.SilentPush.Web.origin_ip | String | Origin IP address of the server. |
| SilentPush.URLScan.SilentPush.Web.origin_jarm | String | JARM \(TLS fingerprint\) value for the origin. |
| SilentPush.URLScan.SilentPush.Web.origin_path | String | Origin path for the URL. |
| SilentPush.URLScan.SilentPush.Web.origin_port | Number | Port used for the origin server. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl.CHV | String | SSL Certificate Chain Value \(CHV\). |
| SilentPush.URLScan.SilentPush.Web.origin_ssl.SHA1 | String | SHA1 hash of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl.SHA256 | String | SHA256 hash of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_authority_key_id | String | Authority Key Identifier for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_expired | Boolean | Indicates if the SSL certificate is expired. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_issuer_common_name | String | Issuer common name for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_issuer_country | String | Issuer country for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_issuer_organization | String | Issuer organization for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_not_after | String | Expiration date of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_not_before | String | Start date of the SSL certificate validity. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl.sans | Unknown | List of Subject Alternative Names \(SANs\) for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_sans_count | Number | Count of SANs for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_serial_number | String | Serial number of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_sigalg | String | Signature algorithm used for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_subject_common_name | String | Subject common name for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_subject_key_id | String | Subject Key Identifier for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_valid | Boolean | Indicates if the SSL certificate is valid. |
| SilentPush.URLScan.SilentPush.Web.origin_ssl_wildcard | Boolean | Indicates if the SSL certificate is wildcard. |
| SilentPush.URLScan.SilentPush.Web.origin_subdomain | String | Subdomain of the origin. |
| SilentPush.URLScan.SilentPush.Web.origin_tld | String | Top-level domain of the origin. |
| SilentPush.URLScan.SilentPush.Web.origin_url | String | Complete URL of the origin. |
| SilentPush.URLScan.SilentPush.Web.path | String | Path for the URL. |
| SilentPush.URLScan.SilentPush.Web.port | Number | Port for the URL. |
| SilentPush.URLScan.SilentPush.Web.proxy_enabled | Boolean | Indicates if the proxy is enabled. |
| SilentPush.URLScan.SilentPush.Web.redirect | Boolean | Indicates if a redirect occurs. |
| SilentPush.URLScan.SilentPush.Web.redirect_count | Number | Count of redirects. |
| SilentPush.URLScan.SilentPush.Web.redirect_list | Unknown | List of redirect URLs. |
| SilentPush.URLScan.SilentPush.Web.resolves_to | Unknown | List of IPs the domain resolves to. |
| SilentPush.URLScan.SilentPush.Web.response | Number | HTTP response code. |
| SilentPush.URLScan.SilentPush.Web.scheme | String | URL scheme \(e.g., https\). |
| SilentPush.URLScan.SilentPush.Web.screenshot | String | URL for the domain screenshot. |
| SilentPush.URLScan.SilentPush.Web.ssl_CHV | String | SSL Certificate Chain Value \(CHV\). |
| SilentPush.URLScan.SilentPush.Web.ssl_SHA1 | String | SHA1 hash of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_SHA256 | String | SHA256 hash of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_authority_key_id | String | Authority Key Identifier for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_expired | Boolean | Indicates if the SSL certificate is expired. |
| SilentPush.URLScan.SilentPush.Web.ssl_issuer_common_name | String | Issuer common name for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_issuer_country | String | Issuer country for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_issuer_organization | String | Issuer organization for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_not_after | String | Expiration date of the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_not_before | String | Start date of the SSL certificate validity. |
| SilentPush.URLScan.SilentPush.Web.ssl_sans | Unknown | List of Subject Alternative Names \(SANs\) for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_sans_count | Number | Count of SANs for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_serial_number | String | Serial number of SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_sigalg | String | Signature algorithm used for the SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_subject_common_name | String | Subject common name for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_subject_key_id | String | Subject Key Identifier for SSL certificate. |
| SilentPush.URLScan.SilentPush.Web.ssl_valid | Boolean | Indicates if the SSL certificate is valid. |
| SilentPush.URLScan.SilentPush.Web.ssl_wildcard | Boolean | Indicates if the SSL certificate is a wildcard. |
| SilentPush.URLScan.SilentPush.Web.SHV | String | Unique identifier for body analysis. |
| SilentPush.URLScan.SilentPush.Web.body_sha256 | String | SHA-256 hash of the body content. |
| SilentPush.URLScan.SilentPush.Web.google-GA4 | Unknown | List of Google GA4 tracking IDs. |
| SilentPush.URLScan.SilentPush.Web.google-UA | Unknown | List of Google Universal Analytics tracking IDs. |
| SilentPush.URLScan.SilentPush.Web.google-adstag | Unknown | List of Google Adstag tracking IDs. |
| SilentPush.URLScan.SilentPush.Web.js_sha256 | Unknown | List of SHA-256 hashes of JavaScript files. |
| SilentPush.URLScan.SilentPush.Web.js_ssdeep | Unknown | List of ssdeep fuzzy hashes of JavaScript files. |

#### Command example

```!silentpush-live-url-scan url=https://www.example.com region=EU platform=Mobile```

#### Human Readable Output

### silentpush-multi-conditional-padns-lookup

***
searches passive DNS data for records matching both query and answer.

#### Base Command

`silentpush-multi-conditional-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | The filter results to include only records first seen after this date. | Optional |
| first_seen_before | The filter results to include only records first seen before this date. | Optional |
| last_seen_after | The filter results to include only records last seen after this date. | Optional |
| last_seen_before | The filter results to include only records last seen before this date. | Optional |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| qtype | The DNS record type. | Required |
| query | The DNS record name to lookup. | Required |
| netmask | The netmask to filter the lookup results. | Optional |
| match | The type of match for the query (e.g., exact, partial). | Optional |
| as_of | The date or time to get the DNS records as of a specific point in time. | Optional |
| sort | The sort the results by the specified field (e.g., date, score). | Optional |
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |
| answer | The DNS record answer to lookup. | Required |
| name | The additional name to match qanswer, up to 5. | Optional |
| net | The find ptr4 or a records where ipv4 in or not in subnet defined by netmask. in (default) - find records in subnet, notin - find records not in subnet. | Optional |
| network | The additional network and net mask in the format 1.1.1.1/24, up to 5. | Optional |
| asnum | The Autonomous System (AS) number to filter domains. | Optional |
| asn | Whether include asn diversity, 0 = do not include, 1 (default) = include asn diversity. | Optional |
| asname | The search for all AS numbers where the AS Name begins with the specified value. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.qname | String | The DNS record name that was looked up. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.qtype | String | The DNS record type queried \(e.g., NS\). |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.answer | String | The answer \(e.g., name server\) for the DNS record. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.count | Number | The number of occurrences for this DNS record. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.first_seen | String | The timestamp when this DNS record was first seen. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.last_seen | String | The timestamp when this DNS record was last seen. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.nshash | String | Unique hash for the DNS record. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.query | String | The DNS record query name \(e.g., silentpush.com\). |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.ttl | Number | Time to live \(TTL\) value for the DNS record. |
| SilentPush.MultiConditionalPADNSLookup.SilentPush.PADNS.type | String | The type of the DNS record \(e.g., NS\). |

#### Command example

```!silentpush-multi-conditional-padns-lookup qtype=ns query=example.com answer=ns1.example.com last_seen_after=2021-07-01```

#### Human Readable Output

### silentpush-retry-job

***
retry another command which returned a Job ID

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
retrieve reverse Passive DNS data for specific DNS record types.

#### Base Command

`silentpush-reverse-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | The filter results to include only records first seen after this date. | Optional |
| first_seen_before | The filter results to include only records first seen before this date. | Optional |
| last_seen_after | The filter results to include only records last seen after this date. | Optional |
| last_seen_before | The filter results to include only records last seen before this date. | Optional |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| qtype | The DNS record type. | Required |
| query | The DNS record name to lookup. | Required |
| netmask | The netmask to filter the lookup results. | Optional |
| match | The type of match for the query (e.g., exact, partial). | Optional |
| as_of | The date or time to get the DNS records as of a specific point in time. | Optional |
| sort | The sort the results by the specified field (e.g., date, score). | Optional |
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |
| subdomains | The flag to include subdomains in the lookup results. | Optional |
| regex | The regular expression to filter the DNS records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.qname | String | The DNS record name that was looked up. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.qtype | String | The DNS record type queried \(e.g., NS\). |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.answer | String | The answer \(e.g., name server\) for the DNS record. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.count | Number | The number of occurrences for this DNS record. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.first_seen | String | The timestamp when this DNS record was first seen. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.last_seen | String | The timestamp when this DNS record was last seen. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.nshash | String | Unique hash for the DNS record. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.query | String | The DNS record query name \(e.g., silentpush.com\). |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.ttl | Number | Time to live \(TTL\) value for the DNS record. |
| SilentPush.ReversePADNSLookup.SilentPush.PADNS.type | String | The type of the DNS record \(e.g., NS\). |

#### Command example

```!silentpush-reverse-padns-lookup qtype=a query=198.51.100.1```

#### Human Readable Output

### silentpush-run-threat-check

***
runs the threat check on the specified

#### Base Command

`silentpush-run-threat-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The name of the data source to query. | Required |
| query | The value to check for threats (e.g., IP or domain). | Required |
| type | The type of the value being queried (e.g., ip, domain). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.RunThreatCheck.SilentPush.Feed.is_listed | Boolean | Indicates whether the queried value is listed as a threat. |
| SilentPush.RunThreatCheck.SilentPush.Feed.listed_txt | String | Textual description of the listing status. |
| SilentPush.RunThreatCheck.SilentPush.Feed.query | String | The original value that was checked. |

#### Command example

```!silentpush-run-threat-check data=iofa query=198.51.100.1 type=ip```

#### Human Readable Output

### silentpush-search-domains

***
search for domains with optional filters.

#### Base Command

`silentpush-search-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_seen_after | The filter results to include only records first seen after this date. | Optional |
| first_seen_before | The filter results to include only records first seen before this date. | Optional |
| prefer | The preference for specific DNS servers or sources. | Optional |
| skip | The number of results to skip for pagination purposes. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | The flag to include metadata in the DNS records. | Optional |
| max_wait | The maximum number of seconds to wait for results before timing out. | Optional |
| domain | The name or wildcard pattern of domain names to search for. | Optional |
| domain_regex | The valid RE2 regex pattern to match domains. Overrides the domain argument. | Optional |
| nsname | The server name or wildcard pattern of the name server used by domains. | Optional |
| mxname | The mx server name or wildcard pattern of mx server used by domains, use mxname=self to find domains hosting their own mailservers. | Optional |
| first_seen_min | The only domains that have A records seen for the first time after the given date. | Optional |
| first_seen_max | The only domains that have A records seen for the first time before the given date. | Optional |
| first_seen_min_mode | The match mode for first_seen_min parameter, strict (default) - select A records that do not have any timestamps before first_seen_min, any - select A records that have at least one timestamp after first_seen_min. | Optional |
| first_seen_max_mode | The match mode for first_seen_max parameter, strict (default) - select A records that do not have any timestamps after first_seen_max, any - select A records that have at least one timestamp before first_seen_max. | Optional |
| last_seen_min | The only domains that have A records last seen more recently than the given date. | Optional |
| last_seen_max | The only domains that have A records last seen earlier than the given date. | Optional |
| last_seen_min_mode | The match mode for last_seen_min parameter, strict - select A records that do not have any timestamps before last_seen_min, any (default) - select A records that have at least one timestamp after first_seen_min. | Optional |
| last_seen_max_mode | The match mode for last_seen_max parameter, strict (default) - select A records that do not have any timestamps after last_seen_max, any - select A records that have at least one timestamp before last_seen_max. | Optional |
| asnum | The Autonomous System (AS) number to filter domains. | Optional |
| asname | The search for all AS numbers where the AS Name begins with the specified value. | Optional |
| network | The additional network and net mask, give option as 1.1.1.1/24, network parameter may be given multiple times and the search will be performed as an 'or' condition. | Optional |
| timeline | Whether to include details of IPs, ASNs, first_seen and last_seen for each domain, 0 (default) = do not include, 1 = include timeline. | Optional |
| ip_diversity_all_min | The Minimum IP diversity limit to filter domains. | Optional |
| registrar | The name or partial name of the registrar used to register domains. | Optional |
| email | The email used to register domains - no wildcards, the given string is used in exact match - this is a slow search option and should only be used in combination with the domain match option. | Optional |
| nschange_from_ns | The domain has changed name server from nsname, exact match, wildcards and 'self' options supported. | Optional |
| nschange_to_ns | The domain has changed name server to nsname, exact match, wildcards and 'self' options supported. | Optional |
| nschange_date_after | The only domains with name server changes that occurred after the given date, if nschange_date_after is not given, the default is to find name server changes in the last 30 days, if nschange_date_before is not given. | Optional |
| nschange_date_before | The only domains with name server changes that occurred before the given date. | Optional |
| cert_date_min | The only domains that have had ssl certificates issued on or after the given date. | Optional |
| cert_date_max | The only domains that have had ssl certificates issued on or before the given date. | Optional |
| cert_issuer | The filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported. | Optional |
| infratag | The search by infratag, infratag must include mx part, ns part, asname part, or registrar part, overrides mxname, nsname and registrar parameters, if infratag contains these parts, can be combined with all other parameters. | Optional |
| asn_diversity_min | The minimum ASN diversity limit to filter domains. | Optional |
| ip_diversity_all_min | The minimum diversity limit, default = 1. | Optional |
| ip_diversity_groups_min | The minimum diversity limit. | Optional |
| whois_date_after | The filter domains with a WHOIS creation date after this date (YYYY-MM-DD). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.host | String | The domain name \(host\) associated with the record. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.ip_diversity_all | Number | The total number of unique IPs associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. |
| SilentPush.IPDiversityPatterns.SilentPush.Diversity.timeline | Unknown | timeline of \{ip, first_seen, last_seen\}. |

#### Command example

```!silentpush-search-domains nsname=ns1.example.com asn_diversity_min=2 limit=3 timeline=1```

#### Human Readable Output

### silentpush-search-scan-data

***
search Silent Push scan data repositories using SPQL queries.

#### Base Command

`silentpush-search-scan-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The SPQL query string. | Required |
| fields | The dields to return in the response. | Optional |
| sort | The aorting criteria for results. | Optional |
| skip | The number of records to skip in the response. | Optional |
| limit | The maximum number of results to return. | Optional |
| with_metadata | Whether to include metadata in the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ScanData.SilentPush.Web.HHV | String | Unique identifier for the scan data entry. |
| SilentPush.ScanData.SilentPush.Web.adtech | Unknown | Adtech information for the scan data entry. |
| SilentPush.ScanData.SilentPush.Web.adtech_ads_txt | Boolean | Indicates if ads.txt is used. |
| SilentPush.ScanData.SilentPush.Web.adtech_app_ads_txt | Boolean | Indicates if app_ads.txt is used. |
| SilentPush.ScanData.SilentPush.Web.adtech_sellers_json | Boolean | Indicates if sellers.json used. |
| SilentPush.ScanData.SilentPush.Web.body_analysis | Unknown | Body analysis for the scan data entry. |
| SilentPush.ScanData.SilentPush.Web.body_sha256 | String | SHA256 hash of the body. |
| SilentPush.ScanData.SilentPush.Web.language | Unknown | Languages detected in the body. |
| SilentPush.ScanData.SilentPush.Web.ICP_license | String | ICP License information. |
| SilentPush.ScanData.SilentPush.Web.SHV | String | Server Hash Verification value. |
| SilentPush.ScanData.SilentPush.Web.adsense | Unknown | List of AdSense data. |
| SilentPush.ScanData.SilentPush.Web.footer_sha256 | String | SHA-256 hash of the footer content. |
| SilentPush.ScanData.SilentPush.Web.google-GA4 | Unknown | List of Google GA4 identifiers. |
| SilentPush.ScanData.SilentPush.Web.google-UA | Unknown | List of Google Universal Analytics identifiers. |
| SilentPush.ScanData.SilentPush.Web.google-adstag | Unknown | List of Google adstag identifiers. |
| SilentPush.ScanData.SilentPush.Web.header_sha256 | Unknown | SHA-256 hash of the header content. |
| SilentPush.ScanData.SilentPush.Web.js_sha256 | Unknown | List of JavaScript files with SHA-256 hash values. |
| SilentPush.ScanData.SilentPush.Web.js_ssdeep | Unknown | List of JavaScript files with SSDEEP hash values. |
| SilentPush.ScanData.SilentPush.Web.onion | Unknown | List of Onion URLs detected. |
| SilentPush.ScanData.SilentPush.Web.telegram | Unknown | List of Telegram-related information. |
| SilentPush.ScanData.SilentPush.Web.datahash | String | Hash of the data. |
| SilentPush.ScanData.SilentPush.Web.datasource | String | Source of the scan data. |
| SilentPush.ScanData.SilentPush.Web.domain | String | Domain associated with the scan data. |
| SilentPush.ScanData.SilentPush.Web.geoip | Unknown | GeoIP information related to the scan. |
| SilentPush.ScanData.SilentPush.Web.city_name | String | City where the scan data was retrieved. |
| SilentPush.ScanData.SilentPush.Web.country_name | String | Country name from GeoIP information. |
| SilentPush.ScanData.SilentPush.Web.location | Unknown | Geo-location coordinates. |
| SilentPush.ScanData.SilentPush.Web.location.lat | Number | Latitude from GeoIP location. |
| SilentPush.ScanData.SilentPush.Web.location.lon | Number | Longitude from GeoIP location. |
| SilentPush.ScanData.SilentPush.Web.header | Unknown | HTTP header information for the scan. |
| SilentPush.ScanData.SilentPush.Web.header_content-length | String | Content length from HTTP response header. |
| SilentPush.ScanData.SilentPush.Web.header_location | String | Location from HTTP response header. |
| SilentPush.ScanData.SilentPush.Web.header_connection | String | Connection type used, e.g., keep-alive. |
| SilentPush.ScanData.SilentPush.Web.header.server | String | Server software used to serve the content, e.g., openresty. |
| SilentPush.ScanData.SilentPush.Web.hostname | String | Hostname associated with the scan data. |
| SilentPush.ScanData.SilentPush.Web.html_body_sha256 | String | SHA256 hash of the HTML body. |
| SilentPush.ScanData.SilentPush.Web.htmltitle | String | Title of the HTML page scanned. |
| SilentPush.ScanData.SilentPush.Web.ip | String | IP address associated with the scan. |
| SilentPush.ScanData.SilentPush.Web.jarm | String | JARM hash value. |
| SilentPush.ScanData.SilentPush.Web.mobile_enabled | Boolean | Indicates if the page is mobile-enabled. |
| SilentPush.ScanData.SilentPush.Web.origin_domain | String | Origin domain associated with the scan. |
| SilentPush.ScanData.SilentPush.Web.origin_geoip | Unknown | GeoIP information of the origin domain. |
| SilentPush.ScanData.SilentPush.Web.city_name | String | City of the origin domain from GeoIP information. |
| SilentPush.ScanData.SilentPush.Web.origin_hostname | String | Origin hostname associated with the scan data. |
| SilentPush.ScanData.SilentPush.Web.origin_ip | String | Origin IP address of the scan. |
| SilentPush.ScanData.SilentPush.Web.origin_jarm | String | JARM hash value of the origin domain. |
| SilentPush.ScanData.SilentPush.Web.origin_ssl | Unknown | SSL certificate information for the origin domain. |
| SilentPush.ScanData.SilentPush.Web.origin_ssl_SHA256 | String | SHA256 of the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.origin_ssl_subject | Unknown | Subject of the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.origin_ssl_subject_common_name | String | Common name in the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.port | Number | Port used during the scan. |
| SilentPush.ScanData.SilentPush.Web.redirect | Boolean | Indicates if a redirect occurred during the scan. |
| SilentPush.ScanData.SilentPush.Web.redirect_count | Number | Count of redirects encountered. |
| SilentPush.ScanData.SilentPush.Web.redirect_list | Unknown | List of redirect URLs encountered during the scan. |
| SilentPush.ScanData.SilentPush.Web.response | Number | HTTP response code received during the scan. |
| SilentPush.ScanData.SilentPush.Web.scan_date | String | Timestamp of the scan date. |
| SilentPush.ScanData.SilentPush.Web.scheme | String | URL scheme used in the scan. |
| SilentPush.ScanData.SilentPush.Web.ssl | Unknown | SSL certificate details for the scan. |
| SilentPush.ScanData.SilentPush.Web.ssl_SHA256 | String | SHA256 of the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.ssl_subject | Unknown | Subject of the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.ssl_subject_common_name | String | Common name in the SSL certificate. |
| SilentPush.ScanData.SilentPush.Web.subdomain | String | Subdomain associated with the scan data. |
| SilentPush.ScanData.SilentPush.Web.tld | String | Top-level domain \(TLD\) of the scanned URL. |
| SilentPush.ScanData.SilentPush.Web.url | String | The URL scanned. |

#### Command example

```!silentpush-search-scan-data query=domain=example.com fields=scan_date,domain,ip,user-agent sort=scan_date/desc,domain/asc limit=10```

#### Human Readable Output

### silentpush-whois

***
get Whois information

#### Base Command

`silentpush-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to search. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.whois.SilentPush.Whois.registrar | String | Name or partial name of the registrar used to register domains. |
| SilentPush.whois.SilentPush.Whois.name | String | The registrant name |
| SilentPush.whois.SilentPush.Whois.whois_server | String | The server queried |
| SilentPush.whois.SilentPush.Whois.org | String | Organization |
| SilentPush.whois.SilentPush.Whois.address | String | Address |
| SilentPush.whois.SilentPush.Whois.city | Number | City |
| SilentPush.whois.SilentPush.Whois.country | String | Country |
| SilentPush.whois.SilentPush.Whois.created | String | Date created |
| SilentPush.whois.SilentPush.Whois.date | String | Date |
| SilentPush.whois.SilentPush.Whois.domain | String | Domain |
| SilentPush.whois.SilentPush.Whois.emails | Number | Emails |
| SilentPush.whois.SilentPush.Whois.expires | String | Expires |
| SilentPush.whois.SilentPush.Whois.nameservers | String | Nameservers |
| SilentPush.whois.SilentPush.Whois.state | String | State |
| SilentPush.whois.SilentPush.Whois.updated | String | Date updated |
| SilentPush.whois.SilentPush.Whois.zipcode | String | Zip code |

#### Command example

```!silentpush-whois domain=example.com```

#### Human Readable Output
