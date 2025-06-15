The Silent Push Platform uses first-party data and a proprietary scanning engine to enrich global DNS data with risk and reputation scoring, giving security teams the ability to join the dots across the entire IPv4 and IPv6 range, and identify adversary infrastructure before an attack is launched. The content pack integrates with the Silent Push system to gain insights into domain/IP information, reputations, enrichment, and infratag-related details. It also provides functionality to live-scan URLs and take screenshots of them. Additionally, it allows fetching future attack feeds from the Silent Push system.
This integration was integrated and tested with version 4.2 of SilentPush.

## Configure SilentPush in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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

```!silentpush-density-lookup qtype="nssrv" query="vida.ns.cloudflare.com"```

#### Context Example

```json
{
	"qtype": "nssrv",
	"query": "vida.ns.cloudflare.com",
	"records": [
		{
			"density": 100601,
			"nssrv": "vida.ns.cloudflare.com"
		}
	]
}
```

#### Human Readable Output

>### Results  

>| Field   | Value                        |
>|---------|------------------------------|
>| Density | 100601                       |
>| NSSRV   | vida.ns.cloudflare.com       |

### silentpush-forward-padns-lookup

***
This command performs a forward PADNS lookup using various filtering parameters.

#### Base Command

`silentpush-forward-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qtype | DNS record type. | Required | 
| qname | The DNS record name to lookup. | Required | 
| netmask | The netmask to filter the lookup results. | Optional | 
| subdomains | Flag to include subdomains in the lookup results. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| match | Type of match for the query (e.g., exact, partial). | Optional | 
| first_seen_after | Filter results to include only records first seen after this date. | Optional | 
| first_seen_before | Filter results to include only records first seen before this date. | Optional | 
| last_seen_after | Filter results to include only records last seen after this date. | Optional | 
| last_seen_before | Filter results to include only records last seen before this date. | Optional | 
| as_of | Date or time to get the DNS records as of a specific point in time. | Optional | 
| sort | Sort the results by the specified field (e.g., date, score). | Optional | 
| output_format | The format in which the results should be returned (e.g., JSON, XML). | Optional | 
| prefer | Preference for specific DNS servers or sources. | Optional | 
| with_metadata | Flag to include metadata in the DNS records. | Optional | 
| max_wait | Maximum number of seconds to wait for results before timing out. | Optional | 
| skip | Number of results to skip for pagination purposes. | Optional | 
| limit | Maximum number of results to return. | Optional | 

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

### **Command Example**  

```!silentpush-forward-padns-lookup qtype="ns" qname="silentpush.com"```

### **Context Example**  

```json
{
	"qtype": "ns",
	"qname": "silentpush.com",
	"records": [
		{
			"answer": "henry.ns.cloudflare.com",
			"count": 23043,
			"first_seen": "2020-12-24 19:04:43",
			"last_seen": "2025-04-08 07:06:24",
			"nshash": "850c47a684c9ea9c32ece18e7be4cddc",
			"query": "silentpush.com"
		}
	]
}
```

### **Human Readable Output**  

>### Results  

>| Field        | Value                        |
>|--------------|------------------------------|
>| Answer       | henry.ns.cloudflare.com      |
>| Count        | 23043                        |
>| First Seen   | 2020-12-24 19:04:43          |
>| Last Seen    | 2025-04-08 07:06:24          |
>| NSHash       | 850c47a684c9ea9c32ece18e7be4cddc |
>| Query        | silentpush.com               |
  


### silentpush-get-asn-reputation

***
This command retrieve the reputation information for an IPv4.

#### Base Command

`silentpush-get-asn-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | The ASN to lookup. | Required | 
| explain | Show the information used to calculate the reputation score. | Optional | 
| limit | The maximum number of reputation history records to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ASNReputation.asn | Number | Autonomous System Number \(ASN\) associated with the reputation history. | 
| SilentPush.ASNReputation.asn_reputation | Number | Reputation score of the ASN at a given point in time. | 
| SilentPush.ASNReputation.asn_reputation_explain.ips_in_asn | Number | Total number of IPs within the ASN. | 
| SilentPush.ASNReputation.asn_reputation_explain.ips_num_active | Number | Number of actively used IPs in the ASN. | 
| SilentPush.ASNReputation.asn_reputation_explain.ips_num_listed | Number | Number of IPs in the ASN that are listed as malicious. | 
| SilentPush.ASNReputation.asname | String | Name of the ASN provider or organization. | 
| SilentPush.ASNReputation.date | Number | Date of the recorded reputation history in YYYYMMDD format. | 


### **Command Example**  

```!silentpush-get-asn-reputation asn="12345"```

### **Context Example**  

```json
{
	"asn": "12345",
	"reputation": 0,
	"as_name": "AS12345, IT",
	"date": "20250408"
}
```

### **Human Readable Output**  

>### Results  

>| Field        | Value                  |
>|--------------|------------------------|
>| ASN          | 12345                  |
>| Reputation   | 0                      |
>| AS Name      | AS12345, IT            |
>| Date         | 2025-04-08             |


### silentpush-get-asn-takedown-reputation

***
This command retrieve the takedown reputation information for an Autonomous System Number (ASN).

#### Base Command

`silentpush-get-asn-takedown-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | The ASN to lookup. | Required | 
| explain | Show the information used to calculate the reputation score. | Optional | 
| limit | The maximum number of reputation history records to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ASNTakedownReputation.takedown_reputation.asname | String | The name of the Autonomous System \(AS\). | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn | String | The Autonomous System Number \(ASN\). | 
| SilentPush.ASNTakedownReputation.takedown_reputation.allocation_age | Number | The age of the ASN allocation in days. | 
| SilentPush.ASNTakedownReputation.takedown_reputation.allocation_date | Number | The date when the ASN was allocated \(YYYYMMDD\). | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn_takedown_reputation | Number | The takedown reputation score for the ASN. | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn_takedown_reputation_explain.ips_in_asn | Number | The total number of IP addresses associated with the ASN. | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn_takedown_reputation_explain.ips_num_listed | Number | The number of IP addresses within the ASN that are flagged or listed in security threat databases. | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn_takedown_reputation_explain.items_num_listed | Number | The total number of security-related listings associated with the ASN, including IP addresses and domains. | 
| SilentPush.ASNTakedownReputation.takedown_reputation.asn_takedown_reputation_explain.listings_max_age | Number | The maximum age \(in hours\) of the listings, indicating how recent the flagged IPs/domains are. | 

### **Command Example**  

```!silentpush-get-asn-takedown-reputation asn="211298"```

### **Context Example**  

```json
{
	"asn": "211298",
	"asn_allocation_age": 1420,
	"asn_allocation_date": "2021-05-19",
	"asn_takedown_reputation": 0,
	"as_name": "INTERNET-MEASUREMENT, GB"
}
```

### **Human Readable Output**  

>### Results  

>| Field                        | Value                      |
>|------------------------------|----------------------------|
>| ASN                          | 211298                     |
>| ASN Allocation Age           | 1420 days                  |
>| ASN Allocation Date          | 2021-05-19                 |
>| ASN Takedown Reputation      | 0                          |
>| AS Name                      | INTERNET-MEASUREMENT, GB   |



### silentpush-get-asns-for-domain

***
This command retrieves Autonomous System Numbers (ASNs) associated with a domain.

#### Base Command

`silentpush-get-asns-for-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to search ASNs for. Retrieves ASNs associated with a records for the specified domain and its subdomains in the last 30 days. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.DomainASNs.domain | String | The domain name for which ASNs are retrieved. | 
| SilentPush.DomainASNs.asns | Unknown | Dictionary of Autonomous System Numbers \(ASNs\) associated with the domain. |

### **Command Example**  

```!silentpush-get-asns-for-domain domain="silentpush.com"```

### **Context Example**  

```json
{
	"domain": "silentpush.com",
	"asns": [
		{
			"asn": "13335",
			"description": "CLOUDFLARENET, US"
		},
		{
			"asn": "14618",
			"description": "AMAZON-AES, US"
		},
		{
			"asn": "16509",
			"description": "AMAZON-02, US"
		},
		{
			"asn": "209242",
			"description": "CLOUDFLARESPECTRUM Cloudflare, Inc., US"
		},
		{
			"asn": "213230",
			"description": "HETZNER-CLOUD2-AS, DE"
		},
		{
			"asn": "24940",
			"description": "HETZNER-AS, DE"
		}
	]
}
```

### **Human Readable Output**  

>### Results  

>| ASN     | Description                              |
>|---------|------------------------------------------|
>| 13335   | CLOUDFLARENET, US                        |
>| 14618   | AMAZON-AES, US                           |
>| 16509   | AMAZON-02, US                            |
>| 209242  | CLOUDFLARESPECTRUM Cloudflare, Inc., US  |
>| 213230  | HETZNER-CLOUD2-AS, DE                    |
>| 24940   | HETZNER-AS, DE                           |



### silentpush-get-domain-certificates

***
This command get certificate data collected from domain scanning.

#### Base Command

`silentpush-get-domain-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to query certificates for. | Required | 
| domain_regex | Regular expression to match domains. | Optional | 
| certificate_issuer | Filter by certificate issuer. | Optional | 
| date_min | Filter certificates issued on or after this date. | Optional | 
| date_max | Filter certificates issued on or before this date. | Optional | 
| prefer | Prefer to wait for results for longer running queries or to return job_id immediately (Defaults to Silent Push API behaviour). | Optional | 
| max_wait | Number of seconds to wait for results before returning a job_id, with a range from 0 to 25 seconds. | Optional | 
| with_metadata | Includes a metadata object in the response, containing returned results, total results, and job_id. | Optional | 
| skip | Number of results to skip. | Optional | 
| limit | Number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Certificate.domain | String | Queried domain. | 
| SilentPush.Certificate.metadata | String | Metadata of the response | 
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

### **Command Example**  

```!silentpush-get-domain-certificates domain="silentpush.com"```

### **Context Example**  

```json
{
	"domain": "silentpush.com",
	"certificates": [
		{
			"common_name": "silentpush.com",
			"expires_on": "2025-07-03 16:02:40",
			"fingerprint_sha256": "f7ec9de47a7b22181e6a394a2af8a59793c6ea07538fc49a2351b25c6dc20d69",
			"issued_on": "2025-04-04 16:02:41",
			"issuer": "E5",
			"serial_number": "6E51EEDAA93109DCA31CE852A8D0C27C001",
			"subject_alternative_names": ["silentpush.com"]
		}
	]
}
```

### **Human Readable Output**  

>### Result  

>| Field                        | Value                                        |
>|------------------------------|----------------------------------------------|
>| Common Name                  | silentpush.com                              |
>| Expires On                   | 2025-07-03 16:02:40                         |
>| Fingerprint (SHA256)         | f7ec9de47a7b22181e6a394a2af8a59793c6ea07538fc49a2351b25c6dc20d69 |
>| Issued On                   | 2025-04-04 16:02:41                         |
>| Issuer                       | E5                                           |
>| Serial Number                | 6E51EEDAA93109DCA31CE852A8D0C27C001        |
>| Subject Alternative Names    | silentpush.com                              |



### silentpush-get-enrichment-data

***
This command retrieves comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).

#### Base Command

`silentpush-get-enrichment-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | Type of resource for which information needs to be retrieved {e.g. domain}. | Required | 
| value | Value corresponding to the selected "resource" for which information needs to be retrieved{e.g. silentpush.com}. | Required | 
| explain | Include explanation of data calculations. | Optional | 
| scan_data | Include scan data (IPv4 only). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Enrichment.value | String | Queried value | 
| SilentPush.Enrichment.domain_string_frequency_probability.avg_probability | Number | Average probability score of the domain string. | 
| SilentPush.Enrichment.domain_string_frequency_probability.dga_probability_score | Number | Probability score indicating likelihood of being a DGA domain. | 
| SilentPush.Enrichment.domain_string_frequency_probability.domain | String | Domain name analyzed. | 
| SilentPush.Enrichment.domain_string_frequency_probability.domain_string_freq_probabilities | Unknown | List of frequency probabilities for different domain string components. | 
| SilentPush.Enrichment.domain_string_frequency_probability.query | String | Domain name queried. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_rank | Number | Alexa rank of the domain. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_top10k | Boolean | Indicates if the domain is in the Alexa top 10k. | 
| SilentPush.Enrichment.domain_urls.results_summary.alexa_top10k_score | Number | Score indicating domain’s Alexa top 10k ranking. | 
| SilentPush.Enrichment.domain_urls.results_summary.dynamic_domain_score | Number | Score indicating likelihood of domain being dynamically generated. | 
| SilentPush.Enrichment.domain_urls.results_summary.is_dynamic_domain | Boolean | Indicates if the domain is dynamic. | 
| SilentPush.Enrichment.domain_urls.results_summary.is_url_shortener | Boolean | Indicates if the domain is a known URL shortener. | 
| SilentPush.Enrichment.domain_urls.results_summary.results | Number | Number of results found for the domain. | 
| SilentPush.Enrichment.domain_urls.results_summary.url_shortner_score | Number | Score of the shortned URL | 
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
| SilentPush.Enrichment.ns_reputation.is_expired | Boolean | Indicates if the domain’s nameserver is expired. | 
| SilentPush.Enrichment.ns_reputation.is_parked | Boolean |  The domain is not parked \(a parked domain is one without active content\). | 
| SilentPush.Enrichment.ns_reputation.is_sinkholed | Boolean | The domain is not sinkholed \(not forcibly redirected to a security researcher’s trap\). | 
| SilentPush.Enrichment.ns_reputation.ns_reputation_max | Number | Maximum reputation score for nameservers. | 
| SilentPush.Enrichment.ns_reputation.ns_reputation_score | Number | Reputation score of the domain’s nameservers. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.domain | String | The nameservers of domain. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server | String | Provided nameserver. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_domain_density | Number | Number of domains sharing this NS | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_domains_listed | Number | Number of listed domains using this NS. | 
| SilentPush.Enrichment.ns_reputation.ns_srv_reputation.ns_server_reputation | Number | Reputation score for this NS | 
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
| SilentPush.Enrichment.scan_data.headers.headers.cache-control | String | HTTP cache-control | 
| SilentPush.Enrichment.scan_data.headers.headers.content-length" | String | Content lenght of the HTTP response. | 
| SilentPush.Enrichment.scan_data.headers.headers.date | String | The date/time of the response. | 
| SilentPush.Enrichment.scan_data.headers.headers.expires | String | Indicates an already expired response. | 
| SilentPush.Enrichment.scan_data.headers.headers.server | String | The web server handling the request \(Cloudflare proxy\). | 
| SilentPush.Enrichment.scan_data.html.hostname | String | HTTP response code for the domain scan. | 
| SilentPush.Enrichment.scan_data.html.html_body_murmur3 | String | hash of the page content | 
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
| SilentPush.Enrichment.ip2asn.benign_info.known_benign | Boolean | Indicates whether this IP/ASN is explicitly known to be safe \(e.g., a reputable cloud provider or public service\) | 
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

### **Command Example**  

```bash
!silentpush-get-enrichment-data resource="ipv4" value="142.251.188.102"
```

### **Context Example**  

```json
{
	"resource": "ipv4",
	"value": "142.251.188.102",
	"enrichment_data": {
		"asn": "15169",
		"asn_allocation_age": 9140,
		"asn_allocation_date": "2000-03-30",
		"asn_rank": 0,
		"asn_rank_score": 0,
		"asn_reputation": 0,
		"asn_reputation_score": 0,
		"asn_takedown_reputation": 80,
		"asn_takedown_reputation_score": 80,
		"as_name": "GOOGLE, US",
		"benign_info": {
			"actor": "",
			"known_benign": false
		},
		"tags": [],
		"date": "2025-04-08",
		"density": 0,
		"ip": "142.251.188.102",
		"ip_flags": {
			"is_proxy": false,
			"is_sinkhole": false,
			"is_vpn": false
		},
		"ip_has_expired_certificate": false,
		"ip_has_open_directory": false,
		"ip_is_dsl_dynamic": false,
		"ip_is_dsl_dynamic_score": 0,
		"ip_is_ipfs_node": false
	}
}
```

### **Human Readable Output**  

>### Result

>| Field                          | Value                    |
>|--------------------------------|--------------------------|
>| ASN                            | 15169                    |
>| ASN Allocation Age             | 9140 days                |
>| ASN Allocation Date            | 2000-03-30               |
>| ASN Rank                       | 0                        |
>| ASN Rank Score                 | 0                        |
>| ASN Reputation                 | 0                        |
>| ASN Reputation Score           | 0                        |
>| ASN Takedown Reputation        | 80                       |
>| ASN Takedown Reputation Score  | 80                       |
>| AS Name                        | GOOGLE, US               |
>| Known Benign                   | No                       |
>| Date                           | 2025-04-08               |
>| Density                        | 0                        |
>| IP Flags (Proxy, Sinkhole, VPN)| No, No, No               |
>| Expired Certificate            | No                       |
>| Open Directory                 | No                       |
>| DSL Dynamic                    | No                       |
>| DSL Dynamic Score              | 0                        |
>| IPFS Node                      | No                       |



### silentpush-get-future-attack-indicators

***
This command fetch indicators of potential future attacks using a feed UUID.

#### Base Command

`silentpush-get-future-attack-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_uuid | Unique ID for the feed. | Required | 
| page_no | The page number to fetch results from. | Optional | 
| page_size | The number of indicators to fetch per page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.FutureAttackIndicators.feed_uuid | String | Unique identifier for the feed. | 
| SilentPush.FutureAttackIndicators.page_no | Number | Current page number for pagination. | 
| SilentPush.FutureAttackIndicators.page_size | Number | Number of items to be retrieved per page. | 
| SilentPush.FutureAttackIndicators.indicators.total_ioc | Number | Total number of Indicators of Compromise \(IOCs\) associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.total | Number | Total occurrences of the indicator across all sources. | 
| SilentPush.FutureAttackIndicators.indicators.total_source_score | Number | Cumulative score assigned to the indicator by all sources. | 
| SilentPush.FutureAttackIndicators.indicators.name | String | Name associated with the indicator, such as a domain name. | 
| SilentPush.FutureAttackIndicators.indicators.total_custom | Number | Total number of custom indicators for the specific entry. | 
| SilentPush.FutureAttackIndicators.indicators.source_name | String | Name of the source providing the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.first_seen_on | String | Date and time when the indicator was first observed. | 
| SilentPush.FutureAttackIndicators.indicators.last_seen_on | String | Date and time when the indicator was last observed. | 
| SilentPush.FutureAttackIndicators.indicators.type | String | Type of the indicator \(e.g., domain, IP address, URL\). | 
| SilentPush.FutureAttackIndicators.indicators.uuid | String | Unique identifier assigned to the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.ioc_template | String | Template type describing the indicator \(e.g., domain template\). | 
| SilentPush.FutureAttackIndicators.indicators.ioc_uuid | String | Unique identifier for the IOC related to the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.source_vendor_name | String | Name of the vendor providing the indicator source \(e.g., Silent Push\). | 
| SilentPush.FutureAttackIndicators.indicators.source_uuid | String | Unique identifier for the source of the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.total_ioc | Number | Total count of Indicators of Compromise associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.collected_tags | Unknown | Tags associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.listing_score | Number | Score assigned by the source indicating the severity or importance of the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.sp_risk_score | Number | Risk score calculated by the source for the indicator, reflecting its potential threat level. | 
| SilentPush.FutureAttackIndicators.indicators.ip_is_tor_exit_node | Boolean | Indicates whether the IP address is a known TOR exit node. | 
| SilentPush.FutureAttackIndicators.indicators.ip_is_dsl_dynamic | Boolean | Indicates whether the IP address is a DSL dynamic IP. | 
| SilentPush.FutureAttackIndicators.indicators.ip_reputation_score | Number | Reputation score assigned to the IP address based on its history and activities. | 
| SilentPush.FutureAttackIndicators.indicators.known_sinkhole_ip | String | Indicates if the IP address is associated with a known sinkhole. | 
| SilentPush.FutureAttackIndicators.indicators.known_benign | Number | Indicates whether the indicator is known to be benign or harmless. | 
| SilentPush.FutureAttackIndicators.indicators.asn_rank_score | Number | Score indicating the reputation rank of the ASN. | 
| SilentPush.FutureAttackIndicators.indicators.asn_reputation_score | Number | Reputation score assigned to the ASN based on its activities. | 
| SilentPush.FutureAttackIndicators.indicators.ip_is_dsl_dynamic_score | Number | Score indicating the likelihood of the IP being a DSL dynamic IP. | 
| SilentPush.FutureAttackIndicators.indicators.subnet_reputation_score | Number | Reputation score assigned to a subnet based on its history and activities. | 
| SilentPush.FutureAttackIndicators.indicators.asn_takedown_reputation_score | Number | Reputation score of the ASN considering takedown activities or abuse reports. | 
| SilentPush.FutureAttackIndicators.indicators.asn | Number | Autonomous System Number \(ASN\) associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.density | Number | Indicator density score based on traffic or other relevant factors. | 
| SilentPush.FutureAttackIndicators.indicators.asn_rank | Number | Rank of the ASN indicating its reputation or trustworthiness. | 
| SilentPush.FutureAttackIndicators.indicators.malscore | Number | Maliciousness score assigned to the indicator based on threat analysis. | 
| SilentPush.FutureAttackIndicators.indicators.asn_reputation | Number | Reputation score associated with the ASN. | 
| SilentPush.FutureAttackIndicators.indicators.subnet_reputation | Number | Reputation score associated with the subnet. | 
| SilentPush.FutureAttackIndicators.indicators.asn_allocation_age | Number | Age of the ASN allocation in days. | 
| SilentPush.FutureAttackIndicators.indicators.subnet_allocation_age | Number | Age of the subnet allocation in days. | 
| SilentPush.FutureAttackIndicators.indicators.asn_takedown_reputation | Number | Reputation score of the ASN considering takedown reports or abuse. | 
| SilentPush.FutureAttackIndicators.indicators.ipv4 | String | IPv4 address associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.asname | String | Autonomous System Name \(ASName\) associated with the ASN. | 
| SilentPush.FutureAttackIndicators.indicators.ip_ptr | String | PTR \(reverse DNS\) record associated with the IP address. | 
| SilentPush.FutureAttackIndicators.indicators.subnet | String | Subnet associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.country_code | Number | Country code associated with the indicator \(e.g., US, CA\). | 
| SilentPush.FutureAttackIndicators.indicators.continent_code | Number | Continent code associated with the indicator \(e.g., NA, EU\). | 
| SilentPush.FutureAttackIndicators.indicators.it_exists | Boolean | Indicates if the indicator currently exists in the dataset. | 
| SilentPush.FutureAttackIndicators.indicators.is_new | Boolean | Indicates if the indicator is newly detected. | 
| SilentPush.FutureAttackIndicators.indicators.is_alexa_top10k | Boolean | Indicates if the domain is part of the Alexa Top 10K list. | 
| SilentPush.FutureAttackIndicators.indicators.is_dynamic_domain | Boolean | Indicates if the domain is classified as dynamic. | 
| SilentPush.FutureAttackIndicators.indicators.is_url_shortener | Boolean | Indicates if the URL is associated with a URL shortener service. | 
| SilentPush.FutureAttackIndicators.indicators.is_parked | Boolean | Indicates if the domain is a parked domain. | 
| SilentPush.FutureAttackIndicators.indicators.is_expired | Boolean | Indicates if the domain registration has expired. | 
| SilentPush.FutureAttackIndicators.indicators.is_sinkholed | Boolean | Indicates if the domain is associated with a sinkhole operation. | 
| SilentPush.FutureAttackIndicators.indicators.ns_entropy_score | Number | Entropy score of the nameserver, indicating randomness or irregularity. | 
| SilentPush.FutureAttackIndicators.indicators.age_score | Number | Score indicating the age of the domain, with higher scores for older domains. | 
| SilentPush.FutureAttackIndicators.indicators.is_new_score | Boolean | Score indicating the likelihood of the domain being newly registered. | 
| SilentPush.FutureAttackIndicators.indicators.ns_avg_ttl_score | Number | Score representing the average TTL of the nameservers. | 
| SilentPush.FutureAttackIndicators.indicators.ns_reputation_max | Number | Maximum reputation score of the nameservers. | 
| SilentPush.FutureAttackIndicators.indicators.ns_reputation_score | Number | Overall reputation score of the nameservers. | 
| SilentPush.FutureAttackIndicators.indicators.avg_probability_score | Number | Average probability score indicating the likelihood of malicious activity. | 
| SilentPush.FutureAttackIndicators.indicators.alexa_top10k_score | Number | Score indicating the rank within the Alexa Top 10K list. | 
| SilentPush.FutureAttackIndicators.indicators.url_shortener_score | Number | Score indicating the likelihood of the URL being a URL shortener. | 
| SilentPush.FutureAttackIndicators.indicators.dynamic_domain_score | Number | Score indicating the likelihood of the domain being dynamic. | 
| SilentPush.FutureAttackIndicators.indicators.ns_entropy | Number | Entropy value of the nameserver, indicating randomness or irregularity. | 
| SilentPush.FutureAttackIndicators.indicators.age | Number | Age of the domain in days. | 
| SilentPush.FutureAttackIndicators.indicators.whois_age | Number | Age of the domain based on the WHOIS creation date. | 
| SilentPush.FutureAttackIndicators.indicators.alexa_rank | Number | Alexa rank of the domain, indicating its popularity. | 
| SilentPush.FutureAttackIndicators.indicators.asn_diversity | Number | Diversity score of the ASN, indicating the variety of ASNs associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.ip_diversity_all | Number | Count of all unique IP addresses associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.ip_diversity_groups | Number | Count of unique IP address groups associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.avg_probability | Number | Average probability indicating the likelihood of malicious activity. | 
| SilentPush.FutureAttackIndicators.indicators.whois_created_date | String | Creation date of the domain from WHOIS records. | 
| SilentPush.FutureAttackIndicators.indicators.domain | String | Domain name associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.subdomain | String | Subdomain associated with the indicator, if applicable. | 
| SilentPush.FutureAttackIndicators.indicators.host | String | Host associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.nameservers_tags | String | Tags related to the nameservers associated with the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.source_false_positive_ratio | Number | Ratio of false positives reported by the source. | 
| SilentPush.FutureAttackIndicators.indicators.source_true_positive_ratio | Number | Ratio of true positives reported by the source. | 
| SilentPush.FutureAttackIndicators.indicators.source_last_updated_score | Number | Score indicating the last update time of the source. | 
| SilentPush.FutureAttackIndicators.indicators.source_frequency_score | Number | Score representing the frequency of updates from the source. | 
| SilentPush.FutureAttackIndicators.indicators.source_accuracy_score | Number | Score indicating the accuracy of the source reporting. | 
| SilentPush.FutureAttackIndicators.indicators.source_geographic_spread_score | Number | Score indicating the geographic spread of the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.source_custom_score | Number | Custom score provided by the source for the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.source_score | Number | Overall score assigned by the source to the indicator. | 
| SilentPush.FutureAttackIndicators.indicators.source_frequency | Number | Frequency of the indicator appearance in the source data. | 
| SilentPush.FutureAttackIndicators.indicators.source_geographic_spread_explain | Unknown | Explanation of the geographic spread of the indicator as provided by the source. | 

### **Command Example**  

```bash
!silentpush-get-future-attack-indicators feed_uuid="99da9b6a-146b-4a4d-9929-5fd5c6e2c257"
```

### **Context Example**  

```json
{
	"feed_uuid": "99da9b6a-146b-4a4d-9929-5fd5c6e2c257",
	"future_attack_indicators": {
		"total_source_score": 100,
		"total_ioc": 100,
		"total_custom": 0,
		"total": 100,
		"name": "capital-gainers.com",
		"uuid": "560ee6da03f56cec",
		"ioc_uuid": "f2556a5a18607c70",
		"type": "domain",
		"ioc_template": "domain",
		"last_seen_on": "2025-04-08T01:24:57",
		"source_uuid": "99da9b6a-146b-4a4d-9929-5fd5c6e2c257",
		"source_name": "AI Generated Investment/Banks Domains",
		"source_vendor_name": "Silent Push",
		"first_seen_on": "2025-04-07T07:24:36"
	}
}
```

### **Human Readable Output**  

>### Result 

>| Field                         | Value                                      |
>|-------------------------------|--------------------------------------------|
>| Feed Name                     | capital-gainers.com                       |
>| Feed UUID                     | 560ee6da03f56cec                           |
>| IOC UUID                      | f2556a5a18607c70                           |
>| Type                          | Domain                                     |
>| IOC Template                  | Domain                                     |
>| Source UUID                   | 99da9b6a-146b-4a4d-9929-5fd5c6e2c257      |
>| Source Name                   | AI Generated Investment/Banks Domains      |
>| Source Vendor Name            | Silent Push                                 |
>| First Seen                    | 2025-04-07T07:24:36                        |
>| Last Seen                     | 2025-04-08T01:24:57                        |
>| Total Source Score            | 100                                        |
>| Total IOCs                    | 100                                        |
>| Total Custom IOCs             | 0                                          |
>| Total IOCs Reported           | 100                                        |



### silentpush-get-ipv4-reputation

***
This command retrieve the reputation information for an IPv4.

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

### **Command Example**  

```bash
!silentpush-get-nameserver-reputation nameserver="a.dns-servers.net.ru" limit="5"
```

### **Context Example**  

```json
{
	"nameserver": "a.dns-servers.net.ru",
	"limit": 5,
	"nameserver_reputation_data": {
		"date": "2025-04-05",
		"ns_server": "a.dns-servers.net.ru",
		"ns_server_reputation": 0
	}
}
```

### **Human Readable Output**  

>### Result  

>| Field                   | Value                        |
>|-------------------------|------------------------------|
>| Nameserver              | a.dns-servers.net.ru        |
>| Date                    | 2025-04-05                   |
>| Nameserver Reputation   | 0                            |



### silentpush-get-job-status

***
This command retrieve status of running job or results from completed job.

#### Base Command

`silentpush-get-job-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | ID of the job returned by Silent Push actions. | Required | 
| max_wait | Number of seconds to wait for results (0-25 seconds). | Optional | 
| status_only | Return job status, even if job is complete. | Optional | 
| force_metadata_on | Always return query metadata, even if original request did not include metadata. | Optional | 
| force_metadata_off | Never return query metadata, even if original request did include metadata. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.JobStatus.get | String | URL to retrieve the job status. | 
| SilentPush.JobStatus.job_id | String | Unique identifier for the job. | 
| SilentPush.JobStatus.status | String | Current status of the job. | 

### **Command Example**  

```bash
!silentpush-get-job-status job_id="d4067541-eafb-424c-98d3-de12d7a91331"
```

### **Context Example**  

```json
{
	"job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
	"job_status": {
		"job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
		"status": "PENDING"
	}
}
```

### **Human Readable Output**  

>### Result 

>| Field      | Value                                   |
>|------------|-----------------------------------------|
>| Job ID     | d4067541-eafb-424c-98d3-de12d7a91331    |
>| Status     | PENDING                                 |


### silentpush-get-nameserver-reputation

***
This command retrieve historical reputation data for a specified nameserver, including reputation scores and optional detailed calculation information.

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

### **Command Example**  

```bash
!silentpush-get-nameserver-reputation nameserver="a.dns-servers.net.ru" limit="5"
```

### **Context Example**  

```json
{
	"nameserver": "a.dns-servers.net.ru",
	"limit": 5,
	"nameserver_reputation_data": {
		"date": "2025-04-05",
		"ns_server": "a.dns-servers.net.ru",
		"ns_server_reputation": 0
	}
}
```

### **Human Readable Output**  

>### Result  

>| Field                   | Value                        |
>|-------------------------|------------------------------|
>| Nameserver              | a.dns-servers.net.ru        |
>| Date                    | 2025-04-05                   |
>| Nameserver Reputation   | 0                            |



### silentpush-get-subnet-reputation

***
This command retrieves the reputation history for a specific subnet.

#### Base Command

`silentpush-get-subnet-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | IPv4 subnet for which reputation information needs to be retrieved. | Required | 
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

### **Command Example**  

```bash
!silentpush-get-subnet-reputation subnet="192.168.0.0/16"
```

### **Context Example**  

```json
{
	"subnet": "192.168.0.0/16",
	"subnet_reputation_data": {
		"date": "2025-04-08",
		"subnet": "192.168.0.0/16",
		"subnet_reputation": 0
	}
}
```

### **Human Readable Output**  

>### Result 

>| Field               | Value                    |
>|---------------------|--------------------------|
>| Subnet              | 192.168.0.0/16           |
>| Date                | 2025-04-08               |
>| Subnet Reputation   | 0                        |



### silentpush-list-domain-information

***
This command get domain information along with Silent Push risk score and live whois information for multiple domains.

#### Base Command

`silentpush-list-domain-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domains to query. | Required | 
| fetch_risk_score | Whether to fetch risk scores for the domains. | Optional | 
| fetch_whois_info | Whether to fetch WHOIS information for the domains. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Domain.domain | String | The domain name queried. | 
| SilentPush.Domain.last_seen | Number | The last seen date of the domain in YYYYMMDD format. | 
| SilentPush.Domain.query | String | The domain name used for the query. | 
| SilentPush.Domain.whois_age | Number | The age of the domain in days based on WHOIS creation date. | 
| SilentPush.Domain.first_seen | Number | The first seen date of the domain in YYYYMMDD format. | 
| SilentPush.Domain.is_new | Boolean | Indicates whether the domain is newly observed. | 
| SilentPush.Domain.zone | String | The top-level domain \(TLD\) or zone of the queried domain. | 
| SilentPush.Domain.registrar | String | The registrar responsible for the domain registration. | 
| SilentPush.Domain.age_score | Number | A risk score based on the domain's age. | 
| SilentPush.Domain.whois_created_date | String | The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format. | 
| SilentPush.Domain.is_new_score | Number | A risk score indicating how new the domain is. | 
| SilentPush.Domain.age | Number | The age of the domain in days. | 

### **Command Example**  

```bash
!silentpush-list-domain-information domains="silentpush.com"
```

### **Context Example**  

```json
{
	"domains": ["silentpush.com"],
	"domain_information": {
		"domain": "silentpush.com",
		"age": 1904,
		"age_score": 0,
		"first_seen": "2020-01-21",
		"is_new": false,
		"is_new_score": 0,
		"last_seen": "2025-04-08",
		"registrar": "ENOM, INC.",
		"whois_age": 1904,
		"whois_created_date": "2020-01-20 08:14:27",
		"zone": "com"
	}
}
```

### **Human Readable Output**  

>### Results 

>| Field                 | Value                        |
>|-----------------------|------------------------------|
>| Domain                | silentpush.com               |
>| Age                   | 1904 years                  |
>| Age Score             | 0                            |
>| First Seen            | 2020-01-21                   |
>| Is New                | No                           |
>| Is New Score          | 0                            |
>| Last Seen             | 2025-04-08                   |
>| Registrar             | ENOM, INC.                   |
>| WHOIS Age             | 1904 years                  |
>| WHOIS Created Date    | 2020-01-20 08:14:27          |
>| Zone                  | com                          |


### silentpush-list-domain-infratags

***
This command get infratags for multiple domains with optional clustering.

#### Base Command

`silentpush-list-domain-infratags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domains. | Required | 
| cluster | Whether to cluster the results. | Optional | 
| mode | Mode for lookup (live/padns). Defaults to "live". Default is live. | Optional | 
| match | Handling of self-hosted infrastructure. Defaults to "self". Default is self. | Optional | 
| as_of | Build infratags from padns data where the as_of timestamp equivalent is between the first_seen and the last_seen timestamp - automatically sets mode to padns. Example :- date: yyyy-mm-dd (2021-07-09) - fixed date, epoch: number (1625834953) - fixed time in epoch format, sec: negative number (-172800) - relative time &lt;sec&gt; seconds ago. Default is self. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.InfraTags.infratags.domain | String | The domain associated with the infratag. | 
| SilentPush.InfraTags.infratags.mode | String | The mode associated with the domain infratag. | 
| SilentPush.InfraTags.infratags.tag | String | The tag associated with the domain infratag. | 
| SilentPush.InfraTags.tag_clusters.25.domains | Unknown | List of domains in the tag cluster with score 25. | 
| SilentPush.InfraTags.tag_clusters.25.match | String | The match string associated with the domains in the tag cluster with score 25. | 
| SilentPush.InfraTags.tag_clusters.50.domains | Unknown | List of domains in the tag cluster with score 50. | 
| SilentPush.InfraTags.tag_clusters.50.match | String | The match string associated with the domains in the tag cluster with score 50. | 
| SilentPush.InfraTags.tag_clusters.75.domains | Unknown | List of domains in the tag cluster with score 75. | 
| SilentPush.InfraTags.tag_clusters.75.match | String | The match string associated with the domains in the tag cluster with score 75. | 
| SilentPush.InfraTags.tag_clusters.100.domains | Unknown | List of domains in the tag cluster with score 100. | 
| SilentPush.InfraTags.tag_clusters.100.match | String | The match string associated with the domains in the tag cluster with score 100. | 

### **Command Example**  

```bash
!silentpush-list-domain-infratags domains="silentpush.com" mode="live" match="self" as_of="self"
```

### **Context Example**  

```json
{
	"domains": ["silentpush.com"],
	"mode": "live",
	"match": "self",
	"as_of": "self",
	"infratags": {
		"domain": "silentpush.com",
		"mode": "padns",
		"tags": ["outlook.com", "cloudflare.com", "cloudflarenet", "enom"]
	}
}
```

### **Human Readable Output**  

>### Results 

>| Field   | Value                                    |
>|---------|------------------------------------------|
>| Domain  | silentpush.com                           |
>| Mode    | padns                                    |
>| Tags    | outlook.com, cloudflare.com, cloudflarenet, enom |


### silentpush-list-ip-information

***
This command get IP information for multiple IPv4s and IPv6s.

#### Base Command

`silentpush-list-ip-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Comma-separated list of IP addresses. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.IPInformation.ip_is_dsl_dynamic | Boolean | Indicates if the IP is a DSL dynamic IP. | 
| SilentPush.IPInformation.ip_has_expired_certificate | Boolean | Indicates if the IP has an expired certificate. | 
| SilentPush.IPInformation.subnet_allocation_age | String | Age of the subnet allocation. | 
| SilentPush.IPInformation.asn_rank_score | Number | Rank score of the ASN. | 
| SilentPush.IPInformation.asn_allocation_age | Number | Age of the ASN allocation in days. | 
| SilentPush.IPInformation.sp_risk_score | Number | Risk score of the service provider \(SP\). | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.ips_active | Number | Number of active IPs in the ASN takedown reputation. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.ips_in_asn | Number | Total number of IPs in the ASN. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.ips_num_listed | Number | Number of IPs listed in the ASN takedown reputation. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.items_num_listed | Number | Number of items listed in the ASN takedown reputation. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.lifetime_avg | Number | Average lifetime of items in the ASN takedown reputation. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.lifetime_max | Number | Maximum lifetime of items in the ASN takedown reputation. | 
| SilentPush.IPInformation.asn_takedown_reputation_explain.lifetime_total | Number | Total lifetime of items in the ASN takedown reputation. | 
| SilentPush.IPInformation.ip_reputation_score | Number | Reputation score of the IP. | 
| SilentPush.IPInformation.listing_score_feeds_explain | String | Explanation of the listing score feeds. | 
| SilentPush.IPInformation.ip | String | The IP address being evaluated. | 
| SilentPush.IPInformation.density | Number | Density score of the IP. | 
| SilentPush.IPInformation.benign_info.actor | String | Actor associated with the benign info. | 
| SilentPush.IPInformation.benign_info.known_benign | Boolean | Indicates if the IP is known benign. | 
| SilentPush.IPInformation.benign_info.tags | String | Tags associated with the benign info. | 
| SilentPush.IPInformation.ip_reputation_explain | String | Explanation of the IP reputation. | 
| SilentPush.IPInformation.asn_allocation_date | Number | The ASN allocation date. | 
| SilentPush.IPInformation.subnet_allocation_date | String | The subnet allocation date. | 
| SilentPush.IPInformation.asn_takedown_reputation | Number | Reputation score of ASN takedown. | 
| SilentPush.IPInformation.ip_location.continent_code | String | Continent code of the IP location. | 
| SilentPush.IPInformation.ip_location.continent_name | String | Continent name of the IP location. | 
| SilentPush.IPInformation.ip_location.country_code | String | Country code of the IP location. | 
| SilentPush.IPInformation.ip_location.country_is_in_european_union | Boolean | Indicates if the country is in the European Union. | 
| SilentPush.IPInformation.ip_location.country_name | String | Country name of the IP location. | 
| SilentPush.IPInformation.date | Number | Date associated with the IP data. | 
| SilentPush.IPInformation.subnet_reputation_score | Number | Reputation score of the subnet. | 
| SilentPush.IPInformation.asn_rank | Number | Rank of the ASN. | 
| SilentPush.IPInformation.listing_score_explain | String | Explanation of the listing score. | 
| SilentPush.IPInformation.asn_reputation_score | Number | Reputation score of the ASN. | 
| SilentPush.IPInformation.ip_is_ipfs_node | Boolean | Indicates if the IP is an IPFS node. | 
| SilentPush.IPInformation.ip_reputation | Number | Reputation score of the IP. | 
| SilentPush.IPInformation.subnet_reputation_explain | String | Explanation of the subnet reputation. | 
| SilentPush.IPInformation.ip_is_dsl_dynamic_score | Number | Score indicating if the IP is a DSL dynamic IP. | 
| SilentPush.IPInformation.asn_reputation_explain | String | Explanation of the ASN reputation. | 
| SilentPush.IPInformation.ip_has_open_directory | Boolean | Indicates if the IP has an open directory. | 
| SilentPush.IPInformation.ip_ptr | String | Pointer \(PTR\) record for the IP. | 
| SilentPush.IPInformation.listing_score | Number | Listing score of the IP. | 
| SilentPush.IPInformation.malscore | Number | Malware score associated with the IP. | 
| SilentPush.IPInformation.sinkhole_info.known_sinkhole_ip | Boolean | Indicates if the IP is a known sinkhole IP. | 
| SilentPush.IPInformation.sinkhole_info.tags | String | Tags associated with the sinkhole information. | 
| SilentPush.IPInformation.subnet_reputation | Number | Reputation score of the subnet. | 
| SilentPush.IPInformation.asn_reputation | Number | Reputation score of the ASN. | 
| SilentPush.IPInformation.asn | Number | Autonomous System Number \(ASN\) of the IP. | 
| SilentPush.IPInformation.sp_risk_score_explain.sp_risk_score_decider | String | Decider for the service provider risk score. | 
| SilentPush.IPInformation.asname | String | Name of the ASN. | 
| SilentPush.IPInformation.subnet | String | The subnet the IP belongs to. | 
| SilentPush.IPInformation.ip_is_tor_exit_node | Boolean | Indicates if the IP is a TOR exit node. | 
| SilentPush.IPInformation.asn_takedown_reputation_score | Number | Reputation score of ASN takedown. | 
| SilentPush.IPInformation.ip_flags.is_proxy | Boolean | Indicates if the IP is a proxy \(True/False\). | 
| SilentPush.IPInformation.ip_flags.is_sinkhole | Boolean | Indicates if the IP is a sinkhole \(True/False\). | 
| SilentPush.IPInformation.ip_flags.is_vpn | Boolean | Indicates if the IP is a VPN \(True/False\). | 
| SilentPush.IPInformation.ip_flags.proxy_tags | Unknown | List of proxy-related tags or null if not a proxy. | 
| SilentPush.IPInformation.ip_flags.vpn_tags | Unknown | List of VPN-related tags or null if not a VPN. | 

### **Command Example**  

```bash
!silentpush-list-ip-information ips="142.251.188.102"
```

### **Context Example**  

```json
{
	"ips": ["142.251.188.102"],
	"ip_information": {
		"asn": "15169",
		"asn_allocation_age": 9140,
		"asn_allocation_date": "2000-03-30",
		"asn_rank": 0,
		"asn_rank_score": 0,
		"asn_reputation": 0,
		"asn_reputation_score": 0,
		"asn_takedown_reputation": 10,
		"asn_takedown_reputation_explain": "ips_active: 327064, ips_in_asn: 15309568, ips_num_listed: 5",
		"asn_takedown_reputation_score": 10,
		"as_name": "GOOGLE, US",
		"benign_info": {
			"actor": "",
			"known_benign": false
		},
		"tags": [],
		"date": "2025-04-08",
		"density": 0,
		"ip": "142.251.188.102",
		"ip_flags": {
			"is_proxy": false,
			"is_sinkhole": false,
			"is_vpn": false
		},
		"ip_has_expired_certificate": false,
		"ip_has_open_directory": false,
		"ip_is_dsl_dynamic": false,
		"ip_is_dsl_dynamic_score": 0
	}
}
```

### **Human Readable Output**  

>### Results 

>| Field                                   | Value                                      |
>|-----------------------------------------|--------------------------------------------|
>| ASN                                     | 15169                                      |
>| ASN Allocation Age                      | 9140 days                                  |
>| ASN Allocation Date                     | 2000-03-30                                 |
>| ASN Rank                                | 0                                          |
>| ASN Rank Score                          | 0                                          |
>| ASN Reputation                          | 0                                          |
>| ASN Reputation Score                    | 0                                          |
>| ASN Takedown Reputation                 | 10                                         |
>| Takedown Explanation                    | ips_active: 327064, ips_in_asn: 15309568, ips_num_listed: 5 |
>| ASN Takedown Reputation Score           | 10                                         |
>| AS Name                                 | GOOGLE, US                                 |
>| Known Benign                            | No                                         |
>| Date                                    | 2025-04-08                                 |
>| Density                                 | 0                                          |
>| IP Flags (Proxy, Sinkhole, VPN)         | No, No, No                                 |
>| Expired Certificate                     | No                                         |
>| Open Directory                          | No                                         |
>| DSL Dynamic                             | No                                         |
>| DSL Dynamic Score                       | 0                                          |


### silentpush-live-url-scan

***
This command scan a URL to retrieve hosting metadata..

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

### **Command Example**  

```bash
!silentpush-live-url-scan url="https://silentpush.com"
```

### **Context Example**  

```json
{
	"url": "https://silentpush.com",
	"scan_results": {
		"status": "No scan results found",
		"url": "https://silentpush.com"
	}
}
```

### **Human Readable Output**  

>### Results

>| Field          | Value                      |
>|----------------|----------------------------|
>| URL            | <https://silentpush.com>     |
>| Scan Status    | No scan results found      |


### silentpush-reverse-padns-lookup

***
This command retrieve reverse Passive DNS data for specific DNS record types.

#### Base Command

`silentpush-reverse-padns-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qtype | Type of DNS record. | Required | 
| qname | The DNS record name to lookup. | Required | 
| netmask | The netmask for the lookup. | Optional | 
| subdomains | Whether to include subdomains in the lookup. | Optional | 
| regex | Regular expression to filter the DNS records. | Optional | 
| first_seen_after | Filter for records first seen after a specific date/time. | Optional | 
| first_seen_before | Filter for records first seen before a specific date/time. | Optional | 
| last_seen_after | Filter for records last seen after a specific date/time. | Optional | 
| last_seen_before | Filter for records last seen before a specific date/time. | Optional | 
| as_of | Specify a date/time for the PADNS lookup. | Optional | 
| sort | Sort the results by specified criteria. | Optional | 
| output_format | Format for the output (e.g., JSON, XML). | Optional | 
| prefer | Preference for certain record types during the lookup. | Optional | 
| with_metadata | Include metadata in the results. | Optional | 
| max_wait | Maximum wait time in seconds for the lookup results. | Optional | 
| skip | Number of results to skip in pagination. | Optional | 
| limit | Limit the number of results returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.ReversePADNSLookup.qname | String | The DNS record name looked up. | 
| SilentPush.ReversePADNSLookup.qtype | String | The type of the DNS record. | 
| SilentPush.ReversePADNSLookup.records.answer | String | The answer for the DNS query. | 
| SilentPush.ReversePADNSLookup.records.count | Number | The number of occurrences of the DNS record. | 
| SilentPush.ReversePADNSLookup.records.first_seen | String | Timestamp of when the record was first seen. | 
| SilentPush.ReversePADNSLookup.records.last_seen | String | Timestamp of the most recent occurrence of the record. | 
| SilentPush.ReversePADNSLookup.records.nshash | String | The hash of the NS record. | 
| SilentPush.ReversePADNSLookup.records.query | String | The DNS query associated with the record. | 
| SilentPush.ReversePADNSLookup.records.ttl | Number | Time-to-live \(TTL\) of the DNS record. | 
| SilentPush.ReversePADNSLookup.records.type | String | The type of DNS record \(e.g., NS\). | 

### **Command Example**  

```bash
!silentpush-reverse-padns-lookup qtype="ns" qname="vida.ns.cloudflare.com"
```

### **Context Example**  

```json
{
	"qtype": "ns",
	"qname": "vida.ns.cloudflare.com",
	"reverse_padns_lookup": {
		"answer": "vida.ns.cloudflare.com",
		"count": 541,
		"first_seen": "2023-10-25 18:46:27",
		"last_seen": "2025-04-08 09:37:41",
		"nshash": "9448b4ad541f0e539d2f5ad271d6d581",
		"query": "ernestchadwick.com"
	}
}
```

### **Human Readable Output**  

>### Results

>| Field             | Value                                |
>|-------------------|--------------------------------------|
>| Answer            | vida.ns.cloudflare.com               |
>| Query Count       | 541                                  |
>| First Seen        | 2023-10-25 18:46:27                  |
>| Last Seen         | 2025-04-08 09:37:41                  |
>| NS Hash           | 9448b4ad541f0e539d2f5ad271d6d581    |
>| Query Domain      | ernestchadwick.com                   |


### silentpush-screenshot-url

***
This commandGenerate screenshot of a URL.

#### Base Command

`silentpush-screenshot-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL for the screenshot. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Screenshot.file_id | String | Unique identifier for the generated screenshot file. | 
| SilentPush.Screenshot.file_name | String | Name of the screenshot file. | 
| SilentPush.Screenshot.screenshot_url | String | URL to access the generated screenshot. | 
| SilentPush.Screenshot.status | String | Status of the screenshot generation process. | 
| SilentPush.Screenshot.status_code | Number | HTTP status code of the response. | 
| SilentPush.Screenshot.url | String | The URL that was used to generate the screenshot. | 

### **Command Example**  

```bash
!silentpush-screenshot-url url="https://www.virustotal.com/gui/domain/tbibank-bg.com"
```

### **Context Example**  

```json
{
	"url": "https://www.virustotal.com/gui/domain/tbibank-bg.com",
	"screenshot_data": {
		"status": "Success",
		"screenshot_url": "https://fs.silentpush.com/screenshots/virustotal.com/f2fa9440ee769ad6f6702529c006522b.jpg",
		"file_name": "www.virustotal.com_screenshot.jpg"
	}
}
```

### **Human Readable Output**  

>### Results  

>| Field             | Value                                                             |
>|-------------------|-------------------------------------------------------------------|
>| URL               | <https://www.virustotal.com/gui/domain/tbibank-bg.com>              |
>| Status            | Success                                                            |
>| Screenshot URL    | [View Screenshot](https://fs.silentpush.com/screenshots/virustotal.com/f2fa9440ee769ad6f6702529c006522b.jpg) |
>| File Name         | www.virustotal.com_screenshot.jpg                                 |


### silentpush-search-domains

***
This command search for domains with optional filters.

#### Base Command

`silentpush-search-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Name or wildcard pattern of domain names to search for. | Optional | 
| domain_regex | A valid RE2 regex pattern to match domains. Overrides the domain argument. | Optional | 
| name_server | Name server name or wildcard pattern of the name server used by domains. | Optional | 
| asnum | Autonomous System (AS) number to filter domains. | Optional | 
| asname | Search for all AS numbers where the AS Name begins with the specified value. | Optional | 
| min_ip_diversity | Minimum IP diversity limit to filter domains. | Optional | 
| registrar | Name or partial name of the registrar used to register domains. | Optional | 
| min_asn_diversity | Minimum ASN diversity limit to filter domains. | Optional | 
| certificate_issuer | Filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported. | Optional | 
| whois_date_after | Filter domains with a WHOIS creation date after this date (YYYY-MM-DD). | Optional | 
| skip | Number of results to skip in the search query. | Optional | 
| limit | Number of results to return. Defaults to the SilentPush API's behavior. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SilentPush.Domain.asn_diversity | Number | The diversity of Autonomous System Numbers \(ASNs\) associated with the domain. | 
| SilentPush.Domain.host | String | The domain name \(host\) associated with the record. | 
| SilentPush.Domain.ip_diversity_all | Number | The total number of unique IPs associated with the domain. | 
| SilentPush.Domain.ip_diversity_groups | Number | The number of unique IP groups associated with the domain. | 

### **Command Example**  

```bash
!silentpush-search-domains
```

### **Context Example**  

```json
{
	"domain_search_results": [
		{
			"asn_diversity": 1,
			"host": "0-------------------------------------------------------------0.com",
			"ip_diversity_all": 1,
			"ip_diversity_groups": 1
		}
	]
}
```

### **Human Readable Output**  

>### Results  

>| Field                | Value                              |
>|----------------------|------------------------------------|
>| ASN Diversity        | 1                                  |
>| Host                 | 0-------------------------------------------------------------0.com |
>| IP Diversity (All)   | 1                                  |
>| IP Diversity Groups  | 1                                  |


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

### **Command Example**  

```bash
!silentpush-search-scan-data query="tld=cool" limit="5"
```

### **Context Example**  

```json
{
	"query": "tld=cool",
	"limit": 5,
	"scan_data": [
		{
			"domain": "volunteering.cool",
			"ip": "44.227.65.245",
			"asn": "16509",
			"asn_org": "AMAZON-02",
			"city": "Boardman",
			"country": "United States",
			"region": "Oregon",
			"latitude": 45.8401,
			"longitude": -119.705,
			"timezone": "America/Los_Angeles",
			"server": "openresty",
			"ssl": "http",
			"favicon": "http://volunteering.cool/favicon.ico",
			"user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.3",
			"scan_date": "2025-04-08T09:12:45Z",
			"status_code": 200
		}
	]
}
```

### **Human Readable Output**  

>### Results  

>| Field                   | Value                                      |
>|-------------------------|--------------------------------------------|
>| Domain                  | [volunteering.cool](http://volunteering.cool) |
>| IP Address              | 44.227.65.245                              |
>| ASN                     | 16509                                      |
>| ASN Organization        | AMAZON-02                                  |
>| City                    | Boardman                                  |
>| Country                 | United States                              |
>| Region                  | Oregon                                    |
>| Latitude                | 45.8401                                   |
>| Longitude               | -119.705                                  |
>| Timezone                | America/Los_Angeles                       |
>| Server                  | openresty                                 |
>| SSL/TLS Status          | HTTP (No SSL)                             |
>| Favicon                 | ![Favicon](http://volunteering.cool/favicon.ico) |
>| User Agent              | Mozilla/5.0 (Linux x86_64)                |
>| Scan Date               | 2025-04-08T09:12:45Z                      |
>| HTTP Status Code        | 200                                        |
