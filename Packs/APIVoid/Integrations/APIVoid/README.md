APIVoid wraps up a number of services such as ipvoid & urlvoid.

## Configure APIVoid in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API KEY |  | True |
| Benign Reputation (Percentage) | If the percentage of detections is BELOW this value, the indicator is considered Benign | True |
| Suspicious Reputation (Percentage) | If the percentage of detections is ABOVE this value, the indicator is considered Suspicious | True |
| Malicious Reputation (Percentage) | If the percentage of detections is ABOVE this value, the indicator is considered Malicious | True |
| Malicious | Consider the indicator malicious if either Suspicious or Malicious | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### apivoid-ip
***
Returns the reputation and extended context of the IP.


#### Base Command

`apivoid-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | IP address | 
| IP.DetectionEngines | number | The total number of engines that checked the indicator. | 
| IP.Geo | unknown |  | 
| IP.Geo.Country | string | The country in which the IP address is located. | 
| IP.Geo.Description | string | Additional information about the location. | 
| IP.Geo.Location | string | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Hostname | string | The hostname that is mapped to this IP address. | 
| IP.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| DBotScore | unknown |  | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| APIVoid.IP.anonymity.is_hosting | boolean |  | 
| APIVoid.IP.anonymity.is_proxy | boolean |  | 
| APIVoid.IP.anonymity.is_tor | boolean |  | 
| APIVoid.IP.anonymity.is_vpn | boolean |  | 
| APIVoid.IP.anonymity.is_webproxy | boolean |  | 
| APIVoid.IP.blacklists.detection_rate | string |  | 
| APIVoid.IP.blacklists.detections | number |  | 
| APIVoid.IP.blacklists.engines.detected | boolean |  | 
| APIVoid.IP.blacklists.engines.elapsed | string |  | 
| APIVoid.IP.blacklists.engines.engine | string |  | 
| APIVoid.IP.blacklists.engines.reference | string |  | 
| APIVoid.IP.blacklists.engines_count | number |  | 
| APIVoid.IP.blacklists.scantime | string |  | 
| APIVoid.IP.information.isp | string |  | 
| APIVoid.IP.information.latitude | string |  | 
| APIVoid.IP.information.reverse_dns | string |  | 
| APIVoid.IP.information.longitude | string |  | 
| APIVoid.IP.information.country_calling_code | string |  | 
| APIVoid.IP.information.country_name | string |  | 
| APIVoid.IP.information.region_name | string |  | 
| APIVoid.IP.information.country_code | string |  | 
| APIVoid.IP.information.continent_name | string |  | 
| APIVoid.IP.information.continent_code | string |  | 
| APIVoid.IP.information.country_currency | string |  | 
| APIVoid.IP.information.city_name | string |  | 
| APIVoid.IP.ip | string |  | 

### apivoid-domain
***
Returns the reputation of the domain.


#### Base Command

`apivoid-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The Domain to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain | unknown |  | 
| Domain.DNS | string | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | number | The total number of engines that checked the indicator. | 
| Domain.Name | string | The domain name, for example: "google.com". | 
| Domain.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| DBotScore | unknown |  | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| APIVoid.Domain.alexa_top_100k | boolean |  | 
| APIVoid.Domain.domain_length | number |  | 
| APIVoid.Domain.server.isp | string |  | 
| APIVoid.Domain.server.ip | string |  | 
| APIVoid.Domain.server.latitude | string |  | 
| APIVoid.Domain.server.reverse_dns | string |  | 
| APIVoid.Domain.server.longitude | string |  | 
| APIVoid.Domain.server.country_name | string |  | 
| APIVoid.Domain.server.region_name | string |  | 
| APIVoid.Domain.server.country_code | string |  | 
| APIVoid.Domain.server.continent_name | string |  | 
| APIVoid.Domain.server.continent_code | string |  | 
| APIVoid.Domain.server.city_name | string |  | 
| APIVoid.Domain.alexa_top_250k | boolean |  | 
| APIVoid.Domain.alexa_top_10k | boolean |  | 
| APIVoid.Domain.most_abused_tld | boolean |  | 
| APIVoid.Domain.host | string |  | 
| APIVoid.Domain.blacklists.detection_rate | string |  | 
| APIVoid.Domain.blacklists.detections | number |  | 
| APIVoid.Domain.blacklists.engines.confidence | string |  | 
| APIVoid.Domain.blacklists.engines.detected | boolean |  | 
| APIVoid.Domain.blacklists.engines.elapsed | string |  | 
| APIVoid.Domain.blacklists.engines.engine | string |  | 
| APIVoid.Domain.blacklists.engines.reference | string |  | 
| APIVoid.Domain.blacklists.engines_count | number |  | 
| APIVoid.Domain.blacklists.scantime | string |  | 
| APIVoid.Domain.category.is_anonymizer | boolean |  | 
| APIVoid.Domain.category.is_free_dynamic_dns | boolean |  | 
| APIVoid.Domain.category.is_free_hosting | boolean |  | 
| APIVoid.Domain.category.is_url_shortener | boolean |  | 

### apivoid-url
***
Returns the reputation of the URL.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`apivoid-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL | unknown |  | 
| URL.Data | string | The URL | 
| URL.DetectionEngines | number | The total number of engines that checked the indicator. | 
| URL.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| DBotScore | unknown |  | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| APIVoid.URL.risk_score.result | number |  | 
| APIVoid.URL.domain_blacklist.detections | number |  | 
| APIVoid.URL.domain_blacklist.engines.detected | boolean |  | 
| APIVoid.URL.domain_blacklist.engines.name | string |  | 
| APIVoid.URL.domain_blacklist.engines.reference | string |  | 
| APIVoid.URL.geo_location.countries | string |  | 
| APIVoid.URL.server_details.isp | string |  | 
| APIVoid.URL.server_details.ip | string |  | 
| APIVoid.URL.server_details.latitude | string |  | 
| APIVoid.URL.server_details.longitude | string |  | 
| APIVoid.URL.server_details.hostname | string |  | 
| APIVoid.URL.server_details.country_name | string |  | 
| APIVoid.URL.server_details.region_name | string |  | 
| APIVoid.URL.server_details.country_code | string |  | 
| APIVoid.URL.server_details.continent_name | string |  | 
| APIVoid.URL.server_details.continent_code | string |  | 
| APIVoid.URL.server_details.city_name | string |  | 
| APIVoid.URL.response_headers.server | string |  | 
| APIVoid.URL.response_headers.code | number |  | 
| APIVoid.URL.response_headers.content-type | string |  | 
| APIVoid.URL.response_headers.date | date |  | 
| APIVoid.URL.response_headers.cache-control | string |  | 
| APIVoid.URL.response_headers.host-header | string |  | 
| APIVoid.URL.response_headers.status | string |  | 
| APIVoid.URL.response_headers.x-redirect-by | string |  | 
| APIVoid.URL.response_headers.expires | date |  | 
| APIVoid.URL.response_headers.location | string |  | 
| APIVoid.URL.response_headers.content-length | string |  | 
| APIVoid.URL.response_headers.upgrade | string |  | 
| APIVoid.URL.response_headers.connection | string |  | 
| APIVoid.URL.security_checks.is_windows_exe_file_on_ipv4 | boolean |  | 
| APIVoid.URL.security_checks.is_credit_card_form | boolean |  | 
| APIVoid.URL.security_checks.is_windows_exe_file_on_free_hosting | boolean |  | 
| APIVoid.URL.security_checks.is_linux_elf_file_on_ipv4 | boolean |  | 
| APIVoid.URL.security_checks.is_linux_elf_file_on_free_hosting | boolean |  | 
| APIVoid.URL.security_checks.is_masked_windows_exe_file | boolean |  | 
| APIVoid.URL.security_checks.is_zip_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_masked_linux_elf_file | boolean |  | 
| APIVoid.URL.security_checks.is_sinkholed_domain | boolean |  | 
| APIVoid.URL.security_checks.is_suspended_page | boolean |  | 
| APIVoid.URL.security_checks.is_suspicious_file_extension | boolean |  | 
| APIVoid.URL.security_checks.is_uncommon_clickable_url | boolean |  | 
| APIVoid.URL.security_checks.is_suspicious_content | boolean |  | 
| APIVoid.URL.security_checks.is_risky_geo_location | boolean |  | 
| APIVoid.URL.security_checks.is_php_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_doc_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_doc_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_empty_page_title | boolean |  | 
| APIVoid.URL.security_checks.is_login_form | boolean |  | 
| APIVoid.URL.security_checks.is_robots_noindex | boolean |  | 
| APIVoid.URL.security_checks.is_suspicious_domain | boolean |  | 
| APIVoid.URL.security_checks.is_windows_exe_file_on_free_dynamic_dns | boolean |  | 
| APIVoid.URL.security_checks.is_most_abused_tld | boolean |  | 
| APIVoid.URL.security_checks.is_linux_elf_file_on_free_dynamic_dns | boolean |  | 
| APIVoid.URL.security_checks.is_suspicious_url_pattern | boolean |  | 
| APIVoid.URL.security_checks.is_valid_https | boolean |  | 
| APIVoid.URL.security_checks.is_exe_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_pdf_on_directory_listing | boolean |  | 
| APIVoid.URL.security_checks.is_host_an_ipv4 | boolean |  | 
| APIVoid.URL.security_checks.is_domain_blacklisted | boolean |  | 
| APIVoid.URL.security_checks.is_china_country | boolean |  | 
| APIVoid.URL.security_checks.is_windows_exe_file | boolean |  | 
| APIVoid.URL.security_checks.is_masked_file | boolean |  | 
| APIVoid.URL.security_checks.is_email_address_on_url_query | boolean |  | 
| APIVoid.URL.security_checks.is_phishing_heuristic | boolean |  | 
| APIVoid.URL.security_checks.is_non_standard_port | boolean |  | 
| APIVoid.URL.security_checks.is_linux_elf_file | boolean |  | 
| APIVoid.URL.security_checks.is_defaced_heuristic | boolean |  | 
| APIVoid.URL.security_checks.is_directory_listing | boolean |  | 
| APIVoid.URL.dns_records.mx.records.country_code | string |  | 
| APIVoid.URL.dns_records.ns.records.country_name | string |  | 
| APIVoid.URL.dns_records.ns.records.ip | string |  | 
| APIVoid.URL.dns_records.ns.records.isp | string |  | 
| APIVoid.URL.dns_records.ns.records.target | string |  | 
| APIVoid.URL.redirection.external | boolean |  | 
| APIVoid.URL.redirection.found | boolean |  | 
| APIVoid.URL.redirection.url | string |  | 
| APIVoid.URL.url | string |  | 
| APIVoid.URL.url_parts.host | string |  | 
| APIVoid.URL.url_parts.host_nowww | string |  | 
| APIVoid.URL.url_parts.path | string |  | 
| APIVoid.URL.url_parts.port | number |  | 
| APIVoid.URL.url_parts.query | string |  | 
| APIVoid.URL.url_parts.scheme | string |  | 
| APIVoid.URL.site_category.is_anonymizer | boolean |  | 
| APIVoid.URL.site_category.is_free_dynamic_dns | boolean |  | 
| APIVoid.URL.site_category.is_free_hosting | boolean |  | 
| APIVoid.URL.site_category.is_torrent | boolean |  | 
| APIVoid.URL.site_category.is_url_shortener | boolean |  | 
| APIVoid.URL.site_category.is_vpn_provider | boolean |  | 
| APIVoid.URL.web_page.description | string |  | 
| APIVoid.URL.web_page.keywords | string |  | 
| APIVoid.URL.web_page.title | string |  | 
| APIVoid.URL.html_forms.credit_card_field_present | boolean |  | 
| APIVoid.URL.html_forms.email_field_present | boolean |  | 
| APIVoid.URL.html_forms.number_of_total_forms | number |  | 
| APIVoid.URL.html_forms.number_of_total_input_fields | number |  | 
| APIVoid.URL.html_forms.password_field_present | boolean |  | 
| APIVoid.URL.html_forms.two_text_inputs_in_a_form | boolean |  | 
| APIVoid.URL.file_type.extension | string |  | 
| APIVoid.URL.file_type.headers | string |  | 
| APIVoid.URL.file_type.signature | string |  | 

### ip
***
Returns the reputation of the IP.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP | unknown |  | 
| IP.Address | string | IP address | 
| IP.DetectionEngines | number | The total number of engines that checked the indicator. | 
| IP.Geo | unknown |  | 
| IP.Geo.Country | string | The country in which the IP address is located. | 
| IP.Geo.Description | string | Additional information about the location. | 
| IP.Geo.Location | string | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Hostname | string | The hostname that is mapped to this IP address. | 
| IP.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 

### domain
***
Returns the reputation of the domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The Domain to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.DNS | string | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | number | The total number of engines that checked the indicator. | 
| Domain.Name | string | The domain name, for example: "google.com". | 
| Domain.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 

### url
***
Returns the reputation of the URL.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL | 
| URL.DetectionEngines | number | The total number of engines that checked the indicator. | 
| URL.PositiveDetections | number | The number of engines that positively detected the indicator as malicious. | 
| URL.RiskScore | number |  | 
| URL.Score | string |  | 
| DBotScore | unknown |  | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 

### apivoid-dns-lookup
***
Gets DNS records of a host.


#### Base Command

`apivoid-dns-lookup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Host to lookup. | Required | 
| type | The DNS record type to lookup. Possible values are: A, AAAA, MX, NS, DMARK, Reverse, TXT, ANY, CNAME, SOA, SRV, CAA. Default is A. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.DNS | unknown |  | 
| APIVoid.DNS.items.host | string |  | 
| APIVoid.DNS.items.class | string |  | 
| APIVoid.DNS.items.ttl | number |  | 
| APIVoid.DNS.items.type | string |  | 
| APIVoid.DNS.items.ip | string |  | 
| APIVoid.DNS.found | boolean |  | 
| APIVoid.DNS.count | number |  | 
| APIVoid.DNS.items.ipv6 | string |  | 
| APIVoid.DNS.items.pri | number |  | 
| APIVoid.DNS.items.target | string |  | 
| APIVoid.DNS.items.txt | string |  | 
| APIVoid.DNS.items.entries | unknown |  | 
| APIVoid.DNS.items.mname | string |  | 
| APIVoid.DNS.items.rname | string |  | 
| APIVoid.DNS.items.serial | number |  | 
| APIVoid.DNS.items.refresh | number |  | 
| APIVoid.DNS.items.retry | number |  | 
| APIVoid.DNS.items.expire | number |  | 
| APIVoid.DNS.items.minimum-ttl | number |  | 
| APIVoid.DNS.items.weight | number |  | 
| APIVoid.DNS.items.port | number |  | 
| APIVoid.DNS.items.flags | number |  | 
| APIVoid.DNS.items.tag | string |  | 
| APIVoid.DNS.items.value | string |  | 

### apivoid-ssl-info
***
Get useful SSL information from a remote host


#### Base Command

`apivoid-ssl-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Host to lookup SSL. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.SSL | unknown |  | 
| APIVoid.SSL.found | boolean |  | 
| APIVoid.SSL.fingerprint | string |  | 
| APIVoid.SSL.deprecated_issuer | boolean |  | 
| APIVoid.SSL.expired | boolean |  | 
| APIVoid.SSL.valid_peer | boolean |  | 
| APIVoid.SSL.host | string |  | 
| APIVoid.SSL.name_match | boolean |  | 
| APIVoid.SSL.debug_message | string |  | 
| APIVoid.SSL.blacklisted | boolean |  | 
| APIVoid.SSL.valid | boolean |  | 
| APIVoid.SSL.details | unknown |  | 
| APIVoid.SSL.details.extensions | unknown |  | 
| APIVoid.SSL.details.extensions.authority_info_access | string |  | 
| APIVoid.SSL.details.extensions.authority_key_identifier | string |  | 
| APIVoid.SSL.details.extensions.basic_constraints | string |  | 
| APIVoid.SSL.details.extensions.certificate_policies | string |  | 
| APIVoid.SSL.details.extensions.crl_distribution_points | string |  | 
| APIVoid.SSL.details.extensions.extended_key_usage | string |  | 
| APIVoid.SSL.details.extensions.key_usage | string |  | 
| APIVoid.SSL.details.extensions.subject_key_identifier | string |  | 
| APIVoid.SSL.details.hash | string |  | 
| APIVoid.SSL.details.issuer | unknown |  | 
| APIVoid.SSL.details.issuer.common_name | string |  | 
| APIVoid.SSL.details.issuer.country | string |  | 
| APIVoid.SSL.details.issuer.location | string |  | 
| APIVoid.SSL.details.issuer.organization | string |  | 
| APIVoid.SSL.details.issuer.organization_unit | string |  | 
| APIVoid.SSL.details.issuer.state | string |  | 
| APIVoid.SSL.details.signature | unknown |  | 
| APIVoid.SSL.details.signature.serial | string |  | 
| APIVoid.SSL.details.signature.serial_hex | string |  | 
| APIVoid.SSL.details.signature.type | string |  | 
| APIVoid.SSL.details.subject | unknown |  | 
| APIVoid.SSL.details.subject.postal_code | string |  | 
| APIVoid.SSL.details.subject.street | string |  | 
| APIVoid.SSL.details.subject.name | string |  | 
| APIVoid.SSL.details.subject.organization_unit | string |  | 
| APIVoid.SSL.details.subject.state | string |  | 
| APIVoid.SSL.details.subject.organization | string |  | 
| APIVoid.SSL.details.subject.location | string |  | 
| APIVoid.SSL.details.subject.alternative_names | string |  | 
| APIVoid.SSL.details.subject.country | string |  | 
| APIVoid.SSL.details.subject.category | string |  | 
| APIVoid.SSL.details.subject.common_name | string |  | 
| APIVoid.SSL.details.validity | unknown |  | 
| APIVoid.SSL.details.validity.days_left | number |  | 
| APIVoid.SSL.details.validity.valid_from | date |  | 
| APIVoid.SSL.details.validity.valid_from_timestamp | date |  | 
| APIVoid.SSL.details.validity.valid_to | date |  | 
| APIVoid.SSL.details.validity.valid_to_timestamp | date |  | 
| APIVoid.SSL.details.version | string |  | 

### apivoid-email-verify
***
Checks if an email address is disposable, if it has MX records, and more.


#### Base Command

`apivoid-email-verify`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.Email | unknown |  | 
| APIVoid.Email.email | string |  | 
| APIVoid.Email.valid_format | boolean |  | 
| APIVoid.Email.username | string |  | 
| APIVoid.Email.role_address | boolean |  | 
| APIVoid.Email.suspicious_username | boolean |  | 
| APIVoid.Email.dirty_words_username | boolean |  | 
| APIVoid.Email.domain | string |  | 
| APIVoid.Email.valid_tld | boolean |  | 
| APIVoid.Email.disposable | boolean |  | 
| APIVoid.Email.has_mx_records | boolean |  | 
| APIVoid.Email.free_email | boolean |  | 
| APIVoid.Email.russian_free_email | boolean |  | 
| APIVoid.Email.china_free_email | boolean |  | 
| APIVoid.Email.suspicious_domain | boolean |  | 
| APIVoid.Email.did_you_mean | string |  | 
| APIVoid.Email.dirty_words_domain | boolean |  | 
| APIVoid.Email.domain_popular | boolean |  | 
| APIVoid.Email.risky_tld | boolean |  | 
| APIVoid.Email.police_domain | boolean |  | 
| APIVoid.Email.government_domain | boolean |  | 
| APIVoid.Email.educational_domain | boolean |  | 
| APIVoid.Email.should_block | boolean |  | 
| APIVoid.Email.score | number |  | 

### apivoid-threatlog
***
Check if a website is present on ThreatLog database


#### Base Command

`apivoid-threatlog`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The host the check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.ThreatLog.detected | boolean |  | 
| APIVoid.ThreatLog.host | string |  | 
| APIVoid.ThreatLog.scantime | string |  | 
| Domain.Name | string | The domain name, for example: "google.com". | 

### apivoid-parked-domain
***
Detect if a domain (i.e google.com) is actually parked


#### Base Command

`apivoid-parked-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.ParkedDomain.host | string |  | 
| APIVoid.ParkedDomain.parked_domain | boolean |  | 
| Domain.Name | string | The domain name, for example: "google.com". | 

### apivoid-domain-age
***
Get the registration date of a domain and the domain age in days


#### Base Command

`apivoid-domain-age`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.DomainAge.debug_message | string |  | 
| APIVoid.DomainAge.domain_age_found | boolean |  | 
| APIVoid.DomainAge.domain_age_in_days | number |  | 
| APIVoid.DomainAge.domain_age_in_months | number |  | 
| APIVoid.DomainAge.domain_age_in_years | number |  | 
| APIVoid.DomainAge.domain_creation_date | string |  | 
| APIVoid.DomainAge.domain_registered | string |  | 
| APIVoid.DomainAge.host | string |  | 
| Domain.CreationDate | date | The date that the domain was created. | 
| Domain.Name | string | The domain name, for example: "google.com". | 

### apivoid-url-to-image
***
Capture a high-quality screenshot of any website or URL


#### Base Command

`apivoid-url-to-image`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to capture screenshot of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The size of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA512 | string | The SHA512 hash of the file. | 
| File.Name | string | The name of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 
| File.EntryID | string | The EntryID of the file. | 
| File.Info | string | Info regarding the file. | 
| File.Type | string | The type of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Extension | string | The extension of the file. | 

### apivoid-url-to-pdf
***
Convert an URL info high-quality and printable PDF document


#### Base Command

`apivoid-url-to-pdf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to create PDF of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The size of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA512 | string | The SHA512 hash of the file. | 
| File.Name | string | The name of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 
| File.EntryID | string | The EntryID of the file. | 
| File.Info | string | Info regarding the file. | 
| File.Type | string | The type of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Extension | string | The extension of the file. | 

### apivoid-url-to-html
***
Get the body of an html page after javascript has been executed


#### Base Command

`apivoid-url-to-html`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to create PDF of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The size of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA512 | string | The SHA512 hash of the file. | 
| File.Name | string | The name of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 
| File.EntryID | string | The EntryID of the file. | 
| File.Info | string | Info regarding the file. | 
| File.Type | string | The type of the file. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Extension | string | The extension of the file. | 

### apivoid-site-trustworthiness
***
A smart API that accurately checks a website's trustworthiness.


#### Base Command

`apivoid-site-trustworthiness`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The host to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| APIVoid.SiteTrust.domain_blacklist.detections | number |  | 
| APIVoid.SiteTrust.domain_blacklist.engines.detected | boolean |  | 
| APIVoid.SiteTrust.domain_blacklist.engines.name | string |  | 
| APIVoid.SiteTrust.domain_blacklist.engines.reference | string |  | 
| APIVoid.SiteTrust.geo_location.countries | unknown |  | 
| APIVoid.SiteTrust.domain_age.domain_age_in_days | number |  | 
| APIVoid.SiteTrust.domain_age.domain_age_in_months | number |  | 
| APIVoid.SiteTrust.domain_age.domain_age_in_years | number |  | 
| APIVoid.SiteTrust.domain_age.domain_creation_date | string |  | 
| APIVoid.SiteTrust.domain_age.found | boolean |  | 
| APIVoid.SiteTrust.server_details.isp | string |  | 
| APIVoid.SiteTrust.server_details.ip | string |  | 
| APIVoid.SiteTrust.server_details.latitude | number |  | 
| APIVoid.SiteTrust.server_details.longitude | number |  | 
| APIVoid.SiteTrust.server_details.hostname | string |  | 
| APIVoid.SiteTrust.server_details.country_name | string |  | 
| APIVoid.SiteTrust.server_details.region_name | string |  | 
| APIVoid.SiteTrust.server_details.country_code | string |  | 
| APIVoid.SiteTrust.server_details.continent_name | string |  | 
| APIVoid.SiteTrust.server_details.continent_code | string |  | 
| APIVoid.SiteTrust.server_details.city_name | string |  | 
| APIVoid.SiteTrust.response_headers.server | string |  | 
| APIVoid.SiteTrust.response_headers.content-encoding | string |  | 
| APIVoid.SiteTrust.response_headers.code | number |  | 
| APIVoid.SiteTrust.response_headers.content-type | string |  | 
| APIVoid.SiteTrust.response_headers.date | date |  | 
| APIVoid.SiteTrust.response_headers.vary | string |  | 
| APIVoid.SiteTrust.response_headers.status | string |  | 
| APIVoid.SiteTrust.response_headers.x-amz-rid | string |  | 
| APIVoid.SiteTrust.response_headers.content-length | string |  | 
| APIVoid.SiteTrust.response_headers.connection | string |  | 
| APIVoid.SiteTrust.host | string |  | 
| APIVoid.SiteTrust.security_checks.is_website_popular | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_suspended_site | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_domain_recent | string |  | 
| APIVoid.SiteTrust.security_checks.is_heuristic_pattern | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_sinkholed_domain | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_risky_geo_location | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_empty_page_title | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_robots_noindex | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_suspicious_domain | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_most_abused_tld | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_valid_https | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_domain_blacklisted | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_email_configured | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_china_country | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_directory_listing | boolean |  | 
| APIVoid.SiteTrust.security_checks.is_free_email | boolean |  | 
| APIVoid.SiteTrust.trust_score.result | number |  | 
| APIVoid.SiteTrust.dns_records | unknown |  | 
| APIVoid.SiteTrust.redirection.external | boolean |  | 
| APIVoid.SiteTrust.redirection.found | boolean |  | 
| APIVoid.SiteTrust.redirection.url | string |  | 
| APIVoid.SiteTrust.url_parts.host | string |  | 
| APIVoid.SiteTrust.url_parts.host_nowww | string |  | 
| APIVoid.SiteTrust.url_parts.path | string |  | 
| APIVoid.SiteTrust.url_parts.port | string |  | 
| APIVoid.SiteTrust.url_parts.query | string |  | 
| APIVoid.SiteTrust.url_parts.scheme | string |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_magento | boolean |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_opencart | boolean |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_prestashop | boolean |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_shopify | boolean |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_woocommerce | boolean |  | 
| APIVoid.SiteTrust.ecommerce_platform.is_zencart | boolean |  | 
| APIVoid.SiteTrust.web_page.description | string |  | 
| APIVoid.SiteTrust.web_page.keywords | string |  | 
| APIVoid.SiteTrust.web_page.title | string |  | 
| APIVoid.SiteTrust.targeted_brands.patagonia | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.rolex | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.timberland | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.hugoboss | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.moncler | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.longchamp | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.abercrombie | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.montblanc | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.carhartt | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.rayban | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.drmartens | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.hermes | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.oakley | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.michaelkors | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.louisvuitton | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.birkenstock | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.adidas | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.vans | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.ralphlauren | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.mulberry | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.converse | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.versace | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.ugg | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.nike | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.swarovski | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.peuterey | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.cartier | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.pandora | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.burberry | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.gucci | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.salomon | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.liujo | boolean |  | 
| APIVoid.SiteTrust.targeted_brands.truereligion | boolean |  | 