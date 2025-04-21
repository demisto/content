Enrich and analyze any domain, URL, or IP. Pivot to search on data points and linked indicators to investigate risky properties.
This integration was integrated and tested with version 5.1.15 of Pulsedive

## Configure Pulsedive in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | True |
| Minimum severity of alerts to fetch |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Pulsedive.IP.asn | String | The autonomous system name for the IP address. | 
| Pulsedive.IP.asn_cidr | String | The ASN CIDR. | 
| Pulsedive.IP.asn_country_code | String | The ASN country code. | 
| Pulsedive.IP.asn_date | Date | The date on which the ASN was assigned. | 
| Pulsedive.IP.asn_description | String | The ASN description. | 
| Pulsedive.IP.asn_registry | String | The registry the ASN belongs to. | 
| Pulsedive.IP.entities | String | Entities associated to the IP. | 
| Pulsedive.IP.ip | String | The actual IP address. | 
| Pulsedive.IP.network.cidr | String | Network CIDR for the IP address. | 
| Pulsedive.IP.network.country | Unknown | The country of the IP address. | 
| Pulsedive.IP.network.end_address | String | The last IP address of the CIDR. | 
| Pulsedive.IP.network.events.action | String | The action that happened on the event. | 
| Pulsedive.IP.network.events.actor | Unknown | The actor that performed the action on the event. | 
| Pulsedive.IP.network.events.timestamp | String | The timestamp when the event occurred. | 
| Pulsedive.IP.network.handle | String | The handle of the network. | 
| Pulsedive.IP.network.ip_version | String | The IP address version. | 
| Pulsedive.IP.network.links | String | Links associated to the IP address. | 
| Pulsedive.IP.network.name | String | The name of the network. | 
| Pulsedive.IP.network.notices.description | String | The description of the notice. | 
| Pulsedive.IP.network.notices.links | Unknown | Links associated with the notice. | 
| Pulsedive.IP.network.notices.title | String | Title of the notice. | 
| Pulsedive.IP.network.parent_handle | String | Handle of the parent network. | 
| Pulsedive.IP.network.raw | Unknown | Additional raw data for the network. | 
| Pulsedive.IP.network.remarks | Unknown | Additional remarks for the network. | 
| Pulsedive.IP.network.start_address | String | The first IP address of the CIDR. | 
| Pulsedive.IP.network.status | String | Status of the network. | 
| Pulsedive.IP.network.type | String | The type of the network. | 
| Pulsedive.IP.query | String | IP address that was queried. | 
| Pulsedive.IP.raw | Unknown | Additional raw data for the IP address. | 
| Pulsedive.IP.score | Number | Reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). | 
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.ASN | String | The autonomous system name for the IP address. | 

### domain
***
Returns Domain information and reputation.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.ExpirationDate | Date | The expiration date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example 'GoDaddy' | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| Pulsedive.Domain.address | String | Domain admin address. | 
| Pulsedive.Domain.city | String | Domain admin city. | 
| Pulsedive.Domain.country | String | Domain admin country. | 
| Pulsedive.Domain.creation_date | Date | Domain creation date. Format is ISO8601. | 
| Pulsedive.Domain.dnssec | String | DNSSEC status. | 
| Pulsedive.Domain.domain | String | The domain name. | 
| Pulsedive.Domain.domain_name | String | Domain name options. | 
| Pulsedive.Domain.emails | String | Contact emails. | 
| Pulsedive.Domain.expiration_date | Date | Expiration date. Format is ISO8601. | 
| Pulsedive.Domain.name | String | Domain admin name. | 
| Pulsedive.Domain.name_servers | String | Name server. | 
| Pulsedive.Domain.org | String | Domain organization. | 
| Pulsedive.Domain.referral_url | Unknown | Referral URL. | 
| Pulsedive.Domain.registrar | String | Domain registrar. | 
| Pulsedive.Domain.score | Number | Reputation score from HelloWorld for this domain \(0 to 100, where higher is worse\). | 
| Pulsedive.Domain.state | String | Domain admin state. | 
| Pulsedive.Domain.status | String | Domain status. | 
| Pulsedive.Domain.updated_date | Date | Updated date. Format is ISO8601. | 
| Pulsedive.Domain.whois_server | String | WHOIS server. | 
| Pulsedive.Domain.zipcode | Unknown | Domain admin zipcode. | 

### url
***
Returns URL information and reputation.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of Urls. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL. | 
| URL.Malicious.Vendor | string | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | string | A description of the malicious URL. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| URL.DetectionEngines | string | The total number of engines that checked the indicator. | 
| URL.PositiveDetections | string | The number of engines that positively detected the indicator as malicious. | 

### pulsedive-scan
***
Scan an indicator (IP/URL/Domain)


#### Base Command

`pulsedive-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value to scan. | Required | 
| scan_type | You can choose between passive and active scanning. Passive scans fetch data without reaching out directly to the indicator, including performing WHOIS and DNS requests. Active scans are more noisy; we'll do a quick port scan and reach out to the indicator with a web browser. Possible values are: active, passiv. Default is active. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Pulsedive.Scan.qid | Number | QID of the scan. | 
| Pulsedive.Scan.value | string | The value which was scanned. | 
| Pulsedive.Scan.success | string | The success message. | 

### pulsedive-scan-result
***
Retrieve the Result


#### Base Command

`pulsedive-scan-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qid | QID recieved from scan command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| Pulsedive.ScanResult | Unknown | Complete data returned from the scan. | 
| Domain.Name | String | The domain name. | 
| Domain.DomainStatus | String | The status of the domain. | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Pulsedive.Scan.success | string | The success message. | 
| IP.Address | String | IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Port | String | Ports that are associated with the IP. | 
| IP.ASN | String | The autonomous system name for the URL, for example: 'AS8948'. | 
| URL.DATA | String | The URL. | 