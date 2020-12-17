This is the RST Threat Feed integration for interacting with API
This integration was integrated and tested with RST Cloud - Threat Feed API v1

Please contact the RST Cloud team via email support@rstcloud.net to obtain a key and ask any questions you have.
Also, the following contact details can be used:
- **URL**: [https://www.rstcloud.net/contact](https://www.rstcloud.net/contact)

Each indicator is ranked from 0 to 100. Indicators are being collected from multiple sources and are cross-verified using multiple criteria. 
Please check indicator tags and malware family fields. An indicator may describe a known malware or a scanning host. Therefore, different actions may be required based on the context.

## Configure RST Cloud - Threat Feed API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RST Cloud - Threat Feed API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g. https://api.rstcloud.net/v1\) | True |
    | apikey | API Key | True |
    | threshold_ip | Score threshold for IP reputation command | False |
    | threshold_domain | Score threshold for domain reputation command | False |
    | threshold_url | Score threshold for url reputation command | False |
    | indicator_expiration_ip | indicator_expiration_ip \(days\) | False |
    | indicator_expiration_domain | indicator_expiration_domain \(days\) | False |
    | indicator_expiration_url | indicator_expiration_url \(days\) | False |
    | proxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rst-threat-feed-ip
***
Return IP information and reputation


#### Base Command

`rst-threat-feed-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 45. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | IP address. | 
| IP.Geo.Country | String | Country of origin. | 
| IP.Tags | String | The associated tags | 
| IP.MalwareFamily | String | The associated Malware Family or threat name | 
| IP.FirstSeenBySource | Date | The Fist Seen date | 
| IP.LastSeenBySource | Date | The Last Seen date | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Malicious.Score | String | The score calculated for the indicator by the vendor | 
| IP.Suspicious.Vendor | String | The vendor reporting the IP address as suspicious. | 
| IP.Suspicious.Description | String | A description explaining why the IP address was reported as suspicious | 
| IP.Suspicious.Score | String | The score calculated for the indicator by the vendor | 
| RST.IP.Address | String | The actual IP address. | 
| RST.IP.Geo.Country | String | The country name | 
| RST.IP.Geo.Region | String | The geo region name | 
| RST.IP.Geo.City | String | The city name | 
| RST.IP.ASN.Name | String | The autonomous system name for the IP address. | 
| RST.IP.ASN.Org | String | The organisation name for the autonomous system name for the IP address. | 
| RST.IP.ASN.ISP | String | The Internet Service Provider name for the autonomous system name for the IP address. | 
| RST.IP.ASN.Cloud | String | The Cloud Provider name for the IP address. | 
| RST.IP.ASN.DomainNumber | String | The number of domain names for the IP address. | 
| RST.IP.ASN.FirstIP | String | The ASN FirstIP | 
| RST.IP.ASN.LastIP | String | The ASN LastIP | 
| RST.IP.FirstSeen | Date | First Seen | 
| RST.IP.LastSeen | Date | Last Seen | 
| RST.IP.Tags | String | The associated tags | 
| RST.IP.Threat | String | The associated Malware Family or threat name | 
| RST.IP.Score | Number | The total score | 
| RST.IP.Description | String | The associated Description provided by the vendor | 
| RST.IP.FalsePositive | String | true if it is likely a False Positive | 
| RST.IP.FalsePositiveDesc | String | Description why we think it may be a False Positive | 


#### Command Example
``` rst-threat-feed-ip ip=['118.243.83.70','8.8.8.8'] threshold=40 ```

#### Human Readable Output



### rst-threat-feed-domain
***
Returns Domain information and reputation.


#### Base Command

`rst-threat-feed-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 45. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.MalwareFamily | String | The associated Malware Family or threat name | 
| Domain.Tags | String | The associated tags | 
| Domain.FirstSeenBySource | Date | The Fist Seen date | 
| Domain.LastSeenBySource | Date | The Last Seen date | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Malicious.Score | String | The score calculated for the indicator by the vendor | 
| Domain.Suspicious.Vendor | String | The vendor reporting the domain as suspicious. | 
| Domain.Suspicious.Description | String | A description explaining why the domain was reported as suspicious. | 
| Domain.Suspicious.Score | String | The score calculated for the indicator by the vendor | 
| RST.Domain.Name | String | The domain name. | 
| RST.Domain.WHOIS.Age | Number | Days since creation | 
| RST.Domain.WHOIS.CreationDate | Date | Creation date. Format is ISO8601. | 
| RST.Domain.WHOIS.UpdatedDate | Date | Update date. Format is ISO8601. | 
| RST.Domain.WHOIS.ExpirationDate | Date | Expiration date. Format is ISO8601. | 
| RST.Domain.WHOIS.Registrar | String | Domain Registrar | 
| RST.Domain.WHOIS.Registrant | String | Domain Registrant | 
| RST.Domain.FirstSeen | Date | First Seen | 
| RST.Domain.LastSeen | Date | Last Seen | 
| RST.Domain.Tags | String | The associated tags | 
| RST.Domain.Threat | String | The associated Malware Family or threat name | 
| RST.Domain.Score | Number | The total score | 
| RST.Domain.Description | String | The associated Description provided by the vendor | 
| RST.Domain.FalsePositive | String | true if it is likely a False Positive | 
| RST.Domain.FalsePositiveDesc | String | Description why we think it may be a False Positive | 


#### Command Example
``` rst-threat-feed-domain domain=['thec0de-22249.portmap.io'] threshold=25  ```

#### Human Readable Output



### rst-threat-feed-url
***
Returns URL information and reputation.


#### Base Command

`rst-threat-feed-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 
| threshold | If the URL has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| URL.Data | String | The URL | 
| URL.MalwareFamily | String | The associated Malware Family or threat name | 
| URL.Tags | String | The associated tags | 
| URL.FirstSeenBySource | Date | The Fist Seen date | 
| URL.LastSeenBySource | Date | The Last Seen date | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious | 
| URL.Malicious.Description | String | A description explaining why the URL was reported as malicious | 
| URL.Malicious.Score | String | The score calculated for the URL indicator by the vendor | 
| URL.Suspicious.Vendor | String | The vendor reporting the URL as suspicious. | 
| URL.Suspicious.Description | String | A description explaining why the URL was reported as suspicious. | 
| URL.Suspicious.Score | String | The score calculated for the URL indicator by the vendor | 
| RST.URL.Data | String | The URL | 
| RST.URL.ResolveStatus | String | Last HTTP status code | 
| RST.URL.FirstSeen | Date | First Seen | 
| RST.URL.LastSeen | Date | Last Seen | 
| RST.URL.Tags | String | The associated tags | 
| RST.URL.Threat | String | The associated Malware Family or threat name | 
| RST.URL.Score | Number | The total score | 
| RST.URL.Description | String | The associated Description provided by the vendor | 
| RST.URL.FalsePositive | String | true if it is likely a False Positive | 
| RST.URL.FalsePositiveDesc | String | Description why we think it may be a False Positive | 


#### Command Example
``` rst-threat-feed-url url=['http://zpmagura.com/wp-content/nux5wem-08'] threshold=15 ```

#### Human Readable Output



### rst-threat-feed-submit
***
Submits an indicator to RST Threat Feed


#### Base Command

`rst-threat-feed-submit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc | List of IOCs (URLs, domains or IPs). | Required | 
| description | Any context to pass to RST Cloud. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` rst-threat-feed-submit ioc=['118.243.83.70'] description=['potential c2'] ```

#### Human Readable Output



### rst-threat-feed-submit-fp
***
Submits a potential False Positive to RST Threat Feed


#### Base Command

`rst-threat-feed-submit-fp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc | List of IOCs (URLs, domains or IPs). | Required | 
| description | Any context to pass to RST Cloud. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` rst-threat-feed-submitfp ioc=['8.8.8.8'] description=['well-known dns server']  ```

#### Human Readable Output


