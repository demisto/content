Data Mining for Threat Intelligence

## Configure ThreatMiner in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Maximum results per query, enter 'all' to get unlimited results |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| ThreatMiner API URL |  | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Retrieves data from ThreatMiner about a specified domain.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to get information for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMiner.Domain.Whois.Server | string | Whois server address. | 
| ThreatMiner.Domain.Whois.CreateDate | date | Creation date. | 
| ThreatMiner.Domain.Whois.UpdateDate | date | Last update date. | 
| ThreatMiner.Domain.Whois.Expiration | date | Expiration date. | 
| ThreatMiner.Domain.Whois.NameServers | string | Whois name servers. | 
| ThreatMiner.Domain.PassiveDNS.IP | string | Passive DNS IP address. | 
| ThreatMiner.Domain.PassiveDNS.FirstSeen | date | Passive DNS first seen date. | 
| ThreatMiner.Domain.PassiveDNS.LastSeen | date | Passive DNS last seen date. | 
| ThreatMiner.Domain.Subdomains | string | Subdomains. | 
| ThreatMiner.Domain.URI.Address | string | Related URIs. | 
| ThreatMiner.Domain.URI.LastSeen | string | URI last seen date. | 
| ThreatMiner.Domain.MD5 | string | Related samples' MD5 hash. | 
| Domain.Name | string | Searched domain name | 
| ThreatMiner.Domain.Whois.Domain | string | Domain name that was searched. | 
| Domain.DNS | unknown | IPs resolved by DNS. | 
| Domain.Whois.CreateDate | date | Creation date. | 
| Domain.Whois.UpdateDate | date | Last update date. | 
| Domain.Whois.Expiration | date | Expiration date. | 
| Domain.Whois.Registrant.Name | string | Name of the registrant | 
| Domain.Whois.Registrant.Email | string | Email of the registrant | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### ip
***
Retrieves data from ThreatMiner about a specified IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to get information for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMiner.IP.Address | string | IP address that was searched. | 
| ThreatMiner.IP.Whois.Reverse | string | Whois reverse name. | 
| ThreatMiner.IP.Whois.Bgp | string | BGP prefix. | 
| ThreatMiner.IP.Whois.Country | string | Related country. | 
| ThreatMiner.IP.Whois.ASN | string | Related ASN. | 
| ThreatMiner.IP.Whois.Org | string | Organization name. | 
| ThreatMiner.IP.PassiveDNS.Domain | string | PassiveDNS domain. | 
| ThreatMiner.IP.PassiveDNS.FirstSeen | date | Passive DNS first seen date. | 
| ThreatMiner.IP.PassiveDNS.LastSeen | date | Passive DNS last seen date. | 
| ThreatMiner.IP.URI.Address | string | Related URIs. | 
| ThreatMiner.IP.URI.LastSeen | date | URI last seen date. | 
| ThreatMiner.IP.MD5 | string | Related samples MD5 hash. | 
| ThreatMiner.IP.SSL | string | SSL certificates. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | unknown | IP address that was searched. | 
| IP.Geo.Country | unknown | Related country. | 
| IP.ASN | unknown | Related ASN. | 

### file
***
Retrieves data from ThreatMiner about a specified file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash (md5, sha1, sha256). | Required | 
| threshold | If ThreatScore is greater or equal than the threshold, then file will be considered malicious. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMiner.File.MD5 | string | File MD5 hash. | 
| ThreatMiner.File.SHA1 | string | File SHA1 hash. | 
| ThreatMiner.File.SHA256 | string | File SHA256 hash. | 
| ThreatMiner.File.Type | string | File type. | 
| ThreatMiner.File.Name | string | File name. | 
| ThreatMiner.File.Architecture | string | File architecture. | 
| ThreatMiner.File.Size | string | File size. | 
| ThreatMiner.File.Analyzed | date | File analyzed date. | 
| ThreatMiner.File.HTTP.Domain | string | HTTP traffic to domain. | 
| ThreatMiner.File.HTTP.URL | string | HTTP traffic to URL. | 
| ThreatMiner.File.HTTP.Useragent | string | HTTP user agent. | 
| ThreatMiner.File.Domains.IP | string | Related IP address. | 
| ThreatMiner.File.Domains.Domain | string | Related domain name. | 
| ThreatMiner.File.Mutants | string | Used mutexes. | 
| ThreatMiner.File.Registry | string | Used registry keys. | 
| ThreatMiner.File.AV.Name | string | Detected AV name. | 
| ThreatMiner.File.AV.Detection | string | AV detection. | 
| File.MD5 | string | File MD5 hash. | 
| File.SHA1 | string | File SHA1 hash. | 
| File.SHA256 | string | File SHA256 hash. | 
| File.Malicious.Detections | number | For malicious files, the total number of detections. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.Name | string | File name. | 