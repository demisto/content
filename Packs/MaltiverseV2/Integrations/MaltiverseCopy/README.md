Use the Maltiverse integration to analyze suspicious hashes, URLs, domains and IP addresses.
This integration was integrated and tested with version xx of Maltiverse_copy

## Configure Maltiverse_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Maltiverse_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | False |
    | API Key |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| threshold | If the number of positives is higher than the threshold, the IP address will be considered malicious. If the threshold is not specified, the default IP threshold, as configured in the instance settings, will be used. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The checked IP address. | 
| IP.Geo.Country | String | The country code of the IP address. | 
| IP.Malicious.Description | Unknown | Describes the reason why the IP address is in the blacklist. | 
| IP.PositiveDetections | Number | The number of sources that positively reported the indicator as blacklist. | 
| DBotScore.Score | Number | The DBot score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Maltiverse.IP.Address | String | The checked IP address. | 
| Maltiverse.IP.Classification | Unknown | Qualitative maliciousness classification for an IoC. Possible values are malicious, suspicious, neutral, and whitelisted. | 
| Maltiverse.IP.Blacklist.FirstSeen | Date | First time that the IoC was seen. | 
| Maltiverse.IP.Blacklist.LastSeen | Date | Last time that the IoC was seen. | 
| Maltiverse.IP.Blacklist.Description | String | Describes the reason why the IP is in the blacklist. | 
| Maltiverse.IP.Blacklist.Source | String | The name of sources that reported the indicator. | 
| Maltiverse.IP.Tags | String | The type of indicator. | 
| IP.ThreatTypes | Unknown | A list with the description of the elements in the blacklist. | 
| IP.Tags | String | The type of indicator. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Checks the reputation of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain address to check. | Required | 
| threshold | If the number of positives is higher than the threshold, the domain will be considered malicious. If the threshold is not specified, the default domain threshold, as configured in the instance settings, will be used. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.CreationDate | Date | Date when the IoC was created in the system. | 
| Domain.ModificationDate | Date | Date when the IoC was last updated. | 
| Domain.TLD | Number | Top Level Domain of the hostname | 
| Domain.ASName | String | Autonomous system name of the domain. | 
| DBotScore.Score | Number | The DBot score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Maltiverse.Domain.Address | String | The domain name. | 
| Maltiverse.Domain.Classification | String | Qualitative maliciousness classification for an IoC. Possible value are malicious, suspicious, neutral, and whitelist. | 
| Maltiverse.Domain.Blacklist.Firstseen | Date | First time that the IoC was seen. | 
| Maltiverse.Domain.Blacklist.LastSeen | Date | Last time that the IoC was seen. | 
| Maltiverse.Domain.Blacklist.Description | Unknown | Describes the reason why the domain is in the blacklist. | 
| Maltiverse.Domain.Blacklist.Source | String | The name of sources that reported the indicator. | 
| Maltiverse.Domain.Tags | String | Attribute to label an IoC. | 
| Maltiverse.Domain.ModificationTime | Date | Date when the IoC was last updated. | 
| Maltiverse.Domain.CreationTime | Date | Date when the IoC was created in the system. | 
| Maltiverse.Domain.TLD | String | Top-level domain of the hostname. | 
| Maltiverse.Domain.ResolvedIP.IP | String | Stores an IP that was resolved by the domain. | 
| Maltiverse.Domain.ResolvedIP.Timestamp | Date | Stores a timestamp when an IP address has been resolved by the domain. | 
| Domain.ThreatTypes | Unknown | A list with the description of the elements in the blacklist. | 
| Domain.Tags | String | Attribute to label an IoC. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Checks the reputation of an URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL address to check. | Required | 
| threshold | If the number of positives is higher than the threshold, the URL address will be considered malicious. If the threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL that was checked. | 
| URL.Malicious.Description | String | Describes the reason why the URL is in the blacklist. | 
| URL.Malicious.Vendor | String | The vendor that sends the indicator for reputation check. | 
| URL.PositiveDetections | Number | The number of sources that positively reported the indicator as blacklist. | 
| DBotScore.Score | Number | The DBot score | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Maltiverse.URL.Address | String | The checked URL. | 
| Maltiverse.URL.Classification | String | Qualitative maliciousness classification for an IoC. Possible values are malicious, suspicious, neutral, and whitelist. | 
| Maltiverse.URL.Blacklist.FirstSeen | Date | First time that the IoC was seen. | 
| Maltiverse.URL.Blacklist.LastSeen | Date | Last time that the IoC was seen. | 
| Maltiverse.URL.Blacklist.Description | Date | Describes the reason why the URL is in the blacklist. | 
| Maltiverse.URL.Blacklist.Source | String | The name of sources that reported the indicator. | 
| Maltiverse.URL.Tags | String | Attribute to label an IoC. | 
| Maltiverse.URL.ModificationTime | Date | Date when the IOC was last updated. | 
| Maltiverse.URL.CreationTime | Date | Date when the IOC was created in the system. | 
| Maltiverse.URL.Hostname | String | Stores the hostname to which the URL belongs. | 
| Maltiverse.URL.Domain | String | Stores the domain to which the hostname belongs. Hostname and domain can match on level 2 hostnames | 
| Maltiverse.URL.TLD | String | Top-level domain of the hostname. | 
| URL.ThreatTypes | Unknown | A list with the description of the elements in the blacklist. | 
| URL.Tags | String | Attribute to label an IoC. | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Checks the reputation of a file by file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | SHA256 hash to check. | Required | 
| threshold | If the number of positives AV detection is higher than the threshold, the file will be considered malicious. If the threshold is not specified, the default file threshold, as configured in the instance settings, will be used. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 
| File.Extension | String | The extension of the file. | 
| File.Type | String | Description of the file type based on its magic numbers. | 
| File.Path | String | The path of the file. | 
| DBotScore.Score | Number | The DBot score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Maltiverse.File.Score | Number | Qualitative scoring of the maliciousness of the file. Values from 0 to 100. | 
| Maltiverse.File.Tags | String | Attribute to label an IOC. | 
| Maltiverse.File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| Maltiverse.File.Malicious.Description | String | For malicious files, describes the reason for the file to be malicious. | 
| Maltiverse.File.PositiveDetections | Number | The number of sources that positively reported the indicator as blacklist. | 
| Maltiverse.File.Name | String | The file name. | 
| Maltiverse.File.Classification | String | Qualitative maliciousness classification for an IoC. Possible values are malicious, suspicious, neutral, and whitelist. | 
| Maltiverse.File.Blacklist.FirstSeen | Date | First time that the IoC was seen. | 
| Maltiverse.File.Blacklist.LastSeen | Date | Last time that the IoC was seen. | 
| Maltiverse.File.Blacklist.Description | String | Describes the reason why the URL is in the blacklist. | 
| Maltiverse.File.Blacklist.Source | String | The name of sources that reported the indicator. | 
| Maltiverse.File.ModificationTime | Date | Date when the IOC was last updated. | 
| Maltiverse.File.CreationTime | Date | Date when the IOC was created in the system. | 
| Maltiverse.File.Size | Number | Size of the file in bytes. | 
| Maltiverse.File.ProcessList | String | List of processes raised by the file in runtime. | 
| Maltiverse.File.ContactedHost | String | List of the IP addresses contacted by the sample in runtime. | 
| Maltiverse.File.DNSRequest | String | List of hostnames resolved by the sample in runtime. | 
| File.ThreatTypes | Unknown | A list with the description of the elements in the blacklist. | 
| File.Tags | String | Attribute to label an IoC. | 


#### Command Example
``` ```

#### Human Readable Output


