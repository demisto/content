Use the Cofense Intelligence integration to check the reputation of URLs, IP addresses, file hashes, and email addresses.
## Configure Cofense Intelligence in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://www.threathq.com/apiv1) |  | True |
| API username |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| URL Threshold (None, Minor, Moderate, or Major). Minimum severity to consider the URL malicious |  | False |
| File Threshold (None, Minor, Moderate, or Major). Minimum severity to consider the file malicious |  | False |
| IP Threshold (None, Minor, Moderate, or Major). Minimum severity to consider the IP malicious |  | False |
| Email Threshold (None, Minor, Moderate, or Major). Minimum severity to consider the email malicious |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs. | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Cofense.URL.Data | unknown | Bad URLs. | 
| Cofense.URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| Cofense.URL.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| Cofense.URL.Cofense.ThreatIDs | unknown | The thread IDs retrieved by the vendor. | 


#### Command Example
```!url url=example.com using="Cofense Intelligence_instance_1"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "Cofense"
    }
}
```

#### Human Readable Output

>## Cofense URL Reputation for: example.com
>No information found for this url

### file
***
Checks the reputation of a file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A CSV list of file hashes to check (MD5, SHA1, or SHA256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | File MD5 | 
| File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | unknown | For malicious files, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Cofense.File.MD5 | unknown | MD5 hash of the file. | 
| Cofense.File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision. | 
| Cofense.File.Malicious.Description | unknown | For malicious files, the reason that the vendor made the decision. | 
| Cofense.File.ThreatIDs | unknown | The thread IDs retrieved by the vendor. | 


#### Command Example
``` ```

#### Human Readable Output



### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Data | unknown | Bad IP Address found | 
| IP.Malicious.Vendor | unknown | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | unknown | For malicious IPs, the reason that the vendor made the decision | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Cofense.IP.Data | unknown | Bad IP Address found | 
| Cofense.IP.Malicious.Vendor | unknown | For malicious IPs, the vendor that made the decision | 
| Cofense.IP.Malicious.Description | unknown | For malicious IPs, the reason that the vendor made the decision | 
| Cofense.IP.Cofense.ThreatIDs | unknown | The thread ids retrieved by the vendor. | 
| IP.ASN | unknown | Autonomous System name for the IP. | 
| IP.GEO.Location | unknown | Location in format latitude, longitude. | 
| IP.GEO.Country | unknown | Country of the IP. | 
| IP.Address | string | IP address. | 


#### Command Example
```!ip ip=1.2.3.4 using="Cofense Intelligence_instance_1"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.2.3.4",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Cofense"
    }
}
```

#### Human Readable Output

>## Cofense IP Reputation for: x.x.x.x
>No information found for this ip

### email
***
Checks the reputation of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Sender email address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Email.Data | unknown | Sender address to check. | 
| Account.Email.Address | unknown | Sender email address to check. | 
| Account.Email.Malicious.Vendor | unknown | For malicious emails, the vendor that made the decision. | 
| Account.Email.Malicious.Description | unknown | For malicious emails, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Cofense.Email.Data | unknown | Sender address to check. | 
| Cofense.Email.Malicious.Vendor | unknown | For malicious emails, the vendor that made the decision. | 
| Cofense.Email.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| Cofense.Email.Cofense.ThreatIDs | unknown | The thread ids retrieved by the vendor. | 


#### Command Example
```!email email=example@example.com using="Cofense Intelligence_instance_1"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example@example.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "email",
        "Vendor": "Cofense"
    }
}
```

#### Human Readable Output

>## Cofense email Reputation for: example@example.com
>No infomation found for this email

### cofense-search
***
Searches for extracted strings identified within malware campaigns.


#### Base Command

`cofense-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| str | String to search. | Required | 
| limit | Maximum number of strings to search. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.NumOfThreats | unknown | Number of threats. | 
| Cofense.String | unknown | String that was searched. | 


#### Command Example
``` ```

#### Human Readable Output

