Use Anomali ThreatStream to query and submit threats.

## Anomali ThreatStream v2 Playbook
* Detonate File - ThreatStream
* Detonate URL - ThreatStream

## Use Cases
1. Get threat intelligence from the ThreatStream platform.
2. Create and manage threat models.
3. Import indicators to ThreatStream platform.
4. Submit file or URL to sandbox and receive an analysis report.

## Configure Anomali ThreatStream v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://www.test.com\) | True |
| username | Username | True |
| apikey | API Key | True |
| default_threshold | Threshold of the indicator. | True |
| Source Reliability | Reliability of the source providing the intelligence data. The default value is B - Usually reliable. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of the given IP.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to check. | Required | 
| threshold | If severity is greater than or equal to the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with the status "Inactive". Default is "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.ASN | String | Autonomous System \(AS\) number associated with the indicator. | 
| IP.Address | String | IP address of the indicator. | 
| IP.Geo.Country | String | Country associated with the indicator. | 
| IP.Geo.Location | String | Longitude and latitude of the IP address. |
| IP.Tags | Unknown | (List) Tags of the IP. | 
| ThreatStream.IP.ASN | String | Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.IP.Address | String | IP address of the indicator. | 
| ThreatStream.IP.Country | String | Country associated with the indicator. | 
| ThreatStream.IP.Type | String | The indicator type. | 
| ThreatStream.IP.Modified | String | Time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.IP.Severity | String | The indicator severity \("very-high", "high", "medium", or "low". | 
| ThreatStream.IP.Confidence | String | Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.IP.Status | String | Status assigned to the indicator. | 
| ThreatStream.IP.Organization | String | Name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.IP.Source | String | The source of the indicator. | 
| ThreatStream.IP.Tags | Unknown | Tags assigned to the IP. |
| DBotScore.Score | Number | The actual score. | 
| IP.Malicious.Vendor | String | Vendor that reported the indicator as malicious. | 

#### Command Example

    ip ip=39.41.26.166 using-brand="Anomali ThreatStream v2"

#### Context Example

    {
        "IP": {
            "Geo": {
                "Country": "PK", 
                "Location": "33.6007,73.0679"
            }, 
            "ASN": "45595", 
            "Address": "39.41.26.166",
            "Tags": ["phish-target", "victim-hi-tech"]
        }, 
        "DBotScore": {
            "Vendor": "TOR Exit Nodes", 
            "Indicator": "39.41.26.166", 
            "Score": 2, 
            "Type": "ip"
        }, 
        "ThreatStream.IP": {
            "Status": "active", 
            "Confidence": 96, 
            "Severity": "low", 
            "Country": "PK", 
            "Modified": "2019-06-24T10:10:12.289Z", 
            "Source": "TOR Exit Nodes", 
            "Address": "39.41.26.166", 
            "Organization": "PTCL", 
            "Type": "ip", 
            "Tags": [{"id": "4wq", "name": "phish-target", "org_id": "88"}, {"id": "ezn", "name": "victim-hi-tech", "org_id": "88"}],
            "ASN": "45595"
        }
    }

#### Human Readable Output

##### IP reputation for: 39.41.26.166

| Address | Confidence | Source | Type | Status | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 39.41.26.166 | 96 | TOR Exit Nodes | ip | active | 2019-06-24T10:10:12.289Z | PTCL | 45595 | PK | low |


### domain
***
Checks the reputation of the given domain name.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Required | 
| threshold | If severity is greater than or equal to the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with status of "Inactive". Default is "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.DNS | String | IPs resolved by DNS.  | 
| Domain.Tags | Unknown | (List) Tags of the domain. | 
| Domain.WHOIS.CreationDate | Date | Date the domain was created. The date format is: YYYYMMDDThhmmss. Where T denotes the start of the value for time, in UTC time. | 
| Domain.WHOIS.UpdatedDate | Date | Date the domain was last updated. The date format is: YYYYMMDDThhmmss. Where T denotes the start of the value for time, in UTC time. | 
| Domain.WHOIS.Registrant.Name | String | Name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | Email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | Phone number of the registrant. | 
| ThreatStream.Domain.ASN | String | Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Domain.Address | String | The domain name of the indicator. | 
| ThreatStream.Domain.Country | String | Country associated with the indicator. | 
| ThreatStream.Domain.Type | String | The indicator type. | 
| ThreatStream.Domain.Modified | String | Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.Domain.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.Domain.Confidence | String | Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.Domain.Status | String | Status assigned to the indicator. | 
| ThreatStream.Domain.Organization | String | Name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.Domain.Source | String | The source of the indicator. | 
| ThreatStream.Domain.Tags | Unknown | Tags assigned to the domain. |
| Domain.Malicious.Vendor | String | Vendor that reported the indicator as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
    domain domain="microsoftfaq.com" using-brand="Anomali ThreatStream v2" 

##### Context Example 

    {
        "ThreatStream.Domain": {
            "Status": "active", 
            "Confidence": 38, 
            "Severity": "high", 
            "Country": null, 
            "Modified": "2019-06-24T08:39:04.644Z", 
            "Source": "Analyst", 
            "Address": "microsoftfaq.com", 
            "Organization": "", 
            "Type": "domain", 
            "Tags": ["phish-target", "victim-hi-tech"],
            "ASN": ""
        }, 
        "Domain": {
            "Malicious": {
                "Vendor": "ThreatStream"
            }, 
            "Name": "microsoftfaq.com", 
            "DNS": "127.0.0.1", 
            "WHOIS": {
                "UpdatedDate": "2019-06-24T08:39:04.644Z", 
                "CreationDate": "2019-06-24T08:38:53.246Z", 
                "Registrant": {
                    "Phone": "", 
                    "Email": "", 
                    "Name": "Registrant City:"
                }
            },
            "Tags": [{"id": "4wq", "name": "phish-target", "org_id": "88"}, {"id": "ezn", "name": "victim-hi-tech", "org_id": "88"}]
        }, 
        "DBotScore": {
            "Vendor": "Analyst", 
            "Indicator": "microsoftfaq.com", 
            "Score": 3, 
            "Type": "domain"
        }
    }

#### Human Readable Output 

#### Domain reputation for: microsoftfaq.com

| Address | Confidence | Source | Type | Status | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| microsoftfaq.com | 38 | Analyst | domain | active | 2019-06-24T08:39:04.644Z |   |   |   | high |


### file
***
Checks the reputation of the given hash of the file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash of file to check. | Required | 
| threshold | If severity is greater than or equal to the threshold, then the hash of file will be considered malicious. This argument will override the default threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with the status "Inactive". Default is "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.SHA512 | String | SHA512 hash of the file. | 
| File.Malicious.Vendor | String | Vendor that reported the indicator as malicious. |
| File.Tags | Unknown | (List) Tags of the file. |  
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.File.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.File.Confidence | String | Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.File.Status | String | Status assigned to the indicator. | 
| ThreatStream.File.Type | String | The indicator type. | 
| ThreatStream.File.MD5 | String | The MD5 hash of the indicator. | 
| ThreatStream.File.SHA1 | String | The SHA1 hash of the indicator. | 
| ThreatStream.File.SHA256 | String | The SHA256 hash of the indicator. | 
| ThreatStream.File.SHA512 | String | The SHA512 hash of the indicator. | 
| ThreatStream.File.Modified | String | Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.File.Source | String | The source of the indicator. | 
| ThreatStream.File.Tags | Unknown | Tags assigned to the file. |


#### Command Example
    file file=07df6c1d9a76d81f191be288d463784b using-brand="Anomali ThreatStream v2"

#### Context Example

    {
        "DBotScore": {
            "Vendor": "URLHaus Hashes", 
            "Indicator": "07df6c1d9a76d81f191be288d463784b", 
            "Score": 2, 
            "Type": "md5"
        }, 
        "ThreatStream.File": {
            "Status": "active", 
            "Confidence": 75, 
            "Severity": "medium", 
            "Modified": "2019-06-24T10:13:27.284Z", 
            "Source": "URLHaus Hashes", 
            "Type": "md5", 
            "Tags": [{"id": "4wq", "name": "phish-target", "org_id": "88"}, {"id": "ezn", "name": "victim-hi-tech", "org_id": "88"}],
            "MD5": "07df6c1d9a76d81f191be288d463784b"
        }, 
        "File": {
            "MD5": "07df6c1d9a76d81f191be288d463784b",
            "Tags": ["phish-target", "victim-hi-tech"]
        }
    }

#### Human Readable Output

##### MD5 reputation for: 07df6c1d9a76d81f191be288d463784b

| Confidence | Source | Type | Status | Modified | Severity | MD5 |
| --- | --- | --- | --- | --- | --- | --- |
| 75 | URLHaus Hashes | md5 | active | 2019-06-24T10:13:27.284Z | medium | 07df6c1d9a76d81f191be288d463784b |


### threatstream-email-reputation
***
Checks the reputation of the given email address.


#### Base Command

`threatstream-email-reputation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check. | Required | 
| threshold | If severity is greater or equal than the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with the status "Inactive". Default is "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The tested indicator. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.EmailReputation.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.EmailReputation.Confidence | String | Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.EmailReputation.Status | String | Status assigned to the indicator. | 
| ThreatStream.EmailReputation.Type | String | The indicator type. | 
| ThreatStream.EmailReputation.Email | String | The email address of the indicator. | 
| ThreatStream.EmailReputation.Source | String | The source of the indicator. | 
| ThreatStream.EmailReputation.Modified | String | Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.EmailReputation.Tags | Unknown | Tags assigned to the email. |


#### Command Example
    threatstream-email-reputation email=goo@test.com

#### Context Example

    {
        "DBotScore": {
            "Vendor": "Anomali Labs Compromised Credentials", 
            "Indicator": "goo@test.com", 
            "Score": 2, 
            "Type": "email"
        }, 
        "ThreatStream.EmailReputation": {
            "Status": "active", 
            "Confidence": 100, 
            "Severity": "low", 
            "Modified": "2019-06-24T09:50:23.810Z", 
            "Source": "Anomali Labs Compromised Credentials", 
            "Type": "email", 
            "Tags": [{"id": "4wq", "name": "phish-target", "org_id": "88"}, {"id": "ezn", "name": "victim-hi-tech", "org_id": "88"}],
            "Email": "goo@test.com"
        }
    }

#### Human Readable Output

##### Email reputation for: foo@test.com

| Confidence | Source | Type | Status | Modified | Severity | Email |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | Anomali Labs Compromised Credentials | email | active | 2019-06-24T09:50:23.810Z | low | foo@test.com |


### threatstream-get-passive-dns
***
Returns enrichment data for Domain or IP for availabe observables.


#### Base Command

`threatstream-get-passive-dns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of passive DNS search ("ip", "domain"). | Required | 
| value | Possible values are "IP" or "Domain". | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PassiveDNS.Domain | String | The domain value. | 
| ThreatStream.PassiveDNS.Ip | String | The IP value. | 
| ThreatStream.PassiveDNS.Rrtype | String | The Rrtype value. | 
| ThreatStream.PassiveDNS.Source | String | The source value. | 
| ThreatStream.PassiveDNS.FirstSeen | String | The first seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.PassiveDNS.LastSeen | String | The last seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 


#### Command Example
    threatstream-get-passive-dns type=domain value=discoverer.blog

#### Context Example

    {
        "ThreatStream.PassiveDNS": [
            {
                "Domain": "discoverer.blog", 
                "Ip": "184.168.221.52", 
                "Rrtype": "A", 
                "Source": "Spamhaus", 
                "LastSeen": "2019-06-23T08:09:54", 
                "FirstSeen": "2019-06-23T08:09:54"
            }, 
            {
                "Domain": "discoverer.blog", 
                "Ip": "50.63.202.51", 
                "Rrtype": "A", 
                "Source": "Spamhaus", 
                "LastSeen": "2019-06-21T10:33:54", 
                "FirstSeen": "2019-06-21T10:33:54"
            }
        ]
    }

#### Human Readable Output

##### Passive DNS enrichment data for: discoverer.blog

| Domain | Ip | Rrtype | Source | FirstSeen | LastSeen |
| --- | --- | --- | --- | --- | --- |
| discoverer.blog | 184.168.221.52 | A | Spamhaus | 2019-06-23T08:09:54 | 2019-06-23T08:09:54 |
| discoverer.blog | 50.63.202.51 | A | Spamhaus | 2019-06-21T10:33:54 | 2019-06-21T10:33:54 |


### threatstream-import-indicator-with-approval
***
Imports indicators (observables) into ThreatStream. Approval of the imported data is required, usingh the ThreatStream UI. The data can be imported using one of three methods: plain-text, file, or URL. Only one argument can be used.


#### Base Command

`threatstream-import-indicator-with-approval`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The level of certainty that an observable is of the reported indicator type. Default is 50. | Optional | 
| classification | Denotes whether the indicator data is public or private to the organization. Default is "private". | Optional | 
| threat_type | Type of threat associated with the imported observables. Default is "exploit". | Optional | 
| severity | The potential impact of the indicator type with which the observable is thought to be associated. Default is "low". | Optional | 
| import_type | The import type of the indicator. Can be datatext, file-id, or url. | Required | 
| import_value | The source of imported data. Can be one of the following: url, datatext of file-id of uploaded file to the War Rroom. Supported file types for file-id are: CSV, HTML, IOC, JSON, PDF, TXT. | Required | 
| ip_mapping | Whether to include IP mapping. Whether to include url mapping. Can be yes or no. Default is no. | Optional | 
| domain_mapping | Whether to include domain mapping. Whether to include url mapping. Can be yes or no. Default is no. | Optional | 
| url_mapping | Whether to include url mapping. Can be yes or no. Default is no. | Optional | 
| email_mapping | Whether to include email mapping. Whether to include url mapping. Can be yes or no. Default is no. | Optional | 
| md5_mapping | Whether to include MD5 mapping. Whether to include url mapping. Can be yes or no. Default is no. | Optional | 

#### Command Example

    threatstream-import-indicator-with-approval import_type="file-id" import_value=5403@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0

#### Context Example

    {
        "File": {
            "EntryID": "5403@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
            "Extension": "csv",
            "Info": "text/csv; charset=utf-8",
            "MD5": "5b7ed7973e4deb3c98ee3a4bd6d911af",
            "Name": "input.csv",
            "SHA1": "055c5002eb5a4d4abe2eb1768e925bfc3a1a763e",
            "SHA256": "fd16220852b39e2c8fa51766750e3991670766512836212c799c5a0537e3ef8c",
            "SSDeep": "3:Wg8oEIjOH9+KS3qvRBTdRi690oVqzBUGyT0/n:Vx0HgKnTdE6eoVafY8",
            "Size": 102,
            "Type": "UTF-8 Unicode (with BOM) text, with CRLF line terminators\n"
        },
        "ThreatStream": {
            "Import": {
                "ImportID": "894516"
            }
        }
    }

#### Human Readable Output

The data was imported successfully. The ID of imported job is: 894514


### threatstream-import-indicator-without-approval
***
Imports indicators (observables) into ThreatStream. Approval is not required for the imported data. You must have the Approve Intel user permission to import without approval using the API.


#### Base Command

`threatstream-import-indicator-without-approval`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The level of certainty that an observable is of the reported indicator type. Default is 50. | Optional | 
| source_confidence_weight | To use your specified confidence entirely, set source_confidence_ weight to 100. | Optional | 
| expiration_ts | Time stamp of when intelligence will expire on ThreatStream, in ISO format. For example, 2020-12-24T00:00:00. | Optional | 
| severity | Severity you want to assign to the observable when it is imported. | Optional | 
| tags | Comma-separated list of tags. e.g. tag1,tag2. | Optional | 
| trustedcircles | ID of the trusted circle with which this threat data should be shared. If you want to import the threat data to multiple trusted circles, enter a list of comma-separated IDs. | Optional | 
| classification | Denotes whether the indicator data is public or private to the organization. | Required | 
| allow_unresolved | When set to true, domain observables included in the file which do not resolve will be accepted as valid in ThreatStream and imported. | Optional | 
| file_id | Entry id of uploaded file to war room containing a json with "objects" array and "meta" maps. | Required | 


### threatstream-get-model-list
***
Returns a list of threat model.


#### Base Command

`threatstream-get-model-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | Threat model of the returned list. | Required | 
| limit | Limits the list of models size. Specifying limit=0 will return up to a maximum of 1000 models. In case of limit=0 the output won't be set in the context. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.List.Type | String | The type of threat model. | 
| ThreatStream.List.Name | String | The name of the threat model. | 
| ThreatStream.List.ID | String | The ID of the threat model. | 
| ThreatStream.List.CreatedTime | String | Date and time of threat model creation. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 


#### Command Example
    threatstream-get-model-list model=actor limit=10

#### Context Example

    {
        "ThreatStream.List": [
            {
                "CreatedTime": "2015-06-29T17:02:01.885011", 
                "Type": "Actor", 
                "ID": 2, 
                "Name": "Pirpi"
            }, 
            {
                "CreatedTime": "2015-06-30T19:20:05.930697", 
                "Type": "Actor", 
                "ID": 3, 
                "Name": "TeamCyberGhost"
            }, 
            {
                "CreatedTime": "2015-07-01T18:10:53.241301", 
                "Type": "Actor", 
                "ID": 4, 
                "Name": "Wekby"
            }, 
            {
                "CreatedTime": "2015-07-01T19:27:06.180602", 
                "Type": "Actor", 
                "ID": 5, 
                "Name": "Axiom"
            }, 
            {
                "CreatedTime": "2015-07-01T19:52:56.019862", 
                "Type": "Actor", 
                "ID": 7, 
                "Name": "Peace (Group) a/k/a C0d0s0"
            }, 
            {
                "CreatedTime": "2015-07-01T19:58:50.741202", 
                "Type": "Actor", 
                "ID": 8, 
                "Name": "Nitro"
            }, 
            {
                "CreatedTime": "2015-07-06T16:06:12.123839", 
                "Type": "Actor", 
                "ID": 9, 
                "Name": "Comment Crew"
            }, 
            {
                "CreatedTime": "2015-07-07T17:40:04.920012", 
                "Type": "Actor", 
                "ID": 10, 
                "Name": "Comfoo"
            }, 
            {
                "CreatedTime": "2015-07-07T18:53:12.331221", 
                "Type": "Actor", 
                "ID": 11, 
                "Name": "Syrian Electronic Army"
            }, 
            {
                "CreatedTime": "2015-07-08T20:59:29.751919", 
                "Type": "Actor", 
                "ID": 12, 
                "Name": "DD4BC"
            }
        ]
    }

#### Human Readable Output

##### List of Actors

| CreatedTime | ID | Name | Type |
| --- | --- | --- | --- |
| 2015-06-29T17:02:01.885011 | 2 | Pirpi | Actor |
| 2015-06-30T19:20:05.930697 | 3 | TeamCyberGhost | Actor |
| 2015-07-01T18:10:53.241301 | 4 | Wekby | Actor |
| 2015-07-01T19:27:06.180602 | 5 | Axiom | Actor |
| 2015-07-01T19:52:56.019862 | 7 | Peace (Group) a/k/a C0d0s0 | Actor |
| 2015-07-01T19:58:50.741202 | 8 | Nitro | Actor |
| 2015-07-06T16:06:12.123839 | 9 | Comment Crew | Actor |
| 2015-07-07T17:40:04.920012 | 10 | Comfoo | Actor |
| 2015-07-07T18:53:12.331221 | 11 | Syrian Electronic Army | Actor |
| 2015-07-08T20:59:29.751919 | 12 | DD4BC | Actor |


### threatstream-get-model-description
***
Returns an HTML file with a description of the threat model.


#### Base Command

`threatstream-get-model-description`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model. | Required | 
| id | The ID of the threat model. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The file name of the model desctiption. | 
| File.EntryID | String | The entry ID of the model desctipton. | 


#### Command Example

    threatstream-get-model-description model=campaign id=1406

##### Context Example

    {
        "File": {
            "EntryID": "5384@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
            "Extension": "html",
            "Info": "text/html; charset=utf-8",
            "MD5": "66eabc1c704fdac429939eb09bc5346f",
            "Name": "campaign_1406.html",
            "SHA1": "69f3dfe8ae037253e782dd201904aa583d83bcd7",
            "SHA256": "49635483962b38a2fd5d50ebbb51b7002ecab3fd23e0f9f99e915f7b33d3f739",
            "SSDeep": "96:XZcBqz4xqHC2AwALc+nvJN7GBoBGK1IW7h:XC40W/tixmoLTh",
            "Size": 3686,
            "Type": "HTML document text, ASCII text, with very long lines, with no line terminators\n"
        }
    }


### threatstream-get-indicators-by-model
***
Returns a list of indicators associated with the specified model and ID of the model.


#### Base Command

`threatstream-get-indicators-by-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model. | Required | 
| id | The ID of the model. | Required | 
| limit | Maximum number of results to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The type of the threat model. | 
| ThreatStream.Model.ModelID | String | The ID of the threat model. | 
| ThreatStream.Model.Indicators.Value | String | The value of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The courty of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The source of the inidicator. | 
| ThreatStream.Model.Indicators.Type | String | The type of the inidicator. | 


#### Command Example
    threatstream-get-indicators-by-model id=11885 model=incident

##### Context Example

    {
        "ThreatStream.Model": {
            "Indicators": [
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.446", 
                    "Value": "417072b246af74647897978902f7d903562e0f6f", 
                    "ID": "50117813617", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.455", 
                    "Value": "d3c65377d39e97ab019f7f00458036ee0c7509a7", 
                    "ID": "50117813616", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.462", 
                    "Value": "5f51084a4b81b40a8fcf485b0808f97ba3b0f6af", 
                    "ID": "50117813615", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.469", 
                    "Value": "220a8eacd212ecc5a55d538cb964e742acf039c6", 
                    "ID": "50117813614", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.477", 
                    "Value": "a16ef7d96a72a24e2a645d5e3758c7d8e6469a55", 
                    "ID": "50117813612", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.485", 
                    "Value": "275e76fc462b865fe1af32f5f15b41a37496dd97", 
                    "ID": "50117813611", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.493", 
                    "Value": "df4b8c4b485d916c3cadd963f91f7fa9f509723f", 
                    "ID": "50117813610", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.500", 
                    "Value": "66eccea3e8901f6d5151b49bca53c126f086e437", 
                    "ID": "50117813609", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.507", 
                    "Value": "3d90630ff6c151fc2659a579de8d204d1c2f841a", 
                    "ID": "50117813608", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.513", 
                    "Value": "a6d14b104744188f80c6c6b368b589e0bd361607", 
                    "ID": "50117813607", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.520", 
                    "Value": "e3f183e67c818f4e693b69748962eecda53f7f88", 
                    "ID": "50117813606", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.527", 
                    "Value": "f326479a4aacc2aaf86b364b78ed5b1b0def1fbe", 
                    "ID": "50117813605", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.534", 
                    "Value": "c4d1fb784fcd252d13058dbb947645a902fc8935", 
                    "ID": "50117813604", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.541", 
                    "Value": "fb4a4143d4f32b0af4c2f6f59c8d91504d670b41", 
                    "ID": "50117813603", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.548", 
                    "Value": "400e4f843ff93df95145554b2d574a9abf24653f", 
                    "ID": "50117813602", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.555", 
                    "Value": "f82d18656341793c0a6b9204a68605232f0c39e7", 
                    "ID": "50117813601", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.562", 
                    "Value": "c33fe4c286845a175ee0d83db6d234fe24dd2864", 
                    "ID": "50117813600", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.569", 
                    "Value": "d9294b86b3976ddf89b66b8051ccf98cfae2e312", 
                    "ID": "50117813599", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.576", 
                    "Value": "9fc71853d3e6ac843bd36ce9297e398507e5b2bd", 
                    "ID": "50117813597", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }, 
                {
                    "Status": "active", 
                    "Confidence": 100, 
                    "IType": "mal_md5", 
                    "Severity": "very-high", 
                    "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                    "Country": null, 
                    "Modified": "2017-09-25T11:43:54.583", 
                    "Value": "c0ad9c242c533effd50b51e94874514a5b9f2219", 
                    "ID": "50117813596", 
                    "Source": "ThreatStream", 
                    "Organization": "", 
                    "Type": "md5", 
                    "ASN": ""
                }
            ], 
            "ModelType": "Incident", 
            "ModelID": "11885"
        }
    }

#### Human Readable Output

##### Indicators list for Threat Model Incident with id 11885

| IType | Value | ID | Confidence | Source | Type | Status | Tags | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mal_md5 | 417072b246af74647897978902f7d903562e0f6f | 50117813617 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.446 |   |   |   | very-high |
| mal_md5 | d3c65377d39e97ab019f7f00458036ee0c7509a7 | 50117813616 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.455 |   |   |   | very-high |
| mal_md5 | 5f51084a4b81b40a8fcf485b0808f97ba3b0f6af | 50117813615 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.462 |   |   |   | very-high |
| mal_md5 | 220a8eacd212ecc5a55d538cb964e742acf039c6 | 50117813614 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.469 |   |   |   | very-high |
| mal_md5 | a16ef7d96a72a24e2a645d5e3758c7d8e6469a55 | 50117813612 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.477 |   |   |   | very-high |
| mal_md5 | 275e76fc462b865fe1af32f5f15b41a37496dd97 | 50117813611 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.485 |   |   |   | very-high |
| mal_md5 | df4b8c4b485d916c3cadd963f91f7fa9f509723f | 50117813610 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.493 |   |   |   | very-high |
| mal_md5 | 66eccea3e8901f6d5151b49bca53c126f086e437 | 50117813609 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.500 |   |   |   | very-high |
| mal_md5 | 3d90630ff6c151fc2659a579de8d204d1c2f841a | 50117813608 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.507 |   |   |   | very-high |
| mal_md5 | a6d14b104744188f80c6c6b368b589e0bd361607 | 50117813607 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.513 |   |   |   | very-high |
| mal_md5 | e3f183e67c818f4e693b69748962eecda53f7f88 | 50117813606 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.520 |   |   |   | very-high |
| mal_md5 | f326479a4aacc2aaf86b364b78ed5b1b0def1fbe | 50117813605 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.527 |   |   |   | very-high |
| mal_md5 | c4d1fb784fcd252d13058dbb947645a902fc8935 | 50117813604 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.534 |   |   |   | very-high |
| mal_md5 | fb4a4143d4f32b0af4c2f6f59c8d91504d670b41 | 50117813603 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.541 |   |   |   | very-high |
| mal_md5 | 400e4f843ff93df95145554b2d574a9abf24653f | 50117813602 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.548 |   |   |   | very-high |
| mal_md5 | f82d18656341793c0a6b9204a68605232f0c39e7 | 50117813601 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.555 |   |   |   | very-high |
| mal_md5 | c33fe4c286845a175ee0d83db6d234fe24dd2864 | 50117813600 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.562 |   |   |   | very-high |
| mal_md5 | d9294b86b3976ddf89b66b8051ccf98cfae2e312 | 50117813599 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.569 |   |   |   | very-high |
| mal_md5 | 9fc71853d3e6ac843bd36ce9297e398507e5b2bd | 50117813597 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.576 |   |   |   | very-high |
| mal_md5 | c0ad9c242c533effd50b51e94874514a5b9f2219 | 50117813596 | 100 | ThreatStream | md5 | active | FINSPY,FinSpy,community-threat-briefing,Weaponization | 2017-09-25T11:43:54.583 |   |   |   | very-high |


### threatstream-submit-to-sandbox
***
Submits a file or URL to the ThreatStream-hosted Sandbox for detonation.


#### Base Command

`threatstream-submit-to-sandbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_classification | Classification of the Sandbox submission. | Optional | 
| report_platform | Platform on which the submitted URL or file will be run. To obtain a list supported platforms run the threatstream-get-sandbox-platforms command. | Optional | 
| submission_type | The detonation type ("file" or "url". | Required | 
| submission_value | The submission value. Possible values are a valid URL or a file ID that was uploaded to the War Room to detonate. | Required | 
| premium_sandbox | Specifies whether the premium sandbox should be used for detonation. Default is "false". | Optional | 
| detail | A CSV list of additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID that was submitted to the sandbox. | 
| ThreatStream.Analysis.Status | String | The analysis status. | 
| ThreatStream.Analysis.Platform | String | The platform of the submission submitted to the sanbox. | 


#### Command Example
    threatstream-submit-to-sandbox submission_type=file submission_value=5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0 premium_sandbox=false report_platform=WINDOWS7

#### Context Example

    {
        "File": {
            "EntryID": "5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "a36544c75d1253d8dd32070908adebd0",
            "Name": "input_file.png",
            "SHA1": "15868fbe28e34f601b4e07b0f356ecb1f3a14876",
            "SHA256": "5126eb938b3c2dc53837d4805df01c8522a3bd4e5e77e9bc4f825b9ee178e6ab",
            "SSDeep": "98304:pKOjdLh3d35gcNMjnN+FOLEdhVb2t6lLPP9nuyxJ4iQzxKxOduLT/GzxS3UvtT:pHhhvglN+F+GwUlLPP9PxnQzxKxOdEUR",
            "Size": 4938234,
            "Type": "PNG image data, 2572 x 1309, 8-bit/color RGBA, non-interlaced\n"
        },
        "ThreatStream": {
            "Analysis": {
                "Platform": "WINDOWS7",
                "ReportID": 422662,
                "Status": "processing"
            }
        }
    }

#### Human Readable Output

##### The submission info for 5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0

| ReportID | Status | Platform |
| --- | --- | --- |
| 422662 | processing | WINDOWS7 |


### threatstream-get-analysis-status
***
Returns the current status of the report that was submitted to the sandbox. The report ID is returned from threatstream-submit-to-sandbox command.


#### Base Command

`threatstream-get-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID for which to check the status. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID of the file or URL that was detonated to sandbox. | 
| ThreatStream.Analysis.Status | String | The report status of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Platform | String | The platfrom that was used for detonation. | 
| ThreatStream.Analysis.Verdict | String | The report verdict of the file or URL that was detonated in the sandbox. The verdict will remain "benign" until detonation is complete. | 


#### Command Example
``` ```

#### Human Readable Output

##### Report 413336 analysis results

| Category | Started | Completed | Duration | VmName | VmID | ReportID | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| File | 2019-05-30 14:05:25 | 2019-05-30 14:06:33 | 68 |   |   | 413336 | Benign |


### threatstream-analysis-report
***
Returns the report of a file or URL that was submitted to the sandbox.


#### Base Command

`threatstream-analysis-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID to return. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The ID of the report submitted to the sandbox. | 
| ThreatStream.Analysis.Category | String | The report category. | 
| ThreatStream.Analysis.Started | String | Detonation start time. | 
| ThreatStream.Analysis.Completed | String | Detonation completion time. | 
| ThreatStream.Analysis.Duration | Number | Duration of the detonation \(in seconds\). | 
| ThreatStream.Analysis.VmName | String | The name of the VM. | 
| ThreatStream.Analysis.VmID | String | The ID of the VM. | 
| ThreatStream.Analysis.Network.UdpSource | String | The source of UDP. | 
| ThreatStream.Analysis.Network.UdpDestination | String | The destination of UDP. | 
| ThreatStream.Analysis.Network.UdpPort | String | The port of the UDP. | 
| ThreatStream.Analysis.Network.IcmpSource | String | The ICMP source. | 
| ThreatStream.Analysis.Network.IcmpDestination | String | The destinaton of ICMP. | 
| ThreatStream.Analysis.Network.IcmpPort | String | The port of the ICMP. | 
| ThreatStream.Analysis.Network.TcpSource | String | The source of TCP. | 
| ThreatStream.Analysis.Network.TcpDestination | String | The destination of TCP. | 
| ThreatStream.Analysis.Network.TcpPort | String | The port of TCP. | 
| ThreatStream.Analysis.Network.HttpSource | String | The source of HTTP. | 
| ThreatStream.Analysis.Network.HttpDestinaton | String | The destination of HTTP. | 
| ThreatStream.Analysis.Network.HttpPort | String | The port of HTTP. | 
| ThreatStream.Analysis.Network.HttpsSource | String | The source of HTTPS. | 
| ThreatStream.Analysis.Network.HttpsDestinaton | String | The destination of HTTPS. | 
| ThreatStream.Analysis.Network.HttpsPort | String | The port of HTTPS. | 
| ThreatStream.Analysis.Network.Hosts | String | The hosts of network analysis. | 
| ThreatStream.Analysis.Verdict | String | The verdict of the sandbox detonation. | 


#### Command Example
    threatstream-get-analysis-status report_id=422662

#### Context Example

    {
        "ThreatStream": {
            "Analysis": {
                "Platform": "WINDOWS7",
                "ReportID": "422662",
                "Status": "processing",
                "Verdict": "Benign"
            }
        }
    }

#### Human Readable Output

##### The analysis status for id 422662

| Category | Started | Completed | Duration | VmName | VmID | ReportID | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| File | 2019-05-30 14:05:25 | 2019-05-30 14:06:33 | 68 |   |   | 413336 | Benign |


### threatstream-get-indicators
***
Return filtered indicators from ThreatStream. If a query is defined, it overides all othe arguments that were passed to the command.


#### Base Command

`threatstream-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Anomali Observable Search Filter Language query to filter indicatorts results. If a query is passed as an argument, it overides all other arguments. | Optional | 
| asn | Autonomous System (AS) number associated with the indicator. | Optional | 
| confidence | Level of certainty that an observable<br/>is of the reported indicator type. Confidence scores range from 0-100, in increasing order of confidence, and is assigned by ThreatStream based on several factors. | Optional | 
| country | Country associated with the indicator. | Optional | 
| created_ts | When the indicator was first seen on<br/>the ThreatStream cloud platform. Date must be specified in this format:<br/>YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.<br/>For example, 2014-10-02T20:44:35. | Optional | 
| id | Unique ID for the indicator. | Optional | 
| is_public | Classification of the indicator. | Optional | 
| indicator_severity | Severity assigned to the indicator by ThreatStream. | Optional | 
| org | Registered owner (organization) of the IP address associated with the indicator. | Optional | 
| status | Status assigned to the indicator. | Optional | 
| tags_name | Tag assigned to the indicator. | Optional | 
| type | Type of indicator. | Optional | 
| indicator_value | Value of the indicator.  | Optional | 
| limit | Maximum number of results to return from ThreatStrem. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Indicators.IType | String | The indicator type. | 
| ThreatStream.Indicators.Modified | String | Date and time when the indicator was last updated on the ThreatStream. Format: YYYYMMDDThhmmss, where T denotes the start of the value for time, in UTC time. | 
| ThreatStream.Indicators.Confidence | String | Level of certainty that an observable is of the reported indicator type. | 
| ThreatStream.Indicators.Value | String | The indicator value. | 
| ThreatStream.Indicators.Status | String | The indicator status. | 
| ThreatStream.Indicators.Organization | String | Registered owner \(organization\) of the IP address associated with the indicator. | 
| ThreatStream.Indicators.Country | String | Country associated with the indicator. | 
| ThreatStream.Indicators.Tags | String | Tag assigned to the indicator. | 
| ThreatStream.Indicators.Source | String | The source of the indicator. | 
| ThreatStream.Indicators.ID | String | The ID of the indicator. | 
| ThreatStream.Indicators.ASN | String | Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Indicators.Severity | String | The severity assigned to the indicator. | 


#### Command Example

    threatstream-get-indicators type=ip status=active asn=4837 country=CN confidence=84 indicator_severity=medium org="China Unicom Guangxi" limit=5

#### Context Example

    {
        "ThreatStream.Indicators": [
            {
                "Status": "active", 
                "Confidence": 84, 
                "IType": "scan_ip", 
                "Severity": "medium", 
                "Tags": null, 
                "Country": "CN", 
                "Modified": "2019-06-24T10:19:52.077Z", 
                "Value": "121.31.166.99", 
                "ID": 53042398831, 
                "Source": "Anomali Labs MHN", 
                "Organization": "China Unicom Guangxi", 
                "Type": "ip", 
                "ASN": "4837"
            }, 
            {
                "Status": "active", 
                "Confidence": 84, 
                "IType": "scan_ip", 
                "Severity": "medium", 
                "Tags": "port-1433,suricata,TCP", 
                "Country": "CN", 
                "Modified": "2019-06-24T09:51:04.804Z", 
                "Value": "121.31.166.99", 
                "ID": 53042253345, 
                "Source": "Anomali Labs MHN Tagged", 
                "Organization": "China Unicom Guangxi", 
                "Type": "ip", 
                "ASN": "4837"
            }, 
            {
                "Status": "active", 
                "Confidence": 84, 
                "IType": "scan_ip", 
                "Severity": "medium", 
                "Tags": null, 
                "Country": "CN", 
                "Modified": "2019-06-24T06:08:12.585Z", 
                "Value": "182.88.27.168", 
                "ID": 53016547378, 
                "Source": "DShield Scanning IPs", 
                "Organization": "China Unicom Guangxi", 
                "Type": "ip", 
                "ASN": "4837"
            }, 
            {
                "Status": "active", 
                "Confidence": 84, 
                "IType": "scan_ip", 
                "Severity": "medium", 
                "Tags": "AlienVault,OTX", 
                "Country": "CN", 
                "Modified": "2019-06-23T19:38:05.782Z", 
                "Value": "182.91.129.165", 
                "ID": 53038621037, 
                "Source": "Alien Vault OTX Malicious IPs", 
                "Organization": "China Unicom Guangxi", 
                "Type": "ip", 
                "ASN": "4837"
            }, 
            {
                "Status": "active", 
                "Confidence": 84, 
                "IType": "scan_ip", 
                "Severity": "medium", 
                "Tags": null, 
                "Country": "CN", 
                "Modified": "2019-06-23T17:52:51.165Z", 
                "Value": "182.91.129.207", 
                "ID": 52970998522, 
                "Source": "DShield Scanning IPs", 
                "Organization": "China Unicom Guangxi", 
                "Type": "ip", 
                "ASN": "4837"
            }
        ]
    }

#### Human Readable Output

##### The indicators results

| IType | Value | Confidence | ID | Source | Type | Status | Tags | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| scan_ip | 121.31.166.99 | 84 | 53042398831 | Anomali Labs MHN | ip | active |   | 2019-06-24T10:19:52.077Z | China Unicom Guangxi | 4837 | CN | medium |
| scan_ip | 121.31.166.99 | 84 | 53042253345 | Anomali Labs MHN Tagged | ip | active | port-1433,suricata,TCP | 2019-06-24T09:51:04.804Z | China Unicom Guangxi | 4837 | CN | medium |
| scan_ip | 182.88.27.168 | 84 | 53016547378 | DShield Scanning IPs | ip | active |   | 2019-06-24T06:08:12.585Z | China Unicom Guangxi | 4837 | CN | medium |
| scan_ip | 182.91.129.165 | 84 | 53038621037 | Alien Vault OTX Malicious IPs | ip | active | AlienVault,OTX | 2019-06-23T19:38:05.782Z | China Unicom Guangxi | 4837 | CN | medium |
| scan_ip | 182.91.129.207 | 84 | 52970998522 | DShield Scanning IPs | ip | active |   | 2019-06-23T17:52:51.165Z | China Unicom Guangxi | 4837 | CN | medium |



### threatstream-add-tag-to-model
***
Add tags to intelligence for purposes of filtering for related entities.


#### Base Command

`threatstream-add-tag-to-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model entity on which to add the tag. Default is "intelligence" (indicator). | Optional | 
| tags | A CSV list of tags applied to the specified threat model entities or observable.  | Required | 
| model_id | The ID of the model on which to add the tag. | Required | 


#### Context Output

There is no context output for this command.

    threatstream-add-tag-to-model model=intelligence model_id=51375607503 tags="suspicious,not valid"

#### Human Readable Output

Added successfully tags: ['suspicious', 'not valid'] to intelligence
with 51375607503


### threatstream-create-model
***
Creates a threat model with the specified parameters.


#### Base Command

`threatstream-create-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to create. | Required | 
| name | The name of the threat model to create. | Required | 
| is_public | The scope of threat model visibility. | Optional | 
| tlp | Traffic Light Protocol designation for the threat model. | Optional | 
| tags | A CSV list of tags. | Optional | 
| intelligence | A CSV list of indicators IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The type of the threat model. | 
| ThreatStream.Model.ModelID | String | The ID of the threat model. | 
| ThreatStream.Model.Indicators.Value | String | The value of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The courty of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The source of the inidicator. | 
| ThreatStream.Model.Indicators.Type | String | The type of the inidicator. | 


#### Command Example
    threatstream-create-model model=actor name="New_Created_Actor" description="Description of the actor threat model" intelligence=53042425466,53042425532,53042425520 tags="new actor,test" tlp=red

#### Context Example

    {
        "ThreatStream.Model": {
            "Indicators": [
                {
                    "Status": "active", 
                    "Confidence": 86, 
                    "IType": "suspicious_domain", 
                    "Severity": "high", 
                    "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                    "Country": "US", 
                    "Modified": "2019-06-24T10:51:16.384", 
                    "Value": "chatbotshq.com", 
                    "ID": "53042425532", 
                    "Source": "Analyst", 
                    "Organization": "Hostinger International Limited", 
                    "Type": "domain", 
                    "ASN": "12769"
                }, 
                {
                    "Status": "active", 
                    "Confidence": 85, 
                    "IType": "suspicious_domain", 
                    "Severity": "high", 
                    "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                    "Country": "US", 
                    "Modified": "2019-06-24T10:51:16.589", 
                    "Value": "marketshq.com", 
                    "ID": "53042425520", 
                    "Source": "Analyst", 
                    "Organization": "GoDaddy.com, LLC", 
                    "Type": "domain", 
                    "ASN": "26496"
                }, 
                {
                    "Status": "active", 
                    "Confidence": 77, 
                    "IType": "suspicious_domain", 
                    "Severity": "high", 
                    "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                    "Country": "US", 
                    "Modified": "2019-06-24T10:54:31.318", 
                    "Value": "leanomalie.com", 
                    "ID": "53042425466", 
                    "Source": "Analyst", 
                    "Organization": "GoDaddy.com, LLC", 
                    "Type": "domain", 
                    "ASN": "26496"
                }
            ], 
            "ModelType": "Actor", 
            "ModelID": 26697
        }
    }

#### Human Readable Output

##### Indicators list for Threat Model Actor with id 26697

| IType | Value | ID | Confidence | Source | Type | Status | Tags | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| suspicious_domain | chatbotshq.com | 53042425532 | 86 | Analyst | domain | active | Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech | 2019-06-24T10:51:16.384 | Hostinger International Limited | 12769 | US | high |
| suspicious_domain | marketshq.com | 53042425520 | 85 | Analyst | domain | active | Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech | 2019-06-24T10:51:16.589 | GoDaddy.com, LLC | 26496 | US | high |
| suspicious_domain | leanomalie.com | 53042425466 | 77 | Analyst | domain | active | Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech | 2019-06-24T10:54:31.318 | GoDaddy.com, LLC | 26496 | US | high |



### threatstream-update-model
***
Updates a threat model with specific parameters. If one or more optional parameters are defined, the command overides previous data stored in ThreatStream.


#### Base Command

`threatstream-update-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to update. | Required | 
| model_id | The ID of the threat model to update. | Required | 
| name | The name of the threat model to update. | Optional | 
| is_public | The scope of threat model visibility. | Optional | 
| tlp | Traffic Light Protocol designation for the threat model. | Optional | 
| tags | A CSV list of tags. | Optional | 
| intelligence | A CSV list of indicators IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The type of the threat model. | 
| ThreatStream.Model.ModelID | String | The ID of the threat model. | 
| ThreatStream.Model.Indicators.Value | String | The value of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The courty of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The source of the inidicator. | 
| ThreatStream.Model.Indicators.Type | String | The type of the inidicator. | 


#### Command Example
    threatstream-update-model model=actor model_id=26697 intelligence=53042694591 tags="updated tag,gone"

#### Context Example

    {
        "ThreatStream": {
            "Model": {
                "Indicators": [
                    {
                        "ASN": "",
                        "Confidence": 36,
                        "Country": "CA",
                        "ID": "53042694591",
                        "IType": "exploit_ip",
                        "Modified": "2019-06-24T11:28:31.185",
                        "Organization": "OVH Hosting",
                        "Severity": "high",
                        "Source": "Analyst",
                        "Status": "active",
                        "Tags": "HoneyDB",
                        "Type": "ip",
                        "Value": "54.39.20.14"
                    }
                ],
                "ModelID": "26697",
                "ModelType": "Actor"
            }
        }
    }

#### Human Readable Output

##### Indicators list for Threat Model Actor with id 26697

| IType | Value | ID | Confidence | Source | Type | Status | Tags | Modified | Organization | ASN | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exploit_ip | 54.39.20.14 | 53042694591 | 36 | Analyst | ip | active | HoneyDB | 2019-06-24T11:28:31.185 | OVH Hosting |   | CA | high |


### threatstream-supported-platforms
***
Returns list of supported platforms for default or premium sandbox.


#### Base Command

`threatstream-supported-platforms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sandbox_type | The type of sandbox ("default" or "premium"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PremiumPlatforms.Name | String | Name of the supported platform for premium sadnbox. | 
| ThreatStream.PremiumPlatforms.Types | String | Type of supported submissions for premium sanbox. | 
| ThreatStream.PremiumPlatforms.Label | String | The display name of the supported platform of premium sandbox. | 
| ThreatStream.DefaultPlatforms.Name | String | Name of the supported platform for standard sadnbox. | 
| ThreatStream.DefaultPlatforms.Types | String | Type of supported submissions for standard sanbox. | 
| ThreatStream.DefaultPlatforms.Label | String | The display name of the supported platform of standard sandbox. | 


#### Command Example
    threatstream-supported-platforms sandbox_type=default

#### Context Example

    {
        "ThreatStream.DefaultPlatforms": [
            {
                "Name": "WINDOWSXP", 
                "Types": [
                    "file", 
                    "url"
                ], 
                "Label": "Windows XP"
            }, 
            {
                "Name": "WINDOWS7", 
                "Types": [
                    "file", 
                    "url"
                ], 
                "Label": "Windows 7"
            }, 
            {
                "Name": "ALL", 
                "Types": [
                    "file", 
                    "url"
                ], 
                "Label": "All"
            }
        ]
    }

#### Human Readable Output

##### Supported platforms for default sandbox

| Name | Types | Label |
| --- | --- | --- |
| WINDOWSXP | file, url | Windows XP |
| WINDOWS7 | file, url | Windows 7 |
| ALL | file, url | All |



### url
***
Checks the reputation of the given URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 
| threshold | If severity is greater than or equal to the threshold, then the URL will be considered malicious. This argument will override the default threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with the status "Inactive". Default is "False". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Data | String | The URL of the indicator. | 
| URL.Tags | Unknown | (List) Tags of the URL. | 
| URL.Malicious.Vendor | String | Vendor that reported the indicator as malicious. | 
| ThreatStream.URL.Modified | String | Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time. | 
| ThreatStream.URL.Confidence | String | Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.URL.Status | String | The status of the indicator. | 
| ThreatStream.URL.Organization | String | Name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.URL.Address | String | URL of the indicator. | 
| ThreatStream.URL.Country | String | Country associated with the indicator. | 
| ThreatStream.URL.Type | String | The indicator type. | 
| ThreatStream.URL.Source | String | The source of the indicator. | 
| ThreatStream.URL.Severity | String | The indicator severity \("very-high", "high", "medium", or "low"\). | 
| ThreatStream.URL.Tags | Unknown | Tags assigned to the URL. |

#### Command Example
    url url=http://194.147.35.172/mikey.mpsl using-brand="Anomali ThreatStream v2"

#### Context Example

    {
        "URL": {
            "Malicious": {
                "Vendor": "ThreatStream"
            }, 
            "Data": "http://194.147.35.172/mikey.mpsl",
            "Tags": ["phish-target", "victim-hi-tech"]
        }, 
        "ThreatStream.URL": {
            "Status": "active", 
            "Confidence": 90, 
            "Severity": "very-high", 
            "Country": "RU", 
            "Modified": "2019-06-24T10:10:05.890Z", 
            "Source": "H3X Tracker", 
            "Address": "http://194.147.35.172/mikey.mpsl", 
            "Organization": "LLC Baxet", 
            "Type": "url",
            "Tags": [{"id": "4wq", "name": "phish-target", "org_id": "88"}, {"id": "ezn", "name": "victim-hi-tech", "org_id": "88"}]
        }, 
        "DBotScore": {
            "Vendor": "H3X Tracker", 
            "Indicator": "http://194.147.35.172/mikey.mpsl", 
            "Score": 3, 
            "Type": "url"
        }
    }

#### Human Readable Output

##### URL reputation for: `http://194.147.35.172/mikey.mpsl`

| Address | Confidence | Source | Type | Status | Modified | Organization | Country | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `http://194.147.35.172/mikey.mpsl` | 90 | H3X Tracker | url | active | 2019-06-24T10:10:05.890Z | LLC Baxet | RU | very-high |