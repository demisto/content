Use Anomali ThreatStream to query and submit threats.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-anomali-threatstream-v3).

## Configure Anomali ThreatStream v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Anomali ThreatStream v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://www.test.com) |  | True |
    | Username |  | True |
    | API Key |  | True |
    | URL threshold |  | False |
    | IP threshold |  | False |
    | Domain threshold |  | False |
    | File threshold |  | False |
    | Email threshold |  | False |
    | Include inactive results | Whether to include inactive indicators in reputation commands. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Create relationships | Create relationships between indicators as part of enrichment. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of the given IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to check. | Required | 
| threshold | If confidence is greater than the threshold the IP address is considered malicious, otherwise it is considered good. This argument overrides the default IP threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| IP.Address | String | The IP address of the indicator. | 
| IP.Geo.Country | String | The country associated with the indicator. | 
| IP.Geo.Location | String | The longitude and latitude of the IP address. | 
| ThreatStream.IP.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.IP.Address | String | The IP address of the indicator. | 
| ThreatStream.IP.Country | String | The country associated with the indicator. | 
| ThreatStream.IP.Type | String | The indicator type. | 
| ThreatStream.IP.Modified | String | The time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time in UTC time. | 
| ThreatStream.IP.Severity | String | The indicator severity \("very-high", "high", "medium", or "low"\). | 
| ThreatStream.IP.Confidence | String | The observable certainty level of a reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.IP.Status | String | The status assigned to the indicator. | 
| ThreatStream.IP.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.IP.Source | String | The indicator source. | 
| IP.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| ThreatStream.IP.Tags | Unknown | Tags assigned to the IP. | 
| IP.Tags | Unknown | List of IP Tags. | 
| IP.ThreatTypes | Unknown | Threat types associated with the IP. | 


#### Command Example
```!ip ip=78.78.78.67```

#### Human Readable Output

>No intelligence has been found for 78.78.78.67

### domain
***
Checks the reputation of the given domain name.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Required | 
| threshold | If confidence is greater than the threshold the Domain is considered malicious, otherwise it is considered good. This argument overrides the default Domain threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.DNS | String | The IP addresses resolved by DNS. | 
| Domain.WHOIS.CreationDate | Date | The date the domain was created. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.UpdatedDate | Date | The date the domain was last updated. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.Registrant.Name | String | The registrant name. | 
| Domain.WHOIS.Registrant.Email | String | The registrant email address. | 
| Domain.WHOIS.Registrant.Phone | String | The registrant phone number. | 
| ThreatStream.Domain.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Domain.Address | String | The indicator domain name. | 
| ThreatStream.Domain.Country | String | The country associated with the indicator. | 
| ThreatStream.Domain.Type | String | The indicator type. | 
| ThreatStream.Domain.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.Domain.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.Domain.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.Domain.Status | String | The status assigned to the indicator. | 
| ThreatStream.Domain.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.Domain.Source | String | The indicator source. | 
| Domain.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.Domain.Tags | Unknown | Tags assigned to the domain. | 
| Domain.Tags | Unknown | List of domain tags. | 
| Domain.ThreatTypes | Unknown | Threat types associated with the domain. | 


#### Command Example
```!domain domain=y.gp```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "y.gp",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Anomali ThreatStream v3"
    },
    "Domain": {
        "CreationDate": "2021-09-14T13:19:23.801Z",
        "DNS": "78.78.78.67",
        "Geo": {
            "Country": "DE",
            "Location": "51.2993,9.491"
        },
        "Name": "y.gp",
        "Organization": "Hetzner Online GmbH",
        "Relationships": [
            {
                "EntityA": "y.gp",
                "EntityAType": "Domain",
                "EntityB": "78.78.78.67",
                "EntityBType": "IP",
                "Relationship": "resolved-from"
            }
        ],
        "Tags": [
            "malware"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "malware",
                "threatcategoryconfidence": null
            }
        ],
        "TrafficLightProtocol": "amber",
        "UpdatedDate": "2021-09-14T13:19:23.801Z",
        "WHOIS": {
            "CreationDate": "2021-09-14T13:19:23.801Z",
            "UpdatedDate": "2021-09-14T13:19:23.801Z"
        }
    },
    "ThreatStream": {
        "Domain": {
            "ASN": "24940",
            "Address": "y.gp",
            "Confidence": 50,
            "Country": "DE",
            "Modified": "2021-09-14T13:19:23.801Z",
            "Organization": "Hetzner Online GmbH",
            "Severity": "very-high",
            "Source": "Analyst",
            "Status": "active",
            "Tags": [
                "malware"
            ],
            "Type": "domain"
        }
    }
}
```

#### Human Readable Output

>### Domain reputation for: y.gp
>|ASN|Address|Confidence|Country|Modified|Organization|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 24940 | y.gp | 50 | DE | 2021-09-14T13:19:23.801Z | Hetzner Online GmbH | very-high | Analyst | active | malware | domain |


### file
***
Checks the reputation of the given hash of the file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash of file to check. | Required | 
| threshold | If the confidence is greater than the threshold the hash of the file is considered malicious, otherwise it is considered good. This argument overrides the default file threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.File.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.File.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.File.Status | String | The status assigned to the indicator. | 
| ThreatStream.File.Type | String | The indicator type. | 
| ThreatStream.File.MD5 | String | The MD5 hash of the indicator. | 
| ThreatStream.File.SHA1 | String | The SHA1 hash of the indicator. | 
| ThreatStream.File.SHA256 | String | The SHA256 hash of the indicator. | 
| ThreatStream.File.SHA512 | String | The SHA512 hash of the indicator. | 
| ThreatStream.File.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.File.Source | String | The indicator source. | 
| ThreatStream.File.Tags | Unknown | Tags assigned to the file. | 
| File.Tags | Unknown | List of file tags. | 
| File.ThreatTypes | Unknown | Threat types associated with the file. | 


#### Command Example
```!file file=178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "file",
        "Vendor": "Anomali ThreatStream v3"
    },
    "File": {
        "SHA256": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1",
        "Tags": [
            "apt"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "apt",
                "threatcategoryconfidence": null
            }
        ]
    },
    "ThreatStream": {
        "File": {
            "Confidence": 50,
            "Modified": "2021-09-13T12:40:42.596Z",
            "SHA256": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1",
            "Severity": "medium",
            "Source": "TestSource",
            "Status": "active",
            "Tags": [
                "apt"
            ],
            "Type": "SHA256"
        }
    }
}
```

#### Human Readable Output

>### File reputation for: 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1
>|Confidence|Modified|SHA256|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|
>| 50 | 2021-09-13T12:40:42.596Z | 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1 | medium | TestSource | active | apt | SHA256 |


### threatstream-email-reputation
***
Checks the reputation of the given email address.


#### Base Command

`threatstream-email-reputation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check. | Required | 
| threshold | If the confidence is greater than the threshold the email address is considered malicious, otherwise it is considered good. This argument overrides the default email threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The tested indicator. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.EmailReputation.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.EmailReputation.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.EmailReputation.Status | String | The status assigned to the indicator. | 
| ThreatStream.EmailReputation.Type | String | The indicator type. | 
| ThreatStream.EmailReputation.Email | String | The indicator email address. | 
| ThreatStream.EmailReputation.Source | String | The indicator source. | 
| ThreatStream.EmailReputation.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.EmailReputation.Tags | Unknown | Tags assigned to the email. | 


#### Command Example
```!threatstream-email-reputation email=egov@ac.in```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "egov@ac.in",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "Anomali ThreatStream v3"
    },
    "Email": {
        "Address": "egov@ac.in"
    },
    "ThreatStream": {
        "EmailReputation": {
            "Confidence": 10000,
            "Email": "egov@ac.in",
            "Modified": "2021-08-01T10:35:53.484Z",
            "Severity": "high",
            "Source": "Analyst",
            "Status": "active",
            "Tags": [
                "apt"
            ],
            "Type": "email"
        }
    }
}
```

#### Human Readable Output

>### Email reputation for: egov@ac.in
>|Confidence|Email|Modified|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|
>| 10000 | egov@ac.in | 2021-08-01T10:35:53.484Z | high | Analyst | active | apt | email |


### threatstream-get-passive-dns
***
Returns enrichment data for Domain or IP for available observables.


#### Base Command

`threatstream-get-passive-dns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of passive DNS search ("ip", "domain"). Possible values are: ip, domain. Default is ip. | Required | 
| value | Possible values are "IP" or "Domain". | Required | 
| limit | The maximum number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PassiveDNS.Domain | String | The domain value. | 
| ThreatStream.PassiveDNS.Ip | String | The IP value. | 
| ThreatStream.PassiveDNS.Rrtype | String | The Rrtype value. | 
| ThreatStream.PassiveDNS.Source | String | The source value. | 
| ThreatStream.PassiveDNS.FirstSeen | String | The first seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time, in UTC time. | 
| ThreatStream.PassiveDNS.LastSeen | String | The last seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 


#### Command Example
```!threatstream-get-passive-dns type="domain" value="y.gp" limit="1"```

#### Context Example
```json
{
    "ThreatStream": {
        "PassiveDNS": [
            {
                "Domain": "y.gp",
                "FirstSeen": "2015-07-20 02:33:47",
                "Ip": "78.78.78.67",
                "LastSeen": "2015-12-19 06:44:35",
                "Rrtype": "A",
                "Source": "Anomali Labs"
            }
        ]
    }
}
```

#### Human Readable Output

>### Passive DNS enrichment data for: y.gp
>|Domain|FirstSeen|Ip|LastSeen|Rrtype|Source|
>|---|---|---|---|---|---|
>| y.gp | 2015-07-20 02:33:47 | 78.78.78.67 | 2015-12-19 06:44:35 | A | Anomali Labs |


### threatstream-import-indicator-with-approval
***
Imports indicators (observables) into ThreatStream. The imported data must be approved using the ThreatStream UI. The data can be imported using one of three methods: plain-text, file, or URL.


#### Base Command

`threatstream-import-indicator-with-approval`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50. | Optional | 
| classification | Whether the indicator data is public or private to the organization. Possible values are: private, public. Default is private. | Optional | 
| threat_type | Type of threat associated with the imported observables. Can be "adware", "anomalous", "anonymization", "apt", "bot", "brute", "c2", "compromised", "crypto", "data_leakage", "ddos", "dyn_dns", "exfil", "exploit", "hack_tool", "i2p", "informational", "malware", "p2p", "parked", "phish", "scan", "sinkhole", "spam", "suppress", "suspicious", "tor", or "vps". Possible values are: adware, anomalous, anonymization, apt, bot, brute, c2, compromised, crypto, data_leakage, ddos, dyn_dns, exfil, exploit, hack_tool, i2p, informational, malware, p2p, parked, phish, scan, sinkhole, spam, suppress, suspicious, tor, vps. Default is exploit. | Optional | 
| severity | The potential impact of the indicator type with which the observable is believed to be associated. Can be "low", "medium", "high", or "very-high". Possible values are: low, medium, high, very-high. Default is low. | Optional | 
| import_type | The import type of the indicator. Can be "datatext", "file-id", or "url". Possible values are: datatext, file-id, url. | Required | 
| import_value | The source of imported data. Can be one of the following: url, datatext of file-id of uploaded file to the War Room. Supported file types for file-id are: CSV, HTML, IOC, JSON, PDF, TXT. | Required | 
| ip_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported IP-type observable when an explicit itype is not specified for it. | Optional | 
| domain_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported domain-type observable when an explicit itype is not specified for it. | Optional | 
| url_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported URL-type observable when an explicit itype is not specified for it. | Optional | 
| email_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported email-type observable when an explicit itype is not specified for it. | Optional | 
| md5_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported MD5-type observable when an explicit itype is not specified for it. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-import-indicator-with-approval import_type=datatext import_value=78.78.78.67```

#### Context Example
```json
{
    "ThreatStream": {
        "Import": {
            "ImportID": "36118"
        }
    }
}
```

#### Human Readable Output

>The data was imported successfully. The ID of imported job is: 36118

### threatstream-import-indicator-without-approval
***
Imports indicators (observables) into ThreatStream. Approval is not required for the imported data. You must have the Approve Intel user permission to import without approval using the API.


#### Base Command

`threatstream-import-indicator-without-approval`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50. | Optional | 
| source_confidence_weight | To use your specified confidence entirely and not re-assess the value using machine learning algorithms, set source_confidence_ weight to 100. | Optional | 
| expiration_ts | The time stamp when intelligence will expire on ThreatStream, in ISO format. For example, 2020-12-24T00:00:00. | Optional | 
| severity | The severity to assign to the observable when it is imported. Can be "low", "medium", "high" , or "very-high". Possible values are: low, medium, high, very-high. | Optional | 
| tags | A comma-separated list of tags. For example, tag1,tag2. | Optional | 
| trustedcircles | A comma-separated list of trusted circle IDs with which threat data should be shared. | Optional | 
| classification | Denotes whether the indicator data is public or private to the organization. Possible values are: private, public. | Required | 
| allow_unresolved | Whether unresolved domain observables are included in the file will be accepted as valid in ThreatStream and imported. Possible values are: yes, no. | Optional | 
| file_id | The entry ID of a file (containing a JSON with an "objects" array and "meta" maps) that is uploaded to the War Room. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-import-indicator-without-approval classification=private file_id=2761@3c9bd2a0-9eac-465b-8799-459df4997b2d```

#### Human Readable Output

>The data was imported successfully.

### threatstream-get-model-list
***
Returns a list of threat models.


#### Base Command

`threatstream-get-model-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model of the returned list. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| limit | Limits the model size list. Specifying limit=0 returns up to a maximum of 1000 models. For limit=0, the output is not set in the context. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.List.Type | String | The threat model type. | 
| ThreatStream.List.Name | String | The threat model name. | 
| ThreatStream.List.ID | String | The threat model ID. | 
| ThreatStream.List.CreatedTime | String | The date and time of threat model creation. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time in UTC time. | 


#### Command Example
```!threatstream-get-model-list model=actor limit=10```

#### Context Example
```json
{
    "ThreatStream": {
        "List": [
            {
                "CreatedTime": "2019-02-19T16:42:00.933984",
                "ID": 1,
                "Name": "Fleahopper Actor",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2019-08-24T02:47:29.204380",
                "ID": 10158,
                "Name": "report actor 1",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2019-08-28T16:35:39.316135",
                "ID": 10159,
                "Name": "report actor 1",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2020-10-14T12:28:54.937276",
                "ID": 10909,
                "Name": "MANDRA",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2021-09-14T13:37:02.111599",
                "ID": 26769,
                "Name": "New_Created_Actor",
                "Type": "Actor"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Actors
>|CreatedTime|ID|Name|Type|
>|---|---|---|---|
>| 2019-02-19T16:42:00.933984 | 1 | Fleahopper Actor | Actor |
>| 2019-08-24T02:47:29.204380 | 10158 | report actor 1 | Actor |
>| 2019-08-28T16:35:39.316135 | 10159 | report actor 1 | Actor |
>| 2020-10-14T12:28:54.937276 | 10909 | MANDRA | Actor |
>| 2021-09-14T13:37:02.111599 | 26769 | New_Created_Actor | Actor |


### threatstream-get-model-description
***
Returns an HTML file with a description of the threat model.


#### Base Command

`threatstream-get-model-description`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| id | The threat model ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The file name of the model description. | 
| File.EntryID | String | The entry ID of the model description. | 


#### Command Example
```!threatstream-get-model-description model=actor id=1```

#### Context Example
```json
{
    "File": {
        "EntryID": "3171@3c9bd2a0-9eac-465b-8799-459df4997b2d",
        "Extension": "html",
        "Info": "text/html; charset=utf-8",
        "MD5": "18d7610f85c1216e78c59cbde5c470d9",
        "Name": "actor_1.html",
        "SHA1": "c778f72fd7799108db427f632ca6b2bb07c9bde4",
        "SHA256": "6d06bdc613490216373e2b189c8d41143974c7a128da26e8fc4ba4f45a7e718b",
        "SHA512": "989b0ae32b61b3b5a7ea1c3e629b50f07e7086310f8e4057ec046b368e55fc82cae873bd81eada657d827c96c71253b6ba3688561844ce983cdc5019d9666aa4",
        "SSDeep": "48:32u8P32apgpIph9/gldn2++TnlCC4i72gSmB2rXpzNZx:32tuapgpCglM++TCE2gSN/",
        "Size": 1868,
        "Type": "ASCII text, with very long lines, with no line terminators"
    }
}
```

#### Human Readable Output



### threatstream-get-indicators-by-model
***
Returns a list of indicators associated with the specified model and ID of the model.


#### Base Command

`threatstream-get-indicators-by-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| id | The model ID. | Required | 
| limit | The maximum number of results to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The indicator severity associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-get-indicators-by-model id=731 model=incident```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 181481953,
                    "IType": "mal_email",
                    "Modified": "2021-03-25T13:27:58.922Z",
                    "Organization": "",
                    "Severity": "low",
                    "Source": "Analyst",
                    "Status": "inactive",
                    "Tags": "tag-approved",
                    "Type": "email",
                    "Value": "testemail123@test.com"
                }
            ],
            "ModelID": "731",
            "ModelType": "Incident"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Incident with id 731
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 181481953 | mal_email | 2021-03-25T13:27:58.922Z |  | low | Analyst | inactive | tag-approved | email | testemail123@test.com |


### threatstream-submit-to-sandbox
***
Submits a file or URL to the ThreatStream-hosted sandbox for detonation.


#### Base Command

`threatstream-submit-to-sandbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_classification | Classification of the Sandbox submission. Can be "private" or "public". Possible values are: private, public. Default is private. | Optional | 
| report_platform | The platform on which the submitted URL or file is run. To obtain a list supported platforms run the threatstream-supported-platforms command. Can be "WINDOWS7", or "WINDOWSXP". Possible values are: WINDOWS7, WINDOWSXP. Default is WINDOWS7. | Optional | 
| submission_type | The detonation type. Can be "file" or "url". Possible values are: file, url. Default is file. | Required | 
| submission_value | The submission value. Possible values are a valid URL or a file ID that was uploaded to the War Room to detonate. | Required | 
| premium_sandbox | Whether the premium sandbox should be used for detonation. Possible values are: false, true. Default is false. | Optional | 
| detail | A comma-separated list of additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID submitted to the sandbox. | 
| ThreatStream.Analysis.Status | String | The analysis status. | 
| ThreatStream.Analysis.Platform | String | The platform of the submission submitted to the sandbox. | 


#### Command Example
```!threatstream-submit-to-sandbox submission_classification="private" report_platform="WINDOWS7" submission_type="file" submission_value="1711@3c9bd2a0-9eac-465b-8799-459df4997b2d" premium_sandbox="false"```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": 12418,
            "Status": "processing"
        }
    }
}
```

#### Human Readable Output

>### The submission info for 1711@3c9bd2a0-9eac-465b-8799-459df4997b2d
>|Platform|ReportID|Status|
>|---|---|---|
>| WINDOWS7 | 12418 | processing |


### threatstream-get-analysis-status
***
Returns the current status of the report submitted to the sandbox. The report ID is returned from the threatstream-submit-to-sandbox command.


#### Base Command

`threatstream-get-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to check the status. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Status | String | The report status of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Platform | String | The platform used for detonation. | 
| ThreatStream.Analysis.Verdict | String | The report verdict of the file or URL detonated in the sandbox. The verdict remains "benign" until detonation is complete. | 


#### Command Example
```!threatstream-get-analysis-status report_id=12414```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": "12414",
            "Status": "errors",
            "Verdict": "Benign"
        }
    }
}
```

#### Human Readable Output

>### The analysis status for id 12414
>|Platform|ReportID|Status|Verdict|
>|---|---|---|---|
>| WINDOWS7 | 12414 | errors | Benign |


### threatstream-analysis-report
***
Returns the report of a file or URL submitted to the sandbox.


#### Base Command

`threatstream-analysis-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to return. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The ID of the report submitted to the sandbox. | 
| ThreatStream.Analysis.Category | String | The report category. | 
| ThreatStream.Analysis.Started | String | The detonation start time. | 
| ThreatStream.Analysis.Completed | String | The detonation completion time. | 
| ThreatStream.Analysis.Duration | Number | The duration of the detonation \(in seconds\). | 
| ThreatStream.Analysis.VmName | String | The VM name. | 
| ThreatStream.Analysis.VmID | String | The VM ID. | 
| ThreatStream.Analysis.Network.UdpSource | String | The UDP source. | 
| ThreatStream.Analysis.Network.UdpDestination | String | The UDP destination. | 
| ThreatStream.Analysis.Network.UdpPort | String | The UDP port. | 
| ThreatStream.Analysis.Network.IcmpSource | String | The ICMP source. | 
| ThreatStream.Analysis.Network.IcmpDestination | String | The ICMP destination. | 
| ThreatStream.Analysis.Network.IcmpPort | String | The ICMP port. | 
| ThreatStream.Analysis.Network.TcpSource | String | The TCP source. | 
| ThreatStream.Analysis.Network.TcpDestination | String | The TCP destination. | 
| ThreatStream.Analysis.Network.TcpPort | String | The TCP port. | 
| ThreatStream.Analysis.Network.HttpSource | String | The source of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpDestinaton | String | The destination of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpPort | String | The port of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpsSource | String | The source of the HTTPS address. | 
| ThreatStream.Analysis.Network.HttpsDestinaton | String | The destination of the HTTPS address. | 
| ThreatStream.Analysis.Network.HttpsPort | String | The port of the HTTPS address. | 
| ThreatStream.Analysis.Network.Hosts | String | The network analysis hosts. | 
| ThreatStream.Analysis.Verdict | String | The verdict of the sandbox detonation. | 


#### Command Example
```!threatstream-analysis-report report_id="12212"```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Category": "Url",
            "Completed": "2021-08-19 06:51:52",
            "Duration": 152,
            "Network": [
                {
                    "UdpDestination": "8.8.8.8",
                    "UdpPort": 53,
                    "UdpSource": "192.168.2.4"
                },
                {
                    "TcpDestination": "78.78.78.67",
                    "TcpPort": 443,
                    "TcpSource": "78.78.78.67"
                },
                {
                    "TcpDestination": "78.78.78.67",
                    "TcpPort": 443,
                    "TcpSource": "78.78.78.67"
                },
                {
                    "HttpsDestination": "78.78.78.67",
                    "HttpsPort": 443,
                    "HttpsSource": "78.78.78.67"
                },
                {
                    "Hosts": "78.78.78.67"
                }
            ],
            "ReportID": "12212",
            "Started": "2021-08-19 06:49:20",
            "Verdict": "Benign",
            "VmID": "",
            "VmName": ""
        }
    }
}
```

#### Human Readable Output

>### Report 12212 analysis results
>|Category|Completed|Duration|ReportID|Started|Verdict|VmID|VmName|
>|---|---|---|---|---|---|---|---|
>| Url | 2021-08-19 06:51:52 | 152 | 12212 | 2021-08-19 06:49:20 | Benign |  |  |


### threatstream-get-indicators
***
Return filtered indicators from ThreatStream. If a query is defined, it overrides all other arguments that were passed to the command.


#### Base Command

`threatstream-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Anomali Observable Search Filter Language query to filter indicator results. If a query is passed as an argument, it overrides all other arguments. | Optional | 
| asn | The Autonomous System (AS) number associated with the indicator. | Optional | 
| confidence | The observable certainty level<br/>of a reported indicator type. Confidence scores range from 0-100 in increasing order of confidence, and are assigned by ThreatStream based on several factors. | Optional | 
| country | The country associated with the indicator. | Optional | 
| created_ts | When the indicator was first seen on<br/>the ThreatStream cloud platform. The date must be specified in this format:<br/>YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.<br/>For example, 2014-10-02T20:44:35. | Optional | 
| id | The unique ID for the indicator. | Optional | 
| is_public | Whether the classification of the indicator is public. Default is "false". Possible values are: false, true. | Optional | 
| indicator_severity | The severity assigned to the indicator by ThreatStream. | Optional | 
| org | The registered owner (organization) of the IP address associated with the indicator. | Optional | 
| status | The status assigned to the indicator. Can be "active", "inactive", or "falsepos". Possible values are: active, inactive, falsepos. | Optional | 
| tags_name | The tag assigned to the indicator. | Optional | 
| type | The type of indicator. Can be "domain", "email", "ip", "MD5", "string", or "url". Possible values are: domain, email, ip, md5, string, url. | Optional | 
| indicator_value | The value of the indicator. . | Optional | 
| limit | The maximum number of results to return from ThreatStream. Default is 20. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Indicators.IType | String | The indicator type. | 
| ThreatStream.Indicators.Modified | String | The date and time the indicator was last updated in ThreatStream. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| ThreatStream.Indicators.Confidence | String | The observable certainty level of a reported indicator type. | 
| ThreatStream.Indicators.Value | String | The indicator value. | 
| ThreatStream.Indicators.Status | String | The indicator status. | 
| ThreatStream.Indicators.Organization | String | The registered owner \(organization\) of the IP address associated with the indicator. | 
| ThreatStream.Indicators.Country | String | The country associated with the indicator. | 
| ThreatStream.Indicators.Tags | String | The tag assigned to the indicator. | 
| ThreatStream.Indicators.Source | String | The indicator source. | 
| ThreatStream.Indicators.ID | String | The indicator ID. | 
| ThreatStream.Indicators.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Indicators.Severity | String | The severity assigned to the indicator. | 


#### Command Example
```!threatstream-get-indicators type=ip status=active limit=5```

#### Context Example
```json
{
    "ThreatStream": {
        "Indicators": [
            {
                "ASN": "",
                "Confidence": 100,
                "Country": null,
                "ID": 239450621,
                "IType": "apt_ip",
                "Modified": "2021-05-24T16:42:09.245Z",
                "Organization": "",
                "Severity": "very-high",
                "Source": "Analyst",
                "Status": "active",
                "Tags": null,
                "Type": "ip",
                "Value": "78.78.78.67"
            },
            {
                "ASN": "",
                "Confidence": -1,
                "Country": null,
                "ID": 235549247,
                "IType": "apt_ip",
                "Modified": "2021-04-29T16:02:17.558Z",
                "Organization": "",
                "Severity": "very-high",
                "Source": "Analyst",
                "Status": "active",
                "Tags": null,
                "Type": "ip",
                "Value": "78.78.78.67"
            }
        ]
    }
}
```

#### Human Readable Output

>### The indicators results
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 100 |  | 239450621 | apt_ip | 2021-05-24T16:42:09.245Z |  | very-high | Analyst | active |  | ip | 78.78.78.67 |
>|  | -1 |  | 235549247 | apt_ip | 2021-04-29T16:02:17.558Z |  | very-high | Analyst | active |  | ip | 78.78.78.67 |


### threatstream-add-tag-to-model
***
Adds tags to intelligence to filter for related entities.


#### Base Command

`threatstream-add-tag-to-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model entity to which to add the tag. Can be "actor", "campaign", "incident", "intelligence", "signature", "tipreport", "ttp", or "vulnerability". Possible values are: actor, campaign, incident, intelligence, signature, tipreport, ttp, vulnerability. Default is intelligence. | Optional | 
| tags | A comma separated list of tags applied to the specified threat model entities or observable. . | Required | 
| model_id | The ID of the model to which to add the tag. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-add-tag-to-model model=incident model_id=130 tags="suspicious,not valid"```

#### Human Readable Output

>Added successfully tags: ['suspicious', 'not valid'] to incident with 130

### threatstream-create-model
***
Creates a threat model with the specified parameters.


#### Base Command

`threatstream-create-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to create. Can be "actor", "campaign", "incident", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, ttp, vulnerability, tipreport. | Required | 
| name | The name of the threat model to create. | Required | 
| is_public | Whether the scope of threat model is visible. Possible values are: true, false. Default is false. | Optional | 
| tlp | The Traffic Light Protocol designation for the threat model. Can be "red", "amber", "green", or "white". Possible values are: red, amber, green, white. Default is red. | Optional | 
| tags | A comma separated list of tags. | Optional | 
| intelligence | A comma separated list of indicators IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-create-model model=actor name="New_Created_Actor_1" description="Description of the actor threat model" intelligence=191431508 tags="new actor,test" tlp=red```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 191431508,
                    "IType": "apt_md5",
                    "Modified": "2021-09-13T12:40:42.596Z",
                    "Organization": "",
                    "Severity": "medium",
                    "Source": "TestSource",
                    "Status": "active",
                    "Tags": null,
                    "Type": "SHA256",
                    "Value": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
                }
            ],
            "ModelID": 26770,
            "ModelType": "Actor"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Actor with id 26770
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 191431508 | apt_md5 | 2021-09-13T12:40:42.596Z |  | medium | TestSource | active |  | SHA256 | 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1 |


### threatstream-update-model
***
Updates a threat model with specific parameters. If one or more optional parameters are defined, the command overrides previous data stored in ThreatStream.


#### Base Command

`threatstream-update-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to update. Can be "actor", "campaign", "incident", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, ttp, vulnerability, tipreport. | Required | 
| model_id | The ID of the threat model to update. | Required | 
| name | The name of the threat model to update. | Optional | 
| is_public | Whether the scope of threat model is visible. Possible values are: true, false. Default is false. | Optional | 
| tlp | The Traffic Light Protocol designation for the threat model. Can be "red", "amber", "green", or "white". Possible values are: red, amber, green, white. Default is red. | Optional | 
| tags | A comma separated list of tags. | Optional | 
| intelligence | A comma separated list of indicator IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-update-model model=actor model_id=26769 intelligence=191431508 tags="updated tag,gone"```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 191431508,
                    "IType": "apt_md5",
                    "Modified": "2021-09-13T12:40:42.596Z",
                    "Organization": "",
                    "Severity": "medium",
                    "Source": "TestSource",
                    "Status": "active",
                    "Tags": null,
                    "Type": "SHA256",
                    "Value": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
                }
            ],
            "ModelID": "26769",
            "ModelType": "Actor"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Actor with id 26769
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 191431508 | apt_md5 | 2021-09-13T12:40:42.596Z |  | medium | TestSource | active |  | SHA256 | 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1 |


### threatstream-supported-platforms
***
Returns a list of supported platforms for default or premium sandbox.


#### Base Command

`threatstream-supported-platforms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sandbox_type | The type of sandbox ("default" or "premium"). Possible values are: default, premium. Default is default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PremiumPlatforms.Name | String | The name of the supported platform for premium sandbox. | 
| ThreatStream.PremiumPlatforms.Types | String | The type of supported submissions for premium sandbox. | 
| ThreatStream.PremiumPlatforms.Label | String | The display name of the supported platform of premium sandbox. | 
| ThreatStream.DefaultPlatforms.Name | String | The name of the supported platform for standard sandbox. | 
| ThreatStream.DefaultPlatforms.Types | String | The type of the supported submissions for standard sandbox. | 
| ThreatStream.DefaultPlatforms.Label | String | The display name of the supported platform of standard sandbox. | 


#### Command Example
```!threatstream-supported-platforms sandbox_type=default```

#### Context Example
```json
{
    "ThreatStream": {
        "DefaultPlatforms": [
            {
                "Label": "Windows 7",
                "Name": "WINDOWS7",
                "Platform": "windows",
                "Types": [
                    "file",
                    "url"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Supported platforms for default sandbox
>|Label|Name|Platform|Types|
>|---|---|---|---|
>| Windows 7 | WINDOWS7 | windows | file,<br/>url |


### url
***
Checks the reputation of the given URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 
| threshold | If confidence is greater than the threshold the URL is considered malicious, otherwise it is considered good. This argument overrides the default URL threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Data | String | The URL of the indicator. | 
| URL.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| ThreatStream.URL.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.URL.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.URL.Status | String | The indicator status. | 
| ThreatStream.URL.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.URL.Address | String | The indicator URL. | 
| ThreatStream.URL.Country | String | The country associated with the indicator. | 
| ThreatStream.URL.Type | String | The indicator type. | 
| ThreatStream.URL.Source | String | The indicator source. | 
| ThreatStream.URL.Severity | String | The indicator severity \("very-high", "high", "medium", or "low"\). | 
| ThreatStream.URL.Tags | Unknown | Tags assigned to the URL. | 
| URL.Tags | Unknown | List of URL tags. | 
| URL.ThreatTypes | Unknown | Threat types associated with the url. | 


#### Command Example
```!url url=http://www.ujhy1.com/```

#### Human Readable Output

>No intelligence has been found for http:<span>//</span>www.ujhy1.com/

## Additional Considerations for this version
- Remove the **default_threshold** integration parameter.
- Add integration parameter for global threshold in ***ip***, ***domain***, ***file***, ***url***, and ***threatstream-email-reputation*** commands. 
- Add ***Include inactive results*** checkbox in integration settings for the ability to get inactive results.
