Deprecated. Use the ThreatConnect v2 integration instead.

## Configure ThreatConnect v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| baseUrl | Base Url | True |
| accessId | Access ID | True |
| secretKey | Secret Key | True |
| defaultOrg | Default Organization | False |
| Source Reliability | Reliability of the source providing the intelligence data. The default value is: B - Usually reliable. | True |
| rating | Rating threshold for Malicious Indicators | False |
| confidence | Confidence threshold for Malicious Indicators | False |
| freshness | Indicator Reputation Freshness \(in days\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Searches for an indicator of type IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IPv4 or IPv6 address. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!ip ip=88.88.88.88```

#### Context Example
```
{ "TC.Indicator":
	 [ {
		 "Rating": 0,
		 "Confidence": 0,
		 "Name": "88.88.88.88",
		 "LastModified": "2020-04-27T04:57:20Z",
		 "CreateDate": "2020-04-27T04:57:20Z",
		 "Owner": "Demisto Inc.",
		 Type": "Address",
		 "ID": 112677927
	} ],
	"DBotScore": [ {
		"Vendor": "ThreatConnect",
		"Indicator": "88.88.88.88",
		"Score": 1,
		"Type": "ip" } ]
}
```

#### Human Readable Output

>### ThreatConnect IP Reputation for: 88.88.88.88
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 0 | 2020-04-27T04:57:20Z | 112677927 | 2020-04-27T04:57:20Z | 88.88.88.88 | Demisto Inc. | 0 | Address |


### url
***
Searches for an indicator of type URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL for which to search. For example, `www.demisto.com`. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a client’s API user has been granted permission. For example, "owner1", "owner2", or "owner3". | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The date on which the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| URL.Data | string | The data of the URL indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!url url=https://www.domain.com```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "https://www.domain.com",
            "Score": 2,
            "Type": "url",
            "Vendor": "ThreatConnect"
        }
    ],
    "TC": {
        "Indicator": {
            "Confidence": 50,
            "CreateDate": "2020-04-23T14:41:16Z",
            "ID": 112618313,
            "LastModified": "2020-04-27T10:03:38Z",
            "Name": "https://www.domain.com",
            "Owner": "Demisto Inc.",
            "Rating": 3,
            "Type": "URL"
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect URL Reputation for: https://www.domain.com
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 50 | 2020-04-23T14:41:16Z | 112618313 | 2020-04-27T10:03:38Z | https://www.domain.com | Demisto Inc. | 3 | URL |
>### ThreatConnect URL Reputation for: https://www.domain.com
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 50 | 2020-04-23T14:41:16Z | 112618313 | 2020-04-27T10:03:38Z | https://www.domain.com | Demisto Inc. | 3 | URL |



### file
***
Searches for an indicator of type file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash of the file. Can be "MD5", "SHA-1", or "SHA-256". | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| File.MD5 | string | The MD5 hash of the indicator. | 
| File.SHA1 | string | The SHA1 hash of the indicator. | 
| File.SHA256 | string | The SHA256 hash of the indicator. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!file file=4a4a4e885f7189bbaa2fcc2f2403b128f79e951826c57c0e1ab50e085ae390e7```

#### Context Example
```
{
	"TC.Indicator": [ {
		"Rating": 0,
		"Confidence": 0,
		"LastModified": "2020-04-23T14:40:26Z",
		"CreateDate": "2020-04-23T14:40:26Z",
		"File": { 
			"SHA256": "4A4A4E885F7189BBAA2FCC2F2403B128F79E951826C57C0E1AB50E085AE390E7"
		},
		"Owner": "Demisto Inc.",
		"Type": "File",
		"ID": 112618312
	} ],
	"DBotScore": [{
		"Vendor": "ThreatConnect",
		"Score": 1,
		"Type": "file"
	}]
}  
```

#### Human Readable Output

>### ThreatConnect File Report for: 4a4a4e885f7189bbaa2fcc2f2403b128f79e951826c57c0e1ab50e085ae390e7  
>|Confidence|Create Date|File|ID|Last Modified|Owner|Rating|Type|  
>|---|---|---|---|---|---|---|---|  
>| 0 | 2020-04-23T14:40:26Z | SHA256: 4A4A4E885F7189BBAA2FCC2F2403B128F79E951826C57C0E1AB50E085AE390E7 | 112618312 | 2020-04-23T14:40:26Z | Demisto Inc. | 0 | File |  


### tc-owners
***
Retrieves all owners for the current account.


#### Base Command

`tc-owners`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Owner.Name | string | The name of the owner. | 
| TC.Owner.ID | string | The ID of the owner. | 
| TC.Owner.Type | string | The type of the owner. | 


#### Command Example
```!tc-owners```

#### Context Example
```
{
    "TC": {
        "Owner": [
            {
                "ID": 737,
                "Name": "Demisto Inc.",
                "Type": "Organization"
            },
            {
                "ID": 646,
                "Name": "Blocklist.de Strong IPs",
                "Type": "Source"
            },
            {
                "ID": 716,
                "Name": "BotScout Bot List",
                "Type": "Source"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Owners:
>|ID|Name|Type|
>|---|---|---|
>| 737 | Demisto Inc. | Organization |
>| 646 | Blocklist.de Strong IPs | Source |
>| 716 | BotScout Bot List | Source |


### tc-indicators
***
Retrieves a list of all indicators.


#### Base Command

`tc-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | A list of results filtered by the owner of the indicator. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-indicators limit=3 owner="Demisto Inc."```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "88.88.88.88",
            "Score": 1,
            "Type": "ip",
            "Vendor": "ThreatConnect"
        },
        {
            "Indicator": "domain.info",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ThreatConnect"
        },
        {
            "Indicator": "https://www.domain.com",
            "Score": 2,
            "Type": "url",
            "Vendor": "ThreatConnect"
        }
    ],
    "TC": {
        "Indicator": [
            {
                "Confidence": 0,
                "CreateDate": "2020-05-10T09:45:19Z",
                "ID": 112951652,
                "LastModified": "2020-05-10T09:45:19Z",
                "Name": "88.88.88.88",
                "Owner": "Demisto Inc.",
                "Rating": 0,
                "Type": "Address"
            },
            {
                "Confidence": 0,
                "CreateDate": "2020-04-23T14:42:21Z",
                "ID": 112618314,
                "LastModified": "2020-04-23T14:42:21Z",
                "Name": "domain.info",
                "Owner": "Demisto Inc.",
                "Rating": 0,
                "Type": "Host"
            },
            {
                "Confidence": 50,
                "CreateDate": "2020-04-23T14:41:16Z",
                "ID": 112618313,
                "LastModified": "2020-04-27T10:03:38Z",
                "Name": "https://www.domain.com",
                "Owner": "Demisto Inc.",
                "Rating": 3,
                "Type": "URL"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Indicators:
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 0 | 2020-05-10T09:45:19Z | 112951652 | 2020-05-10T09:45:19Z | 88.88.88.88 | Demisto Inc. | 0 | Address |
>| 0 | 2020-04-23T14:42:21Z | 112618314 | 2020-04-23T14:42:21Z | domain.info | Demisto Inc. | 0 | Host |
>| 50 | 2020-04-23T14:41:16Z | 112618313 | 2020-04-27T10:03:38Z | https://www.domain.com | Demisto Inc. | 3 | URL |


### tc-get-tags
***
Returns a list of all ThreatConnect tags.


#### Base Command

`tc-get-tags`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Tags | Unknown | A list of tags. | 


#### Command Example
```!tc-get-tags```

#### Context Example
```
{
    "TC": {
        "Tags": [
            "malicious file",
            "malicious ip",
            "malicious url",
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Tags:
>|Name|
>|---|
>| malicious file |
>| malicious ip |
>| malicious url |


### tc-tag-indicator
***
Adds a tag to an existing indicator.


#### Base Command

`tc-tag-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The name of the tag. | Required | 
| indicator | The indicator to tag. For example, for an IP indicator, "8.8.8.8". | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-tag-indicator indicator=99.99.99.99 tag="malicious ip"```

#### Context Example
```
{}
```

#### Human Readable Output

>Indicator 99.99.99.99 with ID 112951655, was tagged with: malicious ip

### tc-get-indicator
***
Retrieves information about an indicator.


#### Base Command

`tc-get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The name of the indicator by which to search. The command retrieves information from all owners. Can be an IP address, a URL, or a file hash. | Required | 
| indicator_type | Only for custom. Leave empty for standard ones | Optional | 
| owners | Indicator Owner(s) | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 
| group_associations | Retrieve Indicator Group Associations | Required | 
| indicator_associations | Retrieve Indicator Associations | Optional | 
| indicator_observations | Retrieve Indicator Observations | Optional | 
| indicator_tags | Retrieve Indicator Tags | Optional | 
| indicator_attributes | Retrieve Indicator Attributes | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| TC.Indicator.IndicatorAttributes.dateAdded | date | The date on which the indicator attribute was originally added. | 
| TC.Indicator.IndicatorAttributes.displayed | boolean | A boolean flag to show on ThreatConnect.   | 
| TC.Indicator.IndicatorAttributes.id | number | The ID of the attribute. | 
| TC.Indicator.IndicatorAttributes.lastModified | date | The date on which the indicator attribute was last modified. | 
| TC.Indicator.IndicatorAttributes.type | string | The name of the attribute. | 
| TC.Indicator.IndicatorAttributes.value | string | The contents of the attribute. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the indicator of the URL. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-get-indicator indicator=99.99.99.99 group_associations=false```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "99.99.99.99",
            "Score": 2,
            "Type": "ip",
            "Vendor": "ThreatConnect"
        }
    ],
    "TC": {
        "Indicator": {
            "Confidence": 70,
            "CreateDate": "2020-05-10T09:57:18Z",
            "ID": 112951655,
            "LastModified": "2020-05-10T09:57:27Z",
            "Name": "99.99.99.99",
            "Owner": "Demisto Inc.",
            "Rating": 1,
            "Type": "Address"
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect indicator for: 99.99.99.99
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 70 | 2020-05-10T09:57:18Z | 112951655 | 2020-05-10T09:57:27Z | 99.99.99.99 | Demisto Inc. | 1 | Address |


### tc-get-indicators-by-tag
***
Fetches all indicators that have a tag.


#### Base Command

`tc-get-indicators-by-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The name of the tag by which to filter. | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 
| limit | The limit of the indicators that will be available in the raw response. Default value is 100. NOTICE: In the context you will be able to see up to 100 indicators. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the tagged indicator. | 
| TC.Indicator.Type | string | The type of the tagged indicator. | 
| TC.Indicator.ID | string | The ID of the tagged indicator. | 
| TC.Indicator.Description | string | The description of the tagged indicator. | 
| TC.Indicator.Owner | string | The owner of the tagged indicator. | 
| TC.Indicator.CreateDate | date | The date on which the tagged indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the tagged indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the tagged indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the tagged indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | string | The value assigned by DBot for the tagged indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the tagged indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the tagged indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | string | The IP address of the tagged indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the tagged indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the tagged indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-get-indicators-by-tag tag="malicious ip"```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "99.99.99.99",
            "Score": 2,
            "Type": "ip",
            "Vendor": "ThreatConnect"
        },
        {
            "Indicator": "82.28.82.28",
            "Score": 1,
            "Type": "ip",
            "Vendor": "ThreatConnect"
        },
        {
            "Indicator": "111.222.111.222",
            "Score": 2,
            "Type": "ip",
            "Vendor": "ThreatConnect"
        }
    ],
    "TC": {
        "Indicator": [
            {
                "Confidence": 70,
                "CreateDate": "2020-05-10T09:57:18Z",
                "ID": 112951655,
                "LastModified": "2020-05-10T09:57:18Z",
                "Name": "99.99.99.99",
                "Owner": "Demisto Inc.",
                "Rating": 2,
                "Type": "Address"
            },
            {
                "Confidence": 0,
                "CreateDate": "2018-10-18T11:12:20Z",
                "ID": 59227820,
                "LastModified": "2018-10-18T11:12:36Z",
                "Name": "82.28.82.28",
                "Owner": "Demisto Inc.",
                "Rating": 0,
                "Type": "Address"
            },
            {
                "Confidence": 20,
                "CreateDate": "2018-10-22T19:03:29Z",
                "Description": "Added critical rating",
                "ID": 59253542,
                "LastModified": "2018-12-19T15:55:57Z",
                "Name": "111.222.111.222",
                "Owner": "Demisto Inc.",
                "Rating": 1,
                "Type": "Address"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Indicators with tag: malicious ip
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 70 | 2020-05-10T09:57:18Z | 112951655 | 2020-05-10T09:57:18Z | 99.99.99.99 | Demisto Inc. | 2 | Address |
>| 0 | 2018-10-18T11:12:20Z | 59227820 | 2018-10-18T11:12:36Z | 82.28.82.28 | Demisto Inc. | 0 | Address |
>| 20 | 2018-10-22T19:03:29Z | 59253542 | 2018-12-19T15:55:57Z | 111.222.111.222 | Demisto Inc. | 1 | Address |


### tc-add-indicator
***
Adds a new indicator to ThreatConnect.


#### Base Command

`tc-add-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to add. | Required | 
| rating | The threat rating of the indicator. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidence | The confidence rating of the indicator. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 
| owner | The owner of the new indicator. The default is the "defaultOrg" parameter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name the indicator. | 
| TC.Indicator.Type | string | The type of indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the added indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the added indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the added indicator of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-add-indicator indicator=99.99.99.99 confidence=70 rating=2```

#### Context Example
```
{
    "TC": {
        "Indicator": {
            "Confidence": 70,
            "CreateDate": "2020-05-10T09:57:18Z",
            "ID": 112951655,
            "LastModified": "2020-05-10T09:57:18Z",
            "Name": "99.99.99.99",
            "Owner": "Demisto Inc.",
            "Rating": 2,
            "Type": "Address"
        }
    }
}
```

#### Human Readable Output

>### Created new indicator successfully:
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 70 | 2020-05-10T09:57:18Z | 112951655 | 2020-05-10T09:57:18Z | 99.99.99.99 | Demisto Inc. | 2 | Address |


### tc-create-incident
***
Creates a new incident group.


#### Base Command

`tc-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | The owner of the new incident. The default is the "defaultOrg" parameter. | Optional | 
| incidentName | The name of the incident group. | Required | 
| eventDate | The creation time of an incident in the "2017-03-21T00:00:00Z" format. | Optional | 
| tag | The tag applied to the incident. | Optional | 
| securityLabel | The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". | Optional | 
| description | The description of the incident. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Incident.Name | string | The name of the new incident group. | 
| TC.Incident.Owner | string | The owner of the new incident. | 
| TC.Incident.EventDate | date | The date on which the event that indicates an incident occurred. | 
| TC.Incident.Tag | string | The name of the tag of the new incident. | 
| TC.Incident.SecurityLabel | string | The security label of the new incident. | 
| TC.Incident.ID | Unknown | The ID of the new incident. | 


#### Command Example
```!tc-create-incident incidentName=test_incident```

#### Context Example
```
{
    "TC": {
        "Incident": {
            "EventDate": "2020-05-10T09:56:52Z",
            "ID": 5156603,
            "Name": "test_incident",
            "Owner": "Demisto Inc."
        }
    }
}
```

#### Human Readable Output

>Incident test_incident Created Successfully

### tc-fetch-incidents
***
Fetches incidents from ThreatConnect.


#### Base Command

`tc-fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The fetched incidents filtered by ID. | Optional | 
| owner | The fetched incidents filtered by owner. | Optional | 
| incidentName | The fetched incidents filtered by incident name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Incident | string | The name of the group of fetched incidents. | 
| TC.Incident.ID | string | The ID of the fetched incidents. | 
| TC.Incident.Owner | string | The owner of the fetched incidents. | 


#### Command Example
```!tc-fetch-incidents incidentId=5101576```

#### Context Example
```
{
    "TC": {
        "Incident": {
            "dateAdded": "2020-04-21T06:54:46Z",
            "eventDate": "2020-04-21T00:00:00Z",
            "id": 5101576,
            "name": "try",
            "ownerName": "Demisto Inc.",
            "weblink": "https://sandbox.threatconnect.com/auth/incident/incident.xhtml?incident=5101576"
        }
    },
    "ThreatConnect": {
        "incidents": [
            {
                "dateAdded": "2020-04-21T06:54:46Z",
                "eventDate": "2020-04-21T00:00:00Z",
                "id": 5101576,
                "name": "try",
                "ownerName": "Demisto Inc.",
                "type": null,
                "weblink": "https://sandbox.threatconnect.com/auth/incident/incident.xhtml?incident=5101576"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents:
>|Date Added|Event Date|Id|Name|Owner Name|Type|Weblink|
>|---|---|---|---|---|---|---|
>| 2020-04-21T06:54:46Z | 2020-04-21T00:00:00Z | 5101576 | try | Demisto Inc. |  | https://sandbox.threatconnect.com/auth/incident/incident.xhtml?incident=5101576 |


### tc-incident-associate-indicator
***
Associates an indicator with an existing incident. The indicator must exist before running this command. To add an indicator, run the tc-add-indicator command.


#### Base Command

`tc-incident-associate-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicatorType | The type of the indicator. Can be "ADDRESSES", "EMAIL_ADDRESSES", "URLS", "HOSTS", "FILES", or "CUSTOM_INDICATORS". | Required | 
| incidentId | The ID of the incident to which the indicator is associated. | Required | 
| indicator | The name of the indicator. | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator associated was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator associated was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | IP address of the associated indicator of the file. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the associated indicator of the file. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the indicator of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-incident-associate-indicator indicator=99.99.99.99 indicatorType=ADDRESSES incidentId=5101577```

#### Context Example
```
{
    "TC": {
        "Incident": {
            "dateAdded": "2020-04-21T07:03:56Z",
            "eventDate": "2020-04-21T00:00:00Z",
            "id": 5101577,
            "name": "for_try",
            "ownerName": "Demisto Inc.",
            "weblink": "https://sandbox.threatconnect.com/auth/incident/incident.xhtml?incident=5101577"
        }
    }
}
```

#### Human Readable Output

>Incident for_try with ID 5101577, was tagged with: 99.99.99.99

### domain
***
Searches for an indicator of type domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The name of the domain. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the of the indicator. | 
| TC.Indicator.Type | string | The type of the domain. | 
| TC.Indicator.ID | string | The ID of the domain. | 
| TC.Indicator.Description | string | The description of the domain. | 
| TC.Indicator.Owner | string | The owner of the domain. | 
| TC.Indicator.CreateDate | date | The date on which the indicator of the domain was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator of the domain was modified. | 
| TC.Indicator.Rating | number | The threat rating of the domain. | 
| TC.Indicator.Confidence | number | The confidence rating of the domain. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!domain domain=domain.info```

#### Context Example
```
{  
 "TC.Indicator": [ {
	 "Rating": 0,
	 "Confidence": 0,
	 "Name": "domain.info"
	 "LastModified": "2020-04-23T14:42:21Z",
	 "CreateDate": "2020-04-23T14:42:21Z",
	 "Owner": "Demisto Inc.",
	 "Active": "false",
	 "Type": "Host",
	 "ID": 112618314
	 } ],
	"DBotScore": [{
		"Vendor": "ThreatConnect",
		"Indicator": "domain.info",
		"Score": 1,
		"Type": "domain"
	}]
}
```

#### Human Readable Output

>### ThreatConnect Domain Reputation for: domain.info  
>|Active|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|  
>|---|---|---|---|---|---|---|---|---|  
>| false | 0 | 2020-04-23T14:42:21Z | 112618314 | 2020-04-23T14:42:21Z | domain.info | Demisto Inc. | 0 | Host |  


### tc-get-incident-associate-indicators
***
Returns indicators that are related to a specific incident.


#### Base Command

`tc-get-incident-associate-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The ID of the incident. | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the returned indicator. | 
| TC.Indicator.Type | string | The type of the returned indicator. | 
| TC.Indicator.ID | string | The ID of the returned indicator. | 
| TC.Indicator.Description | string | The description of the returned indicator. | 
| TC.Indicator.Owner | string | The owner of the returned indicator. | 
| TC.Indicator.CreateDate | date | The date on which the returned indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the returned indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the returned indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the returned indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | string | The value assigned by DBot for the indicator. | 
| DBotScore.Type | string | The type assigned by DBot for the indicator. | 
| DBotScore.Score | number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | string | The IP address of the returned indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the returned indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 


#### Command Example
```!tc-get-incident-associate-indicators incidentId=5101576 owner="Demisto Inc."```

#### Context Example
```
{"TC.Indicator": [{
	"Rating": 0,
	"Confidence": 0,
	"Name": "88.88.88.88",
	"LastModified": "2020-04-27T04:57:20Z",
	"CreateDate": "2020-04-27T04:57:20Z",
	"Owner": "Demisto Inc.",
	"Type": "Address",
	"ID": 112677927 } ],
"DBotScore": [ {
	"Vendor": "ThreatConnect",
	"Indicator": "88.88.88.88",
	"Score": 1,
	"Type": "ip" } ]
}
```

#### Human Readable Output

>### Incident Associated Indicators:
>|Confidence|Create Date|ID|Last Modified|Name|Owner|Rating|Type|
>|---|---|---|---|---|---|---|---|
>| 0 | 2020-04-27T04:57:20Z | 112677927 | 2020-04-27T04:57:20Z | 88.88.88.88 | Demisto Inc. | 0 | Address |


### tc-update-indicator
***
Updates the indicator in ThreatConnect.


#### Base Command

`tc-update-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The name of the updated indicator. | Required | 
| rating | The threat rating of the updated indicator. | Optional | 
| confidence | The confidence rating of the updated indicator. | Optional | 
| size | The size of the file of the updated indicator. | Optional | 
| dnsActive | The active DNS indicator (only for hosts). | Optional | 
| whoisActive | The active indicator (only for hosts). | Optional | 
| updatedValues | A comma-separated list of field:value pairs to update. For example, "rating=3", "confidence=42", and "description=helloWorld". | Optional | 
| falsePositive | The updated indicator set as a false positive. Can be "True" or "False". | Optional | 
| observations | The number observations on the updated indicator. | Optional | 
| securityLabel | The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". | Optional | 
| threatAssessConfidence | Assesses the confidence rating of the indicator. | Optional | 
| threatAssessRating | Assesses the threat rating of the indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-update-indicator indicator=99.99.99.99 rating=1```

#### Context Example
```
{
    "TC": {
        "Indicator": {
            "Confidence": 70,
            "CreateDate": "2020-05-10T09:57:18Z",
            "ID": 112951655,
            "LastModified": "2020-05-10T09:57:25Z",
            "Name": "99.99.99.99",
            "Owner": "Demisto Inc.",
            "Rating": 1,
            "Type": "Address"
        }
    }
}
```

#### Human Readable Output

>Indicator 112951655 Updated Successfully

### tc-delete-indicator-tag
***
Removes a tag from a specified indicator.


#### Base Command

`tc-delete-indicator-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The name of the indicator from which to remove a tag. | Required | 
| tag | The name of the tag to remove from the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. |


#### Command Example
```!tc-delete-indicator-tag indicator=99.99.99.99 tag="malicious ip"```

#### Context Example
```
{
    "TC": {
        "Indicator": {
            "Confidence": 70,
            "CreateDate": "2020-05-10T09:57:18Z",
            "ID": 112951655,
            "LastModified": "2020-05-10T09:57:18Z",
            "Name": "99.99.99.99",
            "Owner": "Demisto Inc.",
            "Rating": 2,
            "Type": "Address"
        }
    }
}
```

#### Human Readable Output

>Removed tag malicious ip from indicator 99.99.99.99.

### tc-delete-indicator
***
Deletes an indicator from ThreatConnect.


#### Base Command

`tc-delete-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The name of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-delete-indicator indicator=99.99.99.99```

#### Context Example
```
{}
```

#### Human Readable Output

>Indicator 99.99.99.99 removed Successfully

### tc-create-campaign
***
Creates a group based on the "Campaign" type.


#### Base Command

`tc-create-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the campaign group. | Required | 
| firstSeen | The earliest date on which the campaign was seen. | Optional | 
| owner | The owner of the new incident. The default is the "defaultOrg" parameter. | Optional | 
| description | The description of the campaign. | Optional | 
| tag | The name of the tag to apply to the campaign. | Optional | 
| securityLabel | The security label of the campaign. For example, "TLP:Green". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Campaign.Name | string | The name of the campaign. | 
| TC.Campaign.Owner | string | The owner of the campaign. | 
| TC.Campaign.FirstSeen | date | The earliest date on which the campaign was seen. | 
| TC.Campaign.Tag | string | The tag of the campaign. | 
| TC.Campaign.SecurityLevel | string | The security label of the campaign. | 
| TC.Campaign.ID | string | The ID of the campaign. | 


#### Command Example
```!tc-create-campaign name=test_campaign description="test campaign"```

#### Context Example
```
{
    "TC": {
        "Campaign": {
            "FirstSeen": "2020-05-10T00:00:00Z",
            "ID": 5156601,
            "Name": "test_campaign",
            "Owner": "Demisto Inc."
        }
    }
}
```

#### Human Readable Output

>Campaign test_campaign Created Successfully

### tc-create-event
***
Creates a group based on the "Event" type.


#### Base Command

`tc-create-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the event group. | Required | 
| eventDate | The date on which the event occurred. If the date is not specified, the current date is used. | Optional | 
| status | The status of the event. Can be "Needs Review", "False Positive", "No Further Action", or "Escalated". | Optional | 
| owner | The owner of the event. | Optional | 
| description | The description of the event. | Optional | 
| tag | The tag of the event. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Event.Name | string | The name of the event. | 
| TC.Event.Date | date | The date of the event. | 
| TC.Event.Status | string | The status of the event. | 
| TC.Event.Owner | string | The owner of the event. | 
| TC.Event.Tag | string | The tag of the event. | 
| TC.Event.ID | string | The ID of the event. | 


#### Command Example
```!tc-create-event name=test_event```

#### Context Example
```
{
    "TC": {
        "Event": {
            "Date": "2020-05-10T09:56:50Z",
            "ID": 5156602,
            "Name": "test_event",
            "Owner": "Demisto Inc."
        }
    }
}
```

#### Human Readable Output

>Incident test_event Created Successfully

### tc-create-threat
***
Creates a group based on the "Threats" type.


#### Base Command

`tc-create-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the threat group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Threat.Name | string | The name of the threat. | 
| TC.Threat.ID | string | The ID of the threat. | 


#### Command Example
```!tc-create-threat name=test_threat```

#### Context Example
```
{
    "TC": {
        "Threat": {
            "ID": 5156604,
            "Name": "test_threat"
        }
    }
}
```

#### Human Readable Output

>Threat test_threat Created Successfully

### tc-delete-group
***
Deletes a group.


#### Base Command

`tc-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupID | The ID of the group to delete. | Required | 
| type | The type of the group to delete. Can be "Incidents", "Events", "Campaigns", or "Threats". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-delete-group groupID=5101578 type=Campaigns```

#### Human Readable Output
>campaigns 5101578 deleted Successfully


### tc-add-group-attribute
***
Adds an attribute to a specified group.


#### Base Command

`tc-add-group-attribute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to which to add attributes. To get the ID of the group, run the tc-get-groups command. | Required | 
| attribute_type | The type of attribute to add to the group. The type is located in the UI in a specific group or under Org Config. | Required | 
| attribute_value | The value of the attribute. | Required | 
| group_type | The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.DateAdded | Date | The date on which the attribute was added. | 
| TC.Group.LastModified | Date | The date on which the added attribute was last modified. | 
| TC.Group.Type | String | The type of the group to which the attribute was added. | 
| TC.Group.Value | String | The value of the attribute added to the group. | 
| TC.Group.ID | Number | The group ID to which the attribute was added. | 


#### Command Example
```!tc-add-group-attribute group_id=5101576 group_type=incidents attribute_type=description attribute_value="test add group attribute"```

#### Context Example
```
{
    "TC": {
        "Group": {
            "DateAdded": "2020-05-10T09:57:00Z",
            "ID": 23379726,
            "LastModified": "2020-05-10T09:57:00Z",
            "Type": "Description",
            "Value": "test add group attribute"
        }
    }
}
```

#### Human Readable Output

>### The attribute was added successfully to group 5101576
>|Type|Value|ID|DateAdded|LastModified|
>|---|---|---|---|---|
>| Description | test add group attribute | 23379726 | 2020-05-10T09:57:00Z | 2020-05-10T09:57:00Z |


### tc-get-events
***
Returns a list of events.


#### Base Command

`tc-get-events`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Event.DateAdded | Date | The date on which the event was added. | 
| TC.Event.EventDate | Date | The date on which the event occurred. | 
| TC.Event.ID | Number | The ID of the event. | 
| TC.Event.OwnerName | String | The name of the owner of the event. | 
| TC.Event.Status | String | The status of the event. | 


#### Command Example
```!tc-get-events```

#### Context Example
```
{
    "TC": {
        "Event": [
            {
                "DateAdded": "2020-05-10T09:56:51Z",
                "EventDate": "2020-05-10T09:56:50Z",
                "ID": 5156602,
                "Name": "test_event",
                "OwnerName": "Demisto Inc.",
                "Status": "Needs Review"
            },
            {
                "DateAdded": "2020-05-10T05:07:52Z",
                "EventDate": "2020-05-10T05:07:51Z",
                "ID": 5156545,
                "Name": "MyTest",
                "OwnerName": "Demisto Inc.",
                "Status": "Needs Review"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Events
>|ID|Name|OwnerName|EventDate|DateAdded|Status|
>|---|---|---|---|---|---|
>| 5156602 | test_event | Demisto Inc. | 2020-05-10T09:56:50Z | 2020-05-10T09:56:51Z | Needs Review |
>| 5156545 | MyTest | Demisto Inc. | 2020-05-10T05:07:51Z | 2020-05-10T05:07:52Z | Needs Review |


### tc-get-groups
***
Returns all groups, filtered by the group type.


#### Base Command

`tc-get-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.DateAdded | Date | The date on which the group was added. | 
| TC.Group.EventDate | Date | The date on which the event occurred. | 
| TC.Group.Name | String | The name of the group. | 
| TC.Group.OwnerName | String | The name of the owner of the group. | 
| TC.Group.Status | String | The status of the group. | 
| TC.Group.ID | Number | The ID of the group. | 


#### Command Example
```!tc-get-groups group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": [
            {
                "DateAdded": "2020-05-10T09:56:52Z",
                "EventDate": "2020-05-10T00:00:00Z",
                "ID": 5156603,
                "Name": "test_incident",
                "OwnerName": "Demisto Inc.",
                "Status": null
            },
            {
                "DateAdded": "2020-05-10T09:54:44Z",
                "EventDate": "2020-05-10T00:00:00Z",
                "ID": 5156599,
                "Name": "test_incident",
                "OwnerName": "Demisto Inc.",
                "Status": null
            },
            {
                "DateAdded": "2020-05-10T09:47:58Z",
                "EventDate": "2020-05-10T00:00:00Z",
                "ID": 5156595,
                "Name": "test_incident",
                "OwnerName": "Demisto Inc.",
                "Status": null
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect incidents
>|ID|Name|OwnerName|EventDate|DateAdded|
>|---|---|---|---|---|
>| 5156603 | test_incident | Demisto Inc. | 2020-05-10T00:00:00Z | 2020-05-10T09:56:52Z |
>| 5156599 | test_incident | Demisto Inc. | 2020-05-10T00:00:00Z | 2020-05-10T09:54:44Z |
>| 5156595 | test_incident | Demisto Inc. | 2020-05-10T00:00:00Z | 2020-05-10T09:47:58Z |


### tc-add-group-security-label
***
Adds a security label to a group.


#### Base Command

`tc-add-group-security-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to which to add the security label. To get the ID, run the tc-get-groups command. | Required | 
| group_type | The type of the group to which to add the security label. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| security_label_name | The name of the security label to add to the group. For example, "TLP:GREEN". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-add-group-security-label group_id=5101576 group_type=incidents security_label_name=TLP:GREEN```

#### Context Example
```
{}
```

#### Human Readable Output

>The security label TLP:GREEN was added successfully to incidents 5101576

### tc-add-group-tag
***
Adds tags to a specified group.


#### Base Command

`tc-add-group-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to which to add the tag. To get the ID, run the tc-get-groups command. | Required | 
| group_type | The type of the group to which to add the tag. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| tag_name | The name of the tag to add to the group. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-add-group-tag group_id=5101576 group_type=incidents tag_name="malicious ip"```

#### Context Example
```
{}
```

#### Human Readable Output

>The tag malicious ip was added successfully to group incidents 5101576

### tc-get-indicator-types
***
Returns all indicator types available.


#### Base Command

`tc-get-indicator-types`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.IndicatorType.ApiBranch | String | The branch of the API. | 
| TC.IndicatorType.ApiEntity | String | The entity of the API. | 
| TC.IndicatorType.CasePreference | String | The case preference of the indicator. For example, "sensitive", "upper", or "lower". | 
| TC.IndicatorType.Custom | Boolean | Whether the indicator is a custom indicator. | 
| TC.IndicatorType.Parsable | Boolean | Whether the indicator can be parsed. | 
| TC.IndicatorType.Value1Type | String | The name of the indicator. | 
| TC.IndicatorType.Value1Label | String | The value label of the indicator. | 


#### Command Example
```!tc-get-indicator-types```

#### Context Example
```
{
    "TC": {
        "IndicatorType": [
            {
                "ApiBranch": "addresses",
                "ApiEntity": "address",
                "CasePreference": null,
                "Custom": "false",
                "Name": "Address",
                "Parsable": "true",
                "Value1Label": null,
                "Value1Type": null
            },
            {
                "ApiBranch": "files",
                "ApiEntity": "file",
                "CasePreference": null,
                "Custom": "false",
                "Name": "File",
                "Parsable": "true",
                "Value1Label": "MD5",
                "Value1Type": "text"
            },
            {
                "ApiBranch": "hosts",
                "ApiEntity": "host",
                "CasePreference": null,
                "Custom": "false",
                "Name": "Host",
                "Parsable": "true",
                "Value1Label": null,
                "Value1Type": null
            },
            {
                "ApiBranch": "urls",
                "ApiEntity": "url",
                "CasePreference": null,
                "Custom": "false",
                "Name": "URL",
                "Parsable": "true",
                "Value1Label": null,
                "Value1Type": null
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect indicator types
>|Name|Custom|Parsable|ApiBranch|CasePreference|Value1Type|
>|---|---|---|---|---|---|
>| Address | false | true | addresses |  |  |
>| File | false | true | files |  | text |
>| Host | false | true | hosts |  |  |
>| URL | false | true | urls |  |  |


### tc-group-associate-indicator
***
Associates an indicator with a group.


#### Base Command

`tc-group-associate-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The type of the indicator. To get the available types, run the tc-get-indicator-types command. The indicator must be spelled as displayed in the ApiBranch column of the UI. | Required | 
| indicator | The name of the indicator. For example, "indicator_type=emailAddresses" where "indicator=a@a.co.il". | Required | 
| group_type | The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group. To get the ID of the group, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.GroupID | Number | The ID of the group. | 
| TC.Group.GroupType | String | The type of the group. | 
| TC.Group.Indicator | String | The name of the indicator. | 
| TC.Group.IndicatorType | String | The type of the indicator. | 


#### Command Example
```tc-group-associate-indicator indicator_type=addresses group_id=5101576 group_type=incidents indicator=99.99.99.99```

#### Human Readable Output



### tc-create-document-group
***
Creates a document group.


#### Base Command

`tc-create-document-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | The name of the file to display in the UI. | Required | 
| name | The name of the file. | Required | 
| malware | Whether the file is malware. If "true", ThreatConnect creates a password-protected ZIP file on your local machine that contains the sample and uploads the ZIP file. | Optional | 
| password | The password of the ZIP file. | Optional | 
| security_label | The security label of the group. | Optional | 
| description | A description of the group. | Optional | 
| entry_id | The file of the ID of the entry, as displayed in the War Room. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Name | String | The name of the group. | 
| TC.Group.Owner | String | The owner of the group. | 
| TC.Group.EventDate | Date | The date on which the group was created. | 
| TC.Group.Description | String | The description of the group. | 
| TC.Group.SecurityLabel | String | The security label of the group. | 
| TC.Group.ID | Number | The ID of the group to which the attribute was added. | 


#### Command Example
```!tc-create-document-group entry_id=11@11 file_name=test.txt name=test_document```

#### Human Readable Output



### tc-get-group
***
Retrieves a single group.


#### Base Command

`tc-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of group for which to return the ID. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group to retrieve. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.DateAdded | Date | The date on which the group was added. | 
| TC.Group.EventDate | Date | The date on which the event occurred. | 
| TC.Group.Name | String | The name of the group. | 
| TC.Group.Owner.ID | Number | The ID of the group owner. | 
| TC.Group.Owner.Name | String | The name of the group owner. | 
| TC.Group.Owner.Type | String | The type of the owner. | 
| TC.Group.Status | String | The status of the group. | 


#### Command Example
```!tc-get-group group_id=5101576 group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": {
            "DateAdded": "2020-04-21T06:54:46Z",
            "EventDate": "2020-04-21T00:00:00Z",
            "ID": 5101576,
            "Name": "try",
            "Owner": {
                "ID": 737,
                "Name": "Demisto Inc.",
                "Type": "Organization"
            },
            "Status": null
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect Group information
>|DateAdded|EventDate|ID|Name|Owner|
>|---|---|---|---|---|
>| 2020-04-21T06:54:46Z | 2020-04-21T00:00:00Z | 5101576 | try | Name: Demisto Inc.<br/>ID: 737<br/>Type: Organization |


### tc-get-group-attributes
***
Retrieves the attribute of a group.


#### Base Command

`tc-get-group-attributes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of group for which to return the attribute. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group for which to return the attribute. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Attribute.DateAdded | Date | The date on which the group was added. | 
| TC.Group.Attribute.Displayed | Boolean | Whether the attribute is displayed on the UI. | 
| TC.Group.Attribute.AttributeID | Number | The ID of the attribute. | 
| TC.Group.Attribute.LastModified | Date | The date on which the attribute was last modified. | 
| TC.Group.Attribute.Type | String | The type of the attribute. | 
| TC.Group.Attribute.Value | String | The value of the attribute. | 


#### Command Example
```!tc-get-group-attributes group_id=5101576 group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": {
            "Attribute": [
                {
                    "AttributeID": 23379726,
                    "DateAdded": "2020-05-10T09:57:00Z",
                    "Displayed": true,
                    "GroupID": 5101576,
                    "LastModified": "2020-05-10T09:57:00Z",
                    "Type": "Description",
                    "Value": "test add group attribute"
                },
                {
                    "AttributeID": 23379725,
                    "DateAdded": "2020-05-10T09:54:51Z",
                    "Displayed": false,
                    "GroupID": 5101576,
                    "LastModified": "2020-05-10T09:54:51Z",
                    "Type": "Description",
                    "Value": "test add group attribute"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect Group Attributes
>|AttributeID|Type|Value|DateAdded|LastModified|Displayed|
>|---|---|---|---|---|---|
>| 23379726 | Description | test add group attribute | 2020-05-10T09:57:00Z | 2020-05-10T09:57:00Z | true |
>| 23379725 | Description | test add group attribute | 2020-05-10T09:54:51Z | 2020-05-10T09:54:51Z | false |


### tc-get-group-security-labels
***
Retrieves the security labels of a group.


#### Base Command

`tc-get-group-security-labels`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of group for which to return the security labels. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group for which to return the security labels. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.SecurityLabel.Name | String | The name of the security label. | 
| TC.Group.SecurityLabel.Description | String | The description of the security label. | 
| TC.Group.SecurityLabel.DateAdded | Date | The date on which the security label was added. | 


#### Command Example
```!tc-get-group-security-labels group_id=5101576 group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": {
            "SecurityLabel": {
                "DateAdded": "2016-08-31T00:00:00Z",
                "Description": "This security label is used for information that is useful for the awareness of all participating organizations as well as with peers within the broader community or sector.",
                "GroupID": 5101576,
                "Name": "TLP:GREEN"
            }
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect Group Security Labels
>|Name|Description|DateAdded|
>|---|---|---|
>| TLP:GREEN | This security label is used for information that is useful for the awareness of all participating organizations as well as with peers within the broader community or sector. | 2016-08-31T00:00:00Z |


### tc-get-group-tags
***
Retrieves the tags of a group.


#### Base Command

`tc-get-group-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of group for which to return the tags. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group for which to return the tags. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Tag.Name | String | The name of the tag. | 


#### Command Example
```!tc-get-group-tags group_id=5101576 group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": {
            "Tag": {
                "GroupID": 5101576,
                "Name": "malicious ip"
            }
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect Group Tags
>|Name|
>|---|
>| malicious ip |


### tc-download-document
***
Downloads the contents of a document.


#### Base Command

`tc-download-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The ID of the document. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The ssdeep hash of the file \(same as displayed in file entries\). | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | The information of the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 


#### Command Example
```!tc-download-document document_id=12345```

#### Human Readable Output



### tc-get-group-indicators
***
Returns indicators associated with a group.


#### Base Command

`tc-get-group-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of the group for which to return the indicators. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group for which to return the indicators. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Indicator.Summary | String | The summary of the indicator. | 
| TC.Group.Indicator.ThreatAssessConfidence | String | The confidence rating of the indicator. | 
| TC.Group.Indicator.IndicatorID | Number | The ID of the indicator. | 
| TC.Group.Indicator.DateAdded | Date | The date on which the indicator was added. | 
| TC.Group.Indicator.Type | String | The type of the indicator. | 
| TC.Group.Indicator.Rating | Number | The threat rating of the indicator. | 
| TC.Group.Indicator.ThreatAssertRating | Number | The rating of the threat assert. | 
| TC.Group.Indicator.OwnerName | String | The name of the owner of the indicator. | 
| TC.Group.Indicator.LastModified | Date | The date that the indicator was last modified. | 


#### Command Example
```!tc-get-group-indicators group_type="incidents" group_id="5110299"```

#### Context Example
```
{
	"TC.Group.Indicator": [ {
		"Rating": 0,
		"Confidence": 0,
		"DateAdded": "2020-04-27T04:57:20Z",
		"ThreatAssessConfidence": 53,
		"LastModified": "2020-04-27T04:57:20Z",
		"ThreatAssertRating": 3,
		"Summary": "88.88.88.88",
		"OwnerName": "Demisto Inc.",
		"IndicatorID": 112677927,
		"Type": "Address",
		"GroupID": 5110299 } ]
}
```

#### Human Readable Output

>### ThreatConnect Group Indicators
>|Confidence|DateAdded|GroupID|IndicatorID|LastModified|OwnerName|Rating|Summary|ThreatAssertRating|ThreatAssessConfidence|Type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 2020-04-27T04:57:20Z | 5110299 | 112677927 | 2020-04-27T04:57:20Z | Demisto Inc. | 0.0 | 88.88.88.88 | 3.0 | 53.0 | Address |  


### tc-get-associated-groups
***
Returns indicators associated with a specified group.


#### Base Command

`tc-get-associated-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group. To get the ID, run the tc-get-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.AssociatedGroup.DateAdded | Date | The date on which group was added. | 
| TC.Group.AssociatedGroup.GroupID | Number | The ID of the group. | 
| TC.Group.AssociatedGroup.Name | String | The name of the group. | 
| TC.Group.AssociatedGroup.OwnerName | String | The name of the owner of the group. | 
| TC.Group.AssociatedGroup.Type | String | The type of the group. | 


#### Command Example
```!tc-get-associated-groups group_id=5101576 group_type=incidents```

#### Context Example
```
{
    "TC": {
        "Group": {
            "AssociatedGroup": {
                "DateAdded": "2020-04-27T05:03:28Z",
                "GroupID": 5110299,
                "Name": "test_as",
                "OwnerName": "Demisto Inc.",
                "Type": "Incident"
            }
        }
    }
}
```

#### Human Readable Output

>### ThreatConnect Associated Groups
>|GroupID|Name|Type|OwnerName|DateAdded|
>|---|---|---|---|---|
>| 5110299 | test_as | Incident | Demisto Inc. | 2020-04-27T05:03:28Z |


### tc-associate-group-to-group
***
Associates one group with another group.


#### Base Command

`tc-associate-group-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of the group. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| group_id | The ID of the group. To get the ID of the group, run the tc-get-groups command. | Required | 
| associated_group_type | The type of group to associate. Can be "adversaries", "campaigns", "documents", "emails", "events", "incidents", "intrusionSets", "reports", "signatures", or "threats". | Required | 
| associated_group_id | The ID of the group to associate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.AssociatedGroup.AssociatedGroupID | Number | The ID of the associated group. | 
| TC.Group.AssociatedGroup.AssociatedGroupType | String | The type of the associated group. | 
| TC.Group.AssociatedGroup.GroupID | Number | The ID of the group to associate to. | 
| TC.Group.AssociatedGroup.GroupType | String | The type of the group to associate to. | 


#### Command Example
```!tc-associate-group-to-group group_id=5101576 group_type=incidents associated_group_id=5101578 associated_group_type=campaigns```

##### Context Example  
```  
{
	"TC.Group.AssociatedGroup": {
		"GroupType": "incidents",
		"AssociatedGroupID": 5101578,   
        "AssociatedGroupType": "campaigns",   
        "GroupID": 5101576
	}
}  
```  
  
>##### Human Readable Output  
>The group 5101578 was associated successfully. 



### tc-get-indicator-owners
***
Get Owner for Indicator


#### Base Command

`tc-get-indicator-owners`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Indicator Value | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tc-get-indicator-owners indicator=99.99.99.99```

#### Context Example
```
{
    "TC": {
        "Owners": [
            {
                "id": 737,
                "name": "Demisto Inc.",
                "type": "Organization"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatConnect Owners for Indicator:99.99.99.99
>|id|name|type|
>|---|---|---|
>| 737 | Demisto Inc. | Organization |

### tc-download-report
***
The group report to download in PDF format.


#### Base Command

`tc-download-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of the group. Can be: "adversaries", "campaigns", "emails", "incidents", "signatures", or "threats". Possible values are: adversaries, campaigns, emails, incidents, signatures, threats. | Required | 
| group_id | The ID of the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | The information of the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 