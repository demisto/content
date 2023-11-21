Manage block lists, manage allow lists, and perform domain, IP, and/or URL reputation and categorization lookups.
This integration was integrated and tested with version 9.8.38.245 of iboss Zero Trust Secure Service Edge.

## Configure iboss on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for iboss.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username |  | True |
    | Password |  | True |
    | Account Settings ID |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data |  |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iboss-add-entity-to-allow-list
***
Adds domains, IPs, and/or URLs to an allow list.


#### Base Command

`iboss-add-entity-to-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to add to an allow list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 
| allow_keyword | Whether to enforce blocked keywords. Possible values are: 0, 1. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| global | Whether to apply to all groups. Possible values are: 0, 1. Default is 0. | Optional | 
| is_regex | Whether entity consists of a regex pattern. Possible values are: 0, 1. Default is 0. | Optional | 
| priority | Priority of entry (higher number takes precedence) when conflicting entry in allow list. Default is 0. | Optional | 
| time_url_expires_in_minutes | The expiration time in minutes for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 
| note | Note added to the entry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.AddEntityToAllowList.message | String | Operation result. | 

#### Command example
```!iboss-add-entity-to-allow-list entity=iboss.com```
#### Context Example
```json
{
    "iboss": {
        "AddEntityToAllowList": {
            "message": "`iboss.com` successfully added to policy 1 allow list."
        }
    }
}
```

#### Human Readable Output

>`iboss.com` successfully added to policy 1 allow list.

### iboss-add-entity-to-block-list
***
Adds domains, IPs, and/or URLs to a block list.


#### Base Command

`iboss-add-entity-to-block-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to add to the block list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 
| allow_keyword | Whether to enforce blocked keywords. Possible values are: 0, 1. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| global | Whether to apply to all groups. Possible values are: 0, 1. Default is 0. | Optional | 
| is_regex | Whether entity consists of a regex pattern. Possible values are: 0, 1. Default is 0. | Optional | 
| priority | Priority of entry (higher number takes precedence) when conflicting entry in the block list. Default is 0. | Optional | 
| time_url_expires_in_minutes | The expiration time in minutes for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 
| note | Note added to the entry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.AddEntityToBlockList.message | String | Operation result. | 

#### Command example
```!iboss-add-entity-to-block-list entity=iboss.com```
#### Context Example
```json
{
    "iboss": {
        "AddEntityToBlockList": {
            "message": "`iboss.com` successfully added to policy 1 block list."
        }
    }
}
```

#### Human Readable Output

>`iboss.com` successfully added to policy 1 block list.

### domain
***
Lookup reputation for domain names.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain(s) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| Domain.Malicious.Description | String | The indicator context description | 
| Domain.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| Domain.Name | String | The domain. | 
| iboss.Domain.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.Domain.categories | String | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.Domain.categorized | Number | Whether entity is categorized. | 
| iboss.Domain.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.Domain.message | String | Entity lookup message. | 
| iboss.Domain.url | String | The entity to perforum URL check on. | 
| iboss.Domain.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.Domain.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.Domain.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.Domain.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.Domain.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.Domain.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.Domain.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.Domain.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.Domain.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.Domain.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.Domain.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.Domain.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.Domain.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.Domain.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.Domain.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.Domain.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.Domain.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.Domain.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.Domain.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.Domain.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.Domain.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.Domain.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.Domain.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.Domain.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.Domain.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.Domain.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.Domain.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.Domain.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.Domain.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.Domain.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.Domain.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.Domain.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

#### Command example
```!domain domain=iboss.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "iboss.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "iboss"
    },
    "Domain": {
        "DetectionEngines": 5,
        "Name": "iboss.com",
        "PositiveDetections": 0
    },
    "iboss": {
        "Domain": {
            "activeMalwareSubscription": 1,
            "categories": [
                "Business",
                "Technology"
            ],
            "categorized": "true",
            "googleSafeBrowsingDescription": "",
            "googleSafeBrowsingEnabled": 1,
            "googleSafeBrowsingIsSafeUrl": 1,
            "googleSafeBrowsingSuccess": 1,
            "googleSafeBrowsingSupport": 1,
            "isSafeUrl": 1,
            "malwareEngineAnalysisDescription": "",
            "malwareEngineAnalysisEnabled": 1,
            "malwareEngineAnalysisSuccess": 1,
            "malwareEngineIsSafeUrl": 1,
            "malwareEngineResultCode": 0,
            "message": "Status: Url Known. Please see categories below.",
            "realtimeCloudLookupDomainIsGrey": 0,
            "realtimeCloudLookupEnabled": 1,
            "realtimeCloudLookupIsSafeUrl": 1,
            "realtimeCloudLookupRiskDescription": "",
            "realtimeCloudLookupSuccess": 1,
            "reputationDatabaseBotnetDetection": 0,
            "reputationDatabaseEnabled": 1,
            "reputationDatabaseIsSafeUrl": 1,
            "reputationDatabaseLookupSuccess": 1,
            "reputationDatabaseMalwareDetection": 0,
            "url": "iboss.com",
            "webRequestHeuristicBlockUnreachableSites": "1",
            "webRequestHeuristicDescription": "",
            "webRequestHeuristicIsSafeUrl": 1,
            "webRequestHeuristicLevelHighScore": "79",
            "webRequestHeuristicLevelLowScore": "10",
            "webRequestHeuristicLevelMediumScore": "60",
            "webRequestHeuristicLevelNoneScore": "0",
            "webRequestHeuristicProtectionActionHigh": "3",
            "webRequestHeuristicProtectionActionLow": "0",
            "webRequestHeuristicProtectionActionMedium": "3",
            "webRequestHeuristicProtectionLevel": "1",
            "webRequestHeuristicSuccess": 1,
            "webRequestHeuristicSupport": 1
        }
    }
}
```

#### Human Readable Output

>### iboss Result for domain iboss.com
>|message|categories|isSafeUrl|malwareEngineAnalysisSuccess|malwareEngineAnalysisDescription|reputationDatabaseLookupSuccess|reputationDatabaseMalwareDetection|reputationDatabaseBotnetDetection|webRequestHeuristicSuccess|webRequestHeuristicProtectionLevel|webRequestHeuristicDescription|googleSafeBrowsingSuccess|googleSafeBrowsingIsSafeUrl|googleSafeBrowsingDescription|realtimeCloudLookupSuccess|realtimeCloudLookupDomainIsGrey|realtimeCloudLookupRiskDescription|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Status: Url Known. Please see categories below. | Business,<br/>Technology | 1 | 1 |  | 1 | 0 | 0 | 1 | 1 |  | 1 | 1 |  | 1 | 0 |  |


### ip
***
Lookup reputation data for IP addresses.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP(s) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.Malicious.Description | String | The indicator context description | 
| IP.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| IP.Address | String | The IP address. | 
| iboss.IP.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.IP.categories | String | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.IP.categorized | Number | Whether entity is categorized. | 
| iboss.IP.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.IP.message | String | Entity lookup message. | 
| iboss.IP.url | String | The entity to perforum URL check on. | 
| iboss.IP.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.IP.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.IP.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.IP.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.IP.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.IP.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.IP.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.IP.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.IP.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.IP.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.IP.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.IP.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.IP.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.IP.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.IP.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.IP.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.IP.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.IP.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.IP.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.IP.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.IP.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.IP.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.IP.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.IP.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.IP.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.IP.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.IP.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.IP.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.IP.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.IP.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.IP.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.IP.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

#### Command example
```!ip ip=1.1.1.1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 2,
        "Type": "ip",
        "Vendor": "iboss"
    },
    "IP": {
        "Address": "1.1.1.1",
        "DetectionEngines": 5,
        "PositiveDetections": 1
    },
    "iboss": {
        "IP": {
            "activeMalwareSubscription": 1,
            "categories": [
                "Technology"
            ],
            "categorized": "true",
            "googleSafeBrowsingDescription": "",
            "googleSafeBrowsingEnabled": 1,
            "googleSafeBrowsingIsSafeUrl": 1,
            "googleSafeBrowsingSuccess": 1,
            "googleSafeBrowsingSupport": 1,
            "isSafeUrl": 0,
            "malwareEngineAnalysisDescription": "Redirect - Redirects to: https://1.1.1.1/",
            "malwareEngineAnalysisEnabled": 1,
            "malwareEngineAnalysisSuccess": 1,
            "malwareEngineIsSafeUrl": 1,
            "malwareEngineResultCode": 3,
            "message": "Status: Url Known. Please see categories below.",
            "realtimeCloudLookupDomainIsGrey": 0,
            "realtimeCloudLookupEnabled": 1,
            "realtimeCloudLookupIsSafeUrl": 1,
            "realtimeCloudLookupRiskDescription": "",
            "realtimeCloudLookupSuccess": 1,
            "reputationDatabaseBotnetDetection": 0,
            "reputationDatabaseEnabled": 1,
            "reputationDatabaseIsSafeUrl": 1,
            "reputationDatabaseLookupSuccess": 1,
            "reputationDatabaseMalwareDetection": 0,
            "url": "1.1.1.1",
            "webRequestHeuristicBlockUnreachableSites": "1",
            "webRequestHeuristicDescription": "Heuristic Engine Detection",
            "webRequestHeuristicIsSafeUrl": 0,
            "webRequestHeuristicLevelHighScore": "79",
            "webRequestHeuristicLevelLowScore": "10",
            "webRequestHeuristicLevelMediumScore": "60",
            "webRequestHeuristicLevelNoneScore": "0",
            "webRequestHeuristicProtectionActionHigh": "3",
            "webRequestHeuristicProtectionActionLow": "0",
            "webRequestHeuristicProtectionActionMedium": "3",
            "webRequestHeuristicProtectionLevel": "1",
            "webRequestHeuristicSuccess": 1,
            "webRequestHeuristicSupport": 1
        }
    }
}
```

#### Human Readable Output

>### iboss Result for IP 1.1.1.1
>|message|categories|isSafeUrl|malwareEngineAnalysisSuccess|malwareEngineAnalysisDescription|reputationDatabaseLookupSuccess|reputationDatabaseMalwareDetection|reputationDatabaseBotnetDetection|webRequestHeuristicSuccess|webRequestHeuristicProtectionLevel|webRequestHeuristicDescription|googleSafeBrowsingSuccess|googleSafeBrowsingIsSafeUrl|googleSafeBrowsingDescription|realtimeCloudLookupSuccess|realtimeCloudLookupDomainIsGrey|realtimeCloudLookupRiskDescription|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Status: Url Known. Please see categories below. | Technology | 0 | 1 | Redirect - Redirects to: https:<span>//</span>1.1.1.1/ | 1 | 0 | 0 | 1 | 1 | Heuristic Engine Detection | 1 | 1 |  | 1 | 0 |  |


### iboss-remove-entity-from-allow-list
***
Removes domains, IPs, and/or URLs from an allow list


#### Base Command

`iboss-remove-entity-from-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to remove from an allow list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.RemoveEntityFromAllowList.message | String | Operation result. | 

#### Command example
```!iboss-remove-entity-from-allow-list entity=iboss.com```
#### Context Example
```json
{
    "iboss": {
        "RemoveEntityFromAllowList": {
            "message": "`iboss.com` removed from policy 1 allow list."
        }
    }
}
```

#### Human Readable Output

>`iboss.com` removed from policy 1 allow list.

### iboss-remove-entity-from-block-list
***
Removes domains, IPs, and/or URLs to a block list.


#### Base Command

`iboss-remove-entity-from-block-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to remove from a block list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.RemoveEntityFromBlockList.message | String | Operation result. | 

#### Command example
```!iboss-remove-entity-from-block-list entity=iboss.com```
#### Context Example
```json
{
    "iboss": {
        "RemoveEntityFromBlockList": {
            "message": "`iboss.com` removed from policy 1 block list."
        }
    }
}
```

#### Human Readable Output

>`iboss.com` removed from policy 1 block list.

### url
***
Lookup reputation data for URLs.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL(s) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Malicious.Description | String | The indicator context description | 
| URL.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| URL.Data | String | The URL. | 
| iboss.URL.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.URL.categories | String | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.URL.categorized | Number | Whether entity is categorized. | 
| iboss.URL.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.URL.message | String | Entity lookup message. | 
| iboss.URL.url | String | The entity to perforum URL check on. | 
| iboss.URL.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.URL.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.URL.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.URL.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.URL.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.URL.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.URL.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.URL.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.URL.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.URL.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.URL.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.URL.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.URL.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.URL.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.URL.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.URL.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.URL.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.URL.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.URL.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.URL.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.URL.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.URL.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.URL.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.URL.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.URL.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.URL.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.URL.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.URL.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.URL.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.URL.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.URL.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.URL.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

#### Command example
```!url url=https://www.iboss.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://www.iboss.com",
        "Score": 1,
        "Type": "url",
        "Vendor": "iboss"
    },
    "URL": {
        "Data": "https://www.iboss.com",
        "DetectionEngines": 5,
        "PositiveDetections": 0
    },
    "iboss": {
        "URL": {
            "activeMalwareSubscription": 1,
            "categories": [
                "Business",
                "Technology"
            ],
            "categorized": "true",
            "googleSafeBrowsingDescription": "",
            "googleSafeBrowsingEnabled": 1,
            "googleSafeBrowsingIsSafeUrl": 1,
            "googleSafeBrowsingSuccess": 1,
            "googleSafeBrowsingSupport": 1,
            "isSafeUrl": 1,
            "malwareEngineAnalysisDescription": "",
            "malwareEngineAnalysisEnabled": 1,
            "malwareEngineAnalysisSuccess": 1,
            "malwareEngineIsSafeUrl": 1,
            "malwareEngineResultCode": 0,
            "message": "Status: Url Known. Please see categories below.",
            "realtimeCloudLookupDomainIsGrey": 0,
            "realtimeCloudLookupEnabled": 1,
            "realtimeCloudLookupIsSafeUrl": 1,
            "realtimeCloudLookupRiskDescription": "",
            "realtimeCloudLookupSuccess": 1,
            "reputationDatabaseBotnetDetection": 0,
            "reputationDatabaseEnabled": 1,
            "reputationDatabaseIsSafeUrl": 1,
            "reputationDatabaseLookupSuccess": 1,
            "reputationDatabaseMalwareDetection": 0,
            "url": "https://www.iboss.com",
            "webRequestHeuristicBlockUnreachableSites": "1",
            "webRequestHeuristicDescription": "",
            "webRequestHeuristicIsSafeUrl": 1,
            "webRequestHeuristicLevelHighScore": "79",
            "webRequestHeuristicLevelLowScore": "10",
            "webRequestHeuristicLevelMediumScore": "60",
            "webRequestHeuristicLevelNoneScore": "0",
            "webRequestHeuristicProtectionActionHigh": "3",
            "webRequestHeuristicProtectionActionLow": "0",
            "webRequestHeuristicProtectionActionMedium": "3",
            "webRequestHeuristicProtectionLevel": "1",
            "webRequestHeuristicSuccess": 1,
            "webRequestHeuristicSupport": 1
        }
    }
}
```

#### Human Readable Output

>### iboss Result for URL https:<span>//</span>www.iboss.com
>|message|categories|isSafeUrl|malwareEngineAnalysisSuccess|malwareEngineAnalysisDescription|reputationDatabaseLookupSuccess|reputationDatabaseMalwareDetection|reputationDatabaseBotnetDetection|webRequestHeuristicSuccess|webRequestHeuristicProtectionLevel|webRequestHeuristicDescription|googleSafeBrowsingSuccess|googleSafeBrowsingIsSafeUrl|googleSafeBrowsingDescription|realtimeCloudLookupSuccess|realtimeCloudLookupDomainIsGrey|realtimeCloudLookupRiskDescription|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Status: Url Known. Please see categories below. | Business,<br/>Technology | 1 | 1 |  | 1 | 0 | 0 | 1 | 1 |  | 1 | 1 |  | 1 | 0 |  |


### iboss-add-entity-to-policy-layer-list
***
Add entity to policy layer list.


#### Base Command

`iboss-add-entity-to-policy-layer-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_layer_name | Policy layer name to lookup. | Required | 
| entity | Entity to add to policy layer list. | Required | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 
| do_dlp_scan | Whether to perform DLP scanning. Possible values are: 0, 1. Default is 1. | Optional | 
| do_malware_scan | Whether to perform malware scanning. Possible values are: 0, 1. Default is 1. | Optional | 
| priority | Priority of entry (higher number takes precedence) when conflicting entry in the block list. Default is 0. | Optional | 
| time_url_expires_in_seconds | The expiration time in seconds for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 
| note | Note added to the entry. | Optional | 
| is_regex | Whether entity consists of a regex pattern. Possible values are: 0, 1. Default is 0. | Optional | 
| upsert | Update entity if it already exists. Possible values are: 0, 1. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.AddEntityToPolicyLayerList.message | String | Operation result. | 

#### Command example
```!iboss-add-entity-to-policy-layer-list entity=iboss.com policy_layer_name="Test Policy Layer - Allow List"```
#### Context Example
```json
{
    "iboss": {
        "AddEntityToPolicyLayerList": {
            "message": "Successfully added URL to list."
        }
    }
}
```

#### Human Readable Output

>Successfully added URL to list.

### iboss-remove-entity-from-policy-layer-list
***
Remove entity from policy layer list.


#### Base Command

`iboss-remove-entity-from-policy-layer-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_layer_name | Policy layer name to lookup. | Required | 
| entity | Entity to add to policy layer list. | Required | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 
| do_dlp_scan | Whether to perform DLP scanning. Possible values are: 0, 1. Default is 1. | Optional | 
| do_malware_scan | Whether to perform malware scanning. Possible values are: 0, 1. Default is 1. | Optional | 
| priority | Priority of entry (higher number takes precedence) when conflicting entry in the block list. Default is 0. | Optional | 
| time_url_expires_in_seconds | The expiration time in seconds for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 
| note | Note added to the entry. | Optional | 
| is_regex | Whether entity consists of a regex pattern. Possible values are: 0, 1. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iboss.RemoveEntityFromPolicyLayerList.message | String | Operation result. | 

#### Command example
```!iboss-remove-entity-from-policy-layer-list entity=iboss.com policy_layer_name="Test Policy Layer - Allow List"```
#### Context Example
```json
{
    "iboss": {
        "RemoveEntityFromPolicyLayerList": {
            "message": "iboss.com removed from policy layer `Test Policy Layer - Allow List`."
        }
    }
}
```

#### Human Readable Output

>iboss.com removed from policy layer `Test Policy Layer - Allow List`.
