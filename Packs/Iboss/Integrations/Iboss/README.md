Manage block lists, manage allow lists, and perform domain, IP, and/or URL reputation and categorization lookups.
This integration was integrated and tested with version 10.0.0.90 of iboss Cloud.

## Configure iboss on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for iboss.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Username | True |
    | Password | True |
    | Account Settings ID | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iboss-add-entity-to-allow-list
***
Adds domains, IPs, and/or URLs to an allow list


#### Base Command

`iboss-add-entity-to-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to add to the allow list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 
| allow_keyword | Whether to enforce blocked keywords. Possible values are: 0, 1. Default is 0. | Optional | 
| direction | Which direction(s) to match. Possible values are: 0, 1, 2. Default is 2. | Optional | 
| start_port | Which start port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| end_port | Which end port(s) to match; 0 indicates all ports. Default is 0. | Optional | 
| global | Whether to apply to all groups. Possible values are: 0, 1. Default is 0. | Optional | 
| is_regex | Whether entity consists of a regex pattern. Possible values are: 0, 1. Default is 0. | Optional | 
| priority |  Priority of entry (higher number takes precedence) when conflicting entry in allow list. Default is 0. | Optional | 
| time_url_expires_in_minutes | The expiration time in minutes for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 


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
            "message": "URL added successfully."
        }
    }
}
```

#### Human Readable Output

>URL added successfully.

### iboss-add-entity-to-block-list
***
Adds domains, IPs, and/or URLs to a block list
    


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
| priority |  Priority of entry (higher number takes precedence) when conflicting entry in the block list. Default is 0. | Optional | 
| time_url_expires_in_minutes | The expiration time in minutes for the entry (0 indicates an entry that does not expire). Default is 0. | Optional | 


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
            "message": "Successfully added URL to list."
        }
    }
}
```

#### Human Readable Output

>Successfully added URL to list.

### domain
***
Looks up reputation data for IP addresses
    


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain(s) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | Unknown | The indicator. | 
| DBotScore.Type | Unknown | The indicator type. | 
| DBotScore.Vendor | Unknown | The vendor. | 
| DBotScore.Score | Number | The DBot score. | 
| Domain.Malicious.Description | String | The indicator context description | 
| Domain.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| Domain.Name | Unknown | The domain. | 
| iboss.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.categories | Unknown | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.categorized | Number | Whether entity is categorized. | 
| iboss.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.message | String | Entity lookup message. | 
| iboss.url | String | The entity to perforum URL check on. | 
| iboss.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

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
    "iboss": {
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
        "webRequestHeuristicProtectionActionHigh": "0",
        "webRequestHeuristicProtectionActionLow": "0",
        "webRequestHeuristicProtectionActionMedium": "0",
        "webRequestHeuristicProtectionLevel": "1",
        "webRequestHeuristicSuccess": 1,
        "webRequestHeuristicSupport": 1
    }
}
```

#### Human Readable Output

>### Result
>|DBotScore|iboss|
>|---|---|
>| Indicator: iboss.com<br/>Type: domain<br/>Vendor: iboss<br/>Score: 1 | activeMalwareSubscription: 1<br/>categories: Business,<br/>Technology<br/>categorized: true<br/>googleSafeBrowsingDescription: <br/>googleSafeBrowsingEnabled: 1<br/>googleSafeBrowsingIsSafeUrl: 1<br/>googleSafeBrowsingSuccess: 1<br/>googleSafeBrowsingSupport: 1<br/>isSafeUrl: 1<br/>malwareEngineAnalysisDescription: <br/>malwareEngineAnalysisEnabled: 1<br/>malwareEngineAnalysisSuccess: 1<br/>malwareEngineIsSafeUrl: 1<br/>malwareEngineResultCode: 0<br/>message: Status: Url Known. Please see categories below.<br/>realtimeCloudLookupDomainIsGrey: 0<br/>realtimeCloudLookupEnabled: 1<br/>realtimeCloudLookupIsSafeUrl: 1<br/>realtimeCloudLookupRiskDescription: <br/>realtimeCloudLookupSuccess: 1<br/>reputationDatabaseBotnetDetection: 0<br/>reputationDatabaseEnabled: 1<br/>reputationDatabaseIsSafeUrl: 1<br/>reputationDatabaseLookupSuccess: 1<br/>reputationDatabaseMalwareDetection: 0<br/>url: iboss.com<br/>webRequestHeuristicBlockUnreachableSites: 1<br/>webRequestHeuristicDescription: <br/>webRequestHeuristicIsSafeUrl: 1<br/>webRequestHeuristicLevelHighScore: 79<br/>webRequestHeuristicLevelLowScore: 10<br/>webRequestHeuristicLevelMediumScore: 60<br/>webRequestHeuristicLevelNoneScore: 0<br/>webRequestHeuristicProtectionActionHigh: 0<br/>webRequestHeuristicProtectionActionLow: 0<br/>webRequestHeuristicProtectionActionMedium: 0<br/>webRequestHeuristicProtectionLevel: 1<br/>webRequestHeuristicSuccess: 1<br/>webRequestHeuristicSupport: 1 |


### ip
***
Looks up reputation data for IP addresses
    


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP(s) to lookup. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | Unknown | The indicator. | 
| DBotScore.Type | Unknown | The indicator type. | 
| DBotScore.Vendor | Unknown | The vendor. | 
| DBotScore.Score | Number | The DBot score. | 
| IP.Malicious.Description | String | The indicator context description | 
| IP.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| IP.Address | Unknown | The IP address. | 
| iboss.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.categories | Unknown | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.categorized | Number | Whether entity is categorized. | 
| iboss.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.message | String | Entity lookup message. | 
| iboss.url | String | The entity to perforum URL check on. | 
| iboss.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

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
    "iboss": {
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
        "webRequestHeuristicProtectionActionHigh": "0",
        "webRequestHeuristicProtectionActionLow": "0",
        "webRequestHeuristicProtectionActionMedium": "0",
        "webRequestHeuristicProtectionLevel": "1",
        "webRequestHeuristicSuccess": 1,
        "webRequestHeuristicSupport": 1
    }
}
```

#### Human Readable Output

>### Result
>|DBotScore|iboss|
>|---|---|
>| Indicator: 1.1.1.1<br/>Type: ip<br/>Vendor: iboss<br/>Score: 2 | activeMalwareSubscription: 1<br/>categories: Technology<br/>categorized: true<br/>googleSafeBrowsingDescription: <br/>googleSafeBrowsingEnabled: 1<br/>googleSafeBrowsingIsSafeUrl: 1<br/>googleSafeBrowsingSuccess: 1<br/>googleSafeBrowsingSupport: 1<br/>isSafeUrl: 0<br/>malwareEngineAnalysisDescription: Redirect - Redirects to: https:<span>//</span>1.1.1.1/<br/>malwareEngineAnalysisEnabled: 1<br/>malwareEngineAnalysisSuccess: 1<br/>malwareEngineIsSafeUrl: 1<br/>malwareEngineResultCode: 3<br/>message: Status: Url Known. Please see categories below.<br/>realtimeCloudLookupDomainIsGrey: 0<br/>realtimeCloudLookupEnabled: 1<br/>realtimeCloudLookupIsSafeUrl: 1<br/>realtimeCloudLookupRiskDescription: <br/>realtimeCloudLookupSuccess: 1<br/>reputationDatabaseBotnetDetection: 0<br/>reputationDatabaseEnabled: 1<br/>reputationDatabaseIsSafeUrl: 1<br/>reputationDatabaseLookupSuccess: 1<br/>reputationDatabaseMalwareDetection: 0<br/>url: 1.1.1.1<br/>webRequestHeuristicBlockUnreachableSites: 1<br/>webRequestHeuristicDescription: Heuristic Engine Detection<br/>webRequestHeuristicIsSafeUrl: 0<br/>webRequestHeuristicLevelHighScore: 79<br/>webRequestHeuristicLevelLowScore: 10<br/>webRequestHeuristicLevelMediumScore: 60<br/>webRequestHeuristicLevelNoneScore: 0<br/>webRequestHeuristicProtectionActionHigh: 0<br/>webRequestHeuristicProtectionActionLow: 0<br/>webRequestHeuristicProtectionActionMedium: 0<br/>webRequestHeuristicProtectionLevel: 1<br/>webRequestHeuristicSuccess: 1<br/>webRequestHeuristicSupport: 1 |


### iboss-remove-entity-from-allow-list
***
Removes entities from an allow list


#### Base Command

`iboss-remove-entity-from-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to remove from allow list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 


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
            "message": "URL removed successfully."
        }
    }
}
```

#### Human Readable Output

>URL removed successfully.

### iboss-remove-entity-from-block-list
***
Removes entities from a block list


#### Base Command

`iboss-remove-entity-from-block-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Domains, IPs, and/or URLs to remove from block list. | Required | 
| current_policy_being_edited | The group/policy number to update. Default is 1. | Optional | 


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
            "message": "URL removed successfully."
        }
    }
}
```

#### Human Readable Output

>URL removed successfully.

### test-module
***
Tests API connectivity and authentication


#### Base Command

`test-module`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
#### Command example
```!test-module```
#### Human Readable Output

>ok

### url
***
Looks up reputation data for URLs
    


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL(s) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | Unknown | The indicator. | 
| DBotScore.Type | Unknown | The indicator type. | 
| DBotScore.Vendor | Unknown | The vendor. | 
| DBotScore.Score | Number | The DBot score. | 
| URL.Malicious.Description | String | The indicator context description | 
| URL.Malicious.Vendor | String | The vendor that indicator context originated from. | 
| URL.Data | Unknown | The URL. | 
| iboss.isSafeUrl | Number | Whether entity is deemed safe | 
| iboss.categories | Unknown | The entity categories. | 
| DBotScore.activeMalwareSubscription | Number | Whether active malware subscription is active | 
| iboss.categorized | Number | Whether entity is categorized. | 
| iboss.googleSafeBrowsingDescription | String | Google safe browsing description | 
| iboss.message | String | Entity lookup message. | 
| iboss.url | String | The entity to perforum URL check on. | 
| iboss.googleSafeBrowsingEnabled | Number | Whether Google safe browsing is enabled. | 
| iboss.googleSafeBrowsingIsSafeUrl | Number | Whether entity deemed safe by Google safe browsing. | 
| iboss.googleSafeBrowsingSuccess | Number | Whether Google safe browsing check was successful. | 
| iboss.googleSafeBrowsingSupport | String | Whether Google safe browsing is supported | 
| iboss.malwareEngineAnalysisDescription | String | Malware engine analysis description | 
| iboss.malwareEngineAnalysisEnabled | Number | Whether the malware engine analysis is enabled. | 
| iboss.malwareEngineAnalysisSuccess | Number | Whether the malware engine analysis check was successful. | 
| iboss.malwareEngineIsSafeUrl | Number | Whether the entity was deemed safe by the malware engine. | 
| iboss.malwareEngineResultCode | String | The result code from the malware engine analysis | 
| iboss.realtimeCloudLookupDomainIsGrey | Number | Whether realtime cloud lookup is grey. | 
| iboss.realtimeCloudLookupDomainEnabled | Number | Whether realtime cloud lookup is enabled. | 
| iboss.realtimeCloudLookupIsSafeUrl | Number | Whether realtime cloud lookup determined entity is safe. | 
| iboss.realtimeCloudLookupRiskDescription | String | Realtime cloud lookup risk description. | 
| iboss.realtimeCloudLookupSuccess | Number | Whether realtime cloud lookup chec was successful. | 
| iboss.reputationDatabaseBotnetDetection | Number | Whether reputation database detected a botnet. | 
| iboss.reputationDatabaseMalwareDetection | Number | Whether reputation database detected malware. | 
| iboss.reputationDatabaseEnabled | Number | Whether reputation database check is enabled. | 
| iboss.reputationDatabaseIsSafeUrl | String | Whether reputation database check determined entity is safe. | 
| iboss.reputationDatabaseLookupSuccess | Number | Whether reputation database lookup was successful. | 
| iboss.webRequestHeuristicBlockUnreachableSites | Number | Whether unreachable sites will be blocked. | 
| iboss.webRequestHeuristicDescription | String | The web request heuristic description. | 
| iboss.webRequestHeuristicIsSafeUrl | Number | Whether web request heuristics determined URL is safe. | 
| iboss.webRequestHeuristicLevelHighScore | String | The web request heuristic score high threshold. | 
| iboss.webRequestHeuristicLevelLowScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelMediumScore | String | The web request heuristic score low threshold. | 
| iboss.webRequestHeuristicLevelNoneScore | String | The web request heuristic score none threshold. | 
| iboss.webRequestHeuristicProtectionActionHigh | Number | The web request heuristic protection action high threshold. | 
| iboss.webRequestHeuristicProtectionActionLow | Number | The web request heuristic protection action low threshold. | 
| iboss.webRequestHeuristicProtectionActionMedium | Number | The web request heuristic protection action medium threshold. | 
| iboss.webRequestHeuristicProtectionLevel | String | The web request heuristic protection level. | 
| iboss.webRequestHeuristicSuccess | Number | Whether web request heuristic check was successful. | 
| iboss.webRequestHeuristicSupport | Number | Whether web request heuristic support enabled. | 

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
    "iboss": {
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
        "webRequestHeuristicProtectionActionHigh": "0",
        "webRequestHeuristicProtectionActionLow": "0",
        "webRequestHeuristicProtectionActionMedium": "0",
        "webRequestHeuristicProtectionLevel": "1",
        "webRequestHeuristicSuccess": 1,
        "webRequestHeuristicSupport": 1
    }
}
```

#### Human Readable Output

>### Result
>|DBotScore|iboss|
>|---|---|
>| Indicator: https:<span>//</span>www.iboss.com<br/>Type: url<br/>Vendor: iboss<br/>Score: 1 | activeMalwareSubscription: 1<br/>categories: Business,<br/>Technology<br/>categorized: true<br/>googleSafeBrowsingDescription: <br/>googleSafeBrowsingEnabled: 1<br/>googleSafeBrowsingIsSafeUrl: 1<br/>googleSafeBrowsingSuccess: 1<br/>googleSafeBrowsingSupport: 1<br/>isSafeUrl: 1<br/>malwareEngineAnalysisDescription: <br/>malwareEngineAnalysisEnabled: 1<br/>malwareEngineAnalysisSuccess: 1<br/>malwareEngineIsSafeUrl: 1<br/>malwareEngineResultCode: 0<br/>message: Status: Url Known. Please see categories below.<br/>realtimeCloudLookupDomainIsGrey: 0<br/>realtimeCloudLookupEnabled: 1<br/>realtimeCloudLookupIsSafeUrl: 1<br/>realtimeCloudLookupRiskDescription: <br/>realtimeCloudLookupSuccess: 1<br/>reputationDatabaseBotnetDetection: 0<br/>reputationDatabaseEnabled: 1<br/>reputationDatabaseIsSafeUrl: 1<br/>reputationDatabaseLookupSuccess: 1<br/>reputationDatabaseMalwareDetection: 0<br/>url: https:<span>//</span>www.iboss.com<br/>webRequestHeuristicBlockUnreachableSites: 1<br/>webRequestHeuristicDescription: <br/>webRequestHeuristicIsSafeUrl: 1<br/>webRequestHeuristicLevelHighScore: 79<br/>webRequestHeuristicLevelLowScore: 10<br/>webRequestHeuristicLevelMediumScore: 60<br/>webRequestHeuristicLevelNoneScore: 0<br/>webRequestHeuristicProtectionActionHigh: 0<br/>webRequestHeuristicProtectionActionLow: 0<br/>webRequestHeuristicProtectionActionMedium: 0<br/>webRequestHeuristicProtectionLevel: 1<br/>webRequestHeuristicSuccess: 1<br/>webRequestHeuristicSupport: 1 |
