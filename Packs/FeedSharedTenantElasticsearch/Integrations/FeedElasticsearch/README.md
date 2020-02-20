## Overview
---

Fetch Indicators shared by other tenants in a Multi Tenant Elasticsearch environment.

## SharedTenantElasticsearchFeed Playbook
---

## Configure SharedTenantElasticsearchFeed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SharedTenantElasticsearchFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL__
    * __Username for server login__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Fetch indicators__
    * __Indicator Reputation__
    * __Source Reliability__
    * __feedExpirationPolicy__
    * __feedExpirationInterval__
    * __Feed Fetch Interval__
    * __Bypass exclusion list__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. get-shared-indicators
### 1. get-shared-indicators
---
Gets indicators shared with this tenant (MT only).
##### Base Command

`get-shared-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to fetch. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ElasticsearchFeed.SharedIndicators.Indicators | Unknown | Indicators shared from other tenants without enrichments. | 
| ElasticsearchFeed.SharedIndicators.Enrichments | Unknown | Enrichment indicators shared from other tenants. | 


##### Command Example
```!get-shared-indicators```

##### Context Example
```
{
    "ElasticsearchFeed.SharedIndicators": {
        "Indicators": [
            {
                "comment": "", 
                "version": 2, 
                "sequenceNumber": 26, 
                "sortValues": null, 
                "modified": "2020-02-18T11:43:44.200258Z", 
                "lastSeen": "2020-02-18T10:39:05.230163+02:00", 
                "id": "e086aa137fa19f67d27b39d0eca18610", 
                "deletedFeedFetchTime": "0001-01-01T00:00:00Z", 
                "rawJSON": {
                    "comment": "", 
                    "version": 2, 
                    "sequenceNumber": 26, 
                    "sortValues": null, 
                    "modified": "2020-02-18T11:43:44.200258Z", 
                    "lastSeen": "2020-02-18T10:39:05.230163+02:00", 
                    "id": "e086aa137fa19f67d27b39d0eca18610", 
                    "deletedFeedFetchTime": "0001-01-01T00:00:00Z", 
                    "investigationsCount": 0, 
                    "primaryTerm": 2, 
                    "score": 0, 
                    "investigationIDs": [], 
                    "type": "IP", 
                    "isShared": true, 
                    "rawName": "1.1.1.1", 
                    "modifiedTime": "0001-01-01T00:00:00Z", 
                    "lastSeenEntryID": "API", 
                    "CustomFields": {
                        "internal": false
                    }, 
                    "firstSeen": "2020-02-18T10:39:05.230163+02:00", 
                    "name": "1.1.1.1", 
                    "account": "TestAccount-456", 
                    "lastReputationRun": "0001-01-01T00:00:00Z", 
                    "manualSetTime": "0001-01-01T00:00:00Z", 
                    "firstSeenEntryID": "API", 
                    "expirationStatus": "active", 
                    "value": "1.1.1.1", 
                    "expirationSource": {
                        "expirationInterval": 10080, 
                        "source": "indicatorType", 
                        "brand": "", 
                        "instance": "", 
                        "setTime": "2020-02-18T10:39:05.230168+02:00", 
                        "user": "", 
                        "expirationPolicy": "indicatorType", 
                        "moduleId": ""
                    }, 
                    "isIoc": true, 
                    "expiration": "0001-01-01T00:00:00Z", 
                    "context": null, 
                    "createdTime": "2020-02-18T10:39:05.230184+02:00", 
                    "manuallyEditedFields": [
                        "indicator_type"
                    ], 
                    "calculatedTime": "2020-02-18T10:39:05.230163+02:00", 
                    "manualExpirationTime": "0001-01-01T00:00:00Z"
                }, 
                "investigationsCount": 0, 
                "primaryTerm": 2, 
                "score": 0, 
                "investigationIDs": [], 
                "type": "IP", 
                "isShared": true, 
                "rawName": "1.1.1.1", 
                "modifiedTime": "0001-01-01T00:00:00Z", 
                "lastSeenEntryID": "API", 
                "CustomFields": {
                    "internal": false
                }, 
                "firstSeen": "2020-02-18T10:39:05.230163+02:00", 
                "name": "1.1.1.1", 
                "account": "TestAccount-456", 
                "lastReputationRun": "0001-01-01T00:00:00Z", 
                "manualSetTime": "0001-01-01T00:00:00Z", 
                "firstSeenEntryID": "API", 
                "expirationStatus": "active", 
                "value": "1.1.1.1", 
                "expirationSource": {
                    "expirationInterval": 10080, 
                    "source": "indicatorType", 
                    "brand": "", 
                    "instance": "", 
                    "setTime": "2020-02-18T10:39:05.230168+02:00", 
                    "user": "", 
                    "expirationPolicy": "indicatorType", 
                    "moduleId": ""
                }, 
                "isIoc": true, 
                "expiration": "0001-01-01T00:00:00Z", 
                "context": null, 
                "createdTime": "2020-02-18T10:39:05.230184+02:00", 
                "manuallyEditedFields": [
                    "indicator_type"
                ], 
                "calculatedTime": "2020-02-18T10:39:05.230163+02:00", 
                "manualExpirationTime": "0001-01-01T00:00:00Z"
            }, 
            {
                "comment": "", 
                "version": 2, 
                "sequenceNumber": 25, 
                "sortValues": null, 
                "modified": "2020-02-18T11:43:44.200288Z", 
                "lastSeen": "2020-02-18T10:41:22.268124+02:00", 
                "id": "5b8656aafcb40bb58caf1d17ef8506a9", 
                "deletedFeedFetchTime": "0001-01-01T00:00:00Z", 
                "rawJSON": {
                    "comment": "", 
                    "version": 2, 
                    "sequenceNumber": 25, 
                    "sortValues": null, 
                    "modified": "2020-02-18T11:43:44.200288Z", 
                    "lastSeen": "2020-02-18T10:41:22.268124+02:00", 
                    "id": "5b8656aafcb40bb58caf1d17ef8506a9", 
                    "deletedFeedFetchTime": "0001-01-01T00:00:00Z", 
                    "investigationsCount": 0, 
                    "primaryTerm": 2, 
                    "score": 0, 
                    "investigationIDs": [], 
                    "type": "IP", 
                    "isShared": true, 
                    "rawName": "2.2.2.2", 
                    "modifiedTime": "0001-01-01T00:00:00Z", 
                    "lastSeenEntryID": "API", 
                    "CustomFields": {
                        "internal": false
                    }, 
                    "firstSeen": "2020-02-18T10:41:22.268124+02:00", 
                    "name": "2.2.2.2", 
                    "account": "TestAccount-456", 
                    "lastReputationRun": "0001-01-01T00:00:00Z", 
                    "manualSetTime": "0001-01-01T00:00:00Z", 
                    "firstSeenEntryID": "API", 
                    "expirationStatus": "active", 
                    "value": "2.2.2.2", 
                    "expirationSource": {
                        "expirationInterval": 10080, 
                        "source": "indicatorType", 
                        "brand": "", 
                        "instance": "", 
                        "setTime": "2020-02-18T10:41:22.268125+02:00", 
                        "user": "", 
                        "expirationPolicy": "indicatorType", 
                        "moduleId": ""
                    }, 
                    "isIoc": true, 
                    "expiration": "0001-01-01T00:00:00Z", 
                    "context": null, 
                    "createdTime": "2020-02-18T10:41:22.268133+02:00", 
                    "manuallyEditedFields": [
                        "indicator_type"
                    ], 
                    "calculatedTime": "2020-02-18T10:41:22.268124+02:00", 
                    "manualExpirationTime": "0001-01-01T00:00:00Z"
                }, 
                "investigationsCount": 0, 
                "primaryTerm": 2, 
                "score": 0, 
                "investigationIDs": [], 
                "type": "IP", 
                "isShared": true, 
                "rawName": "2.2.2.2", 
                "modifiedTime": "0001-01-01T00:00:00Z", 
                "lastSeenEntryID": "API", 
                "CustomFields": {
                    "internal": false
                }, 
                "firstSeen": "2020-02-18T10:41:22.268124+02:00", 
                "name": "2.2.2.2", 
                "account": "TestAccount-456", 
                "lastReputationRun": "0001-01-01T00:00:00Z", 
                "manualSetTime": "0001-01-01T00:00:00Z", 
                "firstSeenEntryID": "API", 
                "expirationStatus": "active", 
                "value": "2.2.2.2", 
                "expirationSource": {
                    "expirationInterval": 10080, 
                    "source": "indicatorType", 
                    "brand": "", 
                    "instance": "", 
                    "setTime": "2020-02-18T10:41:22.268125+02:00", 
                    "user": "", 
                    "expirationPolicy": "indicatorType", 
                    "moduleId": ""
                }, 
                "isIoc": true, 
                "expiration": "0001-01-01T00:00:00Z", 
                "context": null, 
                "createdTime": "2020-02-18T10:41:22.268133+02:00", 
                "manuallyEditedFields": [
                    "indicator_type"
                ], 
                "calculatedTime": "2020-02-18T10:41:22.268124+02:00", 
                "manualExpirationTime": "0001-01-01T00:00:00Z"
            }
        ], 
        "Enrichments": []
    }
}
```

##### Human Readable Output
### Indicators
|name|
|---|
| 1.1.1.1 |
| 2.2.2.2 |
