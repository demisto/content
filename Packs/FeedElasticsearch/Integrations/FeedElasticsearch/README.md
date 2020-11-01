## Overview
---

Fetch indicators stored in an Elasticsearch database. 
1. The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. 
2. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. 
3. The Generic Feed contains a feed in a format specified by the user.

## Configure ElasticsearchFeed on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SharedTenantElasticsearchFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Server URL__: Elasticsearch database URL. 
    * __Name__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter **_api_key_id:** followed by your API key ID).
    * __Password__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter your API key).    
    * __Trust any certificate (not secure)__: Ignore HTTPS certificates.
    * __Use system proxy settings__: Enable/Disable
    * __Feed Type__: Choose the feed type saved into the Elasticsearch database. Cortex XSOAR Feed are indicators saved by Cortex XSOAR in an Elasticsearch
        configured enviornment. Cortex XSOAR MT Shared Feed are indicators shared by a
        tenant in a MT env. Generic Feed is a feed in a format dictated by the user
    * __Fetch indicators__: Enable/Disable
    * __First Fetch Time__: Determine how far to look back for fetched indicators (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days).
    * __Indicator Reputation__: Indicators from this integration instance will be marked with this reputation.
    * __Source Reliability__: Reliability of the source providing the intelligence data.
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp.
    * __Indicator Value Field__: Source field that contains the indicator value in the index.
    * __Indicator Type Field__: Source field that contains the indicator type in the index.
    * __Indicator Type__: Default indicator type used in case no "Indicator Type Field" was provided
    * __Index From Which To Fetch Indicators__: Multiple indices may be used by separating them with a comma. If none is provided, will search in all indices
    * __Time Field Type__: Time field type used in the database.
    * __Index Time Field__: Used for sorting sort and limiting data. If left empty, no sorting will be done.
    * __Query__: Elasticsearch query to be executed when fetching indicators from Elasticsearch.
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
