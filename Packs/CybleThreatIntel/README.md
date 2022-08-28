Cyble Threat Intel is an integration which will help users to fetch Cyble's TAXII Feed service into XSOAR Environment. User needs to contact their Cyble Account Manager for getting required pre-requisites to access the Cyble's TAXII Feed Service.

## Configure Cyble Threat Intel on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cyble Threat Intel.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators
    fetched from the feed
    * __Discovery Service__: TAXII discovery service endpoint.
    * __Collection__: Collection name to fetch indicators from.
    * __Username__: Username/Password (if required)
    * __First Fetch Time__: The time interval for the first fetch (retroactive). Maximum of 7 days for retroactive value is allowed.
    * __Indicator Fetch Limit__: The value to limit the indicator to be fetched per iteration

4. Click __Test__ to validate the URLs, token, and connection.
 
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

This integration provides following command(s) which can be used to access the Threat Intelligence

### cyble-vision-fetch-taxii

***
Fetch the indicators based on the taxii service

#### Base Command

`cyble-vision-fetch-taxii`

#### Input

| **Argument Name** | **Description**                                                                                        | **Required** |
|-------------------|--------------------------------------------------------------------------------------------------------| --- |
| limit             | Number of records to return, default value will be 50. Using a smaller limit will get faster responses. | Optional | 
| begin             | Returns records starting with given datetime (Format: %Y-%m-%d %H:%M:%S))                              | Optional | 
| end               | Returns records starting with given datetime (Format: %Y-%m-%d %H:%M:%S))                              | Optional | 
| collection        | Collection name to fetch indicators from                                                               | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleIntel.Threat.details | String | Returns the Threat Intel details from the Taxii service  | 

### cyble-vision-get-collection-names

***
Fetch the available collection name for the taxii service

#### Base Command

`cyble-vision-get-collection-names`

#### Context Output

| **Path**                      | **Type** | **Description**                                |
|-------------------------------| --- |------------------------------------------------|
| CybleIntel.collection.names | String | Available collection names for the feed service | 