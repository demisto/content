### Setting up the integration
* __Server URL__: Elasticsearch database URL. 
* __Trust any certificate (not secure)__: Ignore HTTPS certificates.
* __Use system proxy settings__: Enable/Disable
* __Fetch indicators__: Enable/Disable
* __First Fetch Time__: Determine how far to look back for fetched indicators (<number> <time unit>, e.g., 12 hours, 7 days).
* __Indicator Reputation__: Indicators from this integration instance will be marked with this reputation.
* __Source Reliability__: Reliability of the source providing the intelligence data.
* __Indicator Value Field__: Source field that contains the indicator value in the index.
* __Indicator Type Field__: Source field that contains the indicator type in the index.
* __Indicator Type__: Default indicator type used in case no "Indicator Type Field" was provided.
* __Index From Which To Fetch Indicators__: A comma-separated list of indexes. If empty, searches all indexes.
* __Time Field Type__: Time field type used in the database.
* __Index Time Field__: Used for sorting sort and limiting data. If left empty, no sorting is applied.
* __Query__: Elasticsearch query to execute when fetching indicators from Elasticsearch.

#### Authentication
* __Name__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter **_api_key** here).
* __Password__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter you API ID here).

If you wish to use API Key authorization, please enter into the **Password** field your API id, and into the **Username** parameter **_api_key** followed by your API key.
For example, for API key:cortexKey and API ID:cortexID you'll need to enter into username _api_keycortexKey and into password you'll need to enter cortexID.  

#### Feed Type
Fetch indicators stored in an Elasticsearch database. 
1. The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. 
2. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. 
3. The Generic Feed contains a feed in a format specified by the user.
