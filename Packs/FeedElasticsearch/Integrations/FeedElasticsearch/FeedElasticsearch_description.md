### Setting up the integration
* __Server URL__: Elasticsearch database URL. 
* __Client type__: For Elasticsearch version 7 and below, select **Elasticsearch**. For Elasticsearch server version 8, select **Elasticsearch_v8**. In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the **OpenSearch** client type.
* __Trust any certificate (not secure)__: Ignore HTTPS certificates.
* __Use system proxy settings__: Enable/Disable
* __Fetch indicators__: Enable/Disable
* __First Fetch Time__: Determine how far to look back for fetched indicators (<number> <time unit>, e.g., 12 hours, 7 days).
* __Indicator Reputation__: Indicators from this integration instance will be marked with this reputation.
* __Source Reliability__: Reliability of the source providing the intelligence data.
* __Indicator Value Field__: Source field that contains the indicator value in the index. Relevant for generic feed type only.
* __Indicator Type Field__: Source field that contains the indicator type in the index. Relevant for generic feed type only.
* __Indicator Type__: Default indicator type used in case no "Indicator Type Field" was provided. Relevant for generic feed type only.
* __Index From Which To Fetch Indicators__: A comma-separated list of indexes. If empty, searches all indexes.
* __Time Field Type__: Time field type used in the database.
* __Index Time Field__: Used for sorting sort and limiting data. If left empty, no sorting is applied. Relevant for generic feed type only.
* __Query__: Elasticsearch query to execute when fetching indicators from Elasticsearch.

#### Authentication
* __Name__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter **_api_key_id:** followed by your API key ID).
* __Password__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter your API key).]()

If you wish to use API Key authorization, please enter into the **Password** field your API key, and into the **Name** parameter **_api_key_id:** followed by your API key ID.
For example, for API Key with ID: _VuaCfGcBCdbkQm-e5aOx_ and key value: _ui2lp2axTNmsyakw9tvNnw_ you'll need to enter into name **_api_key_id:VuaCfGcBCdbkQm-e5aOx** and into password you'll need to enter the value: **ui2lp2axTNmsyakw9tvNnw**. For more info about API Key management see: https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html

#### Feed Type
Fetch indicators stored in an Elasticsearch database. 
1. The Cortex XSOAR Feed contains system indicators saved in an Elasticsearch index. 
2. The Cortex XSOAR MT Shared Feed contains indicators shared by a tenant account in a multi-tenant environment. 
3. The Generic Feed contains a feed in a format specified by the user.
