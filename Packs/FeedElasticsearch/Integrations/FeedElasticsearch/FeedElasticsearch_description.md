* __Server URL__: Elasticsearch database URL. 
* __Username__: Used for authentication via Username + Password.
* __Password__: Used for authentication via Username + Password.
* __API Key__: Used for authentication via API ID + API Key.
* __API ID__: Used for authentication via API ID + API Key.
* __Trust any certificate (not secure)__: Ignore HTTPS certificates.
* __Use system proxy settings__: Enable/Disable
* __Feed Type__: Choose the feed type saved into the Elasticsearch database. Cortex XSOAR Feed are indicators saved by Cortex XSOAR in an Elasticsearch
    configured environment. Cortex XSOAR MT Shared Feed are indicators shared by a
    tenant account in a multi-tenant environment. Generic Feed is a feed in a format dictated by the user
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
