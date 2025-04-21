The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

#### Authentication
* __Name__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter **_api_key_id:** followed by your API key ID).
* __Password__: Used for authentication via Username + Password or API ID + API Key (If you wish to use API Key authorization enter your API key).]()

To use API Key authorization, in the **Password** field enter your API key, and for the **Username** parameter enter **_api_key_id:** followed by your API key ID.
For example, for an API Key with ID: _VuaCfGcBCdbkQm-e5aOx_ and key value: _ui2lp2axTNmsyakw9tvNnw_ 
- for the Username, enter: **_api_key_id:VuaCfGcBCdbkQm-e5aOx**
- For the Password, enter: **ui2lp2axTNmsyakw9tvNnw**. 

For more info about API Key management see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

#### Instance Configuration

* __Server URL__: The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. By default this is 9200
* __Username foe server login__: Provide Username \+ Passoword instead of API key \+ API ID
* __Trust any certificate (not secure)__: Ignore HTTPS certificates.
* __Use system proxy settings__: Enable/Disable
* __Client type__: For Elasticsearch version 7 and below, select **Elasticsearch**. For Elasticsearch server version 8, select **Elasticsearch_v8**. In some hosted Elasticsearch environments, the standard Elasticsearch client is not supported. If you encounter any related client issues, consider using the **OpenSearch** client type.
* __Index from which to fetch incidents (CSV)|__
* __Query String__: The query will be used when fetching incidents. Index time field will be used as a filter in the query
* __Index Time Field__: The time field on which sorting and limiting are performed. If using a nested field, separate field names using dot notation.
* __Raw Query__: Will override the 'Query String' Lucene syntax string. Results will not be filtered.
* __Time Field Type__: Time field type used in the database.
* __Map JSON fields into labels__
* __First Fetch Time__: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days)
* __The maximum number of results to return per fetch__
* __Request timeout (in seconds)__
* __Incident type__
* __fetch incidents__: Enable/Disable


Query string is queried using the Lucene syntax. For more information about the Lucene syntax, see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax)

**Raw Query** allows raw DSL queries, see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

For further information about request response fields, see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-body.html#request-body-search-explain)

Fetch incidents requires:
    - Index
    - Index time field
    - Query String or Raw Query

For further information about type mapping, see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type)

The types of time-fields supported are:
    
   - **Simple-Date** - A simple date string. Requires inserting the format in which the field is saved. For more info about time formatting ,see: [http://strftime.org/](http://strftime.org/)
   - **Timestamp-Second** - A number referring to seconds since epoch (midnight, 1 January 1970). For example: '1572164838'.
   - **Timestamp-Milliseconds** - A number referring to milliseconds since epoch (midnight, 1 January 1970). For example: '1572164838123'.

Notes:
- Not all fields can be sorted in Elasticsearch. The fields are used to sort the results table.
  The supported result types are boolean, numeric, date, and keyword fields.
- The integration test button doesn't fully test the fetch incidents validity. To verify that the instance is set up correctly for fetching incidents, run the ***!es-integration-health-check*** command.
