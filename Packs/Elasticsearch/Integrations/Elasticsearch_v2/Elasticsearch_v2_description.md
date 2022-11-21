The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.

To use API Key authorization, in the **Password** field enter your API key, and for the **Username** parameter enter **_api_key_id:** followed by your API key ID.
For example, for an API Key with ID: _VuaCfGcBCdbkQm-e5aOx_ and key value: _ui2lp2axTNmsyakw9tvNnw_ 
- for the Username, enter: **_api_key_id:VuaCfGcBCdbkQm-e5aOx**
- For the Password, enter: **ui2lp2axTNmsyakw9tvNnw**. 

For more info about API Key management see: [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

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

Note: Not all fields can be sorted in Elasticsearch. The fields are used to sort the results table.  The supported result types are boolean, numeric, date, and keyword fields.
