The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.

If you wish to use API Key authorization, please enter into the **Password** field your API key, and into the **Username** parameter **_api_key_id:** followed by your API key ID.
For example, for API Key with ID: _VuaCfGcBCdbkQm-e5aOx_ and key value: _ui2lp2axTNmsyakw9tvNnw_ you'll need to enter into username **_api_key_id:VuaCfGcBCdbkQm-e5aOx** and into password you'll need to enter the value: **ui2lp2axTNmsyakw9tvNnw**. For more info about API Key management see: https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html 

Strings are queried using the Lucene syntax. For more information about the Lucene syntax, see: https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax

For further information about request response fields, see: https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-body.html#request-body-search-explain

For further information about type mapping, see: https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type

The types of time-fields supported are:
    
   - **Simple-Date** - A simple date string. Requires inserting the format in which the field is saved. For more info about time formatting ,see: http://strftime.org/
   - **Timestamp-Second** - A number referring to seconds since epoch (midnight, 1 January 1970). For example: '1572164838'.
   - **Timestamp-Milliseconds** - A number referring to milliseconds since epoch (midnight, 1 January 1970). For example: '1572164838123'.

Note: Not all fields can be sorted in Elasticsearch. The fields are used to sort the results table.  The supported result types are boolean, numeric, date, and keyword fields.
