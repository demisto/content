The Elasticsearch Event Collector integration supports Elasticsearch 6.0.0 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Authentication

There are 3 different authentication [methods](https://www.elastic.co/docs/api/doc/elasticsearch#doc-authentication)

### Basic Auth (http)

To use **Basic Authentication**:

* Select **Basic Auth** from the *Authorization type* dropdown.
* Enter your **Username** in the *Username* field.
* Enter your **Password** in the *Password* field.

### API Key Auth (http_api_key)

To use **API Key Authentication**:

* Select **API Key Auth** from the *Authorization type* dropdown.
* Enter your **API key ID** in the *API key ID* field.
* Enter your **API key** in the *API key* field.

For more info about API Key management see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

**Note:** Alternatively, you can select the **Basic Auth** type and enter the API key ID in the *Username* field and the API key in the *Password* field.
Example:
for *API Key ID* kQme5aOx enter: _api_key_id:kQme5aOx
for *API Key* ui2lp2axT enter: ui2lp2axT

### Bearer Auth (http)

To use **Bearer Authentication**:

* Select **Bearer Auth** type from the *Authorization type* dropdown.
* Enter your **Username** in the *Username* field.
* Enter your **Password** in the *Password* field.

For more info see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-get-token.html#security-api-get-token-prereqs)

## Notes

* Not all fields can be used for sorting in Elasticsearch. Sorting is only supported for fields of the following types: **boolean**, **numeric**, **date**, and **keyword**.
* The "Test" button does not fully validate the fetch events functionality.

## Additional Configuration Parameters Details

Fetch events requires:

* Index
* Index time field
* Query String or Raw Query

For further information about type mapping, see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type).

**Query String**
Query String is queried using the Lucene syntax. For more information about Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).

**Raw Query**
Allows raw DSL queries. For more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).

**Time field type**
3 formats supported:

* Simple-Date - A plain date string. You must specify the format in which the date is stored. For more information about time formatting, see [here](http://strftime.org/).
* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: '1572164838'
* Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: '1572164838123'
