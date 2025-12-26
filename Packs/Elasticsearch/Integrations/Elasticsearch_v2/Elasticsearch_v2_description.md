The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Authentication

There are 3 different authentication [methods](https://www.elastic.co/docs/api/doc/elasticsearch#doc-authentication)

### Basic Auth (http)

To use **Basic Auth Authentication**:

* Choose the **Basic Auth** type from the *Authorization type* drop down list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

### API Key Auth (http_api_key)

To use **API Key Authentication**:

* Choose the **API Key Auth** type from the *Authorization type* drop down list.
* Enter your **API key ID** into the *API key ID* field.
* Enter your **API key** into the *API key* field.

For more info about API Key management see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

**Note:** You can optionally use the *Username* and *Password* fields to enter the API key ID and API key. See the hint note on the configuration page for more details.

### Bearer Auth (http)

To use **Bearer Auth Authentication**:

* Choose the **Bearer Auth** type from the *Authorization type* drop down list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

For more info see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-get-token.html#security-api-get-token-prereqs)

Fetch incidents requires: Index - *Index time* field - Query String or Raw Query.
Query string is queried using the Lucene syntax. For more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).

Raw Query allows raw DSL queries, see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).

For further information about type mapping, see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type).

Notes:

* Not all fields can be used for sorting in Elasticsearch. Sorting is only supported for fields of the following types: **boolean**, **numeric**, **date**, and **keyword**.
* The "Test" button does not fully validate the fetch incidents functionality. To ensure the instance is correctly configured for fetching incidents, run the *!es-integration-health-check* command

## Additional Configuration Parameters Details

**Username**
Use for Basic auth username. Optionally you can use this field as an *API key ID* for *API Key auth*. Example: for *API Key ID* kQme5aOx enter: _api_key_id:kQme5aOx

**Password**
Use for Basic auth password. Optionally you can use this field as an *API key* for *API Key auth*. Example: for *API Key* ui2lp2axT enter: ui2lp2axT

**Query String**
for more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax)

**Raw Query**
for more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

**Time field type**
3 formats supported:

* Simple-Date - A plain date string. You must specify the format in which the date is stored. For more information about time formatting, see [here](http://strftime.org/)
* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: ‘1572164838’
* Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: ‘1572164838123’
