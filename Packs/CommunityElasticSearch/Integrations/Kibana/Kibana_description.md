## Kibana

This integration allows for using Elastic Security for SIEM for security operations management and searching Elastic logs.

The Kibana integration supports Elasticsearch 6.0.0 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1, and 9.3.1 of Elasticsearch.

## Authentication

There are 3 different authentication [methods](https://www.elastic.co/docs/api/doc/elasticsearch#doc-authentication)

### Basic Auth (http)

To use **Basic Authentication**:

* Choose the **Basic Auth** type from the *Authorization type* dropdown list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

### API Key Auth (http_api_key)

To use **API Key Authentication**:

* Choose the **API Key Auth** type from the *Authorization type* dropdown list.
* Enter your **API key ID** into the *API key ID* field.
* Enter your **API key** into the *API key* field.

For more info about API Key management see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

**Note:** Optionally, you can choose **Basic Auth** type and use the *Username* and *Password* fields to enter the API key ID and API key.
Example:
for *API Key ID* kQme5aOx enter: _api_key_id:kQme5aOx
for *API Key* ui2lp2axT enter: ui2lp2axT

### Bearer Auth (http)

To use **Bearer Authentication**:

* Choose the **Bearer Auth** type from the *Authorization type* dropdown list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

For more info see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-get-token.html#security-api-get-token-prereqs)

## Notes

* The "Test" button does not fully validate all command functionality. To ensure the commands are working correctly, run each one and validate that API permissions are sufficient.