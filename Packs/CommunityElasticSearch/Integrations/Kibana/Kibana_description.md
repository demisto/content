## Kibana

## Authentication

There are 3 different authentication [methods](https://www.elastic.co/docs/api/doc/elasticsearch#doc-authentication).

### Basic Auth (http)

To use **Basic Authentication**:

1. Choose the **Basic Auth** type from the *Authorization type* dropdown list.
2. Enter your **Username** into the *Username* field.
3. Enter your **Password** into the *Password* field.

### API Key Auth (http_api_key)

To use **API Key Authentication**:

1. Choose the **API Key Auth** type from the *Authorization type* dropdown list.
2. Enter your **API key ID** into the *API key ID* field.
3. Enter your **API key** into the *API key* field.

To create an API key in Kibana:

1. Log in to Kibana.
2. Open the main menu and go to **Stack Management** > **API keys**.
3. Click **Create API key**.
4. Enter a name for the API key and configure the desired settings.
5. Click **Create API key**.
6. Copy the **API key ID** and **API key** values, as the API key is shown only once.

Alternatively, create an API key via the [Create API key API](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html).

**Note:** Optionally, you can choose **Basic Auth** type and use the *Username* and *Password* fields to enter the API key ID and API key.

**Example:**

* For *API Key ID* `kQme5aOx` enter: `_api_key_id:kQme5aOx`
* For *API Key* `ui2lp2axT` enter: `ui2lp2axT`

### Bearer Auth (http)

To use **Bearer Authentication**:

1. Choose the **Bearer Auth** type from the *Authorization type* dropdown list.
2. Enter your **Username** into the *Username* field.
3. Enter your **Password** into the *Password* field.

The integration uses the supplied username and password to obtain a bearer token from Elasticsearch via the Get token API. Before using Bearer Authentication, ensure the token service is enabled on your Elasticsearch cluster:

1. Enable TLS on the HTTP interface of your Elasticsearch cluster (required for the token service).
2. Confirm that `xpack.security.authc.token.enabled` is set to `true` in your Elasticsearch configuration (this is the default when TLS is enabled).

For more information, see the [Get token API documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-token.html#security-api-get-token-prereqs).

## Notes

* The "Test" button does not fully validate all command functionality. To ensure the commands are working correctly, run each one and validate that API permissions are sufficient.