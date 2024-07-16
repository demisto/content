Code42 Insider Risk software solutions provide the right balance of transparency, technology and training to detect and appropriately respond to data risk. Use the Code42EventCollector integration to fetch file events and audit logs.

## Code42 Event Collector Authentication

Code42 API uses the OAuth 2.0 protocol for authentication and authorization.

The domain used for making API requests can be determined using the domain you use to log in to the Code42 console.

| Console Domain      | API Domain         |
|---------------------|--------------------|
| console.us.code42.com | api.us.code42.com  |
| console.us2.code42.com | api.us2.code42.com |
| console.ie.code42.com | api.ie.code42.com  |
| console.gov.code42.com | api.gov.code42.com |


For each request sent to the API, a bearer token will be requested to authenticate your action. The bearer token should be renewed each 15 minutes. This is done automatically by the integration.

You can retrieve your API credentials by following the instructions in the [Code 42 documentation](https://support.code42.com/hc/en-us/articles/14827617150231).

## Code42 Event Collector Rate Limits
The Code42 API can handle up to 120 requests per minute. After that the API will start to reject a client's requests.

The integration with the default configuration should not raise any rate-limits.


## Code42 Event Collector Required Scopes
To use the Code42 Event Collector, make sure you have the correct [product plan](https://support.code42.com/hc/en-us/articles/14827648467351-About-Code42-product-plans) which must include full Code42 API access.
