## Trello (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page.

### Authentication

The connector authenticates to Trello with an **API key and token** (a username / password
connection profile):

- **Username**: your Trello API key.
- **Password**: a Trello user token generated for that API key.

Both values are sent to Trello as the `key` and `token` query parameters on every request.
Retrieve the API key from https://trello.com/app-key and authorize a token for it. The
token must have `read` and `write` access to the boards the integration works with (`read`
is enough for fetching incidents only).

For more information, see the
[Trello REST API documentation](https://developer.atlassian.com/cloud/trello/guides/rest-api/api-introduction/).
