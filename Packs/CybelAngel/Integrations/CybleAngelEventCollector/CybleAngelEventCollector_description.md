CybelAngel is a cybersecurity firm specializing in external attack surface protection and management. 


## CybleAngel EventCollector Authentication
CybelAngel API uses the OAuth 2.0 protocol for authentication and authorization.

For each request on for the API, a Bearer token will be requested to authenticate your action.

You can retrieve the API credentials following instructions from [here](https://developers.cybelangel.com/docs/cybelangel-platform-api/b6b6c2d4906e9-authentication#get-your-api-credentials)

## CybleAngel EventCollector Rate Limits
You are limited to 2000 bearer tokens/month, each token is valid for a period of 1 hour.

This limitation should not affect fetching, **however if the api is used by other sources which require bearer tokens, that could make the integration to not function properly**

The integration uses on average 720 tokens every month.

