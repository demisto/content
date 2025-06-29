CybelAngel is a cybersecurity firm specializing in external attack surface protection and management.

## CybelAngel Authentication

The CybelAngel API uses the OAuth 2.0 protocol for authentication and authorization.

For each request sent to the API, a bearer token will be requested to authenticate your action.

You can retrieve your API credentials by following the instructions in the [CybelAngel developer documentation](https://developers.cybelangel.com/docs/cybelangel-platform-api/b6b6c2d4906e9-authentication#get-your-api-credentials).

## Get your API credentials

To request a token, the system will request your API credentials (client_id and client_secret).
Your API credentials are accessible in the Platform > Settings > API.

## CybelAngel Required Scopes

- To fetch reports, the api role required should be `reports.read`.

- To fetch the Credential watchlist, the api role required should be `credentials.read`

<~XSIAM>

## Required Modules

- Account Takeover Protection module is required for Credentials watchlist events.
  
- Domain Protection module is required for Domain watchlist events.

</~XSIAM>

## CybelAngel Rate Limits

You are limited to 2000 bearer tokens per month, each token is valid for a period of 1 hour.

This limitation should not affect fetching, as the integration uses an average of 720 tokens each month.

**Note:**

**If you use bearer tokens to interact with the CybelAngel API for other purposes outside of this integration, you could run out of bearer tokens before the end of the month. In that case, the integration will not continue to fetch.**
