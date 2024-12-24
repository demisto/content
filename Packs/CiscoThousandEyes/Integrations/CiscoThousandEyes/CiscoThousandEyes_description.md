# Cisco ThousandEyes Event Collector

Use this integration to fetch audit logs, and alerts from **Cisco ThousandEyes** as events in Cortex XSIAM.

_____
## Creating a User API Token in Cisco ThousandEyes
Before you configure the integration, retrieve the User API Token from your Cisco ThousandEyes account:

For users with API access enabled (i.e., users with the API access permission), the User API Tokens section is visible, containing the API authentication tokens.

Two types of API authentication token are available: a token for HTTP Basic authentication and a token for OAuth-based authentication.

To issue or regenerate a user API token, you will need to receive and enter a multi-factor authentication (MFA) code sent to the email attached to the current user, to confirm the user permissions.

Click [here](https://docs.thousandeyes.com/product-documentation/user-management/rbac#user-api-tokens) for User API Tokens documentation.

## Note:
>This API returns a list of activity log events **in the current account group**.