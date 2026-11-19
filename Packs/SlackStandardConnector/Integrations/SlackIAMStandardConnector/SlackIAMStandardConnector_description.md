## Get Your Slack API Token
In order to use this integration, you need to enter your Slack access token in the **Access Token** integration instance parameter.
The simplest way to acquire this token is for an Org Owner to create a new Slack app, add the admin OAuth scope, install the app, and use the generated token.

For more information on getting your Slack access token, see the [Slack Documentation](https://api.slack.com/scim#accessing-the-scim-api)

## Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration settings. By default, all commands are enabled.

## Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the User Profile passed was not found in the 3rd-party integration.