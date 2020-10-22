## Get Your Okta API Token

In order to use this integration, you need to enter your Okta API token in the **API Token** integration instance parameter. For information on getting your Okta API token, see the [Okta documentation](https://developer.okta.com/docs/api/getting_started/getting_a_token).

## Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration settings. By default, all commands are enabled.

## Add Custom Indicator Fields
Follow these steps to add custom fields to the User Profile indicator.

1. In XSOAR, create the custom indicator and incident field, for example, **Middle Name**.
2. Duplicate the **User Profile - Okta (Incoming)** mapper and/or the **User Profile - Okta (Outging)** mapper.
3. Add and map the custom field to the necessary mapper(s).
4. Go to the Okta IAM integration instance and in the mapper textbox, replace the name of the default mapper with the custom mapper you created.

## Update/Enable User Commands
These commands include the *create-if-not-exists* argument, which specifies if a new user should be created when the User Profile indicator passed does not fiFor both of these commands you 
