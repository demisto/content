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

## Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the User Profile passed was not found in the 3rd-party integration.

## Fetch incidents using an "IAM - Configuration" incident
When the "Query only application events configured in IAM Configuration" checkbox is selected, add or remove event types for the applications you configured in the **IAM Configuration** incident are retrieved.  You must have at least one application configured in XSOAR to fetch incidents from Okta.

## Fetch incidents using a manual query filter expression
**Note: Cortex XSOAR recommends you use the Query only application events configured in IAM Configuration option to generate the fetch-incidents query filter. The following following method should be used primarily for debugging purposes.**
Clear the "Query only application events configured in IAM Configuration" checkbox to use a custom fetch query filter expression. The expression must be in SCIM syntax, and include the add and remove event types, as well as the application ID. 
For example: `(eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove") and target.id eq "0oar418fvkm67MWGd0h7"`
You may also use the advanced search in Okta's System Logs to generate the filter expression.
For more details, visit [Okta API reference](https://developer.okta.com/docs/reference/api/system-log/#expression-filter).
