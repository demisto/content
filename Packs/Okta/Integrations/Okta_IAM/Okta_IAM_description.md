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

## Fetch incidents using an "IAM - Configuration" incident
When the "Query only application events configured in IAM Configuration" checkbox is marked, the query filter expression for Okta's logs API request will be automatically generated, such that only events of addition/removal of users to/from **configured applications** will be retrieved. In this case, it is required to create an "IAM - configration" incident and connect at least one Okta application to an IAM instance in XSOAR in order to fetch incident from Okta.

## Fetch incidents using a manual query filter expression
**Note: We recommend to use the above method to generate the fetch-incidents query filter.** Use the following method for debugging purposes.
Unmark the "Query only application events configured in IAM Configuration" checkbox if you wish to use a custom fetch query filter expression, in SCIM syntax. 
For example: `(eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove") and target.id eq "0oar418fvkm67MWGd0h7"`
You may also use the advanced search in Okta's System Logs to generate the filter expression.
For more details, visit [Okta API reference](https://developer.okta.com/docs/reference/api/system-log/#expression-filter).
