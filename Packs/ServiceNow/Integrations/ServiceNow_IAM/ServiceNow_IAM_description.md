## Prerequisites
To use ServiceNow in XSOAR, ensure your user account has the `rest_api_explorer`, `web_service_admin` roles or any other role required to permit working with the `sys_user` table. These roles are required in order to make API calls. However, they may not suffice for viewing records in some tables.

## Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration settings. By default, all commands are enabled.

## Add Custom Indicator Fields
Follow these steps to add custom fields to the User Profile indicator.

1. In XSOAR, create the custom indicator and incident field, for example, **Middle Name**.
2. Duplicate the **User Profile - ServiceNow (Incoming)** mapper and/or the **User Profile - ServiceNow (Outging)** mapper.
3. Add and map the custom field to the necessary mapper(s).
4. Go to the ServiceNow IAM integration instance and in the mapper textbox, replace the name of the default mapper with the custom mapper you created.

## Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the User Profile passed was not found in the 3rd-party integration.
