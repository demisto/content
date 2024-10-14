# WALLIX Bastion integration for Palo Alto XSOAR

This integration provides partial access to the WALLIX Bastion administration API v3.12.

This includes management of users, accounts, devices, sessions, passwords and more.

To use this integration, you can provide a user/password or create an API key on your Bastion appliance.

Go to `Configuration` > `API Keys` to create one.

> Note: using an API key rather than a password allows unrestricted administrative access to the Bastion.

## Configure the API version

This integration is based on the API 3.12 available since Bastion 10.4.

Some commands may still work on older versions of the API. The version used can be configured in the integration parameters.

You can leave the field `api_version` empty to use the latest available API on your Bastion appliance.

To use another version of the API, it is recommended to check the changes made since that version on the API resource related to the command used.

Please note that some features of the API 3.12 are only available to the most recent Bastion versions (12+). You should test each command manually to make sure it is well supported before using it in automation playbooks.

**API endpoints and changes between API versions are documented under the help section in `REST API documentation` (https://my-example-bastion.com/api/doc/Usage.html).**

## Bugs and feature requests

If you encounter an unexpected error while using this integration, first make sure that the feature you want to use is documented in the REST API documentation of your Bastion appliance.

Otherwise, or if you would like to submit a feature request, please contact the WALLIX Customer Success team.