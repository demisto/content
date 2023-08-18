# WALLIX Bastion integration for Palo Alto XSOAR

This integration provides access to the WALLIX Bastion administration API v3.12.

This includes management of users, accounts, devices, sessions and passwords.

To use this integration, you must create an API key on your Bastion appliance.

Go to `Configuration` > `API Keys` to create one.

## Configure the API version

This integration is based on the API 3.12 available since Bastion 10.4.

It may still work on older versions of the API. The version used can be configured in the integration parameters.

You can leave the field `api_version` empty to use the latest available API on your Bastion appliance.

To use another version of the API, it is recommended to check the changes made since that version on the API resource related to the command used.

Changes between API versions are documented under the help section in `REST API documentation`.
