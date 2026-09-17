## Netskope - Direct to Zero Trust

Use this integration to manage Netskope URL lists, file hash lists, destination and network
profiles, device classification, private applications, file inspection, and URL reputation.

### Configure the integration

1. In Netskope, create a REST API v2 token with the least privileges required for the commands
   you plan to use. Destination Profile operations require read access for GET commands,
   read/write access for create and update commands, and read/write/apply access for deployment.
   Device Classification commands require Manage permission for Device Classification and
   Devices, and View permission for CCI. Some APIs are beta or license restricted; contact your
   Netskope account team if an endpoint is not enabled for the tenant.
2. If you will use ***netskopev2-update-file-hash-list***, create a separate Netskope API v1 token.
   This legacy endpoint does not use the API v2 key and replaces the entire file hash list.
3. In Cortex XSOAR, create an instance of **Netskope - Direct to Zero Trust** and enter:
   - The tenant URL, for example `https://tenant.goskope.com`.
   - The API v2 key in **API Key**.
   - The API v1 token in **API v1 Token** only when file hash list commands are required.
4. Select **Test** to verify connectivity and authentication.

The API v1 token is sent to the legacy Netskope endpoint as its required query parameter. Protect
integration logs and rotate the token according to your organization's credential policy.