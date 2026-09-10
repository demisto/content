## Prerequisites

1. Create a user in your SIEM solution with the following application privileges:
   - `sap.secmon::Execute`
   - `sap.secmon.ui::Execute`
   - `sap.secmon::AlertRead`
   - `sap.secmon::NormalizedLogRead`
   - `sap.secmon::ResolveUserOnAlertService`

2. To view actual usernames instead of pseudonyms, assign the sap.secmon::ResolveUserOnAlertService privilege.

3. Configure your SIEM solution to send requests.
   1. Configure the service using basic or X.509 authentication. For basic authentication, provide the credentials for the user created in step 1.
   2. Configure the service to send requests to the following endpoint: `<protocol>://<host>:<port>/sap/secmon/services/Alerts.xsjs`
   3. Configure the parameters as required.
