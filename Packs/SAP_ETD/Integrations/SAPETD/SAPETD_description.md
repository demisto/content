## SAP Enterprise Threat Detection

### Prerequisites

To be able to call the API, create a user in your SIEM solution with the following application privileges:
- `sap.secmon::Execute`
- `sap.secmon.ui::Execute`
- `sap.secmon::AlertRead`
- `sap.secmon::NormalizedLogRead`
- `sap.secmon::ResolveUserOnAlertService`

If you need to see the real users when pulling the alerts, you must also assign the `sap.secmon::ResolveUserOnAlertService` application privilege. Otherwise, you will see the user pseudonyms.

Configure your SIEM solution to send requests:
1. Set up a service using basic authentication or X.509 authentication. For basic authentication you need to send username and password of the user created in step 1.
2. Configure the service to send requests to the following address: `<protocol>://<host>:<port>/sap/secmon/services/Alerts.xsjs`
3. Configure the parameters as required.
