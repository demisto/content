This integration supports both SAP Enterprise Threat Detection editions. Select the edition in the **SAP ETD Edition** parameter.

## On-Premise

Uses Basic authentication against the Alert Pull API (`/sap/secmon/services/Alerts.xsjs`). X.509 authentication is not supported.

1. Create a user with the following application privileges:
   - `sap.secmon::Execute`
   - `sap.secmon.ui::Execute`
   - `sap.secmon::AlertRead`
   - `sap.secmon::NormalizedLogRead`
   - `sap.secmon::ResolveUserOnAlertService` (shows real user names instead of pseudonyms)
2. Activate the alert publishing job `sap.secmon.framework.pattern.publishalerts.jobs::alertPublishingJob`. Without it, no alerts are published to external systems.
3. Configure the instance:
   - **Server URL**: `https://<Server_Host>:<Port>`
   - **Username / Client ID** and **Password / Client Secret**: the credentials of the user from step 1.

## Cloud Edition

Uses OAuth2 client credentials against the Data Retriever service (`/alerts/v1/Alerts`).

1. In the SAP BTP subaccount, add the entitlement **SAP Enterprise Threat Detection, Cloud Edition, Data Retriever**.
2. Create an instance of the Data Retriever service, then create a service binding (key) for it. The binding grants the `AlertsInformationRead` scope.
3. Configure the instance from the binding values:
   - **Server URL**: `url`
   - **Token URL (Cloud Edition only)**: `uaa.url`
   - **Username / Client ID**: `uaa.clientid`
   - **Password / Client Secret**: `uaa.clientsecret`
