## Proofpoint Threat Protection
<b>Note:</b> Your deployment must be running release 8.20.X or greater, and have cloud-based configuration management enabled. In addition, before you can use the Threat Protection APIs, you need to create the key and secret to obtain a token from the Proofpoint authentication service. [See API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management)

Use the key and secret generated from the Admin Portal ([See API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management)) to generate an authentication token. The token is valid for 1 hour.

Click the <b>+Create New</b> button to display the <b>Create New Threat Protection API Key</b> dialog box for the cluster. Add a descriptive name for the key. The Cluster ID and Expiration Date for the key display in the dialog box. Keys are valid for one year from the date they are generated. Click <b>Generate Key</b> to create the key and secret.
- <b>Note</b>: Threat Protection API will honor the key and secret for a 7-day grace period when it expires to give you a chance to <b>Renew</b> it before permanently expiring it.
- The ellipsis menu for each key provides two choices: <b>Renew</b> and <b>Revoke</b>. <b>Renew</b> will extend the key expiration for one more year. <b>Revoke</b> will permanently remove the key and it cannot be restored.

The <b>Create New Threat Protection API Key</b> dialog box displays the key and secret for the currently-selected cluster. Copy the API key and Secret to the clipboard by clicking the page icon next to each and store these in a safe place. The Secret will not be visible once you close this dialog box. <b>You will need the key and secret to obtain the authentication token for the API service</b>.

Creating keys and revoking keys are logged as events in the <b>Audit Logs</b>.

---
View Integration Documentation
