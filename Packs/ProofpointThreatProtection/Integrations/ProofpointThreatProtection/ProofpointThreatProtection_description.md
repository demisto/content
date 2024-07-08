## Proofpoint Threat Protection

### Proofpoint Threat Protection Integration Setup

To setup the Proofpoint Threat Protection API XSOAR integration, a Threat Protection API Key and its associated secret must be configured, along with the associated Proofpoint clusterID. ([See API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management)) for more information regarding Proofpoint Threat Protection API key generation and management.

#### To Create a new Threat Protection API Key

1. From within the Proofpoint Admin Portal, navigate to the API Key Management section.
2. Click <b>+Create New</b>. The <b>Create New Threat Protection API Key</b> dialog box for the cluster appears.
3. Add a descriptive name for the key. 
4. Click <b>Generate Key</b> to create the key and secret.
5. The <b>Create New Threat Protection API Key</b> dialog box displays the key and secret for the currently-selected cluster. Click the page icon next to each cluster to copy the API key and Secret to the clipboard and store them in a safe place. The Secret will not be visible once you close this dialog box. <b>You will need the key and secret to obtain the authentication token for the API service</b>.

#### To Manage previously generated Threat Protection API Keys

1. From within the Proofpoint Admin Portal, navigate to the API Key Management section.
2. For each API key previously generated there is an ellipsis providing two choices of action: <b>Renew</b> and <b>Revoke</b>.
  - <b>Renew</b> will extend the key expiration for one more year.
  - <b>Revoke</b> will permanently remove the key and it cannot be restored.

#### Additional Notes regarding Threat Protection API Keys

- Your deployment must be running release 8.20.X or greater, and have cloud-based configuration management enabled.
- Threat Protection API will honor the key and secret for a 7-day grace period when it expires to give you a chance to <b>Renew</b> it before permanently expiring it.
- Creating keys and revoking keys are logged as events in the <b>Audit Logs</b>.

