Integration to PrivX installation can be used for fetching short term certificates for authenticating against target hosts or fetching secrets from PrivX secrets vault for administrative purposes. To allow fetching certificates, make sure you have the "Use with PrivX Agent" permission enabled in your role.

## Configure PrivX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PrivX.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your PrivX server address (FQDN or IP address) |  | True |
    | Your PrivX server HTTPS port |  | True |
    | OAuth client ID | default value "privx-external" recommended | True |
    | OAuth client secret |  | True |
    | API client ID |  | True |
    | API client secret |  | True |
    | PrivX CA certificate |  | True |
    | User's public key. Can be defined either here or as a parameter for each privx-get-cert request. |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### privx-get-cert

***
Fetches short-term SSH certificate via PrivX for accessing SSH target hosts. Connect to target with SSH client using received certificate and client's private key.

#### Base Command

`privx-get-cert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role-id | UUID of the PrivX role that is used for accessing the target host (Optional). | Optional | 
| username | Target host's username (Optional). Use either username or user id when fetching the certificate. | Optional | 
| hostname | Target host's hostname (Optional). Use either hostname or host-id when fetching the certificate. | Optional | 
| host-id | Target host's UUID (Optional). Use either host-id or hostname when fetching the certificate. | Optional | 
| public-key | User's public key. Required only if the public key was not configured in integration settings. | Optional | 
| service | Target host service (Optional). SSH, RDP or WEB. API clients can only fetch SSH certificates. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | SSH certificates. Copy the used certificate to a file and use it with private key to access target hosts: ssh -o CertificateFile=id_rsa-cert -i ~/.ssh/id_rsa targetuser@targethost | 

#### Command Example
!privx-get-cert username=xsoar hostname=10.1.12.15
!privx-get-cert username=xsoar hostname=10.1.12.15 service=SSH role-id=b4a9749e-bc9b-5e96-4c63-9bfd58b74e7b

### privx-get-secret

***
Fetches a secret from PrivX Secrets Vault.

#### Base Command

`privx-get-secret`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the secret to be fetched. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | Secret from the PrivX secrets vault | 


#### Command Example
!privx-get-secret name="the-secret"
