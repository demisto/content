## Configure API Credentials
To configure an instance of the integration in Demisto, you will need to provide a Devo apiv2 OAuth token with `*.**`
permissions for the time being if you want the fetch incidents to work correctly. Otherwise only grant access to particular
tables but `siem.logtrust.alert.info` is used when fetching alerts.

If writing back to Devo make sure to also create a set of TLS credentials.

### Get your Demisto OAuth Token
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __Authentication Tokens__.
3. If a token for Demisto has not already been  created, Click __CREATE NEW TOKEN__
  * Create the Token with `*.**` table permissions as an `apiv2` token.
4. Note the generated `Token`

### Get your Demisto Writer Credentials
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __X.509 Certificates__.
3. Click `NEW CERTIFICATE` if you do not already have a set of keys for Demisto.
4. Download the following files:
  * `Certificate`
  * `Private Key`
  * `CHAIN CA`
