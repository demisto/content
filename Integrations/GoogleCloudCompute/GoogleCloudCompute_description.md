Create a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Credentials file is downloaded. You will need the information in this file when configuring an instance of the integration.
2. Grant the Compute Admin permission to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. In Demisto, configure an instance of the Google Cloud Compute integration. Copy each value in the Service Account Credentials file to its corresponding integration parameter (without quotation marks).

