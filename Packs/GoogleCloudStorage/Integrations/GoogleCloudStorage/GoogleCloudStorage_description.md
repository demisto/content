Create a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file in step 3.
2. Grant the Storage Admin permission to the Service Account to enable the Service Account to perform all Google Storage API commands.
3. In Cortex XSOAR, configure an instance of the Google Cloud Storage integration. For the Service Account Private Key parameter, copy the JSON contents of the file you downloaded in step 1.
