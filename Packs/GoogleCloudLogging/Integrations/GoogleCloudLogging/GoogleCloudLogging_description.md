## Google Cloud Logging Help
### Scope
We need to provide the below mentioned OAuth scope to execute the commands: https://www.googleapis.com/auth/cloud-platform.
 
### Create a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.
2. Grant the mentioned OAuth scope https://www.googleapis.com/auth/logging.read to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. Grant The service account access to the resource (project/folder/organization/billing) and assign the permission in the GCP IAM level to the service account.
4. Authorization requires one or more of the following IAM permissions on the specified resource:
   logging.logEntries.list
   logging.privateLogEntries.list
   logging.views.access
5. [Enable the Logging API](https://cloud.google.com/logging/docs/api/enable-api)
6. In Cortex XSOAR, configure an instance of the Google Cloud Logging integration. For the Service Account JSON parameter, add the Service Account Private Key file contents (JSON).



