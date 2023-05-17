## Google Cloud Logging Help
### Scope
We need to provide the below mentioned OAuth scope to execute the commands: 
https://www.googleapis.com/auth/cloud-platform.
 
### Create a Service Account
   Go to the [Google documentation](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.

### Grant Permissions
1. Grant one of the following OAuth scopes to the Service Account
   https://www.googleapis.com/auth/logging.read
   https://www.googleapis.com/auth/logging.admin
   https://www.googleapis.com/auth/cloud-platform.read-only
   https://www.googleapis.com/auth/cloud-platform
   to enable the Service Account to perform certain Google Cloud API commands.
2. Grant The service account access to the resource (project/folder/organization/billing) and assign the permission in the GCP IAM level to the service account.
3. Authorization requires one or more of the following IAM permissions on the specified resource:
   logging.logEntries.list
   logging.privateLogEntries.list
   logging.views.access
4. [Enable the Logging API](https://cloud.google.com/logging/docs/api/enable-api)
5. In Cortex XSOAR, configure an instance of the Google Cloud Logging integration. For the Service Account JSON parameter, add the Service Account Private Key file contents (JSON).
   
More information about creating the required resources can be found here:
* [Create a Project](https://cloud.google.com/resource-manager/docs/creating-managing-projects)
* [Enable Google APIs](https://developers.google.com/workspace/guides/enable-apis)
* [Create a Service Account & Service Account Key](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount)



