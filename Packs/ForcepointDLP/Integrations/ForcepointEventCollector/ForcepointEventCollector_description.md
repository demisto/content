## Forcepoint Event Collector

Use this integration to collect activity logs automatically from Forcepoint DLP.

In order to use this integration, you need to enter your Forcepoint DLP credentials in the relevant integration instance parameters.

### Username and Password

#### Before you can connect to the Forcepoint DLP REST APIs.
* you need to create a new Application administrator in the Forcepoint Security Manager to create the username and password for authentication to be used in order to get a JSON Web Token (JWT) that allows you to send API requests.

##### Registering an Application in the Forcepoint Security Manager

To connect an application to Forcepoint DLP through a REST API connection, you need to create an Application administrator in the Forcepoint Security Manager.
1. On the Global Settings > General > Administrators settings page, select Add **Local Account**.
2. On the **Add Local Account** page, add the information for the administrator account, then select the **Application** option for the **Administrator type**.
3. Click **OK** to save the new account.
   
* For more information, see the [Enabling access to the Security Manager](http://www.websense.com/content/support/library/shared/v86/manager/admin%20access.aspx) topic in the Forcepoint Security Manager Help.
