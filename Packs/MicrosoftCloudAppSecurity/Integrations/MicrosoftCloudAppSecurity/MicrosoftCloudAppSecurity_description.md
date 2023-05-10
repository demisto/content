Microsoft Cloud App Security is a Cloud Access Security Broker that supports various deployment modes including log collection, API connectors, and reverse proxy. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your Microsoft and third-party cloud services.
##### There are three ways to authenticate to the Microsoft Cloud App Security:

1. *Client Credentials Flow*.
2. *Device Code Flow*.
3. *By token (legacy method)*. 

In order to use the ***microsoft-cas-files-list*** command, you must use with the legacy Ahtentication.

### Client Credentials Flow
___

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following 
[Microsoft article](https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application#create-an-app).
To connect to the Microsoft Cloud App Security:
1. In the instance configuration, select in the *Authentication Mode* parameter ***Client Credentials***.
2. Enter your Client/Application ID in the ***Application ID*** parameter. 
3. Enter your Client Secret in the ***Password*** parameter.
4. Enter your Tenant ID in the ***Tenant ID*** parameter.


### Device Code Flow
___

To use a Device Code Flow, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en&#45;us/defender&#45;cloud&#45;apps/api&#45;authentication&#45;user).
To connect to the Microsoft Cloud App Security:
1. Fill in the required parameters.
2. Run the ***!microsoft-cas-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-cas-auth-complete*** command.
At the end of the process you'll see a message that you've logged in successfully.
   
#### Required Permissions
*Make sure to provide the following permissions for the app to work with Microsoft Cloud App Security:*
 - ***Discovery.manage*** - https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application#supported-permission-scopes
 - ***offline_access*** - only when using the Device Code flow.

### By token (legacy method)
To access the Microsoft Cloud App Security API, you need to grant authorization.
See the [Microsoft documentation](https://docs.microsoft.com/en-us/cloud-app-security/api-authentication) to view a detailed explanation of how to create the Server URL and User key (token).

## Custom Filters
To filter the call results of the API, make sure it matches the Microsoft Cloud App Security filtering format. Click [here](https://docs.microsoft.com/en-us/cloud-app-security/api-alerts#filters) for details.

