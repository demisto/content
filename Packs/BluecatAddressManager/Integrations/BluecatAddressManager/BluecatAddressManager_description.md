**This integration supports Bluecat Address Manager version 9.1, Other versions might fail to run.**

When you configure an instance of the Bluecat Address Manager integration in Cortex XSOAR, you need to provide an API user account.

## Generate an API user account

1. Using the Address Manager web interface, log in to Address Manager as an administrator.
2. On the Administration page, click **Users and Groups**.
3. In the **Users** section, click **New**.
4. Enter a name in the **Username** field.
5. In the **Authentication** section, type and confirm the API user password in the **Password and ConfirmPassword** fields. If external authenticators are available, an **Other** checkbox and a list of authenticators appears in the **Authentication** section. To use an external authenticator for the API user, select the **Other** checkbox, and then select an authenticator from the list.
6. In the **Extra Information** section, set the following parameters for the API user. 
    - E-mail Address (required) 
    - Phone number (optional)
7. In the **User Access** section, define the user type, security, and history privileges, and access type.
    - Type of User: select either Non-Administrator or Administrator. Non-Administrator users have access only to DNS and IPAM management functions. Administrator users have unlimited access to all Address Manager functions.
    - Security Privilege: select a security privilege type from the drop-down list. This field is available only for Non-Administrator users with GUI, API, or GUI and API access.
    - History Privilege: select a history privilege type from the drop-down list. This field is available only for Non-Administrator users with GUI, or GUI and API access.
    - Access Type: select the type of access; GUI, API, or GUI and API. GUI users can access Address Manager only through the Address Manager web interface. API users can access Address Manager only through the API. GUI and API users can access Address Manager either through the Address Manager web interface or the API.
8. In the **Assign to Group** section, To assign the user to one or more existing user groups, go to Assign to Group section, and enter the name of a use group. Select a name from the list, and then click **Add**.
9. (optional) In the **Change Control** section, add comments to describe the changes. Although this step is optional but maybe set to be required.
10. Click **Add**.

About Integration Parameters:
* **Configuration Name:** In case you have more than one configuration set up, you can use this parameter to manually set the configuration you want the instance to run on, otherwise, if no value was given, the integration will use the first configuration it can find.
