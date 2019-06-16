To use this integration, you must provide an API user account.

To generate an API user account please follow these steps:

1. Using the Address Manager web interface, log in to Address Manager as an administrator.
2. On the Administration page, click Users and Groups. The Users and Groups page appears.
3. In the Users section, click New. The Add User page appears.
4. In the User section, type a name in the Username field.
5. In the Authentication section, type and confirm the API user password in the Password and ConfirmPassword fields. If external authenticators are available, an Other checkbox and a list of authenticatorsappears in the Authentication section. To use an external authenticator for the API user, click the Othercheckbox, and then select an authenticator from the list.
6. In the Extra Information section, set the following parameters:E-mail AddressType an email address for the API user. This information is required.Phone numberType a phone number for the API user. This information is optional.
7. In the User Access section you define the user type, security and history privileges, and access type:Type of UserSelect the type of user, either Non-Administrator or Administrator. Non-Administrator usershave access only to DNS and IPAM management functions. Administrator users have unlimitedaccess to all Address Manager functions.Security Privilegeselect a security privilege type from the drop-down list. This field is available only for Non-Administrator users with GUI, API, or  GUI and API  access.History Privilegeselect a history privilege type from the drop-down list. This field is available only for Non-Administrator users with GUI, or  GUI and API  access.Access Typeselect the type of access; GUI, API, or  GUI and API . GUI (Graphical User Interface) users canaccess Address Manager only through the Address Manager web interface. API (ApplicationProgramming Interface) users can access Address Manager only through the API. GUI and APIusers can access Address Manager either through the Address Manager web interface or the API.
8. In the Assign to Group section, you can assign the user to one or more existing user groups. In thetext field, type the name of a user group. As you type, a list of user groups matching your text appears.Select a name from the list, and then click Add to the right of the text field.20 | Address Manager API Guide
   Session Management
9. In the Change Control section, add comments to describe the changes. This step is optional but maybe set to be required.
10. Click Add at the bottom of the page.

About Integration Parameters:
* **Confguration Name:** In case you have more than one configuration set up, you can use this parameter to manually set the configuration you want the instance to run on, otherwise, if no value was given, the integration will use the first configuration it can find.
