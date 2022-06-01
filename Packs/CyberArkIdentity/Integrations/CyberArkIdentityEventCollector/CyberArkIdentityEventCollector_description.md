Integration with CyberArk Identity using REST API to get the Audit and Auth log for an application.


The first task that you must perform before accessing the events is to configure the
OAuth tenant.
After you complete the configuration, you will have created the following:
* SIEM user
* OAuth app
* SIEM scope for accessing Redrock and query

Setting up the SIEM User and the OAuth App on the Tenant
Follow these steps:
1. On the Idaptive Admin Portal, click the Apps tab.
2. On the Add Web Apps page, click the Custom tab.
3. Locate the OAuth2 Client and click Add.
4. When prompted to add the Web App, OAuth2 Client, click Yes
5. On the OAuth2 Client Description tab, for the Application Name, enter oauthsiem (or whatever you want).
6. On the Settings tab, leave the defaults as shown.
7. On the Tokens tab, for Auth methods, check Client Creds.
8. On the Scope tab, under Scope definitions, click Add to add a new scope.
9. On the Scope definitions dialog:
   1. In the Name field, enter siem (or whatever you want).
   2. Under Allowed REST APIs, click Add, enter Redrock/query.*, and click Save.
10. On the Idaptive Admin Portal, click the Users tab.
11. On the Create Directory User page:
    1. For the Login Name, enter: siemuser. 
    2. For the Suffix, enter your company’s suffix (or leave as is). 
    3. For the Password and Confirm Password, enter the password of your choice.
12. Under Status:
    1. Check Password never expires.
    2. Check Is OAuth confidential client (Preview). 
    3. Click the Create User button.
13. On the Idaptive Admin Portal, click the Roles tab.
14. On the service account page:
    1. For the Name, enter: service account. This entry serves as the role name.
    2. For the Members, add (check) the siemuser that you created earlier.
    3. Click Save
15. For the Administrative Rights, in the Add Rights list, check Read Only System Administrator and click Add.
16. Check the Read Only System Administrator and click Save.
17. For the Assigned Applications, in Add Applications list, check the OAuth2 
18. Click Add.
19. Perform final checks to make sure that:
    1. On the Users tab, the siemuser is shown and the Roles section lists the Name of the role as service account.
    2. On the Apps tab, In Permissions section of the OAuth2 Client app, the permissions for service account role looks as below.
    3. On the Apps tab, the Tokens section shows under Auth methods that Client Creds is checked.


## Configuration Parameters

**Server URL**
Endpoint to get the logs, For example: ``https://{{tenant}}.my.idaptive.app/``.

**App ID**
The application ID from where to fetch the logs, 

**User name and Password**  
The siem user name and password.

For more information see the [CyberArk Identity Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Integrations/SIEM-PlatformEvents/Identity%20Platform%20API%20Usage%20Guide%20for%20ArcSight.pdf).