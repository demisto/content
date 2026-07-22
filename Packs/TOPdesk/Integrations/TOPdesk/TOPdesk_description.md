## TOPdesk
This integration supports SupportingFilesAPI version `1.38.0` and higher. See the integration documentation for additional information on version support and more.

*Person* and *operator* are TOPdesk's user types. Each user type has a different set of actions that he is allowed to perform.
For example, a *person* can only update incidents he created, while an *operator* can update a wider range of incidents.

In general, if an account is able to perform the requested command in TOPdesk's UI, it should be able to perform it using this integration.
Make sure you use the right account for your needs and that the account used has all the required permissions. 
For more details on permissions specific to commands visit the TOPdesk integration documentation.

### Setup TOPdesk's application password
1. Login to TOPdesk with the designated account.
2. In TOPdesk, click **Open user menu** (top right side of the front page) > Choose **My settings**
3. At the bottom of the page should be an **Application passwords** section. You can view all application passwords that are configured for the logged in account. 
4. At the bottom right corner, click **Add**.
5. A window should open requesting a name for the application. Choose any convenient name (e.g., XSOAR-key) and click **Create**. 
6. The application password should be shown - copy it to a safe location. This is the password that will be used for the integration in XSOAR.
7. Once copied for further usage you can click **Close**.

### Configure Username and Password
**Username**: Use the account username from which the application password was generated. (*Not* the key name)

**Password**: Use the application password generated in step 6 of the **Setup TOPdesk's application password** procedure. 

### Troubleshooting
Make sure the application password is not expired by logging in TOPdesk and viewing it as described in step 3 of the **Setup TOPdesk's application password** procedure. 


---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/to-pdesk)