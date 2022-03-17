## Configure an API account in G Suite Admin

In order to get the sufficient permissions for the integration to run properly, follow these steps:

1. **Configure a Service Account and retrieve its key in JSON format.** 
  Perform the steps mentioned [here](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount).


2. **Allow access to the relevant scopes.**
  Perform the steps mentioned [here](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority).
  The scope for this integration is https://www.googleapis.com/auth/admin.reports.audit.readonly


3. **Provide an admin email.**
  To execute the command you must provide an admin email address.
    You can provide the admin email adddress in the integration configuration,
    or pass it as the value of the *admin_email* argument in the command.
      
    The email address precedence is the *admin_email* argument in the command followed by the Admin Email in the integration configuration.