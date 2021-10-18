## Configure an API account on G Suite Admin

In order to get the sufficient permissions for the integration to run properly, follow these steps -

1. **Configure a Service Account and retrieve its key in JSON format.** 
  follow the steps mentioned [here](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount)
   or in the integration README. 


2. **Allow access  to the relevant scopes.**
  how to [here](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority).
  scope for this integration - https://www.googleapis.com/auth/admin.reports.audit.readonly


3. **Provide an admin email**
  To execute the command you must provide an admin email.
    You can provide the admin email in the integration configuration,
    or pass it as the value of the *admin_email* argument in the command.
      
    Precedence of this will be admin_email in command argument > Admin Email in integration configuration

