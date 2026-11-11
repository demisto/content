## Workday

### Prerequisites in Workday

1. Using the **Create Integration System User** task, create an account with a username and password.
2. Create an Integration System Security Group (Unconstrained) using the **Create Security Group** task, and then add the integration system user to it.
3. Based on what data needs to be pulled in through the integration, update the **Domain Security Policy Permissions** as well as the **Business Process Security Policy Permissions**. For example, grant access to the Worker Data domains used by the Staffing web service.
4. Activate pending security policy changes.

### Instance Parameters

- **Server URL**: The web services endpoint up to and including `/ccx/service`, without the tenant name, for example, `https://wd5-services1.myworkday.com/ccx/service`. In Workday, run the **View API Clients** report. The **Workday Web Services Endpoint** is shown as `https://<host>/ccx/service/<tenant>`. Use only the part before the tenant name.
- **Username / Password**: The integration system user created above. Enter the user name **without** `@TenantName`. The integration sends `<username>@<tenant name>` automatically.
- **Tenant name**: The tenant name, for example, `acme` or `acme_preview` (the last part of the web services endpoint).
- **Token**: An identifier used in the WS-Security `UsernameToken` element of the request. It is not a Workday credential and is not validated by Workday. Use any value made of letters, digits, `-` and `_`.
- **API Version**: The Workday Human Resources web service version, in the format `vXX.X`.
