## Office 365 Message Trace Event Collector Help

To use this integration you will need to setup an app registration in Azure AD.

### Create App Registration

1. Create a single tenant app registration in Azure AD
2. Add the Application permission `Office 365 Exchange Online -> ReportingWebService.Read.All`
3. Add the new application to the `Global Reader` role
    - Go to Entra ID `Roles and Administrators`
    - Find and click the role `Global Reader`
    - Click `Add assignments`
    - Click `No member selected`
    - Search for the `Application ID` from the new app registration (it may take time for the new app to show up in a search)
    - Check the box next to the app and choose `Select`
    - Click `Next`
    - Fill out the justification form
    - Click `Assign`
4. Go to the app registration and create a secret

### Setup Integration

- Set the `Tenant ID` to the Entra ID tenant for the app registration
- Set the `Client ID` to the application ID for the app registration
- Set the `Client Secret` to the secret generated for the app
- In the collect section, configure the fetch settings