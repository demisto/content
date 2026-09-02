## CyberArk EPM Help

### Authentication
There are three methods to authenticate: EPM, SAML (currently only via Okta), and Idira OAuth (CyberArk Identity / ISPSS).
Every method needs different parameters as show in the following:

* EPM authentication
    - **url**: `https://<EPM_server>` (for example: https://login.epm.cyberark.com/login)
    - **username**
    - **password**
    - [**application ID**](https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm#%23SpecifytheApplicationID)
    - **set name** (comma separated value)


* SAML authentication (advanced settings) currently supported only via Okta.
    - **url**: `https://login.epm.cyberark.com/SAML/Logon`
    - **username**
    - **password**
    - **authentication URL** [Okta example](https://developer.okta.com/docs/reference/api/authn/#authentication-operations): `https://[COMPANY_NAME].okta.com/api/v1/authn`
    - **Application URL**: `https://[COMPANY_NAME].okta.com/home/[APP_NAME]/[APP_ID]`
    - **Set name** (comma separated value)


* Idira OAuth authentication (CyberArk Identity / ISPSS).
    - **Server URL**: the EPM server address, for example: `https://example.epm.cyberark.com/`
    - **Identity URL**: The CyberArk Identity FQDN, for example: `https://<sub-domain>.id.cyberark.cloud` (used only to obtain the OAuth token)
    - **Web App ID**: The web app's application ID / alias (see the vendor-side setup below)
    - **Username** (the service-user login, used as the Client ID)
    - **Password** (the service-user password, used as the Client Secret)
    - **Set name** (comma separated value)
    - **EPM API Version** (optional, advanced): the version segment in `/EPM/API/<Version>/Sets`. Must be four dot-separated numbers (x.x.x.x). Defaults to `26.8.0.0`.

#### Vendor-side setup for the Idira OAuth (CyberArk Identity / ISPSS) method

1. **Create a service user for API requests** — In Identity Administration go to **Core Services > Users > Add User**. Set a **Login name**, **Display name**, and **Password**. Select **Is OAuth confidential client**, **Is Service User**, and **Password never expires**. Click **Create User**.
   > The service-user login becomes the Client ID; its password becomes the Client Secret.

2. **Create the custom permission group (EPM Management Console)** — Log in to the EPM Management Console as an Account Administrator. In the navigation pane, under **Administration**, select **Permission groups**, then click **Create custom permission group**. Enter a name (e.g. `API_Audit_Viewer`) and an optional description. From the **Based on** dropdown, select **View Only Set Admin** as the starting point. In the permissions matrix, fine-tune access so the API user can query the needed endpoints:
   - **Sets**: Ensure **Set visibility** is enabled.
   - **Policy Audit**: Ensure **View Audit** (or the top-level Policy Audit permission) is enabled.
   - Turn off any other permissions the API service user does not need. Click **Create**.

3. **Create an EPM role using the custom group (EPM Management Console)** — Permission groups cannot be assigned to users directly; they must be bundled with specific Sets into a Role. Still in the EPM Management Console, go to **Administration > Roles** and click **Create role**. Enter a name (e.g. `API_Set_Auditor_Role`), select the custom permission group you just created (`API_Audit_Viewer`), select the specific Set(s) the API is allowed to query, and click **Create**.

4. **Assign the role to your API service user (Identity Administration)** — Once created in EPM, the role automatically syncs to CyberArk Identity Administration with an `EPM_` prefix. Switch to the Identity Administration console, go to **Core Services > Roles**, and search for the role using the `EPM_` prefix (e.g. `EPM_API_Set_Auditor_Role`). Open the role, go to the **Members** tab, click **Add**, search for your OAuth API service user, select it, and click **Add**.
   > Sync between EPM and Identity Administration can take a few moments. If the new `EPM_` role does not appear in Identity Administration immediately, wait a minute or two and refresh.

5. **Create a custom EPM API web app** — In **Apps & Widgets > Web Apps > Add Web Apps**, search for `EPM`, add **Idira EPM API Client**, confirm, and save the required Settings.
   > The web app's application ID / alias becomes the **Web App ID**.

6. **Configure token expiration and bind the service user** — In the web app's **Tokens** tab, set the token expiration period and save. In the **Permissions** tab, add the service user and save. The web app status should become **Deployed**.

7. **Identify the Identity URL** — The CyberArk Identity FQDN, e.g. `https://<sub-domain>.id.cyberark.cloud` (used only to obtain the OAuth token).

### Fetch Information

- There are three event types that are fetched for the Event Collector:
    * Policy audits.
    * Admin audits.
    * Events.

* The **Set name** parameter contains a list of names to which the events are related.
* The **Maximum number of events per fetch** parameter applies to each event type and each name in the **Set name** parameter. For example, if **Maximum number of events per fetch** is set to 1000, the total maximum events fetched is equal to 3000 multiplied by the total number of names specified in the **Set name** parameter.