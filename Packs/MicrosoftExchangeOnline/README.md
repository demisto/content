Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft Office Outlook.

## What does this pack do?

- Monitor a specific email account and create incidents from incoming emails to the defined folder.
- Search for an email message across mailboxes and folders.
- Get email attachment information.
- Delete email items from a mailbox.
- Manage Tenant Allow/Block Lists.

## Integrations

The [EWS O365 integration](https://xsoar.pan.dev/docs/reference/integrations/ewso365) enables you to:

- Retrieve information on emails and activities in a target mailbox.
- Perform operations on the target mailbox such as deleting emails and attachments or moving emails from folder to folder.

The [O365 - EWS - Extension integration](https://xsoar.pan.dev/docs/reference/integrations/ews-extension) enables you to manage and interact with Microsoft O365 - Exchange Online from within XSOAR

- Get junk rules for a specified mailbox.
- Set junk rules for a specified mailbox.
- Set junk rules for all managed accounts.
- Search message data.

The [EWS Extension Online Powershell v2 integration](https://xsoar.pan.dev/docs/reference/integrations/ews-extension-online-powershell-v2) enables you to retrieve information about mailboxes and users in your organization.

- Display client access settings that are configured on mailboxes.
- Display mailbox objects and attributes, populate property pages, or supply mailbox information to other tasks.
- Retrieve permissions on a mailbox.
- Display information about SendAs permissions that are configured for users.
- Display existing recipient objects in your organization such as mailboxes, mail users, mail contacts, and distribution groups.
- Add, remove, list, and count entries in Tenant Allow/Block Lists.

The [Security And Compliance V2](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2) enables you to:

- manage the security of all your organization's emails, SharePoint sites, OneDrives, etc.
- can perform actions (preview and delete) on emails.

## EWS Permissions

To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions.

| Permission |Use Case |
| ----- | ----|
| Delegate | One-to-one relationship between users. |
| Impersonation | A single account needs to access multiple mailboxes. |
| eDiscovery | Search the Exchange server. |
| Compliance Search | Perform searches across mailboxes and get an estimate of the results. |

## Integration Configuration

### App authentication
To use this integration, you need to connect an application with a certificate.
1. Create the application:
   1. Access **portal.azure.com**.
   2. Navigate to **Home** > **App registrations**.
   3. Click **New Registration**, give the application a name (for example: **EWS**) and click **Register**.
   4. In the left menu of the newly created application, click **API permissions**.
   5. Click **Add a permission**.
   6. In the Request API permissions page, click **APIs my organization uses**.
   7. Search for **Office 365 Exchange Online**.
   8. Click **Application permissions**.
   9. Under Exchange, click the **ExchangeManageAsApp** checkbox.
   10. Click **Add permissions**.
   11. Click **Grant admin consent for XSOAR**.
   
2. Create the certificate in Cortex XSOAR.
   1. Run the **CreateCertificate** command in the Playground to acquire the certificate. 

      ***!CreateCertificate days=<# of days> password=\<password>***

     *Note: Remember your password since you will need it to create your integration instance.*

   2. Download the certificateBase34.txt file.
   3. Open the downloaded txt file and copy the text.
   4. In the integration instance configuration, paste the text in the **Certificate** field.


3. Attach the .cer file to your Azure app.
    1. In the Cortex XSOAR Playground, download the publickey.cer file
    2. In the Azure application, in the left menu, click **Certificates & secrets**.
    3. In the Certificates tab, upload the publickey.cer file.


4. Assign Azure AD roles to the application.
   1. You have two options:
      - Assign Azure AD roles to the application.
      - Assign custom role groups to the application using service principals.
   2. In the Azure AD portal at https://portal.azure.com/, start typing "roles and administrators" in the Search box at the
      top of the page, and then select **Microsoft Entra roles and administrators** from the results in the Services section.
   3. On the Roles and administrators page that opens, find and select one of the supported roles by clicking on the
      name of the role (not the checkbox) in the results.
      - The role **Security Administrator** is eligible for this integration.
   4. On the Assignments page that opens, select **Add assignments**.
   5. In the Add assignments flyout that opens, find and select the app that you created in Step 1.

Note: The information in the Playground is sensitive information. You should delete the information by running the following command:

   ***!DeleteContext all=yes***

5. In Cortex XSOAR, in the integration instance configuration, enter your saved password in the **Password** field.
6. In Azure, go to Entra ID (Overview blade) and copy the **Primary domain** field.
7. In Cortex XSOAR, in the integration instance configuration, paste the Domain name in **The organization used in app-only authentication** field.
8. In the Azure app, navigate to **Home** > **App registration** > **\<application name>** and copy the Application (client) ID.
9. In Cortex XSOAR, in the integration instance configuration, paste the application ID in **The application ID from the Azure portal** field.


### Verify that the admin account has sufficient Exchange Online permissions
1. Open the Microsoft Purview Portal: https://purview.microsoft.com/
2. Log in using an admin account that manages the Azure AD application (for example, a Global Administrator or Privileged Role Administrator).
3. In the top bar, select: **Settings → Roles and scopes**
4. In the left sidebar, select: **Role Groups**
5. Search for the following role groups:
   - **Organization Management** – the most privileged role and fully supported for this integration.
   - **Security Administrator** – a highly privileged security role that also provides full access.
   - **Security Operator** – a less-privileged option.  
     *Note:* This role only works when assigned directly in the Exchange admin center at  
     https://admin.exchange.microsoft.com → **Roles** → **Admin Roles**.
6. Open the role and verify that the **service principal of the Azure AD application used by the integration** is listed.
7. If not listed, click **Edit → Add Users** and assign the required roles.

* Note - for more information go to the official [Microsoft Documentation.](https://learn.microsoft.com/en-us/defender-office-365)
