## EWS Extension Online Powershell v3

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
For the integration to work, the Azure AD application's service principal must have the correct permissions assigned in the Exchange Online role groups.
1. Open the Microsoft Purview Portal: https://purview.microsoft.com/
2. Log in using an admin account that can manage role assignments for the Azure AD application (for example, a Global Administrator or Privileged Role Administrator).
3. In the top bar, select: **Settings → Roles and scopes**
4. In the left sidebar, select: **Role Groups**
5. Search for the following role groups:
   - **Organization Management** – the most privileged role and fully supported for this integration.
   - **Security Administrator** – a highly privileged security role that also provides full access.
6. Open the role and verify that the **service principal of the Azure AD application used by the integration** is listed.
7. If not listed, click **Edit → Add Users** and assign the required roles.

* Note - for more information go to the official [Microsoft Documentation.](https://learn.microsoft.com/en-us/defender-office-365)
