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
   11. Click **Grant admin consent**.
   
2. Create the certificate in Cortex XSOAR/XSIAM.
   1. Run the **CreateCertificate** command in the Playground to acquire the certificate. 

      ***!CreateCertificate days=<# of days> password=\<password>***

     *Note: Remember your password since you will need it to create your integration instance.*

   2. Download the certificateBase64.txt file.
   3. Open the downloaded txt file and copy the text.
   4. In the integration instance configuration, paste the text in the **Certificate** field.


3. Attach the .cer file to your Azure app.
    1. In the Cortex XSOAR/XSIAM Playground, download the publickey.cer file
    2. In the Azure application, in the left menu, click **Certificates & secrets**.
    3. In the Certificates tab, upload the publickey.cer file.


4. Assign Exchange Online permissions to the application. Choose **Option A** or **Option B**, as described in the **Assign Exchange Permissions (Choose Option A OR Option B)** section below. Make sure to grant the permissions before configuring the integration in Cortex XSOAR/XSIAM.

Note: The information in the Playground is sensitive information. You should delete the information by running the following command:

   ***!DeleteContext all=yes***

5. In Cortex XSOAR/XSIAM, in the integration instance configuration, enter your saved password in the **Password** field.
6. In Azure, go to Entra ID (Overview blade) and copy the **Primary domain** field.
7. In Cortex XSOAR/XSIAM, in the integration instance configuration, paste the Domain name in **The organization used in app-only authentication** field.
8. In the Azure app, navigate to **Home** > **App registration** > **\<application name>** and copy the Application (client) ID.
9. In Cortex XSOAR/XSIAM, in the integration instance configuration, paste the application ID in **The application ID from the Azure portal** field.


### Assign Exchange Permissions (Choose Option A OR Option B)
Choose one of the two options below to grant the app permission to run Exchange commands. **You only need one of them.** If authentication (the **Test** button) does not work after using one option, try the other.

#### Option A: Assign a Microsoft Entra directory role (easiest)
Use this method to grant tenant-wide management through the portal.
1. In the [Microsoft Entra admin center](https://entra.microsoft.com/), search for **Microsoft Entra roles and administrators** in the Search box.
2. Search for and select the required role (click the role name, not the checkbox):
   - The role **Exchange Administrator** is eligible for this integration.
3. Click **Add assignments**, search for your registered application name, select it, and click **Add**.

#### Option B: Add the service principal via Exchange Online PowerShell
Use this method when Option A does not work, or when you want to scope the application to a specific Exchange role group.

**Step 1: Connect to Exchange Online PowerShell as an administrator**
1. Open PowerShell on your machine.
2. Install the Exchange Online module (only needed the first time):
   `Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser`
3. Import the module:
   `Import-Module ExchangeOnlineManagement`
4. Connect using an administrator account that can manage role assignments (for example, a Global Administrator or Privileged Role Administrator). A sign-in window will open for you to authenticate:
   `Connect-ExchangeOnline -UserPrincipalName <admin@yourdomain.com>`

   Replace `<admin@yourdomain.com>` with your admin account.

**Step 2: Get the correct IDs and create the service principal**

You need two values:
- **Application (client) ID** - take this from the **App registration** Overview page.
- **Enterprise application Object ID** - this is **NOT** the Object ID shown on the App registration page. You must use the Object ID of the **Enterprise application** (the service principal).

To get the Enterprise application Object ID:
1. In the Azure portal, open your App registration (for example, your EWS app).
2. On the Overview page, find the field **Managed application in local directory** and click the application name link next to it. This opens the matching Enterprise application. (Alternatively, go to **Microsoft Entra ID > Enterprise applications**, search for your app, and open it.)
3. On the Enterprise application Overview page, copy the **Object ID**. This value is different from the Object ID on the App registration page.

Now run the following command, using the Application (client) ID and the Enterprise application Object ID:

`New-ServicePrincipal -AppId "<Application-ID>" -ObjectId "<EnterpriseApp-ObjectId>" -DisplayName "<Application Name>"`

**Step 3: Add the service principal to an Exchange Online role group**

After the service principal is created, add it to the **Organization Management** role group so it has the permissions the integration needs to run its cmdlets:

`Add-RoleGroupMember -Identity "Organization Management" -Member "<Application-ID>"`

Use the same `<Application-ID>` value you used in Step 2.

**Step 4: Verify**

You can confirm the service principal is now a member of the role group with the following command:

`Get-RoleGroupMember -Identity "Organization Management"`

**Note:** For more information, see the official [Microsoft Documentation](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2).