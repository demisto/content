## EWS Extension Online Powershell v3

### App Authentication

This integration uses app-only authentication with a certificate. The setup consists of five steps:

1. Register an application in Microsoft Entra ID.
2. Create a certificate in Cortex XSOAR/XSIAM and upload it to the application.
3. Assign Exchange Online permissions to the application.
4. Configure the integration instance in Cortex XSOAR/XSIAM.
5. Clean up the Playground.

#### Step 1: Register the Application in Microsoft Entra ID

1. Sign in to the [Azure portal](https://portal.azure.com/) and navigate to **Microsoft Entra ID** > **App registrations**.
2. Click **New registration**, enter a name for the application (for example, **EWS**), and click **Register**.
3. On the application **Overview** page, copy the **Application (client) ID**. You will need it in Step 4.
4. In the left menu, click **API permissions** > **Add a permission**.
5. Select the **APIs my organization uses** tab and search for **Office 365 Exchange Online**.
6. Click **Application permissions**, expand **Exchange**, and select **Exchange.ManageAsApp**.
7. Click **Add permissions**.
8. Click **Grant admin consent for \<your organization\>** and confirm.

#### Step 2: Create the Certificate and Upload It to the Application

1. In the Cortex XSOAR/XSIAM Playground, run the following command:

   `!CreateCertificate days=<number_of_days> password=<your_password>`

   **Note:** Save the password. You will need it in Step 4.

2. From the command results, download the following files:
   - **certificateBase64.txt** - used for the **Certificate** field in Step 4.
   - **publickey.cer** - uploaded to the Azure application in the next step.
3. In the Azure portal, open your application and click **Certificates & secrets** in the left menu.
4. In the **Certificates** tab, click **Upload certificate**, select the **publickey.cer** file, and click **Add**.

#### Step 3: Assign Exchange Online Permissions

The application must have Exchange Online permissions to run the integration commands. Use **one** of the following options. **Option A** is the easiest. If the **Test** button fails after using one option, try the other.

##### Option A: Assign the Exchange Administrator Role in Microsoft Entra ID (Easiest)

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/), search for **Microsoft Entra roles and administrators** in the search box.
2. Search for **Exchange Administrator** and click the role name (not the checkbox).
3. Click **Add assignments**, search for your application name, select it, and click **Add**.

##### Option B: Add the Application to the Organization Management Role Group via PowerShell

**1. Connect to Exchange Online PowerShell as an administrator**

1. Open PowerShell on your machine.
2. Install the Exchange Online module (only needed the first time):
   `Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser`
3. Import the module:
   `Import-Module ExchangeOnlineManagement`
4. Connect using an administrator account that can manage role assignments (for example, a Global Administrator or Privileged Role Administrator). A sign-in window opens for you to authenticate:
   `Connect-ExchangeOnline -UserPrincipalName <admin@yourdomain.com>`

   Replace `<admin@yourdomain.com>` with your admin account.

**2. Get the correct IDs and create the service principal**

You need two values:

- **Application (client) ID** - take this from the **App registration** Overview page.
- **Enterprise application Object ID** - this is **NOT** the Object ID shown on the App registration page. You must use the Object ID of the **Enterprise application** (the service principal).

To get the Enterprise application Object ID:

1. In the Azure portal, open your App registration (for example, your EWS app).
2. On the Overview page, find the field **Managed application in local directory** and click the application name link next to it. This opens the matching Enterprise application. (Alternatively, go to **Microsoft Entra ID** > **Enterprise applications**, search for your app, and open it.)
3. On the Enterprise application Overview page, copy the **Object ID**. This value is different from the Object ID on the App registration page.

Now run the following command, using the Application (client) ID and the Enterprise application Object ID:

`New-ServicePrincipal -AppId "<Application-ID>" -ObjectId "<EnterpriseApp-ObjectId>" -DisplayName "<Application Name>"`

**3. Add the service principal to the Organization Management role group**

After the service principal is created, add it to the **Organization Management** role group so it has the permissions the integration needs to run its cmdlets:

`Add-RoleGroupMember -Identity "Organization Management" -Member "<Application-ID>"`

Use the same `<Application-ID>` value you used in the previous step.

**4. Verify**

Confirm that the service principal is now a member of the role group:

`Get-RoleGroupMember -Identity "Organization Management"`

**Note:** For more information, see the official [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2).

#### Step 4: Configure the Integration Instance in Cortex XSOAR/XSIAM

Configure the following fields in this integration instance:

- **Certificate** - Open the **certificateBase64.txt** file from Step 2, copy its entire content, and paste it here.
- **Password** - Enter the password you defined when running `!CreateCertificate` in Step 2.
- **The organization used in app-only authentication** - Enter your `<tenant>.onmicrosoft.com` domain (for example, `contoso.onmicrosoft.com`). You can find it in the Azure portal under **Microsoft Entra ID** > **Overview** (**Primary domain**). If your primary domain is a custom domain (for example, `contoso.com`), use the `.onmicrosoft.com` domain listed under **Microsoft Entra ID** > **Custom domain names** instead.
- **The application ID from the Azure portal** - Enter the **Application (client) ID** you copied in Step 1.

Click **Test** to verify connectivity.

#### Step 5: Clean Up the Playground

The Playground now contains sensitive information (the certificate and its private key). Delete it by running the following command:

`!DeleteContext all=yes`
