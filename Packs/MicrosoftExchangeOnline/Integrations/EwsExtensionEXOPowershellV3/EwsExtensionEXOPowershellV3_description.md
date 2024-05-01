## EWS Extension Online Powershell v3

### App authentication
To use this integration, you need to connect an application with a certificate.
1. Create the application:
   1. Access **portal.azure.com**.
   2. Navigate to **Home** > **App registrations** > **EWS**
   3. In the left menu, click **API permissions**.
   4. Click **Add a permission**.
   5. In the Request API permissions page, click **APIs my organization uses**.
   6. Search for **Office 365 Exchange Online**.
   7. Click **Application permissions**.
   8. Under Exchange, click the **ExchangeManageAsApp** checkbox.
   9. Click **Add permissions**.
   10. Click **Grant admin consent for XSOAR**.
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
    2. In the Azure AD portal at https://portal.azure.com/, start typing roles and administrators in the Search box at the
       top of the page, and then select Azure AD roles and administrators from the results in the Services section.
    3. On the Roles and administrators page that opens, find and select one of the supported roles by clicking on the
       name of the role (not the checkbox) in the results.
    4. On the Assignments page that opens, select **Add assignments**.
    5. In the Add assignments flyout that opens, find and select the app that you created in Step 1.


Note: The information in the Playground is sensitive information. You should delete the information by running the following command:

   ***!DeleteContext all=yes***

5. In Cortex XSOAR, in the integration instance configuration, enter your saved password in the **Password** field.
6. In Azure, go to Azure Active Directory (Overview blade) and copy the **Primary domain** field.
7. In Cortex XSOAR, in the integration instance configuration, paste the Domain name in **The organization used in app-only authentication** field.
8. In the Azure app, navigate to **Home** > **App registration** > **\<application name>** and copy the Application (client) ID.
9. In Cortex XSOAR, in the integration instance configuration, paste the application ID in **The application ID from the Azure portal** field.


