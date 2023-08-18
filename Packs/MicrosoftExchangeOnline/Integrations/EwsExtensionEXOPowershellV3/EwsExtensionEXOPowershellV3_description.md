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

Note: The information in the Playground is sensitive information. You should delete the information by running the following command:

   ***!DeleteContext all=yes***

4. In Cortex XSOAR, in the integration instance configuration, enter your saved password in the **Password** field.
5. In Azure, go to Azure Active Directory (Overview blade) and copy the **Primary domain** field.
6. In Cortex XSOAR, in the integration instance configuration, paste the Domain name in **The organization used in app-only authentication** field.
7. In the Azure app, navigate to **Home** > **App registration** > **\<application name>** and copy the Application (client) ID.
8. In Cortex XSOAR, in the integration instance configuration, paste the application ID in **The application ID from the Azure portal** field.
