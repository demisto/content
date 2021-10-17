## O365 Defender Safe Links

### App authentication
To use this integration, you need to add a new Azure App Registration in the Azure Portal. 
1. To create the application, follow the instructions in this [guide](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps). 
2. Run the **CreateCertificate** command in Cortex XSOAR to acquire the certificate. You can also provide your own certificate or follow Microsoft article: [Generate a self-signed certificate](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#step-3-generate-a-self-signed-certificate).
3. Attach the .cer file to your Azure App. See https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#step-4-attach-the-certificate-to-the-azure-ad-application for descriptive example.
4. Copy the contents of the .txt file and paste it in the Certificate parameter of the integration's instance.

#### Required Permissions
 * Exchange.ManageAsApp - Application

For information regarding the products and supported locations see [Safe Links in Microsoft Defender for Office 365](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide)

Known Limitations
----

* Safe Links does not work on mail-enabled public folders.
* 