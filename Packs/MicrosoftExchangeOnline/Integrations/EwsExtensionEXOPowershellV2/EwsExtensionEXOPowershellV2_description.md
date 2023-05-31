Deprecated. Use ***EWS Extension Online Powershell v3*** instead.

## EWS Extension Online Powershell v2

### App authentication
To use this integration, you need to connect an application with a certificate.
1. To create the application, follow the instructions in this [guide](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps). Assign the following API permission to the application: *Exchange.ManageAsApp*
2. Run the **CreateCertificate** command in Cortex XSOAR to acquire the certificate.
3. Attach the .cer file to your Azure App.
4. Copy the contents of the .txt file and paste it in the Certificate parameter of the integration's instance.
