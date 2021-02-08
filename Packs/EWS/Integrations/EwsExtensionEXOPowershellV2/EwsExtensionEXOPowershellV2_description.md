## EWS Extension Online Powershell v2

### App authentication
To use this integration you should connect an application with a certificate.
The certificate can be acquired by using the `CreateCertificate` command in Cortex XSOAR.
You should use the `.txt` content as the 'Certificate' parameter and  attach the `.cer` file to your Azure App.
In order to create the app, you should use the [following guide](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps).

##### Permissions
- Exchange.ManageAsApp