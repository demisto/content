**Google Key Management Service**

This integration allows you to:

* Get CryptoKey information.
* Create a new CryptoKey.
* Encrypt and Decrypt using Google KMS keys from plain text and base64 text.
* Update an existing CryptoKey.
* Destroy/Restore/Enable/Disable a CryptoKeyVersion of your choice. 

Get a Service Account and select a Role:
1) Go to: https://console.developers.google.com.
2) Select your project.
3) From the side-menu go to **IAM & admin** > **Service accounts** > **CREATE SERVICE ACCOUNT**.
5) Type an account name and description and click **CREATE**.
6) From  the drop down list Select a role from one of the following to in the integration:
    - **Project-Owner** and **Project-Editor** - Grants you total access to the Project and allows you to use all the commands in the integration.
    - **Cloud KMS Admin** - Grants you the option to create and edit CryptoKeys and CryptoKeyVersions.
    - **Cloud KMS Encrypter/Decrypter** - Lets you use the encrypt and decrypt commands.
    - **Cloud KMS Encrypter** - lets you use only the encrypt command.
    - **Cloud KMS Decrypter** - lets you use only the decrypt command.
7) Click **CONTINUE** and then click **CREATE KEY**.
8) Select **JSON** and click **CREATE**.
 The .json file downloads.
9) Enter the file contents to the Service Account box in the integration.

