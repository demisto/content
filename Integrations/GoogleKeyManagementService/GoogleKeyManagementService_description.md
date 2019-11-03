**Google Key Management Service**

This integration allows you to:

* Get the info of a CryptoKey.
* Create a new CryptoKey.
* Encrtypt and Decrypt using Google KMS keys from plain-text and base64 text.
* Update an Existing CryptoKey.
* Destroy/Restore/Enable/Disable a CryptoKeyVersion of your choice. 

Get a Service Account and select a Role:
1) Go to: https://console.developers.google.com.
2) Select your project.
3) From the side-menu go to IAM & admin.
4) Select Service accounts and click CREATE SERVICE ACCOUNT.
5) Give the account a name and description of your choice and click CREATE.
6) From Select a role choose your required roles, this will choose which commands the user can use in the integration:
    1) Project-Owner, and Project-Editor - Will grant you total access to the Project and Allow you to use all the commands in the integration.
    2) Cloud KMS Admin -  Will grant you the option to create and edit CryptoKeys and CryptoKeyVersions.
    3) Cloud KMS Encrypter/Decrypter - Will let you use the encrypt and decrypt commands.
    4) Cloud KMS Encrypter - Will let you use only the encrypt command.
    4) Cloud KMS Decrypter - Will let you use only the decrypt command.
7) Click CONTINUE and then CREATE KEY.
8) Choose JSON and click CREATE and a .json file will download.
9) Enter this file contents to the Service Account box in the integration.

