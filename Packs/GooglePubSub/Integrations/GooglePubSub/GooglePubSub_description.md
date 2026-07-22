**To use this integration you must have a service account.** If you do not pot have a service account, 
please see *Getting a Service Account With a Role* below.

### Getting a Service Account With a Role:
1) Go to [google console](https://console.developers.google.com.).
2) Select your project.
3) From the side-menu go to **IAM & admin** > **Service accounts** > **CREATE SERVICE ACCOUNT**.
5) Type an account name and description and click **CREATE**.
6) From  the drop down list Select a role from one of the following to in the integration:
    - **Project-Owner** or **Project-Editor** or ****Pub/Sub Admin** or **Pub/Sub Editor** - Grants you total access to the Project and allows you to use all the commands in the integration.
7) Click **CONTINUE** and then click **CREATE KEY**.
8) Select **JSON** and click **CREATE**.
 The .json file downloads.
9) Enter the file contents in the **Service account private key file contents (JSON)** integration settings parameter.
