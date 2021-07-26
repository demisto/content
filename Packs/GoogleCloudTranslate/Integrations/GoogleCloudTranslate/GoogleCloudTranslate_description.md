## Google Cloud Translation API

In order to use this integration you need the following:
1. [Select or create a Cloud Platform project on GCP](https://console.cloud.google.com/project)
2. [Enable billing for the project.](https://cloud.google.com/billing/docs/how-to/modify-project#enable_billing_for_a_project)
3. [Enable the Google Cloud Translate API.](https://cloud.google.com/translate)
4. [Create a Service Account](#create-a-service-account) with access to Google Translate API
5. Use the Service Account Private Key in JSON format and the GCP project ID to configure a new instance of Google Cloud Translate integration in Cortex XSOAR 

### Create a Service Account
1) Go to: https://console.developers.google.com.
2) Select your project.
3) From the side-menu go to **IAM & admin** > **Service accounts** > **CREATE SERVICE ACCOUNT**.
5) Type an account name and description and click **CREATE**.
6) From  the drop down list Select a role select **Cloud Translation API User**.
7) Click **CONTINUE** and then click **CREATE KEY**.
8) Select **JSON** and click **CREATE**. The .json file downloads.