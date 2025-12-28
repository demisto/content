### Configure an API account on Google SecOps

Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API.

To use the v1 alpha API, your Customer Experience Engineer (CEE) will provide a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the V1 alpha API or you can use the following steps to create a service account. The Google SecOps Project Instance ID and Google SecOps Project Number can be retrieved from the Settings or Profile page of the Google SecOps platform.

**Troubleshooting Connection Issues:** If you encounter connection or access denied errors, update the API URL format and provide the Google SecOps Project Number.

### Create a v1 alpha API supported Service Account JSON

* Log in to [Google Cloud Console](https://console.cloud.google.com/) and select the GCP Project ID shown in the Profile page of the Google SecOps platform.
* Navigate to IAM & Admin → Service Accounts, click \"+ CREATE SERVICE ACCOUNT\", and provide a descriptive name (e.g., secops-v1alpha-service-account).
* Grant appropriate Chronicle roles:
  * Viewer Permission: If you only need to get or list resources, the Chronicle Viewer role is sufficient. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.viewer)
* Go to the created service account → Keys tab → ADD KEY → Create new key → Choose JSON format → Click CREATE.
* The JSON file will automatically download. Keep this file secure as it contains authentication credentials.

### Instance Configuration

* Provide the "**Service Account JSON**".
* Select the "**Region**" based on the location of the Google SecOps instance.
* Select the **Use V1 Alpha API** option to enable the v1 alpha API.
* If "**Use V1 Alpha API**" is selected, Update the "**Region**" and provide the v1 Alpha API supported "**Service Account JSON**" and "**Google SecOps Project Instance ID**".
* Provide the date or relative timestamp from where to start fetching detections.
  * Note: The API is designed to retrieve data for the [past 7 days only](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#body_parameters_4). Requests for data beyond that timeframe will result in errors.

### Generic Notes

* This integration would only ingest the **detections** created by both **user-created rules** and **Google SecOps Rules**.
* Also, It only ingests the detections created by rules whose **alerting status** was **enabled** at the time of detection.
* Enable alerting using the **Google SecOps UI** by setting the **Alerting** option to **enabled**.
  * For **user-created rules**, use the Rules Dashboard to enable each rule's alerting status.
  * For **Google SecOps Rules**, enable alerting status of the Rule Set to get detections created by corresponding rules.
* You are limited to a maximum of 10 simultaneous streaming integration instances for the particular Service Account Credential (your instance will receive a **429 error** if you attempt to create more).
* For more, please check out the [Google SecOps reference doc](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#streamdetectionalerts).
