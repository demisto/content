### Configure an API account on Google SecOps

Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API.

To use the v1 alpha API, your Customer Experience Engineer (CEE) will provide a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the V1 alpha API. The Google SecOps Project Instance ID is available on the Settings or Profile page of the Google SecOps platform.

### Required Permissions for v1 alpha API supported Service Account JSON

* Viewer Permission: If you only need to get or list resources, the Chronicle Viewer role is sufficient. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.viewer)
* Editor Permission: If you need to create or update resources (such as creating or editing rules), the Chronicle Editor role is required. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.editor)

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
