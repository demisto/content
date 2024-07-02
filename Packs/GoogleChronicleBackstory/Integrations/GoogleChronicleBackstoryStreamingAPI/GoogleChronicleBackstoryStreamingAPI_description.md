### Configure an API account on Google Chronicle

Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API.

### Instance Configuration

* Provide the "**Service Account JSON**".
* Select the "**Region**" based on the location of the chronicle backstory instance.
* Provide the date or relative timestamp from where to start fetching detections.
  * Note: The API is designed to retrieve data for the [past 7 days only](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#body_parameters_4). Requests for data beyond that timeframe will result in errors.

### Generic Notes

* This integration would only ingest the **detections** created by both **user-created rules** and **Chronicle Rules**.
* Also, It only ingests the detections created by rules whose **alerting status** was **enabled** at the time of detection.
* Enable alerting using the **Chronicle UI** by setting the **Alerting** option to **enabled**.
  * For **user-created rules**, use the Rules Dashboard to enable each rule's alerting status.
  * For **Chronicle Rules**, enable alerting status of the Rule Set to get detections created by corresponding rules.
* You are limited to a maximum of 10 simultaneous streaming integration instances for the particular Service Account Credential (your instance will receive a **429 error** if you attempt to create more).
* For more, please check out the [Google Chronicle reference doc](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#streamdetectionalerts).
