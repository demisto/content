## Configure an API account on Google SecOps

---
Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the V1 alpha API or you can use the following steps to create a service account. The Google SecOps Project Instance ID and Google SecOps Project Number can be retrieved from the Settings or Profile page of the Google SecOps platform.

**Troubleshooting Connection Issues:** If you encounter connection or access denied errors, update the API URL format and provide the Google SecOps Project Number.

### Create a Service Account JSON

* Log in to [Google Cloud Console](https://console.cloud.google.com/) and select the GCP Project ID shown in the Profile page of the Google SecOps platform.
* Navigate to IAM & Admin → Service Accounts, click \"+ CREATE SERVICE ACCOUNT\", and provide a descriptive name (e.g., secops-v1alpha-service-account).
* Grant appropriate Chronicle roles:
  * Viewer Permission: If you only need to get or list resources, the Chronicle Viewer role is sufficient. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.viewer)
  * Editor Permission: If you need to create or update resources (such as creating or editing rules), the Chronicle Editor role is required. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.editor)
  * Owner (full access; use cautiously)
* Go to the created service account → Keys tab → ADD KEY → Create new key → Choose JSON format → Click CREATE.
* The JSON file will automatically download. Keep this file secure as it contains authentication credentials.

### Reputation Calculation Algorithm

Google SecOps provides the intelligence context to the indicators as provided by the configured threat intelligence sources. The IOC context properties provided by Google SecOps are Severity, Category and Confidence Score. To provide the user with control over the reputation calculation, the integration configuration enables granular control over these properties.

* Users can specify a list of categories, IoCs belonging to which should be considered as Malicious or Suspicious irrespective of its severity and confidence score. For example, if you want to consider all the IoCs of Category 'Blocked' as Malicious, configure the category within instance configuration.
* Users can specify the Severity levels, indicators belonging to such severity would be considered as Malicious/Suspicious irrespective of the category and confidence score.
* The confidence score provided by the Threat Intel sources can be numeric or a string representation (Low, Medium, or High). The configuration allows separate options to control reputation calculation based on the returned confidence score. The user can configure the raw confidence score threshold values(separate configuration for numeric score and string representation) to control the reputation calculation.

Note: While evaluating the reputation of an indicator at multiple stages, if an indicator is found to be Malicious, the overall reputation remains 'Malicious'. For example, if a category is configured with both Malicious and Suspicious categories, the IoCs belonging to such category would be considered Malicious.
