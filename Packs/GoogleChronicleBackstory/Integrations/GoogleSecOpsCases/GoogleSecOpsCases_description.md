## Configure an API account on Google SecOps

---
Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the V1 alpha API or you can use the following steps to create a service account. The Google SecOps Project Instance ID and Google SecOps Project Number can be retrieved from the Settings or Profile page of the Google SecOps platform.

**Troubleshooting Connection Issues:** If you encounter connection or access denied errors, update the API URL format and provide the Google SecOps Project Number.

### Create a Service Account JSON

* Log in to [Google Cloud Console](https://console.cloud.google.com/) and select the GCP Project ID shown in the Profile page of the Google SecOps platform.
* Navigate to IAM & Admin → Service Accounts, click \"+ CREATE SERVICE ACCOUNT\", and provide a descriptive name (e.g., secops-v1alpha-service-account).
* Grant appropriate Chronicle roles:
  * Viewer Permission: If you only need to get or list resources, the Chronicle Viewer role is sufficient. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.viewer)
  * Editor Permission: If you need to create or update resources (such as creating or editing case properties), the Chronicle Editor role is required. [Learn more](https://cloud.google.com/iam/docs/roles-permissions/chronicle#chronicle.editor)
  * Owner (full access; use cautiously)
* Go to the created service account → Keys tab → ADD KEY → Create new key → Choose JSON format → Click CREATE.
* The JSON file will automatically download. Keep this file secure as it contains authentication credentials.

### SOAR Internal Role Mapping (Required for Cases Functionality)

Service accounts require an additional role mapping in the Google SecOps UI to access case details, even when the necessary permissions have already been granted in GCP.

1. Navigate to **Settings > SOAR Settings > Advanced > Group Mapping**.
2. Click **+** to create a new mapping, or select an existing one to update it. Configure the following:
   * **User Group / IDP**: Enter a descriptive name.
   * **Group Members**: Add the Service Account email (e.g., `your-sa@your-project.iam.gserviceaccount.com`).
   * **Permission Group**: Select based on the required access level:
     * **Readers** - If you only need to fetch or list cases, case alerts, and alert entities.
     * **Managed-Plus User** - If you need to update the cases, case alerts, and alert entities information.
     * **Admins** - Full access to all modules and administrative operations (use cautiously).
   * **SOC Role** and **Environments**: Assign the appropriate SOC role and environment(s) for the Service Account.
3. Click the **Save**/**Add** button.

For more information, see [Control access to the platform](https://docs.cloud.google.com/chronicle/docs/soar/admin-tasks/advanced/control-access-to-platform).
