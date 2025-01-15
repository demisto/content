## Digital Guardian ARC Event Collector Help

### How to get the configuration parameters

#### API Client ID

This is the Tenant ID and can be found in the ARC Tenant Settings 

#### API Client Secret

Authentication Token from the ARC Tenant Settings 

#### Gateway Base URL

From DGMC Cloud Services setup screen, Access Gateway Base URL 

#### Auth Server URL

From DGMC Cloud Services setup screen, Authorization server URL 

#### Export Profiles

To view, create, or edit export profiles, in the Digital Guardian platform tenant, navigate to **DG ARC** > **Reports** > **Export Profiles**.

* **Note:** While customers may input custom Digital Guardian export profiles while configuring the integration instance, only `defaultExportProfile` and `demisto` are officially supported.

    The internal document name of an export profile can be confirmed via the **Export Profiles** page in the Digital Guardian platform tenant by hovering over the 'Link' icon in the URL column in the table. For example, if the export profile URL is `{access_gateway_base_url}/rest/1.0/export_profiles/demisto/export`, the internal document name is `demisto`.

* **Important:** Events are fetched starting from the **Last Exported Record** timestamp of the export profile. It is highly recommended to adjust the value of this field in the selected export profile(s) to a recent timestamp for optimal fetch performance.

    _Failure to update this setting to a current timestamp during the initial configuration of the integration instance may result in unnecessary system overhead and the accumulation of outdated events until the event collector eventually begins fetching recent events._

    To update the **Last Exported Record** field, select the relevant export profile and edit its settings. Ensure all changes are saved.

![Digital Guardian export profile edit](../../doc_files/edit_export_profile.png)

#### Number of Export Requests per Fetch

By default, a maximum of **10,000** events can be retrieved per fetch for each Digital Guardian export profile. To increase the volume of fetched events beyond this value, set the "Number of Export Requests per Fetch" configuration parameter to greater than 1.
