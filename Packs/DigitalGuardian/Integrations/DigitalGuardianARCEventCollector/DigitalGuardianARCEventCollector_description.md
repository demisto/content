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

#### Fetch Events

To view, create, or edit export profiles, in the Digital Guardian platform tenant, navigate to **DG ARC** > **Reports** > **Export Profiles**.

To confirm the internal document name of an export profile, hover over the 'Link' icon in the URL column in the table. For example, if the export profile URL is `{access_gateway_base_url}/rest/1.0/export_profiles/demisto/export`, the internal document name is `demisto`.

**Important:** A maximum of **10,000** events can be retrieved per fetch for each Digital Guardian export profile. To optimize throughput, it is recommended to distribute alerts and events across multiple export profiles and configure the export profile in the Digital Guardian ARC platform to include only relevant alarm and event types.

**Important:** Events are fetched starting from the **Last Exported Record** timestamp of the export profile. It is highly recommended to adjust the value of this field in the selected export profile(s) to a recent timestamp for optimal fetch performance.

_Failure to update this setting to a current timestamp may result in unnecessary system overhead and the accumulation of outdated events until the event collector eventually begins fetching recent events._

To update **Last Exported Record** field, select the relevant export profile and edit its settings. Ensure all changes are saved.

![Digital Guardian export profile edit](../../doc_files/edit_export_profile.png)
