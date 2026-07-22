## Google Threat Intelligence - ASM Issues Help

To use the integration, an API Key will be required from your Google Threat Intelligence account.

## Authorization:

Your API key can be found in your Google Threat Intelligence account user menu, clicking on your avatar.
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

### Instance Configuration

1. Configure a Google Threat Intelligence - ASM Issues integration instance with valid API Key.
2. Click **Test** to validate the connection.
3. To fetch ASM Issues as incidents in XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter** | **Description** |
| --- | --- |
| Incident Type | Select "Google Threat Intelligence ASM Issue"|
| Mapper (incoming) | Select "Google Threat Intelligence ASM Issues - Incoming Mapper"|
| API Key | Google Threat Intelligence API Key. |
| Max Fetch | Maximum number of Issues to fetch each time. Maximum value is 200. |
| First Fetch Time | The date or relative timestamp from which to begin fetching Issues.|
| Mirroring Direction | The mirroring direction in which to mirror the details. You can mirror "Outgoing" \(from XSOAR to GTI\) direction for ASM Issues. |
| Mirror tag for notes | The tag value should be used to mirror the issue note by adding the same tag in the notes. |
| Project ID | Provide the project ID to fetch issues for a specific project. |
| Search String | Search String to filter out the ASM Issues.<br/><br/>For Example: collection:google severity:5 status_new:open scoped:true entity_type:domain |
