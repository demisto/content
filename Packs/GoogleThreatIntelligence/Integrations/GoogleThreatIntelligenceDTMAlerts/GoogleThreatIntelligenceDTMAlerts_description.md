## Google Threat Intelligence - DTM Alerts Help

To use the integration, an API Key will be required from your Google Threat Intelligence account.

## Authorization:

Your API key can be found in your Google Threat Intelligence account user menu, clicking on your avatar.
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

### Instance Configuration

1. Configure a Google Threat Intelligence - DTM Alerts integration instance with valid API Key.
2. Click **Test** to validate the connection.
3. To fetch DTM Alerts as incidents in XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter** | **Description** |
| --- | --- |
| Incident Type | Select "Google Threat Intelligence DTM Alert"|
| Mapper (incoming) | Select "Google Threat Intelligence DTM Alerts - Incoming Mapper"|
| API Key | Google Threat Intelligence API Key. |
| Max Fetch | Maximum number of Alerts to fetch each time. Maximum value is 25. |
| First Fetch Time | The date or relative timestamp from which to begin fetching Alerts.|
| Mirroring Direction | The mirroring direction in which to mirror the details. You can mirror "Outgoing" \(from XSOAR to GTI\) direction for DTM Alerts. |
| Alert Type | Fetch Alerts by the specified alert types.<br/>Supported values: Compromised Credentials, Domain Discovery, Forum Post, Message, Paste, Shop Listing, Tweet, Web Content. |
| Alert Monitor ID | Fetch Alerts by the specified monitor IDs. |
| Alert Status | Fetch Alerts by the specified status.<br/>Supported values: New, Read, In Progress, No Action Required, Escalated, Duplicate, Closed, Not Relevant, Tracked External. |
| Alert Severity | Fetch Alerts by the specified severity.<br/>Supported values: Low, Medium, High. |
| Alert Tags | Fetch Alerts by the specified tags. |
| Alert Match Value | Fetch Alerts by specified match value. |
| Alert mscore | Fetch Alerts with mscore greater than or equal to the given value.<br/>Note: Valid range is 0 to 100. |
| Alert Search | Search Alerts and triggering documents using a Lucene query with text values joined by AND/OR. |
