# IronDefense Integration for Demisto
The IronDefense Integration for Demisto allows users to interact with IronDefense alerts within Demisto. The 
Integration provides the ability to rate alerts, update alert statuses, add comments to alerts, to report 
observed bad activity, get alerts, get events, and get IronDome information.
## Setup
The following table describes all the parameters required to setup the Integration.

| Parameter                                      | Description                                                                                       | Example                  |
|------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------------------|
| IronAPI Host/IP                                | The hostname or IP where IronAPI is hosted. This is provided by your IronNet Representative.      | example.ironapi.hostname |
| IronAPI Port                                   | The port number IronAPI communicates on. This is provided by your IronNet Representative.         | 1234                     |
| Username                                       | An IronVue user belonging to the "IronAPI Access" user group.                                     | demisto_user@company.net |
| Password                                       | The password for the IronVue user.                                                                | my_secret_password       |
| Request Timeout (Sec)                          | The number of seconds before requests to IronAPI times out. The default value is 60 seconds.      | 60                       |
| Dome Notification Types to Exclude             | The list of Dome Notification types to exclude. Possible values are Participant Added, Comment Added, Community Severity Changed, Community Severity Mismatched, Enterprise Severity Mismatched, Severity Suspicious, Severity Malicious, Joined High Risk, and High Cognitive System Score. | Participant Added, Comment Added |
| Disable all Dome Notification Ingestion        | Option to turn off ingestion of all Dome Notifications.                                           | true                     |
| Alert Notification Categories to Exclude       | The list of Alert Notification categories to exclude. Possible values are C2, Action, Access, Recon, and Other. | Recon, Other |
| Alert Notification SubCategories to Exclude    | The list of Alert Notification subcategories to exclude.                                          | DNS_TUNNELING, INTERNAL_PORT_SCANNING |
| Lower Bound of Severity for Alert Notification | The minimum severity for an Alert Notifications to be ingested. Alerts with severities below this value will be excluded. | 400 |
| Upper Bound of Severity for Alert Notification | The maximum severity for an Alert Notifications to be ingested. Alerts with severities above this value will be excluded. | 900 |
| Disable all Alert Notification Ingestion       | Option to turn off ingestion of all Alert Notifications.                                          | true                     |
| Event Notification Categories to Exclude       | The list of Event Notification categories to exclude. Possible values are C2, Action, Access, Recon, and Other. | Recon, Other |
| Event Notification SubCategories to Exclude    | The list of Event Notification subcategories to exclude.                                          | DNS_TUNNELING, INTERNAL_PORT_SCANNING |
| Lower Bound of Severity for Event Notification | The minimum severity for an Event Notifications to be ingested. Events with severities below this value will be excluded. | 400 |
| Upper Bound of Severity for Event Notification | The maximum severity for an Event Notifications to be ingested. Events with severities above this value will be excluded. | 900 |
| Disable all Event Notification Ingestion       | Option to turn off ingestion of all Event Notifications.                                          | true                     |
| Dome Notification limit per request            | The limit on Dome Notifications returned per request.                                             | 500                      |
| Alert Notification limit per request           | The limit on Alert Notifications returned per request.                                            | 500                      |
| Event Notification limit per request           | The limit on Event Notifications returned per request.                                            | 500                      |


## Fetching Incidents
This integration can fetch Dome Notifications, Alert Notifications, and Event Notifications as incidents. The default configuration is to fetch just Alert Notifications as incidents. 
## Example Playbook
An example playbook containing all commands defined by this Integration is provided for reference. Look for the 
"Default IronDefense Example" playbook in your content repository.
## Troubleshooting
### Logging
Log entries for the integration can be found in /var/log/demisto/server.log. All entries are prefixed with "IronDefense Integration:"
### Common Issues
Common errors and resolutions are described in the table below.

| Error Message                                                                                                                                                                                                           | Possible Reasons                                                                                                          | Resolution                                                                                                                                 |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| HTTPSConnectionPool(host='example.ironapi.net', port=6944): Max retries exceeded with url: /IronApi/Login (Caused by ConnectTimeoutError(, 'Connection to example.ironapi.net timed out. (connect timeout=60.0)')) (85) | <ul><li>Port number is incorrect.</li><li>IronAPI is not running.</li></ul>                                               | <ul><li>Check if the port number is correct.</li><li>Ask your IronNet representative to check the health of the IronAPI service.</li></ul> |
| ('Connection aborted.', error(104, 'Connection reset by peer')) (85)                                                                                                                                                    | <ul><li>A firewall is blocking the connection</li></ul>                                                                   | <ul><li>Ensure your firewall allows connections to the specified host and port.</li></ul>                                                  |
| Test failed (403): This user does not have permission to access IronAPI. (85)                                                                                                                                           | <ul><li>The IronVue user does not belong to the "IronAPI Access" group.</li></ul>                                         | <ul><li>Add the user to the "IronAPI Access" group in IronVue or login with another user belonging to that group.</li></ul>                |
| Test failed (401): Not authenticated - Failed Login: Username and/or password is incorrect (85)                                                                                                                         | <ul><li>The username/password is incorrect.</li><li>The IronVue user account has been locked or needs a reset .</li></ul> | <ul><li>Correct the username/password.</li><li>Unlock/reset the user in IronVue.</li></ul>                                                 | 
                                           |
