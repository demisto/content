# IronDefense Integration for Cortex XSOAR
The IronDefense Integration allows users to interact with IronDefense alerts within Cortex XSOAR. The 
Integration provides the ability to rate alerts, update alert statuses, add comments to alerts, to report 
observed bad activity, get alerts, get events, and get IronDome information.
## Setup
The following table describes all the parameters required to setup the Integration.

| Parameter                                      | Description                                                                                       | Example                  |
|------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------------------|
| IronAPI Host/IP                                | The hostname or IP where IronAPI is hosted. This is provided by your IronNet Representative.      | example.ironapi.hostname |
| IronAPI Port                                   | The port number IronAPI communicates on. This is provided by your IronNet Representative.         | 1234                     |
| Username                                       | An IronVue user belonging to the "IronAPI Access" user group.                                     | email@company.com |
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
