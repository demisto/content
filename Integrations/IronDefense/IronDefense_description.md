# IronDefense Integration for Demisto
The IronDefense Integration allows users to interact with IronDefense alerts within Demisto. The 
Integration provides the ability to rate alerts, update alert statuses, add comments to alerts, and to report 
observed bad activity.
## Setup
The following table describes all the parameters required to setup the Integration.

| Parameter             | Description                                                                                       | Example                  |
|-----------------------|---------------------------------------------------------------------------------------------------|--------------------------|
| IronAPI Host/IP       | The hostname or IP where IronAPI is hosted. This is supplied by your IronNet Representative.      | example.ironapi.hostname |
| IronAPI Port          | The port number IronAPI communicates on. This is supplied by your IronNet Representative.         | 1234                     |
| Username              | An IronVue user belonging to the "IronAPI Access" user group.                                     | demisto_user@company.net |
| Password              | The password for the IronVue user.                                                                | my_secret_password       |
| Request Timeout (Sec) | The number of seconds before requests to IronAPI times out. The default value is 60 seconds.      | 60                       |

## Fetching Incidents
The Integration does not currently support fetching IronDefense Alerts as incidents. This feature will be supported 
in a later version of the Integration. 

However, you can still create incidents by using the Demisto Add-on for Splunk to create incidents for IronDefense 
alerts ingested into Splunk. Download the Demisto Add-on for Splunk [here](https://splunkbase.splunk.com/app/3448/).
## Test Playbook
An test playbook containing all commands defined by this integration is provided for reference. Search for the 
**IronDefense Test** playbook in your content repository.
## Troubleshooting
### Logging
Log entries for the integration can be found in **/var/log/demisto/server.log**. All entries are prefixed with "IronDefense Integration:"
### Common Issues
Common errors and resolutions are described in the table below.

| Error Message                                                                                                                                                                                                           | Possible Reasons                                                                                                          | Resolution                                                                                                                                 |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| HTTPSConnectionPool(host='example.ironapi.net', port=6944): Max retries exceeded with url: /IronApi/Login (Caused by ConnectTimeoutError(, 'Connection to example.ironapi.net timed out. (connect timeout=60.0)')) (85) | <ul><li>Port number is incorrect.</li><li>IronAPI is not running.</li></ul>                                               | <ul><li>Check if the port number is correct.</li><li>Ask your IronNet representative to check the health of the IronAPI service.</li></ul> |
| ('Connection aborted.', error(104, 'Connection reset by peer')) (85)                                                                                                                                                    | <ul><li>A firewall is blocking the connection.</li></ul>                                                                   | <ul><li>Ensure your firewall allows connections to the specified host and port.</li></ul>                                                  |
| Test failed (403): This user does not have permission to access IronAPI. (85)                                                                                                                                           | <ul><li>The IronVue user does not belong to the "IronAPI Access" group.</li></ul>                                         | <ul><li>Add the user to the "IronAPI Access" group in IronVue or login with another user belonging to that group.</li></ul>                |
| Test failed (401): Not authenticated - Failed Login: Username and/or password is incorrect (85)                                                                                                                         | <ul><li>The username/password is incorrect.</li><li>The IronVue user account has been locked or needs to reset.</li></ul> | <ul><li>Correct the username/password.</li><li>Unlock/reset the user in IronVue.</li></ul>                                                 | 
                                           |
