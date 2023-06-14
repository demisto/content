## Qualys Vulnerability Management Help

- You need a Qualys user account to use the Qualys integration. If a subscription has multiple users, all users with any user role (except Contact) can use the Qualys integration. Each user’s permissions correspond to their assigned user role.
  
- Qualys Vulnerability Management uses basic authentication. You'll need your Qualys login credentials in order to use this integration.
  
- You can get your server URL by identifying your platform in this link: https://www.qualys.com/platform-identification/
  
- Qualys user accounts that have been enabled with VIP two-factor authentication can be used with the Qualys API, however two-factor authentication will not be used when making API requests. Two-factor authentication is only supported when logging into the Qualys GUI.

### Fetch Information

- There are two event types that are being fetched for the Event Collector: 
* Activity logs.
* Hosts Vulnerability.
You can adjust fetch interval using **Activity Logs Fetch Interval** and **Vulnerability Fetch Interval** arguments.

- **Warning**: set "First Fetch Time" for long time ago may cause performance issues.

- Vulnerabilities in the dataset has event_type = "host_list_detections".
