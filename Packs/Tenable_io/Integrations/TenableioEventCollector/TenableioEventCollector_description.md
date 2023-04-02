## Configuration Parameters

#### Access key and Secret key
Tenable.io generates a unique set of API keys for each user account (**access and secret key**). These keys allow your application to authenticate to the Tenable.io API without creating a session.
The method to generate API keys varies depending on the role assigned to your user account. Administrators can generate API keys for any user account. For more information, see Tenable.io Documentation.

#### Vulnerabilities Fetch Interval
Time in minutes between fetches of vulnerabilities (this is not exactly a fetch interval, but the time between each start of vulnerabilities fetching process). Be aware that it should be high (e.g., 240), as the process may take some time.

#### Events Fetch Interval and Max Fetch
This interval affects only **Audit logs** fetch.
