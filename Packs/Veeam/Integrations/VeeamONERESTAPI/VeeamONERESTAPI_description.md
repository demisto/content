Veeam ONE REST API allows you to query information about Veeam ONE entities and perform operations with these entities using HTTP requests and standard HTTP methods.
For more details, see [Veeam ONE REST API Reference.](https://helpcenter.veeam.com/docs/one/rest/overview.html?ver=120)

## Prerequisites

To add a Veeam ONE instance, you need the following information:
- Credentials with administrator privileges you use to connect to the Veeam ONE server. These credentials are used by the integration to obtain an access token and get to Veeam ONE REST API resources.
- The FQDN of the Veeam ONE server.
- Port used to connect to the Veeam ONE REST API on the Veeam ONE server.

## Instance Settings

Specify the following settings:
- **Name** — Name of the Veeam ONE instance. Select the **Fetches incidents** setting to start fetching incidents from the instance and view data on the Veeam Incident Dashboard.
- **Credentials** — Credentials you use to connect to the Veeam ONE server. Must have administrator privileges.
- **Resource URL** — URL that you use to connect to the Veeam ONE REST API:
  - Format — *\<hostname>:\<port>*
  - Default port number — *1239*
- **First fetch time** — Time period for which incidents will be fetched for the first time. The default value is *3 days*.
- **Triggered Alarms Per Request** — Maximum number of triggered alarms that can be fetched per each execution of the **Get All Triggered Alarms** command. The default value is *200*.
- **API Request Timeout (Seconds)** — Timeout for Veeam ONE REST API requests. The default value is *120*.
- **Incidents Fetch Interval** — Time interval for fetching incidents. The default value is *10 minutes*.

Other settings should be specified according to your infrastructure.

## Links
[View Integration Documentation](https://helpcenter.veeam.com/docs/security_plugins_xsoar/guide/)