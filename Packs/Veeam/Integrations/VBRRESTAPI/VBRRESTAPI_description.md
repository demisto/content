Veeam Backup & Replication REST API allows you to query information about Veeam Backup & Replication entities and perform operations with these entities using HTTP requests and standard HTTP methods. 
For more details, see [Veeam Backup & Replication REST API Reference.](https://helpcenter.veeam.com/docs/backup/vbr_rest/overview.html?ver=120)


## Prerequisites

To add a Veeam Backup & Replication instance, you need the following information:
- Credentials with administrator privileges you use to connect to the Veeam Backup & Replication server. These credentials are used by the integration to obtain an access token and get to Veeam Backup & Replication REST API resources.
- The FQDN of the Veeam Backup & Replication server.
- Port used to connect to the Veeam Backup & Replication REST API on the Veeam Backup & Replication server.

## Instance Settings

Specify the following settings:
- **Name** — Name of the Veeam Backup & Replication instance. Select the **Fetches incidents** setting to start fetching incidents from the instance and view data on the Veeam Incident Dashboard.
- **Credentials** — Credentials you use to connect to the Veeam Backup & Replication server. Must have administrator privileges.
- **Resource URL** — URL that you use to connect to the Veeam Backup & Replication REST API:
  - Format — *\<hostname>:\<port>*
  - Default port number — *9419*
- **First fetch time** — Time period for which incidents will be fetched for the first time. The default value is *3 days*.
- **Days Since Last Configuration Backup** — Incident trigger based on the date of the last configuration backup. An incident will be created if there are no successful configuration backups for the specified period. The default value is *30*.

  If you do not want to monitor this incident type, clear the **Fetch configuration backup events** check box.
- **Backup Repository Free Space (GB)** — Incident trigger based on the disk usage of the backup repository. An incident will be created if the free space size is less than the specified amount of GB. The default value is *200*.

  **Backup Repository Events Per Request** — Maximum number of backup repository events that can be fetched per each execution of the **Get All Repository States** command. The default value is 39.

  If you do not want to monitor this incident type, clear the **Fetch backup repository events** check box.
- **Malware Events Per Request** — Maximum number of malware events that can be fetched per each execution of the Get All Malware Events command. The default value is 160.

  If you do not want to monitor this incident type, clear the **Fetch malware events** check box.
- **API Request Timeout (Seconds)** — Timeout for Veeam Backup & Replication REST API requests. The default value is *120*.
- **Incidents Fetch Interval** — Time interval for fetching incidents. The default value is *10 minutes*.

Other settings should be specified according to your infrastructure.

## Links
[View Integration Documentation](https://helpcenter.veeam.com/docs/security_plugins_xsoar/guide/)