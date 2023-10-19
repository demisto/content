Traceable Platform Integration enables publishing Traceable Detected Security Events to be published to Cortex XSOAR for further action.

## Configure Traceable on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Traceable.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Traceable Platform API Endpoint URL | True |
    | API Token | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Max number of records to fetch per API call to Traceable API Endpoint | False |
    | Number of span queries to run in parallel | False |
    | Max spans per thread (1 to 1000) | False |
    | Comma-Separated Environment List To Process | False |
    | Security Score Category | False |
    | Threat Category | False |
    | IP Reputation Level | False |
    | IP Abuse Velocity | False |
    | IP Location Type | False |
    | Traceable Platform Endpoint URL | False |
    | Incident type | False |
    | Ignore Status Codes | False |
    | Incident optional field list | False |
    | Additional API Attributes | False |
    | Fetch unique incidents | False |
    | Time between raising similar incidents (in &lt;number&gt; &lt;time unit&gt;, e.g., in 12 hours, in 7 days) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list_incident_cache

***
List the entries present in the Traceable instance cache.

#### Base Command

`list_incident_cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Traceable.Instancecache.id | string | Cache entry ID. | 
| Traceable.Instancecache.expiry | date | Cache entry expiration date. | 

### purge_incident_cache

***
Delete all entries in the incident cache.

#### Base Command

`purge_incident_cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Traceable.Instancecache.id | string | Cache entry ID. | 
| Traceable.Instancecache.expiry | date | Cache entry expiration date. | 
| Traceable.Instancecache.deletion_status | string | Cache entry deletion status. | 
