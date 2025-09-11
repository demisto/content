# IBM Storage Scale Integration

## Overview

This integration collects Command Line Interface (CLI) audit log records from the IBM Storage Scale API. CLI audit logs provide a detailed history of all administrative and management commands executed on the Storage Scale system, making them a critical data source for security monitoring, compliance, and operational troubleshooting.

The integration is engineered for high performance in demanding, large-scale environments. It utilizes a concurrent producer-consumer pattern to fetch multiple pages of data simultaneously, ensuring efficient and timely data ingestion into Cortex XSIAM.

Use this integration to:

* **Enhance Security Posture**: Monitor for unauthorized or suspicious administrative activities by tracking all executed commands, such as changes to filesystems, access controls, and network configurations.
* **Meet Compliance Requirements**: Maintain a comprehensive audit trail of all administrative actions to satisfy regulatory and compliance mandates.
* **Accelerate Troubleshooting**: Quickly identify configuration changes that may have led to operational issues by reviewing the command history.

---

## Prerequisites

Before configuring the integration, you must complete the following steps in your IBM Storage Scale environment.

### 1. Create a Dedicated Service Account

For security and manageability, create a dedicated user account for this integration. Do not use a personal administrator account.

### 2. Assign Required Permissions

The service account requires the **ProtocolAdmin** role. This role grants the necessary permissions to access the `/scalemgmt/v2/cliauditlog` API endpoint used by the integration.

For detailed instructions on creating users and assigning roles, refer to the official IBM documentation: [Managing user accounts and roles](https://www.ibm.com/docs/en/storage-scale/latest/admin/gui-managing-user-accounts-roles).

### 3. Configure a Non-Expiring Password (Recommended)

By default, user passwords in IBM Storage Scale may expire after 90 days, which would cause the integration to stop collecting events. To ensure uninterrupted operation, it is highly recommended to configure the service account's password to **not expire**.

This can typically be done during user creation or by modifying the user's properties. Please consult your IBM Storage Scale documentation for the specific commands or GUI steps.

---

## Configure IBM Storage Scale on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for **IBM Storage Scale**.
3. Click **Add instance** to create and configure a new integration instance.

    | Parameter | Description | Required |
    | --- | --- | --- |
    | **Server URL** | The base URL of the IBM Storage Scale API server. The URL must include the protocol and port. **Example**: `https://storagescale.example.com:443` | True |
    | **Credentials** | The username and password for the dedicated service account. | True |
    | **Fetch events** | Select this checkbox to enable scheduled, automatic event collection. | False |
    | **Maximum number of events per fetch** | The maximum number of events to pull in a single collection cycle. The default is 10,000. | False |
    | **Server Timezone** | Timezone of the IBM Storage Scale server. Accepts IANA names (e.g., `UTC`, `America/New_York`) or fixed offsets (e.g., `+03:00`, `-0500`, `UTC-7`). Used to build time filters with the correct local time when querying the API. Defaults to `UTC`. | False |
    | **Trust any certificate (not secure)** | This option bypasses SSL certificate validation. Only select this if your API server uses a self-signed certificate. Not recommended for production. | False |
    | **Use system proxy settings** | Select this to route traffic from the integration through the system's configured proxy server. | False |

4. Click **Test** to validate the URL, credentials, and connection to the API.

---

## Technical Details

### API Endpoint

This integration collects data from the following IBM Storage Scale API endpoint:

* `GET /scalemgmt/v2/cliauditlog`

For more information, see the official API documentation: [cliauditlog GET](https://www.ibm.com/docs/en/storage-scale/latest/rest-api-reference/cliauditlog_get.html).

### Concurrent Fetching Mechanism

To achieve high throughput, the integration does not fetch event pages sequentially. Instead, it uses an asynchronous producer-consumer model:

* A **producer** task discovers the URLs for subsequent pages of events.
* A pool of **consumer** tasks concurrently fetches the data from those URLs.

This allows the integration to overlap network requests, significantly reducing the time it takes to collect a large volume of events compared to traditional, one-at-a-time fetching.

### Timezone Handling

IBM Storage Scale's `entryTime` values are matched using a regular-expression filter constructed by the integration. To ensure the filter aligns with how timestamps are stored on the server, you can set the "Server Timezone" parameter. The integration:

* Stores all internal timestamps (like last run) in UTC.
* Converts the fetch time window into the configured server timezone when constructing the `entryTime` regex filter.
* Supports both IANA timezone names and fixed numeric offsets.

If no timezone is provided, the integration defaults to UTC.

---

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook. After running a command, a DBot message appears in the War Room with the command results.

#### 1. ibm-storage-scale-get-events

Gets a limited number of the most recent audit log events for interactive investigation. This command is used for developing/ debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

```
!ibm-storage-scale-get-events limit=10
```

##### Arguments

| Argument | Description | Required |
| --- | --- | --- |
| limit | The maximum number of events to return. The default is 50. The maximum is 1000. | False |

##### Context Output

The command returns a list of audit log events. The context data can be found at `IBMStorageScale.AuditLog`.

```json
{
    "IBMStorageScale.AuditLog": [
        {
            "oid": 12345,
            "arguments": "-A yes -D nfs4 -k nfs4",
            "command": "mmchfs",
            "node": "testnode-11.example.com",
            "returnCode": 0,
            "originator": "GUI",
            "user": "admin_user",
            "pid": 7891,
            "entryTime": "2023-10-27 14:00:00",
            "exitTime": "2023-10-27 14:00:01"
        }
    ]
}
```

#### 2. ibm-storage-scale-debug-connection

Provides comprehensive debugging information for troubleshooting the IBM Storage Scale integration. Please use this command only when instructed by support.

```
!ibm-storage-scale-debug-connection
```

##### Arguments

This command has no arguments.

##### Context Output

| Path | Type | Description |
| --- | --- | --- |
| IBMStorageScale.Debug.connection_status | String | Status of the connection to IBM Storage Scale API (success/failed). |
| IBMStorageScale.Debug.server_url | String | The configured server URL. |
| IBMStorageScale.Debug.api_endpoint | String | The API endpoint being used. |
| IBMStorageScale.Debug.current_time | String | Current timestamp when debug info was collected. |
| IBMStorageScale.Debug.last_run_info | Unknown | Information from the last run object including fetch times and stored hashes. |
| IBMStorageScale.Debug.time_filter_info | Unknown | Time filtering information including constructed query parameters. |
| IBMStorageScale.Debug.deduplication_info | Unknown | Event deduplication statistics and configuration. |
| IBMStorageScale.Debug.configuration | Unknown | Integration configuration details (without sensitive data). |
| IBMStorageScale.Debug.sample_api_response | Unknown | Sample API response data for validation. |
| IBMStorageScale.Debug.error_details | String | Error details if connection failed. |

---

## Troubleshooting

* **Authorization Error**: If you receive an authorization error (e.g., 401 or 403 status code), verify that the provided username and password are correct and that the user has been assigned the **ProtocolAdmin** role.

* **Connection Error**: If the integration cannot connect to the server, ensure the **Server URL** is correct, accessible from the XSIAM engine, and that there are no firewalls blocking the connection.

* **Certificate Validation Error**: If you see an SSL/TLS error, it means the XSIAM engine does not trust the certificate presented by the API server. For production environments, the best practice is to import the server's root CA certificate into the XSIAM trusted certificate store. As a temporary or non-production workaround, you can select the **Trust any certificate (not secure)** option.

* **Fetch Cycle Reached Limit**: If you see a log message stating "Fetch cycle reached the event limit," it means there were more events on the server than the `Maximum number of events per fetch` value. The collector will pick up where it left off on the next cycle. If this message appears frequently, consider increasing the `max_fetch` parameter or decreasing the fetch interval.
