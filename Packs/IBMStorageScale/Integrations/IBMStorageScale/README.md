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

---

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook. After running a command, a DBot message appears in the War Room with the command results.

#### 1. ibm-storage-scale-get-events

Gets a limited number of the most recent audit log events for interactive investigation.

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

---

## Troubleshooting

* **Authorization Error**: If you receive an authorization error (e.g., 401 or 403 status code), verify that the provided username and password are correct and that the user has been assigned the **ProtocolAdmin** role.

* **Connection Error**: If the integration cannot connect to the server, ensure the **Server URL** is correct, accessible from the XSIAM engine, and that there are no firewalls blocking the connection.

* **Certificate Validation Error**: If you see an SSL/TLS error, it means the XSIAM engine does not trust the certificate presented by the API server. For production environments, the best practice is to import the server's root CA certificate into the XSIAM trusted certificate store. As a temporary or non-production workaround, you can select the **Trust any certificate (not secure)** option.

* **Fetch Cycle Reached Limit**: If you see a log message stating "Fetch cycle reached the event limit," it means there were more events on the server than the `Maximum number of events per fetch` value. The collector will pick up where it left off on the next cycle. If this message appears frequently, consider increasing the `max_fetch` parameter or decreasing the fetch interval.
