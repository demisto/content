The UBIRCH solution can be seen as an external data certification provider, as a data notary service, giving data receivers the capability to verify data they have received with regard to its authenticity and integrity and correctness of sequence.
This integration was integrated and tested with version v1.0.0 of UBIRCH
## Configure UBIRCH on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for UBIRCH.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Your MQTT host name | True |
    | port | port | True |
    | credentials | Username | True |
    | longRunning | Long running instance | False |
    | tenantId | Tenant Id | True |
    | stage | Stage | True |

4. Click **Test** to validate the url, port and credentials.

## Usage
The UBIRCH integration is a long-running implementation. Whenever a verification of ubirched data fails, the incident is created with the following fields:

| **Field** | **Type** | **Description** |
| --- | --- | --- |
| name | string | Name of the incident to be created. |
| type | string | Type of the incident to be created. If not provided, the value of the integration parameter ***Incident type*** will be used.  |
| labels | object | RequestId and deviceId of the incident to be created. For example, `[{"type":"requestId", "value":"94a55743-d285-487a-839f-3005f3f8854a"}, {"type":"hwDeviceId", "value":"ba70ad8b-a564-4e58-9a3b-224ac0f0153f"}]` |
| severity | string | Severity level of the incident. levels are Critical, High, Medium, Low, Unknown. | 
| occurred | string | Date the incident occurred in ISO-8601 format. |
| details | object | Details of the incident to be created. For example, `{"field1":"value1","field2":"value2"}` |
| raw_json | object | Details of the incident to be created. For example, `{"field1":"value1","field2":"value2"}` |

