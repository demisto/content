The UBIRCH solution can be seen as an external data certification provider, as a data notary service, giving data receivers the capability to verify data they have received with regard to its authenticity and integrity and correctness of sequence.
This integration was integrated and tested with version v1.0.0 of UBIRCH
## Configure UBIRCH in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Your MQTT host name | True |
| port | port | True |
| credentials | Username | True |
| longRunning | Long running instance | False |
| tenantId | Tenant Id | True |
| stage | Stage | True |


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

The incidents are based on these errors written in this [page](https://github.com/ubirch/niomon-http#error-codes).
- The error codes, NA401 - 4000, have a severity type `HIGH` because it may indicate that someone is trying to get authorization in an invalid manner OR that our ThingAPI is acting up.
- The error codes, ND403 - 1200, have a severity type `HIGH` because this error would likely mean that the UPP is corrected in some way, which can be a red flag.
- The error codes, ND400 - 2300, have a severity type `MEDIUM` as if the payload of a UPP is null, then no Hash can be processed. This is of course controlled, but it is very strange if the UPP is empty.
- The rest of the errors have a severity type `UNKNOWN`.