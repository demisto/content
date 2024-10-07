With Google Cloud Logging, users can centralize all their logs in a single location, making it easier to troubleshoot issues and gain insights from their data.

## Configure Google Cloud Logging in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service Account JSON | User's Service Account key in JSON format. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gcp-logging-log-entries-list

***
Lists log entries. Use this method to retrieve log entries that originated from a project/folder/organization/billing account.

##### Required Permissions

This command requires one of the following OAuth scopes:
* `https://www.googleapis.com/auth/logging.read`
* `https://www.googleapis.com/auth/logging.admin`
* `https://www.googleapis.com/auth/cloud-platform.read-only`
* `https://www.googleapis.com/auth/cloud-platform`
    
The command requires one or more of the following IAM permissions on the specified resource:
* `logging.logEntries.list`
* `logging.privateLogEntries.list`
* `logging.views.access`

#### Base Command

`gcp-logging-log-entries-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | A comma-separated list of projects names of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional | 
| organization_name | A comma-separated list of organizations names of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional | 
| billing_account_name | A comma-separated list of billing accounts names of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional | 
| folder_name | A comma-separated list of folders names of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional | 
| filter | When specified, the results returned are limited to log entries that match the filter. Referencing a parent resource that is not listed in resourceNames will cause the filter to return no results. The maximum length of a filter is 20,000 characters. E.g., "protoPayload.requestMetadata.callerIp:1.1.1.1 AND protoPayload.serviceName:name". | Optional | 
| order_by | How the results should be sorted. Possible values are: timestamp asc, timestamp desc. Default is timestamp asc. | Optional | 
| limit | The maximum number of objects to return. | Optional | 
| page_size | The maximum number of results to return from this request. Default is 50. If the value is negative or exceeds 1000, the request is rejected. | Optional | 
| next_token | If present, then retrieve the next batch of results from the preceding call to this method. pageToken must be the value of nextPageToken from the previous response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudLogging.LogsEntry.logName | String | The resource name of the log to which this log entry belongs. | 
| GoogleCloudLogging.LogsEntry.resource.type | String | The monitored resource type. | 
| GoogleCloudLogging.LogsEntry.resource.labels | Unknown | Values for all of the labels listed in the associated monitored resource descriptor. | 
| GoogleCloudLogging.LogsEntry.resource.labels.project_id | Unknown | The project ID. | 
| GoogleCloudLogging.LogsEntry.resource.labels.cluster_name | Unknown | The cluster name. | 
| GoogleCloudLogging.LogsEntry.timestamp | String | The time the event described by the log entry occurred. | 
| GoogleCloudLogging.LogsEntry.receiveTimestamp | String | The time the log entry was received by Logging. | 
| GoogleCloudLogging.LogsEntry.severity | String | The severity of the log entry. The default value is LogSeverity.DEFAULT. | 
| GoogleCloudLogging.LogsEntry.insertId | String | A unique identifier for the log entry. | 
| GoogleCloudLogging.LogsEntry.httpRequest.requestMethod | String | The request method. | 
| GoogleCloudLogging.LogsEntry.httpRequest.requestUrl | String | The scheme \(http, https\), the host name, the path and the query portion of the URL that was requested. | 
| GoogleCloudLogging.LogsEntry.httpRequest.requestSize | String | The size of the HTTP request message in bytes, including the request headers and the request body. | 
| GoogleCloudLogging.LogsEntry.httpRequest.status | Number | The response code indicating the status of response. | 
| GoogleCloudLogging.LogsEntry.httpRequest.responseSize | String | The size of the HTTP response message sent back to the client, in bytes, including the response headers and the response body. | 
| GoogleCloudLogging.LogsEntry.httpRequest.userAgent | String | The user agent sent by the client. | 
| GoogleCloudLogging.LogsEntry.httpRequest.remoteIp | String | The IP address \(IPv4 or IPv6\) of the client that issued the HTTP request. | 
| GoogleCloudLogging.LogsEntry.httpRequest.serverIp | String | The IP address \(IPv4 or IPv6\) of the origin server that the request was sent to. | 
| GoogleCloudLogging.LogsEntry.httpRequest.referer | String | The referer URL of the request. | 
| GoogleCloudLogging.LogsEntry.httpRequest.latency | String | The request processing latency on the server, from the time the request was received until the response was sent. | 
| GoogleCloudLogging.LogsEntry.httpRequest.cacheLookup | Boolean | Whether or not a cache lookup was attempted. | 
| GoogleCloudLogging.LogsEntry.httpRequest.cacheHit | Boolean | Whether or not an entity was served from cache \(with or without validation\). | 
| GoogleCloudLogging.LogsEntry.httpRequest.cacheValidatedWithOriginServer | Boolean | Whether or not the response was validated with the origin server before being served from cache. This field is only meaningful if cacheHit is True. | 
| GoogleCloudLogging.LogsEntry.httpRequest.cacheFillBytes | String | The number of HTTP response bytes inserted into cache. Set only when a cache fill was attempted. | 
| GoogleCloudLogging.LogsEntry.httpRequest.protocol | String | Protocol used for the request. | 
| GoogleCloudLogging.LogsEntry.labels | Unknown | A map of key, value pairs that provides additional information about the log entry. The labels can be user-defined or system-defined. | 
| GoogleCloudLogging.LogsEntry.operation.id | String | An arbitrary operation identifier. Log entries with the same identifier are assumed to be part of the same operation. | 
| GoogleCloudLogging.LogsEntry.operation.producer | String | An arbitrary producer identifier. The combination of ID and producer must be globally unique. | 
| GoogleCloudLogging.LogsEntry.operation.first | Boolean | Set this to True if this is the first log entry in the operation. | 
| GoogleCloudLogging.LogsEntry.operation.last | Boolean | Set this to True if this is the last log entry in the operation. | 
| GoogleCloudLogging.LogsEntry.trace | String | The REST resource name of the trace being written to Cloud Trace in association with this log entry. | 
| GoogleCloudLogging.LogsEntry.spanId | String | The ID of the Cloud Trace span associated with the current operation in which the log is being written. | 
| GoogleCloudLogging.LogsEntry.traceSampled | Boolean | The sampling decision of the trace associated with the log entry. | 
| GoogleCloudLogging.LogsEntry.sourceLocation.file | String | Source file name. Depending on the runtime environment, this might be a simple name or a fully-qualified name. | 
| GoogleCloudLogging.LogsEntry.sourceLocation.line | String | Line within the source file. 1-based; 0 indicates no line number available. | 
| GoogleCloudLogging.LogsEntry.sourceLocation.function | String | Human-readable name of the function or method being invoked, with optional context such as the class or package name. | 
| GoogleCloudLogging.LogsEntry.split.uid | String | A globally unique identifier for all log entries in a sequence of split log entries. | 
| GoogleCloudLogging.LogsEntry.split.index | Number | The index of this LogEntry in the sequence of split log entries. | 
| GoogleCloudLogging.LogsEntry.split.totalSplits | Number | The total number of log entries that the original LogEntry was split into. | 
| GoogleCloudLogging.LogsEntry.protoPayload.@type | String | A URI identifying the type. | 
| GoogleCloudLogging.LogsEntry.authenticationInfo.principalEmail | String | Identifies the principal that granted the role to the service account. | 
| GoogleCloudLogging.LogsEntry.textPayload | String | The log entry payload, represented as a Unicode string \(UTF-8\). | 
| GoogleCloudLogging.LogsEntry.jsonPayload | Unknown | The log entry payload, represented as a structure that is expressed as a JSON object. | 
| GoogleCloudLogging.nextPageToken | String | If there might be more results than those appearing in this response, then nextPageToken is included. | 

#### Command example
```!gcp-logging-log-entries-list project_name="project_id"```
#### Context Example
```json
{
    "GoogleCloudLogging": {
        "LogsEntry": [
            {
                "insertId": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                "labels": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": "authorization.k8s.io/reason"
                },
                "logName": "logName1",
                "operation": {
                    "first": true,
                    "id": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                    "last": true,
                    "producer": "producer"
                },
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com"
                    },
                    "authorizationInfo": [
                        {
                            "granted": true,
                            "permission": "permission",
                            "resource": "resource"
                        }
                    ],
                    "methodName": "methodName",
                    "requestMetadata": {
                        "callerIp": "callerIp",
                        "callerSuppliedUserAgent": "callerSuppliedUserAgent"
                    },
                    "resourceName": "resourceName",
                    "serviceName": "serviceName",
                    "status": {
                        "code": 0
                    }
                },
                "receiveTimestamp": "2023-05-06T14:39:56.974311Z",
                "resource": {
                    "labels": {
                        "cluster_name": "cluster_name",
                        "location": "some_location",
                        "project_id": "project_id"
                    },
                    "type": "type"
                },
                "timestamp": "2023-05-06T14:39:56.974311Z"
            },
            {
                "insertId": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                "labels": {
                    "authorization.k8s.io/decision": "allow",
                    "authorization.k8s.io/reason": "authorization.k8s.io/reason"
                },
                "logName": "logName2",
                "operation": {
                    "first": true,
                    "id": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                    "last": true,
                    "producer": "producer"
                },
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com"
                    },
                    "authorizationInfo": [
                        {
                            "granted": true,
                            "permission": "permission",
                            "resource": "resource1"
                        }
                    ],
                    "methodName": "methodName",
                    "requestMetadata": {
                        "callerIp": "callerIp",
                        "callerSuppliedUserAgent": "callerSuppliedUserAgent"
                    },
                    "resourceName": "resource1",
                    "serviceName": "appengine.googleapis.com",
                    "status": {
                        "code": 0
                    }
                },
                "receiveTimestamp": "2023-04-06T14:39:56.974311Z",
                "resource": {
                    "labels": {
                        "cluster_name": "cluster_name",
                        "location": "some_location",
                        "project_id": "project_id"
                    },
                    "type": "type"
                },
                "timestamp": "2023-04-06T14:39:56.974311Z"
            }
        ],
        "nextPageToken": "xxx-xxx"
    }
}
```

#### Human Readable Output

>### Lists log entries
>|TimeStamp|Log Name|Insert ID|Principal Email|Type|Project ID|Cluster Name|
>|---|---|---|---|---|---|---|
>| 2023-05-06T14:39:56.974311Z | logName1 | XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX | user@example.com | type | project_id | cluster_name |
>| 2023-04-06T14:39:56.974311Z | logName2 | XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX | user2@example.com | type | project_id | cluster_name |
>### Next page token
>|nextPageToken|
>|---|
>| xxx-xxx |

## Troubleshooting
If you encounter the following error message: 'Failed to generate/refresh token. Subject email or service account credentials are invalid. Reason: invalid_grant: Invalid JWT Signature.', please ensure that your Service Account JSON, permissions and service account scopes are correct.