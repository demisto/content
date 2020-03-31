Sends a HTTP request and returns the response as JSON.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| method | The method for the HTTP request. |
| body | The body for the HTTP request. |
| url | The URL for the HTTP request. |
| headers | The headers for the HTTP request, in the format of "key1:value1,key2:value2, ...". |
| insecure | Trust any certificate (unsecure). |
| unsecure | Trust any certificate (unsecure). |
| proxy | Use the system proxy settings. |
| username | The user for the HTTP request. |
| password | The password for the HTTP request. |
| saveAsFile | Whether to save the file. "Yes" saves the file. The default is no. |
| filename | Uses the filename from the header if the filename is not given. The default is http-file. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HttpRequest.Response | The response for the http request. | Unknown |
