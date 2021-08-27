Sends a HTTP request and returns the response as JSON.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Cortex XSOAR Version | 3.5.0+ |
 
## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| method | The method for the http request. |
| body | The body for the http request. |
| url | The URL for the http request. |
| headers | The headers for the http request, in the format of "key1:value1,key2:value2, ...". |
| insecure | Trust any certificate (not secure). |
| unsecure | Trust any certificate (not secure). |
| proxy | Use the system proxy settings. |
| username | The user for the http request. |
| password | The password for the http request. |
| saveAsFile | Whether to save the file. The default is "no". |
| filename | The filename from headers if the filename is not given. The default is "http-file". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HttpRequest.Response | The response for the http request. | Unknown |
