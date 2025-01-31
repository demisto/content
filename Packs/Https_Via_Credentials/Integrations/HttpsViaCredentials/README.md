This integration is intended to use the credentials store feature for https requests. Referencing the https_v2 script for functionality. 
## Configure Https_via_Credentials on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Https_via_Credentials.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Password | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### http_request

***
Perform an http request using XSOAR stored credentials.

#### Base Command

`http_request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| headers | Specify a hash of headers to send with the request. Headers can be of string type but need to be formatted in the following ways: `\{"key1": "value1", "key2": "value2"\}` or `"key1": "value1", "key2": "value2"`. | Optional | 
| proxy | Use system proxy settings. Possible values are: True, False. Default is False. | Optional | 
| unsecure | Trust any certificate (not secure). Possible values are: False, True. Default is False. | Optional | 
| filename | Specify the name of file to be saved. Defaults to 'http-file'. Default is http-file. | Optional | 
| save_as_file | Save the response in a file. Possible values are: yes, no. Default is no. | Optional | 
| timeout_between_retries | Specify the timeout between each retry in seconds. Defaults to 5. Default is 5. | Optional | 
| retry_count | Specify the number or retries to be made in case of a failure. Defaults to 3. Default is 3. | Optional | 
| enable_redirect | The request will be called again with the new URL. Possible values are: True, False. Default is True. | Optional | 
| timeout | Specify the timeout of the HTTP request in seconds. Defaults to 10 seconds. Default is 10. | Optional | 
| parse_response_as | Specify how you would like to parse the response. Default is raw_response. | Optional | 
| request_content_type | Specify the Content-Type header for the request. Shorthands are provided for the following common content types: json (application/json) xml (text/xml) form (application/x-www-form-urlencoded) data (multipart/form-data) If you choose to define a different type, please include the full type name, e.g: application/pdf. | Optional | 
| body | Specify the body of the request. | Optional | 
| method | Specify the HTTP method to use. Possible values are: GET, POST, PUT, DELETE, PATCH, HEAD. | Required | 
| url | Specify where the request should be sent. Include the URI scheme ('http' or 'https'). | Required | 
| params | URL parameters to specify the query. | Optional | 
| authType | Select or type your method of authentication. If no auth needed, select 'N/A'. Possible values are: Basic, N/A, Bearer. Default is Basic. | Required | 
| response_content_type | Specify the Accept header for the request - the response content type. Shorthands are provided for the following common content types: json (application/json) xml (text/xml) form (application/x-www-form-urlencoded) data (multipart/form-data) If you choose to define a different type, please include the full type name, e.g: application/pdf. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HttpRequest.Response.URL | unknown |  | 
| HttpRequest.Response.StatusCode | unknown |  | 
| HttpRequest.Response.StatusText | unknown |  | 
| HttpRequest.Response.ParsedBody | unknown |  | 
| HttpRequest.Response.Headers | unknown |  | 
| HttpRequest.Response.Body | unknown |  | 
