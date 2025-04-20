Sends a HTTP request with advanced capabilities

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | Specify where the request should be sent. Include the URI scheme \('http' or 'https'\). |
| method | Specify the HTTP method to use. |
| headers | Specify a hash of headers to send with the request.<br/>Headers can be of string type but need to be formatted in the following ways:<br/>\`\{"key1": "value1", "key2": "value2"\}\` or \`"key1": "value1", "key2": "value2"\` |
| body | Specify the body of the request. |
| request_content_type | Specify the Content-Type header for the request.<br/>Shorthands are provided for the following common content types:<br/>json \(application/json\)<br/>xml \(text/xml\)<br/>form \(application/x-www-form-urlencoded\)<br/>data \(multipart/form-data\)<br/>If you choose to define a different type, please include the full type name, e.g: application/pdf |
| response_content_type | Specify the Accept header for the request - the response content type.<br/>Shorthands are provided for the following common content types:<br/>json \(application/json\)<br/>xml \(text/xml\)<br/>form \(application/x-www-form-urlencoded\)<br/>data \(multipart/form-data\)<br/>If you choose to define a different type, please include the full type name, e.g: application/pdf |
| parse_response_as | Specify how you would like to parse the response. |
| auth_credentials | Basic authorization. Please set values in the format: username,password. For Bearer token please use the headers. |
| params | URL parameters to specify the query. |
| timeout | Specify the timeout of the HTTP request in seconds. Defaults to 10 seconds. |
| enable_redirect | The request will be called again with the new URL. |
| retry_on_status |  Specify the array of status codes that should cause a retry. For example: 301-303,400,402. |
| retry_count | Specify the number or retries to be made in case of a failure. Defaults to 3. |
| timeout_between_retries | Specify the timeout between each retry in seconds. Defaults to 5. |
| save_as_file | Save the response in a file. |
| filename | filename |
| unsecure | Trust any certificate \(not secure\) |
| proxy | Use system proxy settings |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HttpRequest.Response.StatusCode | The number that indicates the status of the request. | String |
| HttpRequest.Response.StatusText | The text corresponding to the status code | String |
| HttpRequest.Response.URL | The URL of the response | String |
| HttpRequest.Response.ParsedBody | The parsed response, according to \`parse_response_as\` argument. | String |
| HttpRequest.Response.Headers | The response headers. | String |
| HttpRequest.Response.Body | The response data. | Unknown |


## Script Examples
### Example command
```!HttpV2 method=GET url="https://test.jamfcloud.com/JSSResource/computers/id/1/subset/General" response_content_type=json request_content_type=json auth_credentials=myUser,myPass parse_response_as=json```
### Context Example
```json
{
    "HttpRequest": {
        "Response": {
            "Body": "{\"computer\":{\"general\":{\"id\":1,\"name\":\"Computer 1\",\"network_adapter_type\":\"\",\"mac_address\":\"11:5B:35:CA:12:12\",\"alt_network_adapter_type\":\"\",\"alt_mac_address\":\"A1:34:95:EC:97:C1\",\"ip_address\":\"123.243.192.11\",\"last_reported_ip\":\"192.168.1.11\",\"serial_number\":\"AA40F81C60A3\",\"udid\":\"AA40F812-60A3-11E4-90B8-12DF261F2C7E\",\"jamf_version\":\"9.6.29507.c\",\"platform\":\"Mac\",\"barcode_1\":\"\",\"barcode_2\":\"\",\"asset_tag\":\"\",\"remote_management\":{\"managed\":false,\"management_username\":\"\",\"management_password_sha256\":\"1230c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b811\"},\"supervised\":false,\"mdm_capable\":false,\"mdm_capable_users\":{},\"report_date\":\"2021-03-29 12:44:12\",\"report_date_epoch\":1617021852595,\"report_date_utc\":\"2021-03-29T12:44:12.595+0000\",\"last_contact_time\":\"2014-10-24 10:26:55\",\"last_contact_time_epoch\":1414146415335,\"last_contact_time_utc\":\"2014-10-24T10:26:55.335+0000\",\"initial_entry_date\":\"2021-03-29\",\"initial_entry_date_epoch\":1617021852322,\"initial_entry_date_utc\":\"2021-03-29T12:44:12.322+0000\",\"last_cloud_backup_date_epoch\":0,\"last_cloud_backup_date_utc\":\"\",\"last_enrolled_date_epoch\":1414146339607,\"last_enrolled_date_utc\":\"2014-10-24T10:25:39.607+0000\",\"mdm_profile_expiration_epoch\":0,\"mdm_profile_expiration_utc\":\"\",\"distribution_point\":\"\",\"sus\":\"\",\"site\":{\"id\":-1,\"name\":\"None\"},\"itunes_store_account_is_active\":false}}}",
            "Headers": {
                "Accept-Ranges": "bytes",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0",
                "Connection": "keep-alive",
                "Content-Encoding": "gzip",
                "Content-Length": "641",
                "Content-Type": "text/plain;charset=UTF-8",
                "Date": "Wed, 19 Jan 2022 12:12:16 GMT",
                "Server": "Jamf Cloud Node",
                "Set-Cookie": "AASALB=rbRVEXaRgAKa6+YhXAr2E4JbbP5PSS3eZpm9G1AeWQBNVG/vQ3SOmsNV4tYA5N0v7sEUQd+QYMkuUTOmF/7USLyVnQVz/yW7wQh4dWrbGOY/gAU7rL30IvQwfdut; Expires=Wed, 26 Jan 2022 12:12:16 GMT; Path=/, AWSALBCORS=rbRVEXaRgAKa6+YhXAr2E4JbbP5PSS3eZpm9G1AeWQBNVG/vQ3SOmsNV4tYA5N0v7sEUQd+QYMkuUTOmF/7USLyVnQVz/yW7wQh4dWrbGOY/gAU7rL30IvQwfdut; Expires=Wed, 26 Jan 2022 12:12:16 GMT; Path=/; SameSite=None; Secure, APBALANCEID=aws.usw2-std-ellison2-tc-4; path=/;HttpOnly;Secure;",
                "Strict-Transport-Security": "max-age=31536000; includeSubdomains;, max-age=31536000 ; includeSubDomains",
                "Vary": "Accept-Charset,Accept-Encoding,Accept-Language,Accept",
                "X-FRAME-OPTIONS": "DENY",
                "X-XSS-Protection": "1; mode=block"
            },
            "ParsedBody": {
                "computer": {
                    "general": {
                        "alt_mac_address": "A1:34:95:EC:97:C1",
                        "alt_network_adapter_type": "",
                        "asset_tag": "",
                        "barcode_1": "",
                        "barcode_2": "",
                        "distribution_point": "",
                        "id": 1,
                        "initial_entry_date": "2021-03-29",
                        "initial_entry_date_epoch": 1617021852322,
                        "initial_entry_date_utc": "2021-03-29T12:44:12.322+0000",
                        "ip_address": "200.200.200.200",
                        "itunes_store_account_is_active": false,
                        "jamf_version": "9.6.29507.c",
                        "last_cloud_backup_date_epoch": 0,
                        "last_cloud_backup_date_utc": "",
                        "last_contact_time": "2014-10-24 10:26:55",
                        "last_contact_time_epoch": 1414146415335,
                        "last_contact_time_utc": "2014-10-24T10:26:55.335+0000",
                        "last_enrolled_date_epoch": 1414146339607,
                        "last_enrolled_date_utc": "2014-10-24T10:25:39.607+0000",
                        "last_reported_ip": "192.168.1.10",
                        "mac_address": "11:5B:35:CA:12:12",
                        "mdm_capable": false,
                        "mdm_capable_users": {},
                        "mdm_profile_expiration_epoch": 0,
                        "mdm_profile_expiration_utc": "",
                        "name": "Computer 1",
                        "network_adapter_type": "",
                        "platform": "Mac",
                        "remote_management": {
                            "managed": false,
                            "management_password_sha256": "abc0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "management_username": ""
                        },
                        "report_date": "2021-03-29 12:44:12",
                        "report_date_epoch": 1617021852595,
                        "report_date_utc": "2021-03-29T12:44:12.595+0000",
                        "serial_number": "AA40F81C60A3",
                        "site": {
                            "id": -1,
                            "name": "None"
                        },
                        "supervised": false,
                        "sus": "",
                        "udid": "AA40F812-60A3-11E4-90B8-12DF261F2C7E"
                    }
                }
            },
            "StatusCode": 200,
            "StatusText": "",
            "URL": "https://test.jamfcloud.com/JSSResource/computers/id/1/subset/General"
        }
    }
}
```

### Human Readable Output

>Sent a GET request to https://test.jamfcloud.com/JSSResource/computers/id/1/subset/General
