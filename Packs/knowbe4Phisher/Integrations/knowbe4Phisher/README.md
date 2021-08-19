KnowBE4 PhishER integration allows to pull events from PhishER system and do mutations
This integration was integrated and tested with version 6.2.0 of Phisher

## Configure Phisher on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Phisher.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key |  | True |
    | First Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
    | Fetch incidents |  | False |
    | Fetch Limit | Maximum number of alerts per fetch. Default is 50, maximum is 100. | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### phisher-message-list
***
Command to get messages from PhishER


#### Base Command

`phisher-message-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of messages to fetch. Default is 50. | Optional | 
| query | The Lucene query to search against. | Optional | 
| id | ID of specific message to retrieve. If ID is given query will be ignored. | Optional | 
| include_events | Whether to include all message events in the result. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Phisher.Message.actionStatus | String | Action Status | 
| Phisher.Message.attachments | String | A collection of attachments associated with this message | 
| Phisher.Message.category | String | The message's category | 
| Phisher.Message.comments | String | A collection of comments associated with this message. | 
| Phisher.Message.events | String | A collection of events associated with this message. | 
| Phisher.Message.from | String | Sender's email | 
| Phisher.Message.id | String | Unique identifier for the message. | 
| Phisher.Message.links | String | A collection of links that were found in the message. | 
| Phisher.Message.phishmlReport | String | The PhishML report associated with this message | 
| Phisher.Message.pipelineStatus | String | Pipeline Status | 
| Phisher.Message.reportedBy | String | The person who reported the message. | 
| Phisher.Message.rawUrl | String | URL where to download the raw message | 
| Phisher.Message.rules | String | A collection of rules associated with this message. | 
| Phisher.Message.severity | String | The message's severity | 
| Phisher.Message.subject | String | Subject of the message. | 
| Phisher.Message.tags | String | A collection of tags associated with this message. | 


#### Command Example
```!phisher-message-list```

#### Context Example
```json
{
    "Phisher": {
        "Message": [
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "image/png",
                        "filename": "sys_attachment.do?sys_id=9a00ce4a1b3e80d06b7d0e1dcd4bcb0d",
                        "md5": "2c6e475c1eaae46127acea5dea4fee31",
                        "reportedContentType": "image/png",
                        "s3Key": "nmsjpn3os34s1ssfgekd0nv3a2ovcns18hhv7j81/0b056d1c47e09a4cf17b6cfee2fa08889e9b033248f2e37396f45c4e6864bb14",
                        "sha1": "11aa586cc688788eac804ccbe1eaa8d892a57cc4",
                        "sha256": "0b056d1c47e09a4cf17b6cfee2fa08889e9b033248f2e37396f45c4e6864bb14",
                        "size": 19168,
                        "ssdeep": "384:wSw08+qDnpWTptKFG6fadBe41w/nwO7sIt8UVTsXZaAll5CYLQ:jqDnpWTnLKaPf1wP7sGTillwYLQ",
                        "virustotal": null
                    }
                ],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-08-08T14:06:11+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "bac9cf67-fa8e-46d1-ad67-69513fc44b5b",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-08-08T14:06:11Z",
                        "id": "5dd5151d-342a-472c-a1e2-94c9c1802134",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "https",
                        "target": "https://panservicedesk.service-now.com/esp?id=pan_ticket&table=u_service_request&sys_id=66fb22161b35fc905f28fc43cd4bcb53",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__panservicedesk.service-2Dnow.com_esp-3Fid-3Dpan-5Fticket-26table-3Du-5Fservice-5Frequest-26sys-5Fid-3D66fb22161b35fc905f28fc43cd4bcb53&d=DwMFaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=bnr186lJRwg3jCzucFwcWNwN3Mezt8Hv9uaJLdoX6_g&s=EAXWWVZT-gKGd3B64es-T3_m0P0OUt7ic_BL7imJBUs&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "b1b88ef8-54e5-4c36-9145-2e7c9d61a58c",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-08-08/nmsjpn3os34s1ssfgekd0nv3a2ovcns18hhv7j81/fa318f2f4ece5dd910caec44bb8ddc5dd4c3c7cc4f714980b811a9c2d0fdd4e8?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=9173d0db63d2407cb0f6186ee90d2a789b236ac99539b4a8ce69732b5227e305",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [
                    {
                        "createdAt": "2021-08-08T14:06:31Z",
                        "description": "Commonly used Subject/From words to indicate security issues in phishing attempts",
                        "id": "8837a235-8d21-44bf-8391-3f43a4f9fa47",
                        "matchedCount": 1,
                        "name": "KB4:SECURITY",
                        "tags": [
                            "KB4:SECURITY"
                        ]
                    },
                    {
                        "createdAt": "2021-08-08T14:06:31Z",
                        "description": "Commonly used Subject/From words to reflect urgency in related phishing attempts",
                        "id": "55d29cb8-1825-4d98-89ab-5e511c575a65",
                        "matchedCount": 1,
                        "name": "KB4:URGENCY",
                        "tags": [
                            "KB4:URGENCY"
                        ]
                    }
                ],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: We have received your IT request",
                "tags": [
                    {
                        "name": "KB4:SECURITY",
                        "type": "STANDARD"
                    },
                    {
                        "name": "KB4:URGENCY",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [],
                "category": "THREAT",
                "comments": [
                    {
                        "body": "edi cool",
                        "createdAt": "2021-07-19T09:55:27Z"
                    }
                ],
                "created at": "2021-07-08T18:28:27+00:00",
                "from": "edi.blr@gmail.com",
                "id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:26:40Z",
                        "id": "799955e4-9a31-40df-874d-62c6978c20b4",
                        "lastSeen": "2021-07-08T18:28:27Z",
                        "scheme": "http",
                        "target": "http://shenkar.ac.il",
                        "url": "shenkar.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/jl66qqg08f6sggcm2tpqfa6gg5g2cbk5bb65oog1/858b41fb7fa8af62eabdc96b709c7cf5e8b852747791998e07afce702f7f0401?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=ff1c4a4681740f53eb33b037188a3ea025633289ae7558cdcff2353cffc08230",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05e6\u05d9\u05d5\u05e0\u05d9\u05dd \u05d7\u05d3\u05e9\u05d9\u05dd \u05e9\u05e0\u05d9\u05ea\u05e7\u05d1\u05dc\u05d5 - \u05dc\u05db\u05e6\u05e0\u05dc\u05e1\u05d5\u05df \u05d0\u05d3\u05d9",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "THREAT",
                "comments": [
                    {
                        "body": "Chupi",
                        "createdAt": "2021-07-15T15:11:07Z"
                    },
                    {
                        "body": "From Playbook!!!!!!",
                        "createdAt": "2021-07-15T11:48:47Z"
                    },
                    {
                        "body": "From Playbook!!!!!!",
                        "createdAt": "2021-07-15T11:45:38Z"
                    },
                    {
                        "body": "From Playbook!!!!!!",
                        "createdAt": "2021-07-15T11:37:21Z"
                    },
                    {
                        "body": "From Playbook!!!!!!",
                        "createdAt": "2021-07-14T16:05:45Z"
                    },
                    {
                        "body": "From Playbook!!!!!!",
                        "createdAt": "2021-07-14T15:49:04Z"
                    }
                ],
                "created at": "2021-07-08T18:27:57+00:00",
                "from": "edi.blr@gmail.com",
                "id": "fdd6cda3-505e-4524-a595-86d5d250c722",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:26:40Z",
                        "id": "58a08e21-6047-402d-9d57-1b8fef2c5317",
                        "lastSeen": "2021-07-08T18:28:27Z",
                        "scheme": "http",
                        "target": "http://shenkar.ac.il",
                        "url": "shenkar.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/23ngfi0m74a34uu8abb62mb4aapvbvam3uj3c201/63adf46300726d250116b7fb676abc3a2dee2be922b0e8b10b7386f89e782845?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=1a6327c81d952f0fdb7b4dfe3bb23987f477fdb9fdb587a53bed5e0ca64bd921",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05e6\u05d9\u05d5\u05e0\u05d9\u05dd \u05d7\u05d3\u05e9\u05d9\u05dd \u05e9\u05e0\u05d9\u05ea\u05e7\u05d1\u05dc\u05d5 - \u05dc\u05db\u05e6\u05e0\u05dc\u05e1\u05d5\u05df \u05d0\u05d3\u05d9",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-07-08T18:27:04+00:00",
                "from": "edi.blr@gmail.com",
                "id": "8eff23f7-cd65-49ce-98da-871ecd0e18a1",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:26:40Z",
                        "id": "9e6ce6d7-b05d-49a7-b074-2112a0eb56ea",
                        "lastSeen": "2021-07-08T18:28:27Z",
                        "scheme": "http",
                        "target": "http://shenkar.ac.il",
                        "url": "shenkar.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/3md9p52errogkefdkujrp32ibiuvnsr7vnrmem81/35ea2d36bc7a2c3a60236aabb1bf1c7738cca18c32cd26e842eb9f336d382f2f?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=6c29c9cb5ed5e79cc2a905d5ba357979b4602e1b9f5695c0b96d2941db6776f2",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: \u05e6\u05d9\u05d5\u05e0\u05d9\u05dd \u05d7\u05d3\u05e9\u05d9\u05dd \u05e9\u05e0\u05d9\u05ea\u05e7\u05d1\u05dc\u05d5 - \u05dc\u05db\u05e6\u05e0\u05dc\u05e1\u05d5\u05df \u05d0\u05d3\u05d9",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "THREAT",
                "comments": [
                    {
                        "body": "Dan Einbinder",
                        "createdAt": "2021-07-21T09:59:27Z"
                    },
                    {
                        "body": "Ernestas Setkus",
                        "createdAt": "2021-07-21T09:53:30Z"
                    }
                ],
                "created at": "2021-07-08T18:26:40+00:00",
                "from": "edi.blr@gmail.com",
                "id": "edd66fed-5150-4a73-b447-6572987c7392",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:26:40Z",
                        "id": "3f039d21-30e8-4b8b-ba2f-47eaf2dacd19",
                        "lastSeen": "2021-07-08T18:28:27Z",
                        "scheme": "http",
                        "target": "http://shenkar.ac.il",
                        "url": "shenkar.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/rtoja6l0tbc62f0ib1psj8m7htn2g85kh89o7f81/903a83d3da2b009c8209dbc6d97875f7d609674ec9d65152057ea087daeb2011?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=cbad16ddc3226c183faac1a9bff5d2a46e2b6d071b95566391ac6ffad58b348e",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05e6\u05d9\u05d5\u05e0\u05d9\u05dd \u05d7\u05d3\u05e9\u05d9\u05dd \u05e9\u05e0\u05d9\u05ea\u05e7\u05d1\u05dc\u05d5 - \u05dc\u05db\u05e6\u05e0\u05dc\u05e1\u05d5\u05df \u05d0\u05d3\u05d9",
                "tags": [
                    {
                        "name": "SYIANDA XULU",
                        "type": "STANDARD"
                    },
                    {
                        "name": "OSHER DAVIDA",
                        "type": "STANDARD"
                    },
                    {
                        "name": "'OSHER DAVIDA', 'SHAI AIZEN'",
                        "type": "STANDARD"
                    },
                    {
                        "name": "OSHER DAVIDA, SHAI AIZEN",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [],
                "category": "THREAT",
                "comments": [
                    {
                        "body": "The last Dance",
                        "createdAt": "2021-08-19T17:27:57Z"
                    }
                ],
                "created at": "2021-07-08T18:24:15+00:00",
                "from": "edi.blr@gmail.com",
                "id": "3625caf9-b6c9-416f-8106-23a0d6d58754",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:24:15Z",
                        "id": "1ac16a14-549e-4b08-941a-c5bc1b97af30",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://www.waza.org",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:24:15Z",
                        "id": "8219996d-883c-402a-b68d-29b1205c829c",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://www.safari.co.il",
                        "url": "www.safari.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:24:15Z",
                        "id": "64371c0c-7042-446f-8da6-80839055862a",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://en.wikipedia.org/wiki/Safari_park",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:24:15Z",
                        "id": "51d468fb-bd2b-429b-bd2d-cf697d865136",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://safari.co.il",
                        "url": "safari.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "59def68f-3778-43bc-8e6b-94274b911038",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/sua8ihabj6ut60bp0l2i0q1fpgmmmovk3h9s7v81/b2123ca67cb35d6fafc3d17f1560b6683186d29be931bb7563f29371a89c9fb1?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=54e6b0f3aa7ad31cb46ffb9abf53a1a99150539bfb0b6a7883ae55e3dcb2d920",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: \u200f\u200fRE: \u05d2\u05e0\u05d9 \u05d7\u05d9\u05d5\u05ea \u05e2\u05dd \u05e1\u05e4\u05d0\u05e8\u05d9",
                "tags": [
                    {
                        "name": "PINK",
                        "type": "STANDARD"
                    },
                    {
                        "name": "RIHANNA",
                        "type": "STANDARD"
                    },
                    {
                        "name": "SIA",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-07-08T18:23:14+00:00",
                "from": "edi.blr@gmail.com",
                "id": "5b2d1c54-f9e5-4e35-b042-36f358eab4dd",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "9defac4e-0cd1-4c31-af28-aed17ec734a9",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://url9421.boostapp.co.il/ls/click?upn=I26BJb-2BhudbAgBKbqHtSUFXc5rXN0-2FjCibvLfg9qI3KFeBrUjyq62BvYkZP4Ro07RBLv_KxOhWnQcAGpb7Ve-2B2Azksb3w2WmZZuKKVNzyrquNPbz9djYIAw7-2FVCkzG49UtzQnqivIU-2FyawxGbioPmf5EheqFI64zembzWH9YaQoH6YGslmQCjYimWyr-2B5fg2xEnNjFUpzPmnWlAGQwlmwJaNh35fG0QDe75QSkc-2FcvIVimPWcDw8xQis-2BoZNWNMKU6Hc96HeRsqCZdo4NT2Olgx-2FA2A-3D-3D",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "10388a0a-29e2-44d4-ba1b-02f5e6b2e685",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://boostapp.co.il",
                        "url": "boostapp.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "f31d10ca-41ad-4292-a5db-e9c16aa0d452",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "6d744310-74e1-4fae-9451-99f1223d5a2c",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "https",
                        "target": "https://login.boostapp.co.il/assets/img/LogoMail.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "adad2660-6f91-4ee2-a7ca-79fd7583fdb2",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://url9421.boostapp.co.il/wf/open?upn=afzfs8stcMgGkHvz5VoFjQ94AEJBusbujaIWWAyWV-2F8oNF7ezbdjemcBJqDAdi9-2FGm4dLrDhXoEKdgqPVsgfIx3OpzYm0i14rQa0ZvzIzk3GgoEHeN3sO5CBmR9E0gXB4wKiSAgNapAFYah5purQGuLLj-2BbJrw6jkYiPMQ7XLKk9FRbXS-2BQ2CR3yrybmBpLMw9rN4rRZYnuCSSZ-2BVYB73uN78umg1EFJOh70Tywc9q4-3D",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/1qb5pn0aa9vranducngoeeg45n68l0gl1tkvjho1/07f6dff216ad2f4c638a4eabcd676e9978e5094c91e68c4427e0ca3e891b7287?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=a72e330597e68d14dd5ee2b5f680a4f0129a61e9afaeb5a08b66cebef468fae8",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: \u05e9\u05d9\u05de\u05d5\u05e9 \u05d1\u05de\u05d2\u05e0\u05d6\u05d9\u05d5\u05dd",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "application/ics",
                        "filename": "invite.ics",
                        "md5": "587934db9457338ed8eef07f7bf68500",
                        "reportedContentType": "application/ics",
                        "s3Key": "vcpk0qpc7busroqus77lklq2qgqn6uvb8rv6sk01/cc17d862708ba61c869c19a6e5a406fa6879900e8e33e8b0d303d3e0ccabb5d2",
                        "sha1": "d40c337e5eb8bc294bbab40656ce729de77a42fb",
                        "sha256": "cc17d862708ba61c869c19a6e5a406fa6879900e8e33e8b0d303d3e0ccabb5d2",
                        "size": 4390,
                        "ssdeep": "96:EzZf7sbtWs7WlYego1yBskUZLKvWo73K+V2nNlpvEQ+aXx/Ly+8TOzIB2AMMwTeT:ywe7yRS/d+aXpd637d",
                        "virustotal": null
                    }
                ],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-07-08T18:22:55+00:00",
                "from": "edi.blr@gmail.com",
                "id": "4436f778-1446-4f21-a576-6945f284c93b",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "8e8f85c0-8ff8-49d1-9fdf-b9f7d4a30e09",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://niceactimize.com",
                        "url": "niceactimize.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "16bf34b6-bcd3-4695-b045-5bac5a9aaf01",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://nice.com",
                        "url": "nice.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "0fc0fc35-d743-47d9-8150-56e23dd9f84e",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://tm-group.com",
                        "url": "tm-group.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "4230d49b-89c6-4aa3-8daa-52771b81d1b1",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "1eb7238c-c80b-471c-941b-76ca8ef86d03",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://cyberbitc.com",
                        "url": "cyberbitc.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "2a2c8bff-854b-4909-81aa-cb59e9a3abc5",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://hotmail.com",
                        "url": "hotmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "ef7f74bf-d25d-4ab4-8774-cbf6c45522b3",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://dialogic.com",
                        "url": "dialogic.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/vcpk0qpc7busroqus77lklq2qgqn6uvb8rv6sk01/a43556dd0b30292d7b446668c8c7c31a7b406e1d59d85e754f6996860d62e02a?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175856Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=eae7ec821e1e1627c1aedd709fd8c25d891042f2c59ce561c139c6f80b7785f3",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: \u05db\u05d3\u05d5\u05e8\u05d2\u05dc",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd - \ufffd\ufffd\ufffd\ufffd.pdf",
                        "md5": "862074b6c20f1e5aeb21254172f02cbd",
                        "reportedContentType": "application/pdf",
                        "s3Key": "hekqmb89lnddr8og929if5da5r7oj08gsk3pfa81/c08a5d9c96e17293f3c07495b19f776bc762d2feee11d65101e354fd03f49990",
                        "sha1": "052fe5e4ae34481faeab6501ff41c81c8f6aadd3",
                        "sha256": "c08a5d9c96e17293f3c07495b19f776bc762d2feee11d65101e354fd03f49990",
                        "size": 81125,
                        "ssdeep": "1536:coG1cYRkagnSOF45wQtGv5i/dnIUf4ep9taWRLga/8Sr8tx/ctkC:cfzP59w019f4kdRL//8SM/0",
                        "virustotal": null
                    }
                ],
                "category": "SPAM",
                "comments": [
                    {
                        "body": "Edi's Test 12/08/21",
                        "createdAt": "2021-08-12T10:44:31Z"
                    }
                ],
                "created at": "2021-07-08T18:22:08+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "87c1ae39-9e34-4c17-b6e8-2d5d6fea2d52",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "ae81e62c-dbec-40ed-b479-0b157b69e809",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://tauex.tau.ac.il",
                        "url": "tauex.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "91a2a848-7cf6-4462-8066-542368a99622",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://listserv.tau.ac.il",
                        "url": "listserv.tau.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/hekqmb89lnddr8og929if5da5r7oj08gsk3pfa81/dc5d905fc3cb556c6eca3dd90f4d7e8206d4e52ec98fe03e202f0658a886e665?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=caee99202441190aeb4980a595b2966cd4038bf051fc59746d4dd7ca61a9b801",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05de\u05dc\u05d2\u05ea \u05e0\u05d5\u05d9\u05d1\u05d0\u05d5\u05d0\u05e8 \u05dc\u05d3\u05d5\u05e7\u05d8\u05e8\u05e0\u05d8\u05d9\u05dd \u05d1\u05e0\u05d9 \u05d4\u05d7\u05d1\u05e8\u05d4 \u05d4\u05e2\u05e8\u05d1\u05d9\u05ea",
                "tags": [
                    {
                        "name": "TOTO",
                        "type": "STANDARD"
                    },
                    {
                        "name": "CHUPI",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd - \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd 2021.pdf",
                        "md5": "09986e7c3727e7e18eacd779f23df170",
                        "reportedContentType": "application/pdf",
                        "s3Key": "bj4rpot6e2m4o109uv2kdqdahlm2k8lj2lfsvs81/eda779fda4a8ad2dde49c76b8211c36967047298c0fd61a5d988e8b28a2e0f5f",
                        "sha1": "aee97948d5d0af3f67c45ffc491631d2bb695f62",
                        "sha256": "eda779fda4a8ad2dde49c76b8211c36967047298c0fd61a5d988e8b28a2e0f5f",
                        "size": 426813,
                        "ssdeep": "6144:lY1caY6zI+Z6BlR5lh86GXnMUrayMnjoFkVE4Lkw/nqkrxNc2YU7bE3I:lY1S6zI+Z6/UXnH7Gj+gkwqkrxP7n",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-07-08T18:21:57+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "1a5302e4-69ff-4c67-8f72-1b55b9e27f47",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "f5cd536a-03fc-44c4-84cf-1e60e7f8b8d0",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://listserv.tau.ac.il",
                        "url": "listserv.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "04dea3d7-f72f-484e-b913-1fdab8b19396",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://tauex.tau.ac.il",
                        "url": "tauex.tau.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/bj4rpot6e2m4o109uv2kdqdahlm2k8lj2lfsvs81/82e3edfa6d138687cc90635d322bf0624a8675ad2903db5d9fc6f445e0412f6f?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=85eb301223fcc8df82823a46470ef5184d2698cf78a1649e00468c41731d08a6",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "Fwd: \u05e1\u05d3\u05e0\u05d0 \u05d1\u05e0\u05d5\u05e9\u05d0 \u05e0\u05e0\u05d5-\u05dc\u05d5\u05d5\u05d9\u05d9\u05e0\u05d9\u05dd",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-07-08T18:21:36+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "e7eda9f8-0f1b-4863-8c89-c169c5311a09",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "dfbd3367-f846-40b1-abec-d1bb627e6c94",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XB6E75FE11D9E3B0F537BC118C037AEFBB90F100F1610137DF29770D473EC4439641857D39671F74A053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "f22cde56-0a8f-46fb-9577-ff220c49ac97",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "http",
                        "target": "http://easycopy.co.il",
                        "url": "easycopy.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "c7c0d1e5-f93a-4d06-b2f9-bae7ffc00ee5",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X9071F34DAF5191DE8E3268873BDDCABC14242E795531AC8279405D12068DCD3C02590F63F441014C053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "487d4b50-758b-4488-85cc-de2359ebb865",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X6395D6C8586EE1074265AE2190D74BC6EFA5B7B77E433DD9CBBD6B57A9324D26A4026213EDBB7A00053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "7467d54e-f199-42a4-9ac8-c3be5efc1f3c",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X13715CCAB4D63EFB2A0609EDE622FD213113C6D5B7E46EBD965E550EFD1BC8F6A6F37288672AE081053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "24c0cbca-3f00-4fad-86b6-c0375f6df67d",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X43D5BF1E629911085C4322D0073EC3BCD446D4295E845B21F386C6C7E0515D831B12669A4A5A166E053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "4a3972b8-f847-4d66-b29b-6b31491eb0c4",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X0CF79CD2BBAB896C1FE627F8236576193F08AAC17AF209B128C332C6DB5F785F31ED8F4559E79974053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "13702af4-5c36-4929-a7c9-172e24548a6b",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XBC5C170D00DBA59DACD99F3B58AA49506B6DF45CA5C11A691B16CB7C8EFF75DF4D469F8FCBBA3207053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "a01951e7-9886-466f-bc2b-53c62f4c04eb",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X4FD9C3CFFC08F5DE61ACEBF37C37773DCB90FCE5ED619907C76B6745EB977AF89D7B6DA4059A9788053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "51efae43-28ac-4c96-aebd-48d9a529b02a",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XE02B4C2245D9B401451EDC779283F657C3C1644076240776A020AA18B2ECABC16E4E639160C6C2DB053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "5b70179a-d876-4df2-adaa-5e5408377aee",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/_______-02_0.png?cache=1613398701611",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "f52d8ca8-d64c-4b56-bfff-2f50ac0c0e56",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XF8B427AA871C4C4DAFD9537B2DADFB2749DA092BC6545119818F0E14EFDEBE51646DD0584EA2472B053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "8e280616-3eb8-461a-a8c3-403005d0271f",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/___________60.png?cache=1624952105997",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "89d01069-f949-487e-b97a-37afcea45be5",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/_________34.png?cache=1623903894986",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "05324679-2a15-458b-bb1b-8f23c4385455",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/__________-01_0.png?cache=1620223476328",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "54fe8ab6-cd17-4cf8-829c-11919fe05e15",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/newsleter_new___________-05_0.png?cache=1624452876811",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "32052861-8fae-4d0d-915a-7702d1c3a01c",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/______29.png?cache=1624952652395",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "15982112-7ff0-4526-bdfa-475b81fac861",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X308C20D9FA2DDE9E0CF22EF7956B3AC0C3A40B5C893321B0F864B6D36594131A1A56D42B5942EC27053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "06cde437-56c0-4a78-b63b-15c55d985f8a",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XBE8BB914B2221D60550A8F379FD8A9B8F8FD7D784A8391E808FDF313DBDF8F602B6221AE1EDB82BA053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "5291bcf4-a05e-41e8-b1db-84a0d49523d8",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XEBB8B1269B8866CB47BF89C296D1B0A3CAD84980DE32E766A72AA342102F18A04B0C37700DBB7D6A053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "6aa389c9-9fb7-4b7b-8886-0ddf23cd22c4",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Out_0X9C7C1673E92969332CD301CA5372666857FBE862071E07AF996605DF1535AD66BF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "d837a985-0c71-45fe-893e-fdc3bcee1ab7",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "http",
                        "target": "http://mail.tau.ac.il",
                        "url": "mail.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "b23174e2-d0e7-466d-80e3-4309f5710461",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/header_newsletter-01_2.png?cache=1559118248961",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "c585fc53-8ae5-4e59-94e5-6f2c416e685b",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XF3439857FE2F3C7B5FEC890C1781228CCBA2A9A10A185BF6BBFFBBB48523CBB7058B056AF0DA5B0A053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "34332ff8-a16a-4e11-83d1-a557d24becde",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X044F751A833E7377247E2B24D39079C66606C43A27589BCBBA618B1039D8E114CC5E63B008B54BD3053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "03e70294-7eac-4df3-8785-e81d11828103",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X730787209F2083C81BDEF7A27CD0D9209586C506885DF82905A960AC44F3DEB91CF4768A6B12E835053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "a5f39676-d84a-46c8-8cf9-2f93280fedc1",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X1FD6CD81F4D05256240FE1B7138248F34560D04306F40B06D85869B356993E9A43E19BD099AFBFB9053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "5f507900-3656-4600-9802-60ec99be18ab",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X1F60060C2982193BC13E0110ADA0A009D08ED389F5B41150C1F41F8C05E38A9F18A0506BC5BED8EF053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "9b4e9e9e-6797-49f1-9277-64fcb4d23514",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XEA7C1A251C8E65D14698EBB36528816402B39F80927C1A28AFF86EA614131B5701FF76DBEA2CA16B053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "551cdb54-a577-4a09-9a87-8e342086e29c",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XC1476976806085B636DBC0E598C78B81053077F97FE729BDE52A41F2727B0B8C0A8018A918E2DB6C053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "7a2e1c69-2c4f-43bd-9f7c-75267671a4a0",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/SpamAbuse_0X9C7C1673E92969332CD301CA5372666857FBE862071E07AF996605DF1535AD66BF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "5f544486-67ab-4c07-a5a1-1f5c90c9a14b",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Show/0X9C7C1673E92969332CD301CA5372666857FBE862071E07AF996605DF1535AD66BF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "152ec002-999c-4ab7-b0ce-9fa4c8dace74",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Open/0X9C7C1673E92969332CD301CA5372666857FBE862071E07AF996605DF1535AD66BF2B8A52F813D52F.gif",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "eadf366f-e7b2-4f04-a0c0-3adbfde4bf9b",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/newsleter_new-03_4.png?cache=1624452897132",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "0c1e78af-243d-419f-9210-a57ac384d389",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X74CDA218B18EA76649E191D6A490756DFE93519563103D46B508AFCA0ED8E73ABC1CCA951FD0D850053E8DFF7E790383D73B40C27A426F0AF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "4ffcbc31-d013-45b4-aace-b6cd06c9b0f3",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/nslinks/0XA7B345C74AEB82B7BA022830AA129F80AE751E8DF83E53404402EBD2F42C2690BE03F61F56173B90B95D29F255FEE7606F04B3FFA18E95307C1CD1395241FB41BFA19C57546167EC1603DE791398666F1B53948D642C06EA7A112A14157002DC8D5AEF4FAB280CB0552835B8FF6C759D.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "23f29148-7885-4d8e-a181-169628f3a3dd",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "http",
                        "target": "http://student.co.il",
                        "url": "student.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:36Z",
                        "id": "f94c541b-9e54-4b3b-a788-e5b2cc65f1e2",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/____________7.jpg?cache=1624956161865",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/5vfqaiacf3n4f4eqvvgksupdgpji2ado543pfa81/aa194f6faf6fc3ae31dd9230a6aeaa77a4303b46488d0dcb12b628512edf41b4?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=658c046beb89e373f96fd13949714cf0db52f7f279d75fa122ca48b1bfcae1d4",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: \u05d4\u05d9\u05d9 \u05d0\u05d3\u05d5\u05d0\u05e8\u05d3, \u05d4\u05db\u05e0\u05d5 \u05e2\u05d1\u05d5\u05e8\u05da \u05d0\u05ea \u05d4\u05e2\u05d3\u05db\u05d5\u05df \u05d4\u05e9\u05d1\u05d5\u05e2\u05d9 \u05e9\u05dc \u05d0\u05d2\u05d5\u05d3\u05ea \u05d4\u05e1\u05d8\u05d5\u05d3\u05e0\u05d8\u05d9\u05dd \u05d5\u05d4\u05e1\u05d8\u05d5\u05d3\u05e0\u05d8\u05d9\u05d5\u05ea!",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "UNKNOWN",
                "comments": [],
                "created at": "2021-07-08T18:21:19+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "dd2bca13-eee3-4b01-8c15-27a67b589c46",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "40377ee4-319c-4ed3-904c-32bf6b3fe0a2",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/notification/CPNwlyf7p_KkB_uKAwGPKVMfyjHhTQbCEliZaKx3Cb4RjBXutsuBcEAERd6nF3ZMfWXrRvYb2hrtv8l6klgr3ofSDvcS_q1dbAzqhuxX-BuEZGvRxQPxDDxrPo_HJn1k",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "93948ec6-5c25-4ab2-b534-fc91072ddad3",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/notification/FRS1X4A-iJBxLLdIYOxbKJftoEawWh5ixWo3FdDR1kA79pVWMgxK3q1nQOjuohcdEsJcr0rw2YL0Vy3rPqUolKlS8svAqsVc61g-8l9q8nFnFRqicAuQ_y40GZxjyHQ2",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "f0e716a5-d18f-467b-9113-d48cc1e8236a",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/notification-email-unsubscribe/aa0b1c440b31653914fb78a3d6cdae956e1f38055b198adff8053fb291054fed25698599b074eb968fc081d27ff73a1961ec4d50ed7f7da998f5b3892a14dce4",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "87f8bd7d-e4c1-4a09-ab9f-0f6b9ebfc00b",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "http",
                        "target": "http://lumapps.com",
                        "url": "lumapps.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "96a5dc70-a07c-4b11-8dfe-ca3fdfcdc618",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/client/notification/images/timer.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "d5799236-5c82-45c1-8dab-bceeaa45b6fc",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/notification/GQZ0iIQSzmrI9JnVqcTTjv5AO80_fhyJGVGXsS7uAUb1P5sQr2Vh2G3EDI-sdGFnjYatkBsM85S0KJhVE5Q-MpLOdpl2ab0Pn55cddo6b9j6Rg9430EsCv-b94POBR0h",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "77ac98f4-6bb0-4306-ab01-4bc8ad04333e",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "7fa10a52-7af0-45ba-bfe6-df6dfb0d0785",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://frontprocess2.lumsites.appspot.com/serve/AMIfv947BFFR5QKCFWOUaOvHwDXMxt2b9Jo6PXd0PqYI-b9TLiFGI0ZE5oqUgsp0Lg4RJyKCnqTS6zp8UvP1LT3KSL3xsL3IK7OsNONVEdAztwE4L5j4x6DG4_6VTOMtw8CS6xIzTqIaSwj7Y2e2NY1vO8fE6yVNgQ",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:19Z",
                        "id": "f007257f-5901-4e11-9240-102aab5769db",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/serve/AMIfv97Bj3PTwGt3mGlRPr75WEobWJSMLarFLgRByKrYeFjtg0DkjL4PG6UltAl72bLkAWyKx9Hg9MqHLgLlXhmOV6o4vDS2s9be3MLmMfTyarG7mJNASd5-rgeirp1uzO54dNYjJl1KDgIq15MUzKMyW8YBucMfsA",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-08T18:21:20Z",
                        "id": "5f5e7fee-d198-4fc5-bafd-2ecced46eac9",
                        "lastSeen": "2021-07-08T18:21:20Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/client/notification/images/logo-powered.png",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-08/09ln0a21kkb4a88iiur23vrt7vf9h401b0vat401/34585bcf6bef1405b552e26b6bf682a2496ebcc798936002106d6a1c14d14fee?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=d53424c69075ec3e8dc5a23cbff9c3f73c5561c78dc5c91a8b52c1fd5e4c3bfb",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: [LOOP] Partner Space Overview: Welcome to Partner Space Overview",
                "tags": []
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [],
                "category": "CLEAN",
                "comments": [
                    {
                        "body": "Folarin Balogun",
                        "createdAt": "2021-08-17T14:43:22Z"
                    },
                    {
                        "body": "Emile Smith Rowe 10",
                        "createdAt": "2021-08-17T14:21:17Z"
                    },
                    {
                        "body": "Emile Smith Rowe",
                        "createdAt": "2021-08-17T14:20:32Z"
                    },
                    {
                        "body": "Emile Smith Rowe",
                        "createdAt": "2021-08-17T14:19:31Z"
                    },
                    {
                        "body": "Chupi & Toto",
                        "createdAt": "2021-08-16T12:39:15Z"
                    }
                ],
                "created at": "2021-07-07T15:18:58+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "00a43d65-5802-4df6-9c3c-f7d2024ddb0b",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "f95a1768-bc9e-4919-bc14-633132ba8b73",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://twitter.com/PaloAltoNtwks",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "1fc6a5c0-6ffe-4ceb-a5e4-a21dfe816772",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://www.linkedin.com/company/palo-alto-networks",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "5b75aa9c-80f6-4eeb-9312-a538c95c88a7",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://lh3.googleusercontent.com/j7imQX01W4Xjrlb-RHmYzlKDavLULPycA2lb0zp-OTJ4U1o5J1eR1w1jy4RQBHLZp7t_zOWYHhOWpb0yHDnCdNQFzczvRueu-uM6RNWyXBQnG9ItXg7KWXEMLHB6Ajfdpofpkym3",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "dd6601fb-71d8-49f1-850b-636076893525",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:58Z",
                        "id": "0b08d43f-7356-48fd-aa77-445e32bb2b96",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://smrtr.io/5-YLD",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:58Z",
                        "id": "7884103f-be2b-4872-ba3e-cd7339049bee",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://theloop.paloaltonetworks.com/loop/internal-mobility-policy2",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:58Z",
                        "id": "131b574b-9e2a-487f-928e-21d86a57de97",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://www.facebook.com/PaloAltoNetworks",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:58Z",
                        "id": "35099203-28ec-48c1-a9dd-44cac20c33b2",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://lh3.googleusercontent.com/qooRY0qLqddHjTfs3o7PS01IL_nVD0qthwdz3kXJqHatwGxi2FsP-Ws0d_OEUwUiFoaNScqv8-H2d0oBj_8vVqgbzGFGABoVzjR7xjf9mEnqX8WQplpZDB2BuJV8Nqlpl4qgzPKD",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "2e3ce0c2-5923-4d61-8370-202f4e0f8c93",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://lh6.googleusercontent.com/bxM4CuJ5sRa93cHJrt2NuKoYq0sGOVzIC7afl6e0vGe5w0PKOYYJTlUPS1XMIWNld1vRtcKWlzQXcp63nVD2ndIBXWx8M_QoUCIZDXJ5AMwYtkAQU459GguGI_3RvMI0SYkVV5Rf",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "859472e7-91c0-45c9-9f7f-8f01b93a247c",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://lh4.googleusercontent.com/RQSU1krULpgpEe_WxAtX7NC_BlzSaOu9uLrSp3k8YLe0MbkJML5e5sAafD0s1nvCVxDqdlKEORRmgMUWluPP7TqN2nn8BvEzdS-Vs77lNT_3IORDguz1Bw7_0Ro5FXjQVDChqECW",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "9babca02-87bb-4781-9f1e-ee1c2ac5a296",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://smrtr.io/5JMz-",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "7d5a398c-9da6-4ffa-94eb-8f3e4e69aa76",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://smrtr.io/5RT4K",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "41262dea-0c7e-43a1-85c7-061d34a1e3c5",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://docs.google.com/forms/d/e/1FAIpQLScv4-pUauFaajlKUOpzqGnaYessl0tksacx7Haa1z6vFQXc0A/viewform?usp=sf_link",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "b8064587-9c1b-4aaa-8715-4019dde4af84",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://www.smartrecruiters.com/app/employee-portal/5f0bfc5b150d9a317eac65ea/jobs",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-07-07T15:18:59Z",
                        "id": "0d91f814-8f48-4ae5-9bc8-b9ab9f2734db",
                        "lastSeen": "2021-07-07T15:18:59Z",
                        "scheme": "https",
                        "target": "https://lh6.googleusercontent.com/CtW3YLbCPKPRHvM-7DLeVxWXpDux9VwDCxaDdrqH0RX1TBwqHnY2_IoG8GCdTLxw6xDNmk40FlvDOC1JysSufAlLavO7P6b0NVvf-NeEaYIpP_W806zkTkta2f-LUD58iv79GAFP",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": null,
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-07-07/nf8vb5hr8ba5lppq81n4i86b6b9pb6us6r050rg1/01838153d3d92db678018f8753169315fb38c45c6ff4847ab1f0dbfeee9435a1?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=4ca82310ec0e15cfb7a7299a6f5a7ee8bff472dac11a3aec4cf40c234d8ea02b",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: Your next career opportunity is... Right Here!",
                "tags": [
                    {
                        "name": "SIA",
                        "type": "STANDARD"
                    },
                    {
                        "name": "DAVY KLAASEN",
                        "type": "STANDARD"
                    },
                    {
                        "name": "DUSAN TADIC",
                        "type": "STANDARD"
                    },
                    {
                        "name": "LENO",
                        "type": "STANDARD"
                    },
                    {
                        "name": "BALOGUN",
                        "type": "STANDARD"
                    },
                    {
                        "name": "RYAN GRAVENBERGH",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [
                    {
                        "body": "- Through API #456",
                        "createdAt": "2021-07-14T13:16:28Z"
                    },
                    {
                        "body": "Frenkie De Jong War Room 22",
                        "createdAt": "2021-07-06T17:14:17Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T17:12:35Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T17:12:04Z"
                    },
                    {
                        "body": "Frenkie De Jong War Room 22",
                        "createdAt": "2021-07-06T17:11:39Z"
                    },
                    {
                        "body": "Frenkie De Jong War Room 22",
                        "createdAt": "2021-07-06T17:07:27Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T16:48:35Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T16:46:18Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T16:23:36Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T16:23:01Z"
                    },
                    {
                        "body": "Frenkie De Jong War Room 21",
                        "createdAt": "2021-07-06T13:59:50Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API #456",
                        "createdAt": "2021-07-06T13:59:00Z"
                    },
                    {
                        "body": "Frenkie De Jong War Room",
                        "createdAt": "2021-07-06T13:58:26Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API",
                        "createdAt": "2021-07-04T11:15:16Z"
                    },
                    {
                        "body": "Zlatan1 Ibrahimovic - Through API",
                        "createdAt": "2021-07-04T11:14:50Z"
                    },
                    {
                        "body": "Zlatan Ibrahimovic - Through API",
                        "createdAt": "2021-06-23T11:02:48Z"
                    },
                    {
                        "body": "Edi",
                        "createdAt": "2021-06-23T10:13:04Z"
                    }
                ],
                "created at": "2021-06-23T08:16:17+00:00",
                "from": "s7310424@gmail.com",
                "id": "21b53376-5c7d-4050-ae17-5f3a350a49d8",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "0c6f545d-61d2-469e-b69e-748695d7b81a",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://yandex.ru/support/taxi/troubleshooting/review.xml",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "69ae128a-7769-4b8f-8c2f-fdc78582e54d",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://taxi.yandex.com/email/unsubscribe/?confirmation_code=13dae517d935e8c8ec4d15fb23bea26209311c59b1c1bddca12e0dcb",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "1ca1d5d8-5ebe-4d56-a33c-20eb06ebb37d",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "http",
                        "target": "http://taxi.yandex.ru",
                        "url": "taxi.yandex.ru",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "0ac88fbc-45f6-4b1d-8a51-0c04959c54d3",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "24f94c51-3ce2-4e29-aefc-8c391b407000",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/56833/15417569036e4245365ff16829d5019ca7fd6304/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "0e57d24c-c10e-412c-8d8a-e6a651f7f165",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://avatars.yandex.net/get-bunker/4ab84a91647dceb293f96b81f67112bb959c86b8/normal/4ab84a.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "eba3339c-fcb9-4dad-ad2d-2c47275ef389",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "http",
                        "target": "http://Yandex.Taxi",
                        "url": "Yandex.Taxi",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "a76ae757-efdf-4103-b733-43700bef77a7",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://taxi.yandex.com",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 7.9818615631666e-05,
                    "confidenceSpam": 0.0251930318772793,
                    "confidenceThreat": 0.974757194519043
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/b87gb0v10tuebd6na56tli4sso3k3ue24mi382g1/b37baacdc99f8cd051bf68275ad3ef7c489adc6bec6436a649b38000f23fbb52?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=c2deee0eb54151cd7965ff0567ffd6d211b350bac202e2589ba1483a9d71d815",
                "reportedBy": "s7310424@gmail.com",
                "rules": [],
                "severity": "LOW",
                "subject": "Fwd: Yandex.Taxi ride report for 26 June, 2018",
                "tags": [
                    {
                        "name": "STENGS",
                        "type": "STANDARD"
                    },
                    {
                        "name": "BOADU",
                        "type": "STANDARD"
                    },
                    {
                        "name": "BERGKAMP",
                        "type": "STANDARD"
                    },
                    {
                        "name": "KLUIVERT",
                        "type": "STANDARD"
                    },
                    {
                        "name": "DAVIDS",
                        "type": "STANDARD"
                    },
                    {
                        "name": "AJAX",
                        "type": "STANDARD"
                    },
                    {
                        "name": "GOAT",
                        "type": "STANDARD"
                    },
                    {
                        "name": "LEGEND",
                        "type": "STANDARD"
                    },
                    {
                        "name": "IBRAHIMOVIC",
                        "type": "STANDARD"
                    },
                    {
                        "name": "RUSSIA",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "CLEAN",
                "comments": [
                    {
                        "body": "Shelly Berman",
                        "createdAt": "2021-06-23T15:01:15Z"
                    }
                ],
                "created at": "2021-06-23T08:15:33+00:00",
                "from": "s7310424@gmail.com",
                "id": "11abc56f-3732-4512-953e-dc156ec41b81",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "71cc169c-1c8b-4355-988b-44f7f26b668d",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "89f7066e-e93a-48b0-82cf-cf5b627231ad",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/56833/15417569036e4245365ff16829d5019ca7fd6304/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "f518e5bb-eaa6-4b76-a1c8-2411d0f8090d",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://avatars.yandex.net/get-bunker/4ab84a91647dceb293f96b81f67112bb959c86b8/normal/4ab84a.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "0a805a6e-7161-4bff-a499-4c2e3b9962a9",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "http",
                        "target": "http://Yandex.Taxi",
                        "url": "Yandex.Taxi",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "718b87ef-4d98-407b-89ca-2d38df6d7247",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://taxi.yandex.com",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "e94c1c0b-a469-4a4d-b0f7-433ae45fe4f3",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://yandex.ru/support/taxi/troubleshooting/review.xml",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "f4e479d2-6bf1-4651-bacf-30d93e69838d",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "https",
                        "target": "https://taxi.yandex.com/email/unsubscribe/?confirmation_code=13dae517d935e8c8ec4d15fb23bea26209311c59b1c1bddca12e0dcb",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:33Z",
                        "id": "e807052d-8280-4c19-a430-c86f0d4ec02c",
                        "lastSeen": "2021-06-23T08:16:17Z",
                        "scheme": "http",
                        "target": "http://taxi.yandex.ru",
                        "url": "taxi.yandex.ru",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.000210064725251868,
                    "confidenceSpam": 0.0458849295973778,
                    "confidenceThreat": 0.953935086727142
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/5iuiopnhfecf1q46re4t92nq4708cfg5bhqubmo1/12277f607c5c0bec94685396e73fceef32ae436cea419ad05e55639726d9c52c?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=03953014c9360ac1486bd40a10df393eba314c52238bb1991f9fae25a26a1383",
                "reportedBy": "s7310424@gmail.com",
                "rules": [],
                "severity": "UNKNOWN_SEVERITY",
                "subject": "Fwd: Yandex.Taxi ride report for 13 July, 2018",
                "tags": [
                    {
                        "name": "RUSSIA",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "CLEAN",
                "comments": [
                    {
                        "body": "Teemu Selanee",
                        "createdAt": "2021-07-28T14:42:36Z"
                    },
                    {
                        "body": "Alexander Ovechkin",
                        "createdAt": "2021-07-28T14:36:10Z"
                    }
                ],
                "created at": "2021-06-23T08:15:04+00:00",
                "from": "s7310424@gmail.com",
                "id": "a4a7a267-7e0d-4767-8b96-84c50fd342e6",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "8a6c51ea-e3b9-467e-b3a5-80e198e49a07",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/128809/a023cc1566435200a0532a4bac6a63b8c25cb9bc/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "42af9d05-c5ce-4410-a3c7-729d2e8b2a0f",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://uber.com",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "124608a6-dc9d-4f97-9cd6-913941bc9130",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "http",
                        "target": "http://support-uber.com",
                        "url": "support-uber.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "e91b32ca-93c9-4701-9af1-0aad9e80986d",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://tc.mobile.yandex.net/get-map/1.x/?lg=0&scale=1&pt=27.55699,53.89994,vkbkm~27.53291,53.91705,vkbkm&l=external_taxi&cr=0&size=1320,440&bbox=27.53091,53.89852~27.55899,53.91847",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "209018eb-bdb7-40ee-9bb4-245a62a7e43e",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/994123/e6b877a34096bb0a882c741f210c772ae03bda32/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "789c0ca8-24ad-4c4d-bcf4-9820ada037ad",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/56833/70b8558e46b44d61151d068c01aba81e8b3143c4/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "847d8359-323b-4d90-bb68-8b6e49bb09a9",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://support-uber.com/support",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "4a9e21b4-c331-4a07-a3d7-bce4372d1c1e",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "eb48521d-dfd3-4b2a-b711-517b5bf93f43",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/998550/c2102c61126c64fb1ca1453335e0776ecfee32fb/orig",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:15:04Z",
                        "id": "d702f6c7-3f39-433c-bd0e-8d67d4b9e3b7",
                        "lastSeen": "2021-06-23T08:15:05Z",
                        "scheme": "https",
                        "target": "https://avatars.mds.yandex.net/get-bunker/994123/da9297f4801951a4e5cb7afd2f2c31cabf92122a/orig",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0281630530953407,
                    "confidenceSpam": 0.0341029241681099,
                    "confidenceThreat": 0.93776398897171
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/dbmivn184s7fvnpps1jd5bfvkl205ekub5gf1jg1/1aa4423404565c6c5dffd5465ac9eb6d4b5500afb382277e624b0dd7f74e0dd3?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=652c93cff95865551841aba8164f75b8e0fe942aed21cbfe1390c344379ae992",
                "reportedBy": "s7310424@gmail.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: Uber \u2013 \u043e\u0442\u0447\u0451\u0442 \u043e \u043f\u043e\u0435\u0437\u0434\u043a\u0435 29 August, 2018",
                "tags": [
                    {
                        "name": "NETTA ALHAMISTER",
                        "type": "STANDARD"
                    },
                    {
                        "name": "GAL GADOT",
                        "type": "STANDARD"
                    },
                    {
                        "name": "BELARUS",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T08:12:25+00:00",
                "from": "s7310424@gmail.com",
                "id": "4035a6b8-bdc5-42e5-b2ac-6d1b30e840ed",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "b2e78417-db71-4551-a5b0-2afff54ac597",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/6f3e28_21913b4c5b5d4d2180fe664ac144edea~mv2.png/v1/fill/w_1296,h_320,al_c,lg_1/crop/x_642,y_63,w_639,h_229/image.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "7fd1e05c-0831-4949-92db-eeec1e10f5ae",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=yTqn0acC9fLjH6-Mah8fcIE1ZpcpCt5BClcvnMW4OHw.eyJ1IjoiaHR0cHM6Ly9mZXJuYW5kYUBjb2xvc3NldW1zcG9ydC5jb20iLCJyIjoiYjAzYjRhNWEtMDIwZC00YzhjLTRiYmQtNzY4NjRmOTY5OWI2IiwibSI6Im1haWwiLCJjIjoiNmQyMmQ5ZjgtYmRmZS00OTE3LTllYmUtMjAwMGI2MjljNDc4In0",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "9b989214-4482-4324-b2c2-4fa05c92a399",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=4sXBpr0owjEJQ5P4hGQFbEmFNScRVLKIf0Z3m8EBpLo.eyJ1IjoiaHR0cHM6Ly93d3cubGlua2VkaW4uY29tL2NvbXBhbnkvY29sb3NzZXVtc3BvcnQvIiwiciI6IjA2MDk1OGQwLTQ5NzAtNGIyZS00NzcwLTBmZmQwNGFkNTgzZCIsIm0iOiJtYWlsIiwiYyI6IjZkMjJkOWY4LWJkZmUtNDkxNy05ZWJlLTIwMDBiNjI5YzQ3OCJ9",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "b21c027d-37bc-41cf-8e37-72d352555078",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/6f3e28_df6c6a5dbdbe4a99a4004b29bedd552e~mv2.png/v1/fit/h_244,q_100,w_640,al_c/6f3e28_df6c6a5dbdbe4a99a4004b29bedd552e~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "9c235399-793f-48d3-8697-83c9a9482dc2",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.wix.com/my-account/contacts/unsubscribe?metaSiteId=b7fc3c6e-058a-4522-ac6e-eb904fb57c4a&unsubscribeToken=abcefd4d5885911e7f4ea863ecce180388e169a39e4c714f1a99cb3376c2b706cdb55f7db0ac21cc1f463585d7cbdd6ecef1f99e27d2af1f18cb3b4ad44ea0506a423d111057cbd58f1cf2f11bd3538f445fe65559299dd1ed48d4aea7087f26a2d34cfdc5b9de655e8b0f422976ab4f76d7142e24d4b85cea15f0fd4ebc8bcf03f105a9013c95fa6cb8ec9acea97e38232023a22e4754eaef634ec32766c5e7fee80dd30ac72d580486f0e175fc9403d321e88434f031fa1809c22fa8912cf3f4f9b7026bd636932d1e7f06015cc3c599a19d94e534c5032456c375b4e5fcdb18bac469265da30da36f4dcaf7c9f05b49685071574b9b4c299c0df91df8a21297ee23fb27994150579f76c7b51e95b0e3d1511dcec5e14927719f2ae68907512569e6e1b3e4a2566723cdf5a14697db968502c874b1108f317ca32dd9248e52dc031fdc36c49f5f927275139d46c946c1a4f936084134e4bbb184b1bb47c3531ce2f4c9e76091b8f03c5f55ea83a623",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "bbc380e8-6af1-4105-8436-8cf0d414647f",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "http",
                        "target": "http://colosseumsport.com",
                        "url": "colosseumsport.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "8349ae04-b221-4233-95e8-e88c8e671d5c",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_415ce174e5ca4c9181eb4a1133533636~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_415ce174e5ca4c9181eb4a1133533636~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "1b899798-8a2e-4c53-acbb-9e7b4157d58e",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_e9a4744dce5f4cd09aa2657070399813~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_e9a4744dce5f4cd09aa2657070399813~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "e489ec98-3dcb-42e7-8a11-1bf711685e8f",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/b49ee3_dd9b1a8812ae41138409a667954a6088~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/b49ee3_dd9b1a8812ae41138409a667954a6088~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "8e96d678-e0f5-44ad-b7c2-8fd844487af0",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=X18ryA_I8Za_2iLEbXCsmYK6ZZP5z4eHV_T6feM1Kms.eyJ1IjoiaHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9jb2xvc3NldW0uc3BvcnQiLCJyIjoiMDYwOTU4ZDAtNDk3MC00YjJlLTQ3NzAtMGZmZDA0YWQ1ODNkIiwibSI6Im1haWwiLCJjIjoiNmQyMmQ5ZjgtYmRmZS00OTE3LTllYmUtMjAwMGI2MjljNDc4In0",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "9ff9a738-8fb6-44da-9430-879bad91ed9f",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=ed9pjnmPsKF2_T616fEFlSZeVZml5zHXYYxNHwuTLAQ.eyJ1IjoiaHR0cHM6Ly90d2l0dGVyLmNvbS9zaGFyZT91cmw9aHR0cHM6Ly93d3cuY29sb3NzZXVtc3BvcnQuY29tL3NvL2EzTlo1b24yXz9sYW5ndWFnZVRhZz1lbiIsInIiOiJlYmZkZjM1My0yMmUwLTQwMjUtMDYxYS0xNWQ0YWNiY2RmOWUiLCJtIjoibWFpbCIsImMiOiI2ZDIyZDlmOC1iZGZlLTQ5MTctOWViZS0yMDAwYjYyOWM0NzgifQ",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "7d28e35b-54a5-446a-8789-7643a25a2033",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=R1TxqM46iG78fta6JK4Z_-LzLxt_-dyqQ5viEZ43hU4.eyJ1IjoiaHR0cHM6Ly9waW50ZXJlc3QuY29tL3Bpbi9jcmVhdGUvYnV0dG9uLz91cmw9aHR0cHM6Ly93d3cuY29sb3NzZXVtc3BvcnQuY29tL3NvL2EzTlo1b24yXz9sYW5ndWFnZVRhZz1lbiZtZWRpYT1odHRwcyUzQSUyRiUyRnN0YXRpYy53aXhzdGF0aWMuY29tJTJGbWVkaWElMkY2ZjNlMjhfMjE5MTNiNGM1YjVkNGQyMTgwZmU2NjRhYzE0NGVkZWElMjU3RW12Mi5wbmclMkZ2MSUyRmZpbGwlMkZ3XzEyOTYlMjUyQ2hfMzIwJTI1MkNhbF9jJTI1MkNsZ18xJTJGY3JvcCUyRnhfMyUyNTJDeV82MiUyNTJDd182NDAlMjUyQ2hfMjI1JTJGaW1hZ2UucG5nJmRlc2NyaXB0aW9uPUhleSslMjQlN0Jjb250YWN0Lk5hbWUuRmlyc3QlN0QlMkMrQ29sb3NzZXVtK2FuZCtJREIrVGVjaCthcmUrcHJvdWQrdG8raW52aXRlK3lvdSt0bythK3NwZWNpYWwrd2ViaW5hcitvbitzcG9ydHMrdGVjaCtpbnZlc3RtZW50K3RvK2hlYXIrZnJvbStib3RoK3NpZGVzK29mK3RoaXMrc3BvcnRzK3RlY2grY29pbi4rV2Urd2lsbCt1bml0ZStpbnZlc3RvcnMlMkMrdmVudHVyZStjYXBpdGFsaXN0cyUyQytzdGFydHVwK2VuZ2luZWVycyUyQythbmQrc3BvcnRzK3RlY2graW5ub3ZhdG9ycytvZithbGwra2luZHMrdG8rZXhwbG9yZSt0aGUra2V5K2ludmVzdG1lbnQrdHJlbmRzK3NoYXBpbmcrdGhlK2luZHVzdHJ5LitKb2luK3VzJTJDK09yZW4rU2ltYW5pYW4lMkMrTm9hK0tvbHAlMkMrU2hhaStLbGVpbWFuJTJDK0t5bGUrQnVuY2glMkMrTWljaGFlbCtQcm9tYW4lMkMrSG93YXJkK1dyaWdodCUyQytOaXIrWWFjaGluJTJDK2FuZCtHdXkrQWhhcm9uK29uK0FwcmlsKzE5dGgrdG8rcGFydGljaXBhdGUraW4rdGhpcytmYXNjaW5hdGluZytjb252ZXJzYXRpb24uIiwiciI6ImViZmRmMzUzLTIyZTAtNDAyNS0wNjFhLTE1ZDRhY2JjZGY5ZSIsIm0iOiJtYWlsIiwiYyI6IjZkMjJkOWY4LWJkZmUtNDkxNy05ZWJlLTIwMDBiNjI5YzQ3OCJ9",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "6c80c515-7f17-4bb3-9e17-800d74189e8a",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_a46fa514003c41ab906638635f992277~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_a46fa514003c41ab906638635f992277~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "896e490a-cfe2-4e2c-9515-36f21ba8240c",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=zb9ijVpyUcEtmMkHq-7rRNjT9sOx0QtnMTEZXF2ZKRk.eyJ1IjoiaHR0cHM6Ly93d3cuY29sb3NzZXVtc3BvcnQuY29tL3NvL2EzTlo1b24yXz9sYW5ndWFnZVRhZz1lbiIsIm0iOiJtYWlsIiwiYyI6IjZkMjJkOWY4LWJkZmUtNDkxNy05ZWJlLTIwMDBiNjI5YzQ3OCJ9",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "fcac5994-42dd-47a3-a976-97ff69c5828b",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_a40efa16ac944077a7a8d54d359f1dd0~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_a40efa16ac944077a7a8d54d359f1dd0~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "03025906-3952-45ba-a855-fc39d8c89fc6",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=dgvT2xSDueKbHQse0OmCpTFJoZxo75TVkyq_-3ASFoA.eyJ1IjoiaHR0cHM6Ly93d3cuY29sb3NzZXVtc3BvcnQuY29tLyIsIm0iOiJtYWlsIiwiYyI6IjZkMjJkOWY4LWJkZmUtNDkxNy05ZWJlLTIwMDBiNjI5YzQ3OCJ9",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "9529cca2-9f04-4bd1-9ce9-66f3f6216c78",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "d5c4e1a8-df77-4d59-8fc7-25750cc165e3",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/5e9922_0a9111966d7648649336e1f1546c5ec9~mv2.gif",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "fbf1ddc6-21c5-471f-87f4-5ff1a55fcd94",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://shoutout.wix.com/so/pixel/6f3e288b-2461-4d51-949f-e606ff55ca55/b7fc3c6e-058a-4522-ac6e-eb904fb57c4a/f69883cb-1897-4658-9ea2-50e07da31da3/6d22d9f8-bdfe-4917-9ebe-2000b629c478/bottom/true",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "b4d3dd28-5878-44e7-887f-08f3b30f2a29",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=0Gd1aGujZbVkkW_jyHbMdDt--qhtpbyNPlB5jwxTmzQ.eyJ1IjoiaHR0cHM6Ly93d3cueW91dHViZS5jb20vY2hhbm5lbC9VQ2dOMGoyNmlJeUtDOUpnTzRfcy1oR2ciLCJyIjoiMDYwOTU4ZDAtNDk3MC00YjJlLTQ3NzAtMGZmZDA0YWQ1ODNkIiwibSI6Im1haWwiLCJjIjoiNmQyMmQ5ZjgtYmRmZS00OTE3LTllYmUtMjAwMGI2MjljNDc4In0",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "a9229fd5-ec52-41fc-8b61-60ed56e7ec62",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=hYu--gc_gYVIshT97JvGV2lT38-yVuMMX4PKOtglgNA.eyJ1IjoiaHR0cHM6Ly93d3cuZmFjZWJvb2suY29tL3NoYXJlci9zaGFyZXIucGhwP3U9aHR0cHM6Ly93d3cuY29sb3NzZXVtc3BvcnQuY29tL3NvL2EzTlo1b24yXz9sYW5ndWFnZVRhZz1lbiIsInIiOiJlYmZkZjM1My0yMmUwLTQwMjUtMDYxYS0xNWQ0YWNiY2RmOWUiLCJtIjoibWFpbCIsImMiOiI2ZDIyZDlmOC1iZGZlLTQ5MTctOWViZS0yMDAwYjYyOWM0NzgifQ",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "8078b53f-c321-44df-88fb-ae8a04d317b5",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=Trq9sZ_8_acbPEDzk7PYlZWPJhOEtrdLJP4HwUcjqHE.eyJ1IjoiaHR0cHM6Ly9jb2xvc3NldW1zcG9ydC5jb20iLCJyIjoiZWJmZGYzNTMtMjJlMC00MDI1LTA2MWEtMTVkNGFjYmNkZjllIiwibSI6Im1haWwiLCJjIjoiNmQyMmQ5ZjgtYmRmZS00OTE3LTllYmUtMjAwMGI2MjljNDc4In0",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "2d035b7e-c9cf-40ca-a5f1-ecffdf633d11",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=3V1IVX0WxDhrSOVGK_IMwlSOeeTJsy3AntSxE9cx5fk.eyJ1IjoiaHR0cHM6Ly93d3cuaWRibnkuY29tLyIsInIiOiI0MGU1ZDk2NS1lZTg0LTQ4MWItYTVjZS00N2Q5NTEzNWEwN2MiLCJtIjoibWFpbCIsImMiOiI2ZDIyZDlmOC1iZGZlLTQ5MTctOWViZS0yMDAwYjYyOWM0NzgifQ",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "774ce53c-8141-4552-874d-997927baf41d",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=ArQFfOHHaT1sbrNu5lTKTUz8dUwaXRwvER2Nrm_Idkk.eyJ1IjoiaHR0cHM6Ly93d3cuZXZlbnRicml0ZS5jb20vZS9zcG9ydHMtdGVjaC1pbnZlc3RtZW50LW9wcG9ydHVuaXRpZXMtdGlja2V0cy0xNDk4NTcwMTkzNzkiLCJyIjoiNTU5OGI3ZjUtY2I1YS00ZDk4LWU5YTItMmY5MWQ4MGQ2YTY4IiwibSI6Im1haWwiLCJjIjoiNmQyMmQ5ZjgtYmRmZS00OTE3LTllYmUtMjAwMGI2MjljNDc4In0",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "7ef68a79-9851-4407-a9cf-3c2bba163251",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "http",
                        "target": "http://links.ascendbywix.com/q/MPTySaIO1xX9Bv2oYrNG2A~~/AABFVwA~/RgRiVwIJPlcDc3BjQgpgbwl9dGA7g5PaUhJzNzMxMDQyNEBnbWFpbC5jb21YBAAEc8U~",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "34e31f42-28fe-4af8-aedd-a957484cd77d",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/6f3e28_21913b4c5b5d4d2180fe664ac144edea~mv2.png/v1/fill/w_1296,h_320,al_c,lg_1/crop/x_3,y_62,w_639,h_225/image.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "9ee79c61-6d3a-4b3f-9233-b00bd153807d",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_7b0500cdfdbc403aa4c14e91550e6b6b~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_7b0500cdfdbc403aa4c14e91550e6b6b~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "39057680-12b6-424e-af8e-4b9a1ff40622",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_ffc8a55271d049c5a877632d5b7d52a4~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_ffc8a55271d049c5a877632d5b7d52a4~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "12c90f2a-5a16-4db6-a58f-320f1ae2bcb5",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://static.wixstatic.com/media/a306cb_5bbcc04a306e4a7a93d506cfb81fd7b7~mv2.png/v1/fit/w_750,h_750,br_100,sat_-100,hue_180/a306cb_5bbcc04a306e4a7a93d506cfb81fd7b7~mv2.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "c240b9be-4dcb-46f0-a3f8-ebee8aa42ec4",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://www.colosseumsport.com/so/a3NZ5on2_/c?w=YZO4Eih1uydNS01KP882Z4BSyBoh2_Bq-9NVcFOGHvA.eyJ1IjoiaHR0cHM6Ly90d2l0dGVyLmNvbS9jb2xvc3NldW1zcG9ydCIsInIiOiIwNjA5NThkMC00OTcwLTRiMmUtNDc3MC0wZmZkMDRhZDU4M2QiLCJtIjoibWFpbCIsImMiOiI2ZDIyZDlmOC1iZGZlLTQ5MTctOWViZS0yMDAwYjYyOWM0NzgifQ",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "284b7aae-04e1-4839-8824-b0afc925f48b",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "http",
                        "target": "http://links.ascendbywix.com/q/rKxFAhx9pPEtBkxzAqa8oQ~~/AABFVwA~/RgRiVwIJPVcDc3BjQgpgbwl9dGA7g5PaUhJzNzMxMDQyNEBnbWFpbC5jb21YBAAEc8U~",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:25Z",
                        "id": "05439e34-4cbd-42ed-8346-b978ad547135",
                        "lastSeen": "2021-06-23T08:12:26Z",
                        "scheme": "https",
                        "target": "https://shoutout.wix.com/so/pixel/6f3e288b-2461-4d51-949f-e606ff55ca55/b7fc3c6e-058a-4522-ac6e-eb904fb57c4a/f69883cb-1897-4658-9ea2-50e07da31da3/6d22d9f8-bdfe-4917-9ebe-2000b629c478/top/true",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 1.00030938483542e-05,
                    "confidenceSpam": 0.999742925167084,
                    "confidenceThreat": 0.000277016923064366
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/hdhu339umi84tsdmhbdggsonv8dlrpe3ntsehlg1/ff08cfd109d6ac3445387cdd9bc01ffe4d604a7a17e18b5913f9abcdc33417a0?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=3ac4e7004d045c45b082516e99e1b3f3cb4650f967b41fd621ea139a59abd9a8",
                "reportedBy": "s7310424@gmail.com",
                "rules": [
                    {
                        "createdAt": "2021-06-23T08:44:37Z",
                        "description": "Commonly used Subject/From finance words commonly used in phishing attempts",
                        "id": "8aae2a72-e73a-4cbe-8520-f0dcf5134e06",
                        "matchedCount": 1,
                        "name": "KB4:FINANCIAL",
                        "tags": [
                            "KB4:FINANCIAL"
                        ]
                    },
                    {
                        "createdAt": "2021-06-23T08:44:37Z",
                        "description": "Commonly used Subject/From general words commonly used in phishing attempts",
                        "id": "ce4d2a79-d8cd-417f-96b1-3c4df94be33a",
                        "matchedCount": 1,
                        "name": "KB4:GENERAL",
                        "tags": [
                            "KB4:GENERAL"
                        ]
                    }
                ],
                "severity": "LOW",
                "subject": "Fwd: Sports Tech Investment & Opportunities: Let's Talk about it!",
                "tags": [
                    {
                        "name": "KB4:FINANCIAL",
                        "type": "STANDARD"
                    },
                    {
                        "name": "KB4:GENERAL",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T08:12:13+00:00",
                "from": "s7310424@gmail.com",
                "id": "b3f3371c-e608-43f4-999d-f506e22a1092",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "d784deaf-c276-46b0-bb2a-47bc4b439e7d",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0XA99C17798AB5B6769B6B8AC21937A30821B5608E444D964D7F0314AC97396CE97C40321BA1CC25716690C43DFED16573754F51C2B6E8387C52AD29045FF6509312601A25ABAB4895.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "d5e0f6ac-cc5b-45d1-a25a-214f55804a3f",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/app/img/Icon/limitedOpportunities.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "347faf82-5e3b-43b4-947f-eef65eca6099",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "http",
                        "target": "http://lametayel.co",
                        "url": "lametayel.co",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "104df899-552f-486a-bb58-95603fa62b93",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "3c9692a1-8b96-4e96-9eff-aa0f89653828",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "http",
                        "target": "http://lametayel.co.il",
                        "url": "lametayel.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "a4ed3e2b-b437-4946-bc03-0ddae058f737",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Show/0X09C7BFCC3B074C37DD014EB42545AEE1BC8BB1C2DDF3F6F204B7179384B3C4E3EA45B0491EAE6318.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "a62b950d-8d8c-4d23-a6e2-d97e5074b662",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Out_0X09C7BFCC3B074C37DD014EB42545AEE1BC8BB1C2DDF3F6F204B7179384B3C4E3EA45B0491EAE6318.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "722be193-e538-4b9b-877a-6adad6c2a3cb",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X75B414BF50FE8786633BA163F01D4F03C55DE77B7CC2203A14A635FF63ED937269FB2BDD2342D1346690C43DFED16573754F51C2B6E8387C52AD29045FF6509312601A25ABAB4895.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "677fc9e1-cf2f-4a41-82d1-02d04646a6fc",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/SpamAbuse_0X09C7BFCC3B074C37DD014EB42545AEE1BC8BB1C2DDF3F6F204B7179384B3C4E3EA45B0491EAE6318.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "a7ed0db7-adef-48f2-be3b-76300178268d",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/nslinks/0XA7B345C74AEB82B7BA022830AA129F80AE751E8DF83E53404402EBD2F42C2690BE03F61F56173B90B95D29F255FEE7606F04B3FFA18E95307C1CD1395241FB41BFA19C57546167EC1603DE791398666F7AD4017068F2B2AE7A40342286BAE8DAEEC636DEC917716BBF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "8cab5ee0-ad68-4d15-9dd0-be127951be1f",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Open/0X09C7BFCC3B074C37DD014EB42545AEE1BC8BB1C2DDF3F6F204B7179384B3C4E3EA45B0491EAE6318.gif",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:12:13Z",
                        "id": "191ccc55-cad5-4b31-8d2d-bc333534070f",
                        "lastSeen": "2021-06-23T08:12:14Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/zfaadxd2uups/OUTLET_newsletter.jpg?cache=1624365793013",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.00913903117179871,
                    "confidenceSpam": 0.749583423137665,
                    "confidenceThreat": 0.241307601332664
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/68letei1vsvkqi96pit65qpgg5g2d7loid9s7v81/674fc5cc6102acddc896c109b8d25253d1671ba612de8f51d6a28e12c2a5a2ac?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=084884aa5e3ad2e4d6d707dce6488b9f5b78441ed497fdacb45c8cef65e560bb",
                "reportedBy": "s7310424@gmail.com",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "Fwd: \u05de\u05d7\u05e4\u05e9\u05d9\u05dd \u05d4\u05e0\u05d7\u05d4 \u05e2\u05dc \u05e6\u05d9\u05d5\u05d3 \u05d5\u05d1\u05d9\u05d2\u05d5\u05d3 \u05d8\u05d9\u05d5\u05dc\u05d9\u05dd \u05d1\u05dc\u05de\u05d8\u05d9\u05d9\u05dc? \ud83d\udcb2 \u05db\u05d3\u05d0\u05d9 \u05dc\u05e9\u05d9\u05dd \u05dc\u05d1 \u05dc\u05d6\u05d4! \u05e4\u05e8\u05e1\u05d5\u05de\u05ea",
                "tags": [
                    {
                        "name": "SPAM",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "\ufffd\ufffd\ufffd\ufffd-\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd.pdf",
                        "md5": "90c983d496ae42746681df340e7cb491",
                        "reportedContentType": "application/pdf",
                        "s3Key": "efin26mkitdvnf279j1mt0iiitr3125a79hv7j81/4146ef43f0841e137f39a1ae5e33132789fcf8cd114f78ab3efb589a13ecbdc9",
                        "sha1": "e73e980af62ce2eee506dd870f8b8b0aac0147eb",
                        "sha256": "4146ef43f0841e137f39a1ae5e33132789fcf8cd114f78ab3efb589a13ecbdc9",
                        "size": 97818,
                        "ssdeep": "1536:mkAWsK4YiLxAt7LdEKicDKhz7sUPyCqNPt1Mxa2Fk4XtsZumEK+dTAbnPx1:mYsKPGxm7JrGF7pAl8Cyts4mEbkbnPf",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "application/msword",
                        "filename": "\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd.doc",
                        "md5": "aa1b44979288046c3cef23d4d6c70e72",
                        "reportedContentType": "application/msword",
                        "s3Key": "efin26mkitdvnf279j1mt0iiitr3125a79hv7j81/23b2dfbf437453a6d81785d5be7431622c0aaf619c9fee0a4d01d9497c3fca6a",
                        "sha1": "5f0a86db132afe43fc319ae74eead16899692c4c",
                        "sha256": "23b2dfbf437453a6d81785d5be7431622c0aaf619c9fee0a4d01d9497c3fca6a",
                        "size": 112640,
                        "ssdeep": "1536:PlldNlmrIlllllellElllnlllllFllKIgFzNtUubF4k/kH8KxsLFBqIP7rf+QcQ:tezg0Gk8cKxAqIP7rNQ1OCBk8",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T08:08:27+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "76c99796-f735-4511-a937-dbc9ddcdac72",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "659dfdb7-315f-42ea-bf97-1b90fa96415d",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://tauex.tau.ac.il",
                        "url": "tauex.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "0f01adaa-eb79-4844-8a5b-fbe76f6b50bd",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://listserv.tau.ac.il",
                        "url": "listserv.tau.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.717424988746643,
                    "confidenceSpam": 0.13953223824501,
                    "confidenceThreat": 0.143072754144669
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/efin26mkitdvnf279j1mt0iiitr3125a79hv7j81/a80b856a49cf6fdc5eb472df0fe5cd6206e847985420d35bc86cfec1457d7044?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=40e8f3ac404edfae7ce826b0e71376d6cda90b502caa7256ffd3650d33fe4b16",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "LOW",
                "subject": "Fwd: FW: \u05de\u05dc\u05d2\u05d5\u05ea \u05ea\u05d5\u05d0\u05e8 \u05e9\u05e0\u05d9 \u05de\u05d7\u05e7\u05e8\u05d9 \u05dc \u05e1\u05d8\u05d5\u05d3\u05e0\u05d8\u05d9\u05dd \u05d9\u05d5\u05e6\u05d0\u05d9 \u05d0\u05ea\u05d9\u05d5\u05e4\u05d9\u05d4 - \u05e9\u05e0\u05d4\"\u05dc \u05ea\u05e9\u05e4\"\u05d1",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T08:06:48+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "19640adc-b746-4b86-b816-dc31dfa124aa",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "6565608a-d8d6-454c-8182-2fedef2341d9",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X6194BDE4BF0145F5D04F537C7D6CBB0C96ADF2428FD13CA8720898E89F9445106BE74F9CEF0829ED1763825C3E9B7D4A7FE3439BF2F9E4FEF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "2b4a8695-3c8c-48eb-970c-cf6a1a2de8f5",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Out_0X9C7C1673E92969331F2D725B837BCEB201B61AB34B7EA2D5996605DF1535AD66BF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "11025690-4bc5-4779-ae85-443835929b01",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/SpamAbuse_0X9C7C1673E92969331F2D725B837BCEB201B61AB34B7EA2D5996605DF1535AD66BF2B8A52F813D52F.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "07a264b1-50e8-41cb-a006-3b43e064282d",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/nslinks/0XA7B345C74AEB82B7BA022830AA129F80AE751E8DF83E53404402EBD2F42C2690BE03F61F56173B90B95D29F255FEE7606F04B3FFA18E95307C1CD1395241FB41BFA19C57546167EC1603DE791398666FCDB3E4621C998A888F2946CDC7A84B0BE39619FE1AF0E237552835B8FF6C759D.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "c780121d-9ef6-4262-add5-a98c4a5b61b9",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Links/0X27620CD62F550195EA5203502C2B49C49C5BC95B2E60ED259B8184506AB49A9FB997959534637A381763825C3E9B7D4A7FE3439BF2F9E4FEF24AAE2D93F135E92F4F1B1D33D00A41.htm",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "fd666863-3b35-4ce9-a96d-8fd519630043",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "http",
                        "target": "http://student.co.il",
                        "url": "student.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "80f92bf8-e430-4a06-bfe8-88cabf6adb68",
                        "lastSeen": "2021-07-08T18:21:37Z",
                        "scheme": "http",
                        "target": "http://mail.tau.ac.il",
                        "url": "mail.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "491099ba-93cf-479b-ace8-c295ec052640",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://trailer.web-view.net/Open/0X9C7C1673E92969331F2D725B837BCEB201B61AB34B7EA2D5996605DF1535AD66BF2B8A52F813D52F.gif",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:48Z",
                        "id": "77095a9d-4cf4-4d7f-af6e-2d7ab083dff3",
                        "lastSeen": "2021-06-23T08:06:48Z",
                        "scheme": "https",
                        "target": "https://cdn-media.web-view.net/i/z3xjjwdas88c/newsletter-500x500.jpg?cache=1622989986304",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0340511351823807,
                    "confidenceSpam": 0.755802810192108,
                    "confidenceThreat": 0.210176095366478
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/fttbfj9l332qkijdpbabp7sebiuvmgr06j4lipo1/e2d844131b6564dcc30804c15b222f473a7252b532fcd1b4d32f6e9a431b5cc6?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175857Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=2a48de32b8ddc5fe937cc9f16c6a24f59c25931dd56f6d8222e63521ff664e60",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05e4\u05e8\u05e1\u05d5\u05de\u05ea >> \u05db\u05e8\u05d8\u05d9\u05e1\u05d9\u05dd \u05dc\u05d9\u05d5\u05dd \u05d4\u05e1\u05d8\u05d5\u05d3\u05e0\u05d8 \u05db\u05d1\u05e8 \u05e7\u05e0\u05d9\u05ea\u05dd?",
                "tags": [
                    {
                        "name": "SPAM",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "Seminar Shir Tavor 15-6-21.pdf",
                        "md5": "e6869eb88837b892b19662471a0f43eb",
                        "reportedContentType": "application/pdf",
                        "s3Key": "6utor7vh16p34kgudprjuc8n86gecnjte32laqo1/55ae5001f449ebea90a04adb6f02701e6f64cf00f383a455cbcfde45674e30d7",
                        "sha1": "0c7f118f0631617302e6a155258142fb1500a1ae",
                        "sha256": "55ae5001f449ebea90a04adb6f02701e6f64cf00f383a455cbcfde45674e30d7",
                        "size": 422828,
                        "ssdeep": "6144:Pk71EWbTF47zLkFL/rgx5KtVCCV3MqOX6LEI1qKc0ZKFhuj05ICtIDUV+QZUd52m:c71EWlzXy3qf90KAFhujrCiIhUfQNd63",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "application/pdf",
                        "filename": "Seminar Reut Regev 15-6-21.pdf",
                        "md5": "52d100bcdf61f3ac7ec7a796104afb74",
                        "reportedContentType": "application/pdf",
                        "s3Key": "6utor7vh16p34kgudprjuc8n86gecnjte32laqo1/3b01c17ab81e5bda6656d38d1ae5f7c9fb4966741ca2356ae0d64be68f7e8d98",
                        "sha1": "9a2464faf3a1abaf24447d2590ed0c7947baf937",
                        "sha256": "3b01c17ab81e5bda6656d38d1ae5f7c9fb4966741ca2356ae0d64be68f7e8d98",
                        "size": 570013,
                        "ssdeep": "12288:E5Ls1EWEgXZY890KA5afofPXXIiXd3UzjdHPl11u+rOsFwcIWhujrCiIhUfQNd6k:E5LdPgXZl90KDwfPnVd3sDu5277Nj",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T08:06:54+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "31825085-1b44-4150-833e-bb25602af0ce",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "7f3da981-838b-459e-985f-db093d1a6eb0",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://tauex.tau.ac.il",
                        "url": "tauex.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "a7394661-4cbd-4bca-af2f-6d8114b2570f",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://listserv.tau.ac.il",
                        "url": "listserv.tau.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.942762434482574,
                    "confidenceSpam": 0.0498115755617619,
                    "confidenceThreat": 0.0074560372158885
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/6utor7vh16p34kgudprjuc8n86gecnjte32laqo1/8a296e71b1dab5f0b201d4b9e3519118c9d2f760efa04ec57351435938b53b6c?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175858Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=c503433129abc833cc727b49e69d335bae4b1da87d502bf45dceba5832632bd1",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: \u05e1\u05de\u05d9\u05e0\u05e8 \u05de\u05d7\u05dc\u05e7\u05ea\u05d9 \u05d1\u05d9\u05d5\u05dd \u05e9\u05dc\u05d9\u05e9\u05d9 \u05d4 15/6",
                "tags": []
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [
                    {
                        "actualContentType": "image/png",
                        "filename": "image001.png",
                        "md5": "0b1f96546086c7409daeff0723ee3182",
                        "reportedContentType": "image/png",
                        "s3Key": "1cul743oh01gm3e9v5vitirun1chv9sbflmfpgg1/080951a0145918beef9b4c7f1185bb51de0e5bfeb9a15c01d8d433f2b29b3dee",
                        "sha1": "cf9f4e2836856ec15e102e9ff896e80b9662115e",
                        "sha256": "080951a0145918beef9b4c7f1185bb51de0e5bfeb9a15c01d8d433f2b29b3dee",
                        "size": 14347,
                        "ssdeep": "192:t6cMUfrfcwk3nWRgy6aYEUtKkmck3vFPu9LiDkn/KHph1sbOuL/S91BOQzj0tf5l:t9fzDqmUtKXXfFGOQyTsVL/Csmo",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "filename": "\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd 2021 \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd.xlsx",
                        "md5": "1121e470c1d8d9b21e7d01c5a867008e",
                        "reportedContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "s3Key": "1cul743oh01gm3e9v5vitirun1chv9sbflmfpgg1/397b6b47c0a2671bbe480ff2d61f4e5f927834b644bdc1ee16b135ed7d9373b6",
                        "sha1": "55fbd7c2c80b52a0c6fe1c1d4f197365408b1218",
                        "sha256": "397b6b47c0a2671bbe480ff2d61f4e5f927834b644bdc1ee16b135ed7d9373b6",
                        "size": 16556,
                        "ssdeep": "192:kFblNMlAb3UxfDJOI0b3HgQEehdjODxJ+J6+T6vA2DujPa7YrySnDs50f:kF5NMK3QDAR3Hgehsj+JPmvwjzXf",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "filename": "\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd.docx",
                        "md5": "42bc897d34d50b8dbf0cfa442c4b6074",
                        "reportedContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "s3Key": "1cul743oh01gm3e9v5vitirun1chv9sbflmfpgg1/38a8f5fd179158ed7deaaf44ad8fa8961af80ba3bede36fd1d3ea46e8c4a7df6",
                        "sha1": "324df58181f939a9eae28672befc6ab76850b34e",
                        "sha256": "38a8f5fd179158ed7deaaf44ad8fa8961af80ba3bede36fd1d3ea46e8c4a7df6",
                        "size": 40342,
                        "ssdeep": "768:YYotjiKxDDz40x035jd3Hcb3tw7Zj6s3dBEtYx:YYoteK5DzxActw7ZOsY2x",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T08:06:35+00:00",
                "from": "eduardk1@mail.tau.ac.il",
                "id": "d2dc06ce-5dcf-4caa-93ca-7747dd3afb02",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "8d1bb7c3-89fc-4bc3-8925-0403793a03e2",
                        "lastSeen": "2021-06-23T08:06:35Z",
                        "scheme": "http",
                        "target": "http://Go.tau.ac.il",
                        "url": "Go.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "b78f918a-8ec7-45e5-a5ed-7347dd85095c",
                        "lastSeen": "2021-06-23T08:06:35Z",
                        "scheme": "https",
                        "target": "https://forms.gle/X7EBdr9gNHwXep3R9",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "b9d40c63-6a53-4bfd-9774-c784eb36a461",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://tauex.tau.ac.il",
                        "url": "tauex.tau.ac.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T08:06:35Z",
                        "id": "af4ce7d7-7cb2-43ff-a8a0-df5d02b4f04d",
                        "lastSeen": "2021-07-08T18:22:08Z",
                        "scheme": "http",
                        "target": "http://listserv.tau.ac.il",
                        "url": "listserv.tau.ac.il",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.780951797962189,
                    "confidenceSpam": 0.0490451753139496,
                    "confidenceThreat": 0.170033007860184
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/1cul743oh01gm3e9v5vitirun1chv9sbflmfpgg1/e6e5c5694c62d4761dea52cdf83d367b07ae364a12b488c94ecabb41e025b295?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175858Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=1bf533e3cc43c4c63e9e14f4242c11e4aed292e0317ade4c130d84d66791862e",
                "reportedBy": "eduardk1@mail.tau.ac.il",
                "rules": [],
                "severity": "LOW",
                "subject": "Fwd: \u05e7\u05d5\u05e8\u05e1\u05d9 \u05e7\u05d9\u05e5 \u05d1\u05e0\u05d9\u05d4\u05d5\u05dc- \u05ea\u05e9\u05e4\"\u05d0",
                "tags": []
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [],
                "category": "THREAT",
                "comments": [],
                "created at": "2021-06-23T07:45:20+00:00",
                "from": "kgal@paloaltonetworks.com",
                "id": "c036fb13-d108-4564-9c52-129baf75d835",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:20Z",
                        "id": "64c4a8ff-2108-4a6b-80f1-f9244796549c",
                        "lastSeen": "2021-06-23T07:45:20Z",
                        "scheme": "https",
                        "target": "https://theresnosuchdomain.co.mars",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.1514051258564,
                    "confidenceSpam": 0.702346444129944,
                    "confidenceThreat": 0.146278440952301
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/rf7qau0413mca9up6mg28vbvto7kjsfec5tunl81/8464cd6e7e985f5ad9c3223312b5715d9a40db79ca762d7aacd1591b490a2247?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=83d0d9e42d3951a93275b9f08d6f01c4bd1b5f6861385c83b2c0abf2df7c6d89",
                "reportedBy": "kgal@paloaltonetworks.com",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "you've won a vacation to Tel Aviv",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "service-report-30418915550-20210530.pdf",
                        "md5": "9b6559e68480b771ceedae7bea688ba0",
                        "reportedContentType": "application/pdf",
                        "s3Key": "8onb5qmdclu4a2qs75g66v1uv4c5tpnpfei382g1/0b8ba282a0b970fa71375fdced100922a6c4fb62867956a5f6e079558298ea22",
                        "sha1": "20028cd1f430b2f756f38a20d7d7f75394e4f504",
                        "sha256": "0b8ba282a0b970fa71375fdced100922a6c4fb62867956a5f6e079558298ea22",
                        "size": 89222,
                        "ssdeep": "1536:UuARl9149yNTH//ZHmh7W1f9c3Fso1csxP:bA7969AH/Bf0p1bP",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T07:45:24+00:00",
                "from": "edi.blr@gmail.com",
                "id": "8ac6e2f7-9757-4b56-b624-115834f88f7d",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "c6004d32-1655-48a7-968b-54bb483c3371",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "http",
                        "target": "http://www.dell.com",
                        "url": "www.dell.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "7b82618e-884b-4b6b-bb65-200651ac2b6c",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "http",
                        "target": "http://www.dell.com/servicecontracts/global",
                        "url": "www.dell.com/servicecontracts/global",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "bcb2b3a9-8e19-4f2e-b9fa-4fb4cf1eefa5",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "https",
                        "target": "https://www.dell.com/support/incidents-online/il/en/ilbsdt1/contactus/Dynamic?lwp=rt",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "758c14e9-2f9f-4bbe-89cc-3c7eb0e7f245",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "https",
                        "target": "https://www.dell.com/support/Contents/il/en/ilbsdt1/category/Product-Support/Self-support-Knowledgebase?lwp=rt",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "64ab40e0-f29b-4303-bdd7-2c9668276bdc",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "https",
                        "target": "https://www.dell.com/support/contents/il/en/ilbsdt1/category/Product-Support/Self-support-Knowledgebase/software-and-downloads?lwp=rt",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "86237b5b-3fb0-4280-b825-4218eae8ce4b",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "http",
                        "target": "http://dell.com",
                        "url": "dell.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "f6e58bf4-4aa9-4382-a697-fc7d6f7e75fd",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:45:24Z",
                        "id": "41db5ccb-a3e8-442d-bc63-2b2b5bd7a0de",
                        "lastSeen": "2021-06-23T07:45:24Z",
                        "scheme": "http",
                        "target": "http://i.dell.com/sites/csimages/App-Merchandizing_esupport_flatcontent_global_Images/all/dell_logo.png",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0762194842100143,
                    "confidenceSpam": 0.540363311767578,
                    "confidenceThreat": 0.383447200059891
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/8onb5qmdclu4a2qs75g66v1uv4c5tpnpfei382g1/78aa6c0c08834a75a306c1e5546391f60588b39c2ffe7796325eb7e36fa3ccb6?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=1f59668480c241809a0b46dbb68b695ced6bde47df646ad75a296319fb65bccd",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: \u05d3\u05d5\u05d7 \u05e9\u05d9\u05e8\u05d5\u05ea \u05e2\u05d1\u05d5\u05e8 \u05e9\u05d9\u05d2\u05d5\u05e8 30418915550",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T07:43:57+00:00",
                "from": "kgal@paloaltonetworks.com",
                "id": "540e8585-4b1f-4485-8bb9-70f8084e8e9a",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:43:57Z",
                        "id": "6fef856f-a35f-4e81-ad75-af6e8dd7e8bb",
                        "lastSeen": "2021-06-23T07:43:57Z",
                        "scheme": "about",
                        "target": "about://blank",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.00106803758535534,
                    "confidenceSpam": 0.991070210933685,
                    "confidenceThreat": 0.00789174530655146
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/3gdc6vsuqnn9vtmi1qpjofigntf1h85ouis2g5g1/e67fda3f807c0be80648899ff5e2422ab93ff76376a6518064aad153428d7d68?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=3cd5d985db9f68f2789d5786e92d7833ee4a9ea1b0ef9a573eaaec64776d5df5",
                "reportedBy": "kgal@paloaltonetworks.com",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "win a free flight to Mars!",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [
                    {
                        "actualContentType": "application/ics",
                        "filename": "invite.ics",
                        "md5": "f0842192dd9ed7354cfb6ad6046a238c",
                        "reportedContentType": "application/ics",
                        "s3Key": "cj2oojec9sa3fqc31j2la0rp534oudpdf2fguc81/cabe84bef1dc24511e33fb411b717dee4d5d86985bf47038a960bea5240a29a6",
                        "sha1": "3ea53d4b6ed719f0c8cf0926300fc28be88663be",
                        "sha256": "cabe84bef1dc24511e33fb411b717dee4d5d86985bf47038a960bea5240a29a6",
                        "size": 4261,
                        "ssdeep": "96:EzZf7sbtWs7WlYego1yBskUZLKo73K+V2nNlpvEQ+aXxFQV9R8xpOzIR2AMMwTeT:ywe7ygS/d+aX7qj+X37d",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T07:41:40+00:00",
                "from": "edi.blr@gmail.com",
                "id": "2b025b06-b21b-4aa2-8246-92637b995337",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "bc755168-8c7b-41d3-addf-eff555fddb3e",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://cyberbitc.com",
                        "url": "cyberbitc.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "196a6f63-53d6-488b-90ac-7e287c2dc2d8",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://hotmail.com",
                        "url": "hotmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "2821041e-9adc-49e9-b217-1b60daff2bb1",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://dialogic.com",
                        "url": "dialogic.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "39ab683a-eb10-4b96-8be9-be1dcd66bd23",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://niceactimize.com",
                        "url": "niceactimize.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "2310568e-11ce-48a2-86b4-d205c8ca60a6",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://nice.com",
                        "url": "nice.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:41:40Z",
                        "id": "447619fb-9f12-4ec1-8fff-2eb9dd6bab40",
                        "lastSeen": "2021-07-08T18:22:55Z",
                        "scheme": "http",
                        "target": "http://tm-group.com",
                        "url": "tm-group.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "17bb0e5c-9ad3-4075-848b-5733a7b580e6",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0918415635824203,
                    "confidenceSpam": 0.680615246295929,
                    "confidenceThreat": 0.227573186159134
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/cj2oojec9sa3fqc31j2la0rp534oudpdf2fguc81/fa7a206a8b9fa7abaedd3d53ccf5416d504e754a126cf5798e2031f759f1f729?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=e406c72427ac57355b8d6375701aa6b18266f4ecfd40f4f533115fa438622be4",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: \u05db\u05d3\u05d5\u05e8\u05d2\u05dc",
                "tags": [
                    {
                        "name": "ZLATAN",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "IN_REVIEW",
                "attachments": [],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T07:37:10+00:00",
                "from": "edi.blr@gmail.com",
                "id": "bbeb082d-d828-45ed-8571-3c885da6537f",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "95f91f7f-fbbc-4603-9c25-1e7f68807768",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://boostapp.co.il",
                        "url": "boostapp.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "d3e582c5-8ab9-4b8e-a6e9-8e1b57e9e783",
                        "lastSeen": "2021-07-08T18:24:15Z",
                        "scheme": "http",
                        "target": "http://gmail.com",
                        "url": "gmail.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "ad160266-cb0b-43b0-a513-40960b80704c",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "https",
                        "target": "https://login.boostapp.co.il/assets/img/LogoMail.png",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "de837faf-5517-4645-bb73-8bbd399b0d7b",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://url9421.boostapp.co.il/wf/open?upn=afzfs8stcMgGkHvz5VoFjQ94AEJBusbujaIWWAyWV-2F8RF1gfb8wU74vmJ7sIU-2FKvqhvddR3gdVW-2ByjYwkDM01QelK6hqTo0IVPCOXalnNwnKyEOu2flAU50Pj1Fz5bae48E-2FC7vRIjb1cIUGuWFQBttbodwUAg3fwutwQ8IiVn0WrliabJnO0AQoAwFRbM1pdRLnS0NF4UL6igPYekGXmaD8BA0XP-2Bm1lnFYeNqKIrs-3D",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "67cad894-2c85-4156-8c91-2f6a69f54d6e",
                        "lastSeen": "2021-06-23T07:37:11Z",
                        "scheme": "https",
                        "target": "https://docs.google.com/spreadsheets/d/1veuan7lrtiK4uSqvvykcVOWxwxiRbHJWLQ9amAXImuQ/edit?usp=sharing",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:37:10Z",
                        "id": "35793a17-85e8-4ca1-a370-8b9aee5aa115",
                        "lastSeen": "2021-07-08T18:23:14Z",
                        "scheme": "http",
                        "target": "http://url9421.boostapp.co.il/ls/click?upn=I26BJb-2BhudbAgBKbqHtSUFXc5rXN0-2FjCibvLfg9qI3KFeBrUjyq62BvYkZP4Ro07u1dl_KxOhWnQcAGpb7Ve-2B2Azksb3w2WmZZuKKVNzyrquNPbzc5Gwb2Fh0VVG5OUnnkmM5XBgk-2F1n9SBiuaOzdDBniYLt7QdDh8mtvF9Sd3SDudbggQdlh-2BwJmeWhPiMESzJs2kmnIGv0lpACN-2FxhMpgP6WlDprv98HzhPRYrCiCPuksNeOp0lAMkc-2FPKEoOqK-2BhSwdXlpV9tU1UAsLivq9liBmA-3D-3D",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0198078043758869,
                    "confidenceSpam": 0.124783106148243,
                    "confidenceThreat": 0.855439007282257
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/hrqdq24d6q0o5aa5ubqvltump4k6tlmgt6sii5o1/fddb3b627c817263af6608bd4088ae1741ae8fbaf0ae2a2a3ceec7951ed43f0e?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=1bc8c8ea37937c000ce2190e963477a6b553bf7116dc70b8c85b77dac166977a",
                "reportedBy": "edi.blr@gmail.com",
                "rules": [],
                "severity": "LOW",
                "subject": "Fwd: \u05d7\u05d5\u05dc\u05e6\u05d5\u05ea \u05d7\u05d3\u05e9\u05d5\u05ea \u05dc\u05de\u05d5\u05e2\u05d3\u05d5\u05df",
                "tags": [
                    {
                        "name": "ZLATAN",
                        "type": "STANDARD"
                    }
                ]
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T07:30:01+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "e1a5e485-5a66-4a87-924e-2368587bf92b",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "909c17d8-2701-4bb6-bc62-b2eefdcc5de0",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:30:01Z",
                        "id": "f1a4ee0b-d7bb-43f1-9b1b-2f5dfa4f0926",
                        "lastSeen": "2021-06-23T07:30:01Z",
                        "scheme": "https",
                        "target": "https://www.paloaltonetworks.com",
                        "url": null,
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:30:01Z",
                        "id": "6c12ada7-27b0-4e3c-91a3-16e543185648",
                        "lastSeen": "2021-06-23T07:30:01Z",
                        "scheme": "https",
                        "target": "https://lh4.googleusercontent.com/YM7Vf4IeQbHD0XerQZJm5Sozv0tgUIscgHyxtUcoOv1ndgOuQcEcWdywEgqfeznUNZ1QS9hrcbTAaINw9QlLM4A_qHytge5-fU0ud2jz-KaiazgXE80BYsjOy-6TS3Ctih72JV7e",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0774629339575768,
                    "confidenceSpam": 0.862347602844238,
                    "confidenceThreat": 0.0602194666862488
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/tog8f1pof4n8u8qbivadkv72fietmoresksqj5o1/c0ed9bac2e057ec1d8106caa9c1257925f2b2f2ab42292e6f7004feefa65ebba?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=f5b5fdc65aa240fb387dc3d0632cc618b62401c284ec8ec37f20709fb7e1c7b8",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "Fwd: \u05e2\u05d3\u05db\u05d5\u05df \u05d9\u05dc\u05d3\u05d9\u05dd :)",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [
                    {
                        "actualContentType": "image/png",
                        "filename": "thanks_for_eating.png",
                        "md5": "0398a8c1b1801c96304e79d1fcc3dcdd",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/7d820d0d1c3e3a493f28a77e8b778ff46b8544395dd1641c6138c8f30743f14c",
                        "sha1": "06dcfa749bc0c0120d2ae3ecd0d90d18dfcbf883",
                        "sha256": "7d820d0d1c3e3a493f28a77e8b778ff46b8544395dd1641c6138c8f30743f14c",
                        "size": 79497,
                        "ssdeep": "1536:Em2scVobOJxJAutQkl1MPIu+TMFwJpkJ3k5g1+bB6dbFnFFvVtGnglU:QsUoKfOutQGo+A26JU59Bs3FvVt4",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "icon_cellphone.png",
                        "md5": "955a9a3abcac63d6591992f04d3cd2e4",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/f0060ce345aaceae5a1816546a5702f428ccf850a44b0e21a336fd21d39c064b",
                        "sha1": "466f04bf726d88361ed702ed4664e6ba427c4b41",
                        "sha256": "f0060ce345aaceae5a1816546a5702f428ccf850a44b0e21a336fd21d39c064b",
                        "size": 1188,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "fb.png",
                        "md5": "f2687a68babe84c155c784b06bedad3d",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/ea8de8ba714e0ab223e3ab90cf6647fdbacb794927886ba030b520bb74677343",
                        "sha1": "1717b2d89fc72def9712eb4b69aea890ef781bd1",
                        "sha256": "ea8de8ba714e0ab223e3ab90cf6647fdbacb794927886ba030b520bb74677343",
                        "size": 3779,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "google_play.s.png",
                        "md5": "e79330dcd9c3c88d838fa530de5758c7",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/378e1083689c9e654114e7c3a75f015e77698856eff7c5e4649f789b45d14de3",
                        "sha1": "e6cb23aa19aadcebb432537baf2b931918c96d46",
                        "sha256": "378e1083689c9e654114e7c3a75f015e77698856eff7c5e4649f789b45d14de3",
                        "size": 2186,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/jpeg",
                        "filename": "Energy-Bar_600PX.jpg",
                        "md5": "fb2009ffb18ff3e1673f4ea346e859e7",
                        "reportedContentType": "image/jpeg",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/258a856a8938eda834aae437e0deacf3003a4013d2c6a12db3b5e5e9b3fa78d1",
                        "sha1": "9ea9488d538f76f1992ec2beabeee8e4e88551e5",
                        "sha256": "258a856a8938eda834aae437e0deacf3003a4013d2c6a12db3b5e5e9b3fa78d1",
                        "size": 1417,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "cibus_logo.png",
                        "md5": "8c7a8485d50f1135a0dd088ee16f9c44",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/51444949e0ed9ffb228eaec2516a9916f996dfc29b054925ca6b6aec4afc280f",
                        "sha1": "8485d8fda2eec5b9eeff5c97cd9d6d481f9ecb2a",
                        "sha256": "51444949e0ed9ffb228eaec2516a9916f996dfc29b054925ca6b6aec4afc280f",
                        "size": 6013,
                        "ssdeep": "96:ydY2ElQ4K2raIpGsMS2x0NfYbNjuT66BZEqD/JAOVZA3JZ9MYzSx5hw:MGQ4HrbGsM3cYbNjugSJrABMNw",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "app_store.s.png",
                        "md5": "78668e683a651affac11fbc5c7c0b357",
                        "reportedContentType": "image/png",
                        "s3Key": "lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/b25b065cce461deac4ea98b065f1e02242f613eea081f6231d0ec3f2af728404",
                        "sha1": "355ad7070c31b5f97cceaf013894f3826c435267",
                        "sha256": "b25b065cce461deac4ea98b065f1e02242f613eea081f6231d0ec3f2af728404",
                        "size": 1941,
                        "ssdeep": "",
                        "virustotal": null
                    }
                ],
                "category": "SPAM",
                "comments": [],
                "created at": "2021-06-23T07:28:07+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "dc90f592-1943-41a2-90f3-49fd044e9138",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "910f8274-86c5-4f85-b7c8-8ae19fde9ce7",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://mysodexo.co.il",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__mysodexo.co.il&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=opMF1EZjvNFD_os1bTgdV6W2GVQZhnxU-dT54IGc0UM&s=RZcva2AqZSzcjtOP0CDdnZCts0NyVU_wekjO16HWxN8&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "ae098257-4552-42b8-bbb7-00a7a670d4a6",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://www.cibus-sodexo.co.il/%D7%AA%D7%A0%D7%90%D7%99-%D7%A9%D7%99%D7%9E%D7%95%D7%A9",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__www.cibus-2Dsodexo.co.il_-25D7-25AA-25D7-25A0-25D7-2590-25D7-2599-2D-25D7-25A9-25D7-2599-25D7-259E-25D7-2595-25D7-25A9&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=opMF1EZjvNFD_os1bTgdV6W2GVQZhnxU-dT54IGc0UM&s=-X0jvoFkt5La6Rh23N062R6mhdJEWXYhI50cTXyg_6U&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "a1ec7903-26b0-4b58-b5e1-4ba5e629324c",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://www.facebook.com/CibusSodexo",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__www.facebook.com_CibusSodexo&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=opMF1EZjvNFD_os1bTgdV6W2GVQZhnxU-dT54IGc0UM&s=5sbgOU_TDKJQK-72cFp7DWQ2a-RHMrg4h9b5JpZK9B8&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "2557e332-12b7-451b-bf3f-3ff59250dd91",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://cibus-sodexo.onelink.me/XHcT/OPemail",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__cibus-2Dsodexo.onelink.me_XHcT_OPemail&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=opMF1EZjvNFD_os1bTgdV6W2GVQZhnxU-dT54IGc0UM&s=xbuX8Plb9Q2PCtWGxK4FBLaF10Hr6c0CUtwaa3hulZg&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "60388683-1c59-4b21-9858-cd422f83242d",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "http",
                        "target": "http://mysodexo.co.il",
                        "url": "mysodexo.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "16098285-27e5-42b8-b7bc-7ab426613574",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0880486220121384,
                    "confidenceSpam": 0.403300613164902,
                    "confidenceThreat": 0.508680760860443
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/lbo3hi78uim1s9m8eb7bfk1ie68dcrj1kg79t801/3e36b07ac6955195af3b993d53a2b33f4b50bb1cd039419f09b8f29db608c5eb?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=346318efffd4efcfee4ac265ebc4d07f303ffaba15b85d8c46605e5b18cdda24",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "CRITICAL",
                "subject": "Fwd: \u05d0\u05d9\u05e9\u05d5\u05e8 \u05e2\u05e1\u05e7\u05d4 \u05d1\u05de\u05e1\u05e2\u05d3\u05ea \u05e6\u05d9\u05e7\u05df \u05e1\u05d8\u05d9\u05d9\u05e9\u05df \u05de\u05d2\u05d3\u05dc\u05d9 \u05d0\u05dc\u05d5\u05df - \u05ea\u05dc \u05d0\u05d1\u05d9\u05d1 \u05d9\u05e4\u05d5",
                "tags": []
            },
            {
                "actionStatus": "RESOLVED",
                "attachments": [
                    {
                        "actualContentType": "application/pdf",
                        "filename": "\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd_\ufffd\ufffd_\ufffd\ufffd\ufffd\ufffd_564075.pdf",
                        "md5": "6d489e004e14284b449e10abe9a5f638",
                        "reportedContentType": "application/pdf",
                        "s3Key": "7q0d1ctvas9ljqe0en2qiioomd919b533ftmml81/41524399b5b97d6876e09b88509cd3af64eb55b886c9a7cb989cef5d1826b646",
                        "sha1": "69c5cbcadc011491441624e247142d10228ffff3",
                        "sha256": "41524399b5b97d6876e09b88509cd3af64eb55b886c9a7cb989cef5d1826b646",
                        "size": 82382,
                        "ssdeep": "1536:C1t8wU/cuGPe48oH2SWAbiKWhM6MjHy74TMyXTe9iYvI0pmxMnh:C1tBU/tGUs2SkKKgHy74hSV0Mnh",
                        "virustotal": null
                    }
                ],
                "category": "CLEAN",
                "comments": [],
                "created at": "2021-06-23T07:28:01+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "ab7cca91-96a6-45da-814c-dcb3840248e1",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:28:01Z",
                        "id": "f2162c8a-ad33-4d5d-9f04-a732048c9db8",
                        "lastSeen": "2021-06-23T07:28:01Z",
                        "scheme": "http",
                        "target": "http://out.cardcom.co.il",
                        "url": "out.cardcom.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "5419c6a1-2c70-41f0-b700-0fdf366dbec7",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:28:01Z",
                        "id": "856c7638-5374-4943-b9b7-30742d9a11d8",
                        "lastSeen": "2021-06-23T07:28:01Z",
                        "scheme": "http",
                        "target": "http://www.cardcom.co.il",
                        "url": null,
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.00331612257286906,
                    "confidenceSpam": 0.955114781856537,
                    "confidenceThreat": 0.0415991172194481
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/7q0d1ctvas9ljqe0en2qiioomd919b533ftmml81/95f46512ce36d0d28b96ad58a84d692ff915083ff5d314601b1ed0e6c6da32de?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=c83bb48429b965b05359bea9ad7914cb457a4bc69a2ca00455438f87d5ee92e7",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "HIGH",
                "subject": "Fwd: \u05d7\u05e9\u05d1\u05d5\u05e0\u05d9\u05ea \u05de\u05e1 \u05e7\u05d1\u05dc\u05d4 \u05de\u05e1\u05e4\u05e8 564075 \u05de\u05d2'\u05d5\u05dc \u05e9\u05d5\u05e4\u05d9\u05e0\u05d2 \u05d1\u05e2\"\u05de AVO - \u05e2\u05d1\u05d5\u05e8 \u05d0\u05d3\u05d9 \u05db\u05e6\u05e0\u05dc\u05e1\u05d5\u05df",
                "tags": []
            },
            {
                "actionStatus": "RECEIVED",
                "attachments": [
                    {
                        "actualContentType": "image/png",
                        "filename": "cibus_logo.png",
                        "md5": "8c7a8485d50f1135a0dd088ee16f9c44",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/51444949e0ed9ffb228eaec2516a9916f996dfc29b054925ca6b6aec4afc280f",
                        "sha1": "8485d8fda2eec5b9eeff5c97cd9d6d481f9ecb2a",
                        "sha256": "51444949e0ed9ffb228eaec2516a9916f996dfc29b054925ca6b6aec4afc280f",
                        "size": 6013,
                        "ssdeep": "96:ydY2ElQ4K2raIpGsMS2x0NfYbNjuT66BZEqD/JAOVZA3JZ9MYzSx5hw:MGQ4HrbGsM3cYbNjugSJrABMNw",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "fb.png",
                        "md5": "f2687a68babe84c155c784b06bedad3d",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/ea8de8ba714e0ab223e3ab90cf6647fdbacb794927886ba030b520bb74677343",
                        "sha1": "1717b2d89fc72def9712eb4b69aea890ef781bd1",
                        "sha256": "ea8de8ba714e0ab223e3ab90cf6647fdbacb794927886ba030b520bb74677343",
                        "size": 3779,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "app_store.s.png",
                        "md5": "78668e683a651affac11fbc5c7c0b357",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/b25b065cce461deac4ea98b065f1e02242f613eea081f6231d0ec3f2af728404",
                        "sha1": "355ad7070c31b5f97cceaf013894f3826c435267",
                        "sha256": "b25b065cce461deac4ea98b065f1e02242f613eea081f6231d0ec3f2af728404",
                        "size": 1941,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "icon_cellphone.png",
                        "md5": "955a9a3abcac63d6591992f04d3cd2e4",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/f0060ce345aaceae5a1816546a5702f428ccf850a44b0e21a336fd21d39c064b",
                        "sha1": "466f04bf726d88361ed702ed4664e6ba427c4b41",
                        "sha256": "f0060ce345aaceae5a1816546a5702f428ccf850a44b0e21a336fd21d39c064b",
                        "size": 1188,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "google_play.s.png",
                        "md5": "e79330dcd9c3c88d838fa530de5758c7",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/378e1083689c9e654114e7c3a75f015e77698856eff7c5e4649f789b45d14de3",
                        "sha1": "e6cb23aa19aadcebb432537baf2b931918c96d46",
                        "sha256": "378e1083689c9e654114e7c3a75f015e77698856eff7c5e4649f789b45d14de3",
                        "size": 2186,
                        "ssdeep": "",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/png",
                        "filename": "thanks_for_eating.png",
                        "md5": "0398a8c1b1801c96304e79d1fcc3dcdd",
                        "reportedContentType": "image/png",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/7d820d0d1c3e3a493f28a77e8b778ff46b8544395dd1641c6138c8f30743f14c",
                        "sha1": "06dcfa749bc0c0120d2ae3ecd0d90d18dfcbf883",
                        "sha256": "7d820d0d1c3e3a493f28a77e8b778ff46b8544395dd1641c6138c8f30743f14c",
                        "size": 79497,
                        "ssdeep": "1536:Em2scVobOJxJAutQkl1MPIu+TMFwJpkJ3k5g1+bB6dbFnFFvVtGnglU:QsUoKfOutQGo+A26JU59Bs3FvVt4",
                        "virustotal": null
                    },
                    {
                        "actualContentType": "image/jpeg",
                        "filename": "Energy-Bar_600PX.jpg",
                        "md5": "fb2009ffb18ff3e1673f4ea346e859e7",
                        "reportedContentType": "image/jpeg",
                        "s3Key": "ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/258a856a8938eda834aae437e0deacf3003a4013d2c6a12db3b5e5e9b3fa78d1",
                        "sha1": "9ea9488d538f76f1992ec2beabeee8e4e88551e5",
                        "sha256": "258a856a8938eda834aae437e0deacf3003a4013d2c6a12db3b5e5e9b3fa78d1",
                        "size": 1417,
                        "ssdeep": "",
                        "virustotal": null
                    }
                ],
                "category": "THREAT",
                "comments": [],
                "created at": "2021-06-23T07:25:58+00:00",
                "from": "ekatsenelson@paloaltonetworks.com",
                "id": "378ced39-894f-4365-940e-5f6183b14483",
                "links": [
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "677fca3a-9198-492e-9496-c2cc893bf182",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://mysodexo.co.il",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__mysodexo.co.il&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=kIzfySpITaDeNM_RzUFwTtfHfXbH6L9Jgtc7ATrBUpI&s=AJUTStLKIlNhXeJK42b4N4Z8wporE9qk4X5rye96aiA&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "50c6637d-44e5-4fe5-a509-16eb763d5d52",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://www.cibus-sodexo.co.il/%D7%AA%D7%A0%D7%90%D7%99-%D7%A9%D7%99%D7%9E%D7%95%D7%A9",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__www.cibus-2Dsodexo.co.il_-25D7-25AA-25D7-25A0-25D7-2590-25D7-2599-2D-25D7-25A9-25D7-2599-25D7-259E-25D7-2595-25D7-25A9&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=kIzfySpITaDeNM_RzUFwTtfHfXbH6L9Jgtc7ATrBUpI&s=VewGhWy7EmOmWNOHrCJl5Km2gGUP176rRJ8VCOuPomI&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "1bfdd4fe-a054-4f64-98a2-da01b512c768",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://www.facebook.com/CibusSodexo",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__www.facebook.com_CibusSodexo&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=kIzfySpITaDeNM_RzUFwTtfHfXbH6L9Jgtc7ATrBUpI&s=bnxWPlc9E-CNayNbQkwNwlhBtXrRnPnCdSaAh3nQyAI&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "0a67ece5-761d-46ea-ba94-22b7a02ef4a3",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "https",
                        "target": "https://cibus-sodexo.onelink.me/XHcT/OPemail",
                        "url": "https://urldefense.proofpoint.com/v2/url?u=https-3A__cibus-2Dsodexo.onelink.me_XHcT_OPemail&d=DwMGaQ&c=V9IgWpI5PvzTw83UyHGVSoW3Uc1MFWe5J8PTfkrzVSo&r=iPasPoJbyMutmlDBaYuOeY_VmCh7bMpmMNiy2HjbN33h0r2iaXrsasWW5s8drTgC&m=kIzfySpITaDeNM_RzUFwTtfHfXbH6L9Jgtc7ATrBUpI&s=3p9CU-Zb17wpbSbO1JpbVLt90BzVx-9mqBaacxTP-8M&e=",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "aeb53adb-2359-448d-b0f7-2dccf28c30bc",
                        "lastSeen": "2021-06-23T07:28:07Z",
                        "scheme": "http",
                        "target": "http://mysodexo.co.il",
                        "url": "mysodexo.co.il",
                        "virustotal": null
                    },
                    {
                        "dispositions": [
                            "NONE"
                        ],
                        "firstSeen": "2021-06-23T07:25:58Z",
                        "id": "800b3630-9de8-4da4-b13d-cc29d147939e",
                        "lastSeen": "2021-08-08T14:06:11Z",
                        "scheme": "http",
                        "target": "http://paloaltonetworks.com",
                        "url": "paloaltonetworks.com",
                        "virustotal": null
                    }
                ],
                "phishmlReport": {
                    "confidenceClean": 0.0281141791492701,
                    "confidenceSpam": 0.424505144357681,
                    "confidenceThreat": 0.547410666942596
                },
                "pipelineStatus": "PROCESSED",
                "rawUrl": "https://phisher-parts-production-eu-west-1.s3.eu-west-1.amazonaws.com/06d1a635-8206-4ddb-bc59-8bd5d4f95e05/2021-06-23/ta8d1gvgpmtlv1110v0ek23dvgelnova39gf1jg1/8d32bc12887581f4a953a8a827e3d5bd48d306c8482998235bc2bdfdff11061d?response-content-disposition=attachment%3B%20filename%3D%22%22%3B%20filename%2A%3DUTF-8%27%27&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA37KREM2QGUA4U76L%2F20210819%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20210819T175859Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEIH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMSJGMEQCICsVDsDg8OlThqE1eHv7tzUDZiR0Xo1wRmF0raOX47TfAiAq7%2BSQ7saAdgs3yJxcpN%2BmcxtlvgM%2FXCOKo0m4V8kfwSqIBAip%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDgyMzE5MzI2NTgyNCIMY8eTIJwTmB5SmDHYKtwDFjI4Z5G%2FeiqWjVpUoTXLrqXf3B4ZcqLs76A8J%2BDWIy7M2bxUtLl3Wz%2BOexzjd1CHlN212CRlBkrXYUoaSnjbOT1c%2FSjewJPDDI4qxC96ZDzR4jnyEhmAXd%2FX3P1Eh8w%2BrgffbRzeZ4FlCVWHLu3YhuXI%2FsBPF5sAj%2FpaWNSBG5czhIDrWuULsTzVF3jBoCMYyLX5H6W%2FulkanoCsN%2FmWJ6bOXhXXTV7tnrWGCBadabu1QkgocPE2rrBWtpKig5WYF9UgKmHzpfa7J7Jwscju%2FkDAH0SDIrMmBzyV%2B8VYo7CVLctIroxeoUxFTh4MgX3AbYKA46RtNEj6ynEhh5av3qRetcIfP6Dju3aO7Oc2g1OBbHunGbb0VJvnTUnugid8MwJpu297T74pwTjTQ1kEpfYJpxstDTjmBQYXXsNP0wXi%2BFWoNzMeU538%2B%2FhOZHcpzQDxv9DIIWWe0wp%2B%2F240GKekfnLmZJKc%2BNKqZDXA1zMWzKbr4A%2BOLxrNV2Ai%2FZy05R8vYTkudVYRlP6d4hMIa7mK7FTAC%2FFPuOTVlAX%2B4qomUWbVSuDG8Zh1lTVpFZDb1seA4TniW4hGUPgB%2FmnFCT8g%2FPLed5T5yQl3vSsrZoXcw6Qr%2FdDe6U%2B%2F49AwtIX6iAY6pgEpt5Gapt3mx2n7JBpGECiSpOkiN59OLEQzbVg1DlkdE9Tamgd4nMtG505FsG5zglJDWD51awlJ6QkK4fIAQ2OBkxuZwB2vZTZubrfsWX5egptUqj0fpbFdpw4HLdI1%2BWeMjPGzJ95rNQaBSI4ZbkqoTTI64nYZBprScXEeTdCMXlh%2FTNBVJmK1%2Bzkxhugp9Cw040V11Pe3DB2Xj6YH3MPVNgtQMVo3&X-Amz-Signature=aa7307feed3addb39dcec543fe7382fdf4708bbd23ab5a5090c847d77469eab1",
                "reportedBy": "ekatsenelson@paloaltonetworks.com",
                "rules": [],
                "severity": "MEDIUM",
                "subject": "Fwd: \u05d0\u05d9\u05e9\u05d5\u05e8 \u05e2\u05e1\u05e7\u05d4 \u05d1\u05de\u05e1\u05e2\u05d3\u05ea \u05d4\u05e4\u05dc\u05d0\u05e4\u05dc \u05e9\u05dc \u05d3\u05d5\u05d9\u05d3 - \u05ea\u05dc \u05d0\u05d1\u05d9\u05d1",
                "tags": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Messages
>|ID|Status|Category|From|Severity|Created At|
>|---|---|---|---|---|---|
>| bac9cf67-fa8e-46d1-ad67-69513fc44b5b | RECEIVED | UNKNOWN | ekatsenelson@paloaltonetworks.com | UNKNOWN_SEVERITY | 2021-08-08T14:06:11+00:00 |
>| cff35e34-aeb6-4263-b592-c68fc03ea7cb | IN_REVIEW | THREAT | edi.blr@gmail.com | HIGH | 2021-07-08T18:28:27+00:00 |
>| fdd6cda3-505e-4524-a595-86d5d250c722 | RECEIVED | THREAT | edi.blr@gmail.com | HIGH | 2021-07-08T18:27:57+00:00 |
>| 8eff23f7-cd65-49ce-98da-871ecd0e18a1 | RECEIVED | UNKNOWN | edi.blr@gmail.com | UNKNOWN_SEVERITY | 2021-07-08T18:27:04+00:00 |
>| edd66fed-5150-4a73-b447-6572987c7392 | RESOLVED | THREAT | edi.blr@gmail.com | HIGH | 2021-07-08T18:26:40+00:00 |
>| 3625caf9-b6c9-416f-8106-23a0d6d58754 | IN_REVIEW | THREAT | edi.blr@gmail.com | MEDIUM | 2021-07-08T18:24:15+00:00 |
>| 5b2d1c54-f9e5-4e35-b042-36f358eab4dd | RECEIVED | UNKNOWN | edi.blr@gmail.com | UNKNOWN_SEVERITY | 2021-07-08T18:23:14+00:00 |
>| 4436f778-1446-4f21-a576-6945f284c93b | RECEIVED | UNKNOWN | edi.blr@gmail.com | UNKNOWN_SEVERITY | 2021-07-08T18:22:55+00:00 |
>| 87c1ae39-9e34-4c17-b6e8-2d5d6fea2d52 | RESOLVED | SPAM | eduardk1@mail.tau.ac.il | HIGH | 2021-07-08T18:22:08+00:00 |
>| 1a5302e4-69ff-4c67-8f72-1b55b9e27f47 | RECEIVED | CLEAN | eduardk1@mail.tau.ac.il | CRITICAL | 2021-07-08T18:21:57+00:00 |
>| e7eda9f8-0f1b-4863-8c89-c169c5311a09 | RECEIVED | UNKNOWN | eduardk1@mail.tau.ac.il | UNKNOWN_SEVERITY | 2021-07-08T18:21:36+00:00 |
>| dd2bca13-eee3-4b01-8c15-27a67b589c46 | RECEIVED | UNKNOWN | ekatsenelson@paloaltonetworks.com | UNKNOWN_SEVERITY | 2021-07-08T18:21:19+00:00 |
>| 00a43d65-5802-4df6-9c3c-f7d2024ddb0b | IN_REVIEW | CLEAN | ekatsenelson@paloaltonetworks.com | MEDIUM | 2021-07-07T15:18:58+00:00 |
>| 21b53376-5c7d-4050-ae17-5f3a350a49d8 | RECEIVED | SPAM | s7310424@gmail.com | LOW | 2021-06-23T08:16:17+00:00 |
>| 11abc56f-3732-4512-953e-dc156ec41b81 | RESOLVED | CLEAN | s7310424@gmail.com | UNKNOWN_SEVERITY | 2021-06-23T08:15:33+00:00 |
>| a4a7a267-7e0d-4767-8b96-84c50fd342e6 | RESOLVED | CLEAN | s7310424@gmail.com | MEDIUM | 2021-06-23T08:15:04+00:00 |
>| 4035a6b8-bdc5-42e5-b2ac-6d1b30e840ed | RESOLVED | SPAM | s7310424@gmail.com | LOW | 2021-06-23T08:12:25+00:00 |
>| b3f3371c-e608-43f4-999d-f506e22a1092 | RESOLVED | SPAM | s7310424@gmail.com | CRITICAL | 2021-06-23T08:12:13+00:00 |
>| 76c99796-f735-4511-a937-dbc9ddcdac72 | RECEIVED | CLEAN | eduardk1@mail.tau.ac.il | LOW | 2021-06-23T08:08:27+00:00 |
>| 19640adc-b746-4b86-b816-dc31dfa124aa | RECEIVED | SPAM | eduardk1@mail.tau.ac.il | HIGH | 2021-06-23T08:06:48+00:00 |
>| 31825085-1b44-4150-833e-bb25602af0ce | RESOLVED | CLEAN | eduardk1@mail.tau.ac.il | MEDIUM | 2021-06-23T08:06:54+00:00 |
>| d2dc06ce-5dcf-4caa-93ca-7747dd3afb02 | IN_REVIEW | CLEAN | eduardk1@mail.tau.ac.il | LOW | 2021-06-23T08:06:35+00:00 |
>| c036fb13-d108-4564-9c52-129baf75d835 | IN_REVIEW | THREAT | kgal@paloaltonetworks.com | CRITICAL | 2021-06-23T07:45:20+00:00 |
>| 8ac6e2f7-9757-4b56-b624-115834f88f7d | RECEIVED | CLEAN | edi.blr@gmail.com | MEDIUM | 2021-06-23T07:45:24+00:00 |
>| 540e8585-4b1f-4485-8bb9-70f8084e8e9a | RESOLVED | SPAM | kgal@paloaltonetworks.com | CRITICAL | 2021-06-23T07:43:57+00:00 |
>| 2b025b06-b21b-4aa2-8246-92637b995337 | RESOLVED | CLEAN | edi.blr@gmail.com | MEDIUM | 2021-06-23T07:41:40+00:00 |
>| bbeb082d-d828-45ed-8571-3c885da6537f | IN_REVIEW | CLEAN | edi.blr@gmail.com | LOW | 2021-06-23T07:37:10+00:00 |
>| e1a5e485-5a66-4a87-924e-2368587bf92b | RESOLVED | SPAM | ekatsenelson@paloaltonetworks.com | CRITICAL | 2021-06-23T07:30:01+00:00 |
>| dc90f592-1943-41a2-90f3-49fd044e9138 | RESOLVED | SPAM | ekatsenelson@paloaltonetworks.com | CRITICAL | 2021-06-23T07:28:07+00:00 |
>| ab7cca91-96a6-45da-814c-dcb3840248e1 | RESOLVED | CLEAN | ekatsenelson@paloaltonetworks.com | HIGH | 2021-06-23T07:28:01+00:00 |
>| 378ced39-894f-4365-940e-5f6183b14483 | RECEIVED | THREAT | ekatsenelson@paloaltonetworks.com | MEDIUM | 2021-06-23T07:25:58+00:00 |


### phisher-create-comment
***
Adds a comment to a PhishER message


#### Base Command

`phisher-create-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| comment | The comment to add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-create-comment id=3625caf9-b6c9-416f-8106-23a0d6d58754 comment="Test Comment"```

#### Human Readable Output

>The comment was added successfully

### phisher-update-message
***
Updates a PhishER message status. User must provide at least one argument.


#### Base Command

`phisher-update-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Message Category, can be: UNKNOWN,CLEAN,SPAM,THREAT		. Possible values are: UNKNOWN, CLEAN, SPAM, THREAT. | Optional | 
| status | Message Status, can be: RECEIVED,IN_REVIEW,RESOLVED. Possible values are: RECEIVED, IN_REVIEW, RESOLVED. | Optional | 
| severity | Message Severity, can be: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL. Possible values are: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| id | Message ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-update-message id=3625caf9-b6c9-416f-8106-23a0d6d58754 category=THREAT severity=MEDIUM status=IN_REVIEW```

#### Human Readable Output

>The message was updated successfully

### phisher-tags-create
***
Add tags to a given message


#### Base Command

`phisher-tags-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Comma separated list of tags to add. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-tags-create id=3625caf9-b6c9-416f-8106-23a0d6d58754 tags="Tag1, Tag2"```

#### Human Readable Output

>The tags were updated successfully

### phisher-tags-delete
***
Removes tags from a given message.


#### Base Command

`phisher-tags-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Message ID. | Required | 
| tags | Comma separated list of tags to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!phisher-tags-delete id=3625caf9-b6c9-416f-8106-23a0d6d58754 tags="Tag2"```

#### Human Readable Output

>The tags were deleted successfully
