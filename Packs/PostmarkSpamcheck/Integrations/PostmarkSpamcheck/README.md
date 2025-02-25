Postmark's spam API, Spamcheck, is a RESTfull interface to the Spam filter tool SpamAssassin.


## Configure Postmark Spamcheck in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL | Postmark Spamcheck API URL | True |
| Trust any certificate (not secure) | When ‘trust any certificate’ is selected, the integration ignores TLS/SSL certificate validation errors. Used to test connection issues or connect to a server without a valid certificate. | False |
| Use system proxy settings | Runs the integration instance using the proxy server \(HTTP or HTTPS\) that you defined in the server configuration. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### postmark-spamcheck
***
Check the spamscore of your email message


#### Base Command

`postmark-spamcheck`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryid | Entry ID of mail EML file. | Required | 
| short | Only return spam score. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Postmark.Spamcheck.score | unknown | Value of SpamAssassin score | 
| Postmark.Spamcheck.success | unknown | State of SpamAssassin check | 
| Postmark.Spamcheck.rules | unknown |  List the matched SpamAssassin rules | 
| Postmark.Spamcheck.report | unknown | Detailed SpamAssassin report | 

#### Command example
```!postmark-spamcheck entryid="654@731f1b54-bdea-4d4a-860f-328527df0cd7"```
#### Context Example
```json
{
    "Postmark": {
        "Spamcheck": {
            "entryid": "654@731f1b54-bdea-4d4a-860f-328527df0cd7",
            "report": " pts rule                     description                                       \n---- ----------------------   --------------------------------------------------\n-0.0 NO_RELAYS                Informational: message was not relayed via SMTP   \n 0.6 TVD_FW_GRAPHIC_NAME_LONG BODY: Long image attachment name                  \n 1.6 HTML_IMAGE_ONLY_12       BODY: HTML: images with 800-1200 bytes of words   \n 0.0 HTML_MESSAGE             BODY: HTML included in message                    \n 0.0 URIBL_BLOCKED            ADMINISTRATOR NOTICE: The query to URIBL was      \n                              blocked. See                                      \n                              http://wiki.apache.org/spamassassin/DnsBlocklists\u2026\n                              #dnsbl-block for more information. [URIs:         \n                              phpclasses.org]                                   \n-0.0 NO_RECEIVED              Informational: message has no Received headers    \n-0.0 T_SCC_BODY_TEXT_LINE     No description available.                         ",
            "rules": [
                {
                    "description": "Informational: message was not relayed via SMTP",
                    "score": "-0.0"
                },
                {
                    "description": "BODY: Long image attachment name",
                    "score": "0.6"
                },
                {
                    "description": "BODY: HTML: images with 800-1200 bytes of words",
                    "score": "1.6"
                },
                {
                    "description": "BODY: HTML included in message",
                    "score": "0.0"
                },
                {
                    "description": "ADMINISTRATOR NOTICE: The query to URIBL was blocked. See http://wiki.apache.org/spamassassin/DnsBlocklists#dnsbl-block for more information. [URIs: phpclasses.org]",
                    "score": "0.0"
                },
                {
                    "description": "Informational: message has no Received headers",
                    "score": "-0.0"
                },
                {
                    "description": "No description available.",
                    "score": "-0.0"
                }
            ],
            "score": "2.3",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Postmark - Spamcheck
>Spamcheck completed
> 
>|entryid|report|rules|score|success|
>|---|---|---|---|---|
>| 654@731f1b54-bdea-4d4a-860f-328527df0cd7 |  pts rule                     description                                       <br/>---- ----------------------   --------------------------------------------------<br/>-0.0 NO_RELAYS                Informational: message was not relayed via SMTP   <br/> 0.6 TVD_FW_GRAPHIC_NAME_LONG BODY: Long image attachment name                  <br/> 1.6 HTML_IMAGE_ONLY_12       BODY: HTML: images with 800-1200 bytes of words   <br/> 0.0 HTML_MESSAGE             BODY: HTML included in message                    <br/> 0.0 URIBL_BLOCKED            ADMINISTRATOR NOTICE: The query to URIBL was      <br/>                              blocked. See                                      <br/>                              http:<span>//</span>wiki.apache.org/spamassassin/DnsBlocklists…<br/>                              #dnsbl-block for more information. [URIs:         <br/>                              phpclasses.org]                                   <br/>-0.0 NO_RECEIVED              Informational: message has no Received headers    <br/>-0.0 T_SCC_BODY_TEXT_LINE     No description available.                          | {'score': '-0.0', 'description': 'Informational: message was not relayed via SMTP'},<br/>{'score': '0.6', 'description': 'BODY: Long image attachment name'},<br/>{'score': '1.6', 'description': 'BODY: HTML: images with 800-1200 bytes of words'},<br/>{'score': '0.0', 'description': 'BODY: HTML included in message'},<br/>{'score': '0.0', 'description': 'ADMINISTRATOR NOTICE: The query to URIBL was blocked. See http:<span>//</span>wiki.apache.org/spamassassin/DnsBlocklists#dnsbl-block for more information. [URIs: phpclasses.org]'},<br/>{'score': '-0.0', 'description': 'Informational: message has no Received headers'},<br/>{'score': '-0.0', 'description': 'No description available.'} | 2.3 | true |


#### Command example
```!postmark-spamcheck entryid="654@731f1b54-bdea-4d4a-860f-328527df0cd7" short=True```
#### Context Example
```json
{
    "Postmark": {
        "Spamcheck": {
            "entryid": "654@731f1b54-bdea-4d4a-860f-328527df0cd7",
            "score": "2.3",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Postmark - Spamcheck
>Spamcheck completed
> 
>|entryid|score|success|
>|---|---|---|
>| 654@731f1b54-bdea-4d4a-860f-328527df0cd7 | 2.3 | true |
