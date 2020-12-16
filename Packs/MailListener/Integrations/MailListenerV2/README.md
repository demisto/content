## Overview
---

Listens to a mailbox and enables incident triggering via e-mail.

---

## Configure Mail Listener v2 on XSOAR

---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Mail Listener v2. 
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__: Whether to fetch incidents or not
    * __MailServerURL__: Mail Server Hostname / IP address
    * __port__: IMAP Port
    * __credentials__: Username and password
    * __folder__: Incoming mail folder
    * __permittedFromAdd__: Fetch mails from these senders addresses only (eg. admin@demo.com,test@demo.com)
    * __first_fetch__: First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)
    * __limit__: The maximum number of incidents to fetch each time
    * __delete_processed__: Delete processed emails
    * __Include_raw_body__: Include raw body in incidents
    * __save_file__: Save the email .eml file
    * __TLS_connection__: Use TLS for connection (defaults to True)
    * __insecure__: Trust any certificate (not secure)
    * __incidentFetchInterval__: Incidents Fetch Interval
4. Click __Test__ to validate the connection and the authentication.

## Commands:

1. mail-listener-list-emails
2. mail-listener-get-email
3. mail-listener-get-email-as-eml
### 1. mail-listener-list-emails
***
Fetches mails according to the configuration


#### Base Command

`mail-listener-list-emails`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MailListener.EmailPreview.Subject | String | The subject of the mail | 
| MailListener.EmailPreview.Date | Date | The date when the mail was recived | 
| MailListener.EmailPreview.To | String | The recipient of the mail | 
| MailListener.EmailPreview.From | String | The sender of the mail | 
| MailListener.EmailPreview.ID | string | The ID of the mail | 


#### Command Example
```!mail-listener-list-emails```

#### Context Example
```
{
    "MailListener": {
        "EmailPreview": {
            "Date": "2020-08-12T11:13:35+00:00",
            "From": "test@demistodev.com",
            "ID": 65445,
            "Subject": "foooSubject",
            "To": [
                "test@demistodev.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|Date|From|ID|Subject|To|
>|---|---|---|---|---|
>| 2020-08-12T11:13:35+00:00 | test@demistodev.com | 65445 | foooSubject | test@demistodev.com |

### 2. mail-listener-get-email
***
Fetches an email by email ID


#### Base Command

`mail-listener-get-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message-id | Message ID as fetched in 'mail-listener-list-emails' command | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MailListener.Email.to | String | The recipients of the mail | 
| MailListener.Email.cc | String | The mail's cc | 
| MailListener.Email.bcc | String | The mail's bcc | 
| MailListener.Email.from | String | The sender of the mail | 
| MailListener.Email.format | String | The format of the mail | 
| MailListener.Email.text | String | The plain text of the mail | 
| MailListener.Email.HTML | String | The HTML display of the mail if exists | 
| MailListener.Email.subject | String | The subject of the mail | 
| MailListener.Email.attachments | String | The attachments of the mail if exists | 
| MailListener.Email.headers | String | The headers of the mail | 


#### Command Example
```!mail-listener-get-email message-id=65445```

#### Context Example
```
{
    "MailListener": {
        "Email": {
            "attachments": [],
            "bcc": "",
            "cc": "",
            "format": "text/plain",
            "from": "test@demistodev.com",
            "headers": {
                "Content-Transfer-Encoding": "quoted-printable",
                "Content-Type": "text/plain; charset=UTF-8",
                "Date": "Wed, 12 Aug 2020 11:13:35 +0000",
                "From": "test@demistodev.com",
                "Message-ID": "<5f33cedf.1c69fb81.e5562.38a5@mx.google.com>",
                "Mime-Version": "1.0",
                "Received": "from localhost (13.100.68.34.bc.googleusercontent.com. [192.0.0.1])\r\n        by smtp.gmail.com with ESMTPSA id t5sm917197ilp.15.2020.08.12.04.13.35\r\n        for <test@demistodev.com>\r\n        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);\r\n        Wed, 12 Aug 2020 04:13:35 -0700 (PDT)",
                "Return-Path": "<test@demistodev.com>",
                "Subject": "foooSubject",
                "To": "test@demistodev.com",
                "X-Google-Original-From": "koko@demisto.com"
            },
            "rawHeaders": "Return-Path: <test@demistodev.com>\nReceived: from localhost (13.100.68.34.bc.googleusercontent.com. [34.68.100.13])\r\n        by smtp.gmail.com with ESMTPSA id t5sm917197ilp.15.2020.08.12.04.13.35\r\n        for <test@demistodev.com>\r\n        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);\r\n        Wed, 12 Aug 2020 04:13:35 -0700 (PDT)\nMessage-ID: <5f33cedf.1c69fb81.e5562.38a5@mx.google.com>\nFrom: test@demistodev.com\nX-Google-Original-From: koko@demisto.com\nMime-Version: 1.0\nDate: Wed, 12 Aug 2020 11:13:35 +0000\nTo: test@demistodev.com\nSubject: foooSubject\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: quoted-printable",
            "subject": "foooSubject",
            "text": "foooBody",
            "to": "test@demistodev.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|attachments|bcc|cc|format|from|headers|rawHeaders|subject|text|to|
>|---|---|---|---|---|---|---|---|---|---|
>|  |  |  | text/plain | test@demistodev.com | Return-Path: <test@demistodev.com><br/>Received: from localhost (13.100.68.34.bc.googleusercontent.com. [34.68.100.13])<br/>        by smtp.gmail.com with ESMTPSA id t5sm917197ilp.15.2020.08.12.04.13.35<br/>        for <test@demistodev.com><br/>        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);<br/>        Wed, 12 Aug 2020 04:13:35 -0700 (PDT)<br/>Message-ID: <5f33cedf.1c69fb81.e5562.38a5@mx.google.com><br/>From: test@demistodev.com<br/>X-Google-Original-From: koko@demisto.com<br/>Mime-Version: 1.0<br/>Date: Wed, 12 Aug 2020 11:13:35 +0000<br/>To: test@demistodev.com<br/>Subject: foooSubject<br/>Content-Type: text/plain; charset=UTF-8<br/>Content-Transfer-Encoding: quoted-printable | Return-Path: <test@demistodev.com><br/>Received: from localhost (13.100.68.34.bc.googleusercontent.com. [34.68.100.13])<br/>        by smtp.gmail.com with ESMTPSA id t5sm917197ilp.15.2020.08.12.04.13.35<br/>        for <test@demistodev.com><br/>        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);<br/>        Wed, 12 Aug 2020 04:13:35 -0700 (PDT)<br/>Message-ID: <5f33cedf.1c69fb81.e5562.38a5@mx.google.com><br/>From: test@demistodev.com<br/>X-Google-Original-From: koko@demisto.com<br/>Mime-Version: 1.0<br/>Date: Wed, 12 Aug 2020 11:13:35 +0000<br/>To: test@demistodev.com<br/>Subject: foooSubject<br/>Content-Type: text/plain; charset=UTF-8<br/>Content-Transfer-Encoding: quoted-printable | foooSubject | foooBody | test@demistodev.com |

### 3. mail-listener-get-email-as-eml
***
Fetches an email by message ID and download it's eml file


#### Base Command

`mail-listener-get-email-as-eml`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message-id | Message ID as fetched in 'mail-listener-list-emails' command | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!mail-listener-get-email-as-eml message-id=65445```

#### Context Example
```
{
    "File": {
        "EntryID": "1276@97a9b81e-928e-4c93-80bc-2729ca35cb1c",
        "Extension": "eml",
        "Info": "message/rfc822",
        "MD5": "4411c30b672dd8fee62d332c970e07bb",
        "Name": "original-email-file.eml",
        "SHA1": "1713dc8369f89bc1c3f665eeffc3a2b7de4c2f7b",
        "SHA256": "d6e145175a9abd9b51f3af71a6a4971ec922888addd2f96cdd484c52ff6fcb43",
        "SHA512": "0b4af9cd6899e15fcbb3fbdde4592ccd44f681769c554afd437214984cdc254923167563e6d7b763bb96cc3de40f684e9852ec2617ba90efdf6d9342564dddfd",
        "SSDeep": "12:k11sxpBGVTdLS4NuFWsRqzR2kAmM4YTxXX6oFTrYQWptR9zHxXARx2mi7xoQFQ0f:SydGVTdLS4cJGRzCT96odcpHR2x2milL",
        "Size": 680,
        "Type": "SMTP mail text, ASCII text, with CRLF line terminators"
    }
}
```

## Additional Information
In the first fetch iteration, it might take a few minutes for email messages to be ingested due to filter limitations on the IMAP client.