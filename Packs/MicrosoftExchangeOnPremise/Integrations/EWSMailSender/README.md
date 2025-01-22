Exchange Web Services and Office 365 Email sender.
## Configure EWS Mail Sender in Cortex

    
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ewsServer | Exchange URL or Server IP address | True |
| credentials | Authentication: Email address \(for Office 365\) or DOMAIN\\USERNAME \(e.g. XSOAR.INT\\admin\) | True |
| defaultServerVersion | Server Version \(2007, 2010, 2010_SP2, 2013, or 2016\) | True |
| authType | Authentication Type \(NTLM, Basic, or Digest\). For Office 365 use Basic. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| impersonation | Has impersonation rights | False |
| mailbox | Sender Mailbox | False |
| Single engine | If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc.  that prevent the Cortex XSOAR server from accessing the remote networks. For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a><br>| False |


## Top Use-cases:
- Send notifications to external users.
- Send an email asking for a response to be returned as part of a playbook. See [Receiving an email reply](https://xsoar.pan.dev/docs/reference/scripts/email-ask-user)

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### send-mail
***
Sends an email using EWS.

#### Base Command

`send-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A CSV list of email addresses for the 'to' field. | Required | 
| cc | A CSV list of email addresses for the 'cc' field. | Optional | 
| bcc | A CSV list of email addresses for the 'bcc' field. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| replyTo | The email address specified in the 'reply to' field. | Optional | 
| body | The contents (body) of the email to send. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| attachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| attachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 
| from_address | The email address from which to reply. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!send-mail body="hello this is a test" subject=Hi to=avishai@demistodev.onmicrosoft.com```

#### Human Readable Output

>### Sent email
>|attachments|from|subject|to|
>|---|---|---|---|
>|  | avishai@demistodev.onmicrosoft.com | Hi | avishai@demistodev.onmicrosoft.com |


### reply-mail
***
Replies to an email using EWS.


#### Base Command

`reply-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inReplyTo | ID of the item to reply to. | Required | 
| to | A CSV list of email addresses for the 'to' field. | Required | 
| cc | A CSV list of email addresses for the 'cc' field. | Optional | 
| bcc | A CSV list of email addresses for the 'bcc' field. | Optional | 
| subject | Subject for the email to be sent. | Optional | 
| body | The contents (body) of the email to send. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| attachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| attachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!reply-mail item_id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq/zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq/zTrN6vWSzK4OWAAPYQGFeAAA= body=hello subject=hi to="avishai@demistodev.onmicrosoft.com"```

#### Human Readable Output

>### Sent email
>|attachments|from|subject|to|
>|---|---|---|---|
>|  | avishai@demistodev.onmicrosoft.com | hi | avishai@demistodev.onmicrosoft.com |
