Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft Office Outlook.

## What does this pack do?

- Monitor a specific email account and create incidents from incoming emails to the defined folder.
- Search for an email message across mailboxes and folders.
- Get email attachment information.
- Delete email items from a mailbox.

The [EWS v2 integration](https://xsoar.pan.dev/docs/reference/integrations/ews-v2) enables you to:
- Run compliance search commands as part of Office 365 to search for an email message across mailboxes and folders.
- Retrieve information on emails and activities in a target mailbox.
- Perform operations on the target mailbox such as deleting emails and attachments or moving emails from folder to folder. 

## EWS Permissions
To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions. 

| Permission |Use Case |
| ----- | ----|
| Delegate | One-to-one relationship between users. |
| Impersonation	| A single account needs to access multiple mailboxes. |
| eDiscovery | Search the Exchange server. |	
| Compliance Search | Perform searches across mailboxes and get an estimate of the results. |