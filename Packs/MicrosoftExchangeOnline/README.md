Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft Office Outlook.

## What does this pack do?

- Monitor a specific email account and create incidents from incoming emails to the defined folder.
- Search for an email message across mailboxes and folders.
- Get email attachment information.
- Delete email items from a mailbox.
- Manage Tenant Allow/Block Lists.

## Integrations
The [EWS O365 integration](https://xsoar.pan.dev/docs/reference/integrations/ewso365) enables you to:
- Retrieve information on emails and activities in a target mailbox.
- Perform operations on the target mailbox such as deleting emails and attachments or moving emails from folder to folder.

The [O365 - EWS - Extension integration](https://xsoar.pan.dev/docs/reference/integrations/ews-extension) enables you to manage and interact with Microsoft O365 - Exchange Online from within XSOAR
- Get junk rules for a specified mailbox.
- Set junk rules for a specified mailbox.
- Set junk rules for all managed accounts.
- Search message data.

The [EWS Extension Online Powershell v2 integration](https://xsoar.pan.dev/docs/reference/integrations/ews-extension-online-powershell-v2) enables you to retrieve information about mailboxes and users in your organization.
- Display client access settings that are configured on mailboxes.
- Display mailbox objects and attributes, populate property pages, or supply mailbox information to other tasks.
- Retrieve permissions on a mailbox.
- Display information about SendAs permissions that are configured for users.
- Display existing recipient objects in your organization such as mailboxes, mail users, mail contacts, and distribution groups.
- Add, remove, list, and count entries in Tenant Allow/Block Lists.

The [Security And Compliance V2](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2) enables you to:
- manage the security of all your organization's emails, SharePoint sites, OneDrives, etc.
- can perform actions (preview and delete) on emails.

## EWS Permissions
To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions. 

| Permission |Use Case |
| ----- | ----|
| Delegate | One-to-one relationship between users. |
| Impersonation	| A single account needs to access multiple mailboxes. |
| eDiscovery | Search the Exchange server. |	
| Compliance Search | Perform searches across mailboxes and get an estimate of the results. |