CimTrak XSOAR integration.

## Configure CimTrak on Cortex XSOAR
- Fill in the URL to your App Server
- Create an API Key in the CimTrak Management Console and populate in XSOAR
- Fill in the Repository IP relative to the App Server (IE: If App Server is running on the same machine as the Repository you can use 127.0.0.1)
- Fill in Repository Port
- Once configured all unreconciled items from CimTrak will be brought into XSOAR.


##Commands

### get-events

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Start | number | Starting number of record to get | 
| End | number | Ending number of record to get | 
| Filter | json | Filter array to limit results IE: [{name: id, operator:>, value:5}] | 
| Sorts | json | Sort array to sort data IE: [{field: id, descending: False}] | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Event.id | number | Event ID | 
| CimTrak.Event.leventid | number | Event ID | 
| CimTrak.Event.lagentid | number | Agent ID | 
| CimTrak.Event.lobjectid | number | Object ID | 
| CimTrak.Event.lobjectdetailid | number | Object Detail ID | 
| CimTrak.Event.lobjectdetailidint | number | Object Detail Intrusion ID | 
| CimTrak.Event.lmessagelevel | number | Message Level | 
| CimTrak.Event.szuser | string | User | 
| CimTrak.Event.szfileuser | string | File User | 
| CimTrak.Event.szmessageid | string | Message ID | 
| CimTrak.Event.szmessage | string | Message | 
| CimTrak.Event.szfile | string | File | 
| CimTrak.Event.szcorrectionid | string | Correction ID | 
| CimTrak.Event.szcorrection | string | Correction | 
| CimTrak.Event.lcategory | number | Category | 
| CimTrak.Event.lemailsent | number | Email Sent | 
| CimTrak.Event.lstoragestatus | number | Storage Status | 
| CimTrak.Event.dtmdatetime1 | string | Date Time 1 | 
| CimTrak.Event.dtmdatetime2 | string | Date Time 2 | 
| CimTrak.Event.szchecksum | string | Checksum | 
| CimTrak.Event.status | string | Status | 
| CimTrak.Event.lprocessid | number | Process ID | 
| CimTrak.Event.lthreadid | number | Thread ID | 
| CimTrak.Event.szprocess | string | Process | 
| CimTrak.Event.szforensicdata | string | Forensic Data | 
| CimTrak.Event.dtmdeleted | string | Deteled Date Time | 
| CimTrak.Event.ltickcount | number | Tick Count | 
| CimTrak.Event.lsubtype | number | SubType | 
| CimTrak.Event.ticketNumber | string | Ticket Number | 
| CimTrak.Event.ldeleteobjectdetailid | number | Deleted Object Detail ID | 
| CimTrak.Event.bfoundinblacklist | number | Found In Blacklist | 
| CimTrak.Event.filecontenthash | string | File Content Hash | 
| CimTrak.Event.lobjectsettingid | number | Object Setting ID | 
| CimTrak.Event.reconciled | number | Reconciled | 
| CimTrak.Event.isauthcopy | number | Is Auth Copy | 
| CimTrak.Event.externalticketnumber | string | External Ticket Number | 
| CimTrak.Event.lparentid | number | Parent ID | 
| CimTrak.Event.szobjectpath | string | Object Path | 
| CimTrak.Event.dfilesize | number | File Size | 
### file-analysis-by-hash

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Hash | string | Hash of file to check | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.FileAnalysis.analysisEngine | string | Analysis Engine used | 
| CimTrak.FileAnalysis.analysisSuccess | boolean | Analysis Success Flag | 
| CimTrak.FileAnalysis.analysisResults | string | Agent ID | 
### file-analysis-by-objectdetail-id

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectDetailId | number | Object Detail Id of file to check | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.FileAnalysis.analysisEngine | string | Analysis Engine used | 
| CimTrak.FileAnalysis.analysisSuccess | boolean | Analysis Success Flag | 
| CimTrak.FileAnalysis.analysisResults | string | Agent ID | 
### check-file-against-trusted-file-registry-by-hash

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Hashes | list | Array of hashes of file to check IE:B47DD22BFE1E5554448262D0C8E6555496B1AA6685AF50F49A12AD82D1109769,D2B3289F12102506717E2A1FB883F62E7DCE09FBDA48BE192905669684E68FD0 | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.TrustedFileRegistry.hash | string | Hash found in registry | 
### promote-authoritative-baseline-files

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectDetaildIds | list | Array of object detail IDs of file to check IE:42,43 | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.AuthoritizeBaseline.objectDetailId | number | objectDetailId of file | 
| CimTrak.AuthoritizeBaseline.status | string | Status | 
| CimTrak.AuthoritizeBaseline.errorCode | string | Error Code | 
| CimTrak.AuthoritizeBaseline.errorDescription | string | Status | 
### demote-authoritative-baseline-files

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectDetaildIds | list | Array of object detail IDs of file to check IE:42,43 | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.AuthoritizeBaseline.objectDetailId | number | objectDetailId of file | 
| CimTrak.AuthoritizeBaseline.status | string | Status | 
### update-task-disposition

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| taskId | number | Task ID | 
| Disposition | string | Disposition of task | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.TaskDisposition.taskId | number | Task Id | 
| CimTrak.TaskDisposition.status | string | Status | 
### get-tickets

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Ticket.id | number | Ticket Id | 
| CimTrak.Ticket.ticketNumber | string | Ticket number | 
| CimTrak.Ticket.sentiment | string | Ticket sentiment | 
| CimTrak.Ticket.sentimenttypeid | string | Ticket sentiment id | 
| CimTrak.Ticket.title | string | Ticket title | 
| CimTrak.Ticket.description | string | Ticket description | 
| CimTrak.Ticket.priority | number | Ticket priority | 
| CimTrak.Ticket.disposition | string | Ticket disposition | 
| CimTrak.Ticket.creationDate | string | Ticket creation date | 
| CimTrak.Ticket.createdByUser | string | Ticket created by user | 
| CimTrak.Ticket.modificationDate | string | Ticket modification date | 
| CimTrak.Ticket.modifiedByUser | string | Ticket modified by user | 
| CimTrak.Ticket.requiresAcknowledgement | boolean | Ticket requires acknowledgement | 
| CimTrak.Ticket.requiresConfirmation | boolean | Ticket requires confirmation | 
| CimTrak.Ticket.requiresAssessment | boolean | Ticket requires assessment | 
| CimTrak.Ticket.startDate | string | Ticket start date | 
| CimTrak.Ticket.endDate | string | Ticket end date | 
| CimTrak.Ticket.autoPromote | boolean | Ticket auto promote | 
| CimTrak.Ticket.assignedToUserId | number | Ticket assigned yo UserId | 
| CimTrak.Ticket.assignedToUser | string | Ticket assigned to user | 
| CimTrak.Ticket.assignedToGroupId | number | Ticket assigned to GroupId | 
| CimTrak.Ticket.assignedToGroup | string | Ticket assigned to group | 
| CimTrak.Ticket.externalTicketNumber | string | Ticket external ticket number | 
| CimTrak.Ticket.externalTicketType | string | Ticket external ticket type | 
| CimTrak.Ticket.tasks | string | Ticket tasks | 
| CimTrak.Ticket.comments | string | Ticket comments | 
| CimTrak.Ticket.events | string | Ticket events | 
### get-ticket-tasks

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.TicketTask.id | number | Ticket Task Id | 
| CimTrak.TicketTask.ticketId | number | Ticket Id | 
| CimTrak.TicketTask.agentObjectId | number | Agent Object id | 
| CimTrak.TicketTask.startDate | string | Ticket start date | 
| CimTrak.TicketTask.endDate | string | Ticket end date | 
| CimTrak.TicketTask.disposition | string | Ticket disposition | 
| CimTrak.TicketTask.creationDate | string | Ticket creation date | 
| CimTrak.TicketTask.createdByUserId | number | Ticket created by user Id | 
| CimTrak.TicketTask.modificationDate | string | Ticket modification date | 
| CimTrak.TicketTask.modifiedByUserId | number | Ticket modified by user Id | 
| CimTrak.TicketTask.assignedToUserId | number | Ticket assigned yo UserId | 
| CimTrak.TicketTask.assignedToGroupId | number | Ticket assigned to GroupId | 
| CimTrak.TicketTask.assigneeDisposition | string | Assignee Disposition | 
| CimTrak.TicketTask.ticketTitle | string | Ticket title | 
| CimTrak.TicketTask.description | string | Ticket description | 
| CimTrak.TicketTask.priority | number | Ticket priority | 
| CimTrak.TicketTask.ticketDisposition | string | Ticket disposition | 
| CimTrak.TicketTask.ticketCreationDate | string | Ticket creation date | 
| CimTrak.TicketTask.ticketCreatedByUserId | string | Ticket vreated by user Id | 
| CimTrak.TicketTask.ticketModificationDate | string | Ticket modification date | 
| CimTrak.TicketTask.requiresAcknowledgement | string | Ticket requires acknowlegment | 
| CimTrak.TicketTask.requiresConfirmation | string | Ticket requires confirmation | 
| CimTrak.TicketTask.requiresAssessment | string | Ticket requires assessment | 
| CimTrak.TicketTask.ticketNumber | string | Ticket number | 
| CimTrak.TicketTask.agentName | string | Agent name | 
| CimTrak.TicketTask.createdByUsername | string | Created By Username | 
| CimTrak.TicketTask.modifiedByUsername | string | Modified by username | 
| CimTrak.TicketTask.assigneeName | string | Assignee Name | 
### add-ticket

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | string | Title of ticket | 
| priority | number | Ticket priority | 
| description | string | Ticket description | 
| startDate | string | Ticket start date | 
| endDate | string | Ticket end date | 
| externalTicketNumber | string |  External ticket number | 
| externalTicketType | string | External ticket type | 
| autoPromote | boolean | Auto promote | 
| disposition | string | Ticket disposition | 
| requiresAcknowledgement | boolean | Requires acknowledgement | 
| requiresAssessment | boolean | Requires assessment | 
| requiresConfirmation | boolean | Requires confirmation | 
| assignedToUserId | number | Assigned to user Id | 
| assignedToUser | string | Assigned to user | 
| assignedToGroupId | number | Assigned to group Id | 
| assignedToGroup | string | Assigned to group | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Ticket.id | number | Ticket Id | 
| CimTrak.Ticket.ticketNumber | string | Ticket number | 
| CimTrak.Ticket.sentiment | string | Ticket sentiment | 
| CimTrak.Ticket.sentimenttypeid | string | Ticket sentiment id | 
| CimTrak.Ticket.title | string | Ticket title | 
| CimTrak.Ticket.description | string | Ticket description | 
| CimTrak.Ticket.priority | number | Ticket priority | 
| CimTrak.Ticket.disposition | string | Ticket disposition | 
| CimTrak.Ticket.creationDate | string | Ticket creation date | 
| CimTrak.Ticket.createdByUser | string | Ticket created by user | 
| CimTrak.Ticket.modificationDate | string | Ticket modification date | 
| CimTrak.Ticket.modifiedByUser | string | Ticket modified by user | 
| CimTrak.Ticket.requiresAcknowledgement | boolean | Ticket requires acknowledgement | 
| CimTrak.Ticket.requiresConfirmation | boolean | Ticket requires confirmation | 
| CimTrak.Ticket.requiresAssessment | boolean | Ticket requires assessment | 
| CimTrak.Ticket.startDate | string | Ticket start date | 
| CimTrak.Ticket.endDate | string | Ticket end date | 
| CimTrak.Ticket.autoPromote | boolean | Ticket auto promote | 
| CimTrak.Ticket.assignedToUserId | number | Ticket assigned yo UserId | 
| CimTrak.Ticket.assignedToUser | string | Ticket assigned to user | 
| CimTrak.Ticket.assignedToGroupId | number | Ticket assigned to GroupId | 
| CimTrak.Ticket.assignedToGroup | string | Ticket assigned to group | 
| CimTrak.Ticket.externalTicketNumber | string | Ticket external ticket number | 
| CimTrak.Ticket.externalTicketType | string | Ticket external ticket type | 
| CimTrak.Ticket.tasks | string | Ticket tasks | 
| CimTrak.Ticket.comments | string | Ticket comments | 
| CimTrak.Ticket.events | string | Ticket events | 
### update-ticket

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | number | Ticket Id | 
| title | string | Title of ticket | 
| priority | number | Ticket priority | 
| description | string | Ticket description | 
| startDate | string | Ticket start date | 
| endDate | string | Ticket end date | 
| externalTicketNumber | string |  External ticket number | 
| externalTicketType | string | External ticket type | 
| autoPromote | boolean | Auto promote | 
| disposition | string | Ticket disposition | 
| requiresAcknowledgement | boolean | Requires acknowledgement | 
| requiresAssessment | boolean | Requires assessment | 
| requiresConfirmation | boolean | Requires confirmation | 
| assignedToUserId | number | Assigned to user Id | 
| assignedToUser | string | Assigned to user | 
| assignedToGroupId | number | Assigned to group Id | 
| assignedToGroup | string | Assigned to group | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Ticket.id | number | Ticket Id | 
| CimTrak.Ticket.ticketNumber | string | Ticket number | 
| CimTrak.Ticket.sentiment | string | Ticket sentiment | 
| CimTrak.Ticket.sentimenttypeid | string | Ticket sentiment id | 
| CimTrak.Ticket.title | string | Ticket title | 
| CimTrak.Ticket.description | string | Ticket description | 
| CimTrak.Ticket.priority | number | Ticket priority | 
| CimTrak.Ticket.disposition | string | Ticket disposition | 
| CimTrak.Ticket.creationDate | string | Ticket creation date | 
| CimTrak.Ticket.createdByUser | string | Ticket created by user | 
| CimTrak.Ticket.modificationDate | string | Ticket modification date | 
| CimTrak.Ticket.modifiedByUser | string | Ticket modified by user | 
| CimTrak.Ticket.requiresAcknowledgement | boolean | Ticket requires acknowledgement | 
| CimTrak.Ticket.requiresConfirmation | boolean | Ticket requires confirmation | 
| CimTrak.Ticket.requiresAssessment | boolean | Ticket requires assessment | 
| CimTrak.Ticket.startDate | string | Ticket start date | 
| CimTrak.Ticket.endDate | string | Ticket end date | 
| CimTrak.Ticket.autoPromote | boolean | Ticket auto promote | 
| CimTrak.Ticket.assignedToUserId | number | Ticket assigned yo UserId | 
| CimTrak.Ticket.assignedToUser | string | Ticket assigned to user | 
| CimTrak.Ticket.assignedToGroupId | number | Ticket assigned to GroupId | 
| CimTrak.Ticket.assignedToGroup | string | Ticket assigned to group | 
| CimTrak.Ticket.externalTicketNumber | string | Ticket external ticket number | 
| CimTrak.Ticket.externalTicketType | string | Ticket external ticket type | 
| CimTrak.Ticket.tasks | string | Ticket tasks | 
| CimTrak.Ticket.comments | string | Ticket comments | 
| CimTrak.Ticket.events | string | Ticket events | 
### add-ticket-comment

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | number | Ticket Id | 
| comment | string | Comment for ticket | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### add-hash-allow-list

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | string | Hash | 
| filename | string | Filename for hash | 
| source | string | Source for hash | 
| sourceReference | string | SourceReference for hash | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.AllowList.status | string | Status of adding hash | 
| CimTrak.AllowList.errorCode | string | Error Code of adding hash | 
| CimTrak.AllowList.errorDescription | string | Error Description of adding hash | 
| CimTrak.AllowList.hash | string | Hash added | 
| CimTrak.AllowList.tagId | number | TagId of adding hash | 
### add-hash-deny-list

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | string | Hash | 
| filename | string | Filename for hash | 
| source | string | Source for hash | 
| sourceReference | string | SourceReference for hash | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.DenyList.status | string | Status of adding hash | 
| CimTrak.DenyList.errorCode | string | Error Code of adding hash | 
| CimTrak.DenyList.errorDescription | string | Error Description of adding hash | 
| CimTrak.DenyList.hash | string | Hash added | 
| CimTrak.DenyList.tagId | number | TagId of adding hash | 
### delete-hash-allow-list

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | string | Hash | 
| reason | string | Reason for deleting hash | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.AllowList.status | string | Status of deleting hash | 
| CimTrak.AllowList.hash | string | Hash deleted | 
| CimTrak.AllowList.tagId | number | TagId of deleting hash | 
### delete-hash-deny-list

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | string | Hash | 
| reason | string | Reason for deleting hash | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.DenyList.status | string | Status of deleting hash | 
| CimTrak.DenyList.hash | string | Hash deleted | 
| CimTrak.DenyList.tagId | number | TagId of deleting hash | 
### get-sub-generations

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.SubGenerations.caseSensitive | number | Case Sensitive | 
| CimTrak.SubGenerations.agentObjectId | number | Agent Object Id | 
| CimTrak.SubGenerations.subGenerationId | number | SubgenerationId | 
| CimTrak.SubGenerations.objectId | number | Object Id | 
| CimTrak.SubGenerations.generationId | number | Generation Id | 
| CimTrak.SubGenerations.subRevision | number | SubRevision | 
| CimTrak.SubGenerations.notes | string | Notes | 
| CimTrak.SubGenerations.creationDate | string | Creation Date | 
| CimTrak.SubGenerations.files | number | Files | 
| CimTrak.SubGenerations.directories | number | Directories | 
| CimTrak.SubGenerations.totalSize | number | Total Size | 
| CimTrak.SubGenerations.revision | number | Revision | 
| CimTrak.SubGenerations.userName | string | User Name | 
### deploy

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentObjectId | number | Agent Object Id | 
| subGenerationId | number | Sub Generation Id | 
| notes | string | Notes | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### get-object-group

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.ObjectGroup.agentIsFilesystem | boolean | Agent Is Filesystem | 
| CimTrak.ObjectGroup.cancel | boolean | Cancel | 
| CimTrak.ObjectGroup.connected | boolean | Connected | 
| CimTrak.ObjectGroup.logsByDays | boolean | Logs By Days | 
| CimTrak.ObjectGroup.requireNotes | boolean | Require Notes | 
| CimTrak.ObjectGroup.inService | string | In Service | 
| CimTrak.ObjectGroup.children | number | Children | 
| CimTrak.ObjectGroup.events | number | Events | 
| CimTrak.ObjectGroup.intrusions | number | Intrusions | 
| CimTrak.ObjectGroup.intrusionSize | number | Intrusion Size | 
| CimTrak.ObjectGroup.objectId | number | Object Id | 
| CimTrak.ObjectGroup.objectStatus | number | Object Status | 
| CimTrak.ObjectGroup.objectSubType | number | Object SubType | 
| CimTrak.ObjectGroup.objectType | number | Object Type | 
| CimTrak.ObjectGroup.parentId | number | Parent Id | 
| CimTrak.ObjectGroup.revisions | number | Revisions | 
| CimTrak.ObjectGroup.templateId | number | Template Id | 
| CimTrak.ObjectGroup.securityAdd | boolean | Security Add | 
| CimTrak.ObjectGroup.securityEdit | boolean | Security Edit | 
| CimTrak.ObjectGroup.securityLock | boolean | Security Lock | 
| CimTrak.ObjectGroup.securityReport | boolean | Security Report | 
| CimTrak.ObjectGroup.securityUnlock | boolean | Security Unlock | 
| CimTrak.ObjectGroup.securityView | boolean | Security View | 
| CimTrak.ObjectGroup.warnMinutes | number | Warn Minutes | 
| CimTrak.ObjectGroup.contact | string | Contact | 
| CimTrak.ObjectGroup.createDate | string | Create Date | 
| CimTrak.ObjectGroup.description | string | Description | 
| CimTrak.ObjectGroup.location | string | Location | 
| CimTrak.ObjectGroup.name | string | Name | 
| CimTrak.ObjectGroup.objectPath | string | Object Path | 
| CimTrak.ObjectGroup.url | string | URL | 
| CimTrak.ObjectGroup.agentObjectId | number | Agent Object Id | 
| CimTrak.ObjectGroup.objectsCustom | string | Objects Custom | 
| CimTrak.ObjectGroup.watchArray | string | Watch Array | 
| CimTrak.ObjectGroup.comparisonMethod | number | Comparison Method | 
### unlock

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### lock

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### get-object

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Object.agentIsFilesystem | boolean | Agent Is Filesystem | 
| CimTrak.Object.cancel | boolean | Cancel | 
| CimTrak.Object.connected | boolean | Connected | 
| CimTrak.Object.logsByDays | boolean | Logs By Days | 
| CimTrak.Object.requireNotes | boolean | Require Notes | 
| CimTrak.Object.inService | string | In Service | 
| CimTrak.Object.children | number | Children | 
| CimTrak.Object.events | number | Events | 
| CimTrak.Object.intrusions | number | Intrusions | 
| CimTrak.Object.intrusionSize | number | Intrusion Size | 
| CimTrak.Object.objectId | number | Object Id | 
| CimTrak.Object.objectStatus | number | Object Status | 
| CimTrak.Object.objectSubType | number | Object SubType | 
| CimTrak.Object.objectType | number | Object Type | 
| CimTrak.Object.parentId | number | Parent Id | 
| CimTrak.Object.revisions | number | Revisions | 
| CimTrak.Object.templateId | number | Template Id | 
| CimTrak.Object.securityAdd | boolean | Security Add | 
| CimTrak.Object.securityEdit | boolean | Security Edit | 
| CimTrak.Object.securityLock | boolean | Security Lock | 
| CimTrak.Object.securityReport | boolean | Security Report | 
| CimTrak.Object.securityUnlock | boolean | Security Unlock | 
| CimTrak.Object.securityView | boolean | Security View | 
| CimTrak.Object.warnMinutes | number | Warn Minutes | 
| CimTrak.Object.contact | string | Contact | 
| CimTrak.Object.createDate | string | Create Date | 
| CimTrak.Object.description | string | Description | 
| CimTrak.Object.location | string | Location | 
| CimTrak.Object.name | string | Name | 
| CimTrak.Object.objectPath | string | Object Path | 
| CimTrak.Object.url | string | URL | 
| CimTrak.Object.agentObjectId | number | Agent Object Id | 
### force-sync

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### view-file

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectDetailId | number | Object Detail Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Sync.contents | string | Contents | 
### run-report-by-name

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | string | Name | 
| objectId | number | Object Id | 
| ReportParameters | json | Parameters for report | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Sync.html | string | HTML Report | 
### deploy-by-date

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date | string | Date | 
| objectId | number | Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### get-current-compliance-items

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectId | number | Object ID to retrieve compliance items | 
| ComplianceScanId | number | Compliance Scan ID to retrieve compliance items | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.ComplianceItems.objectid | number | Object ID | 
| CimTrak.ComplianceItems.type | number | Type of item | 
| CimTrak.ComplianceItems.name | string | Name | 
| CimTrak.ComplianceItems.description | string | Description | 
| CimTrak.ComplianceItems.scanstarttime | string | Scan Start Time | 
| CimTrak.ComplianceItems.scanendtime | string | Scan End Time | 
| CimTrak.ComplianceItems.scanid | number | Scanid | 
| CimTrak.ComplianceItems.compliancemappingid | number | Compliance Mapping id | 
| CimTrak.ComplianceItems.id | number | id | 
### get-objects

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectType | number | Object Type to retrieve | 
| ObjectSubType | number | Object Sub Type to retrieve | 
| ParentId | number | Parent ID to retrieve | 
| ObjectId | number | Object ID to retrieve | 
| ObjectPathAndName | string | Object path and name to retrieve | 
| Recursive | boolean | Recursive | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Objects.repositoryDisplayName | string | Repository display name | 
| CimTrak.Objects.connected | boolean | Connected | 
| CimTrak.Objects.agentObjectId | number | Agent object Id | 
| CimTrak.Objects.description | string | Description | 
| CimTrak.Objects.name | string | Name | 
| CimTrak.Objects.objectPath | string | Object Path | 
| CimTrak.Objects.agentIsFilesystem | boolean | Agent is filesystem | 
| CimTrak.Objects.cancel | boolean | Cancel | 
| CimTrak.Objects.logsByDays | boolean | Logs by days | 
| CimTrak.Objects.requireNotes | boolean | Require notes | 
| CimTrak.Objects.inService | string | In service | 
| CimTrak.Objects.events | number | Events | 
| CimTrak.Objects.intrusions | number | Intrusions | 
| CimTrak.Objects.intrusionSize | number | Intrusion size | 
| CimTrak.Objects.objectId | number | Object ID | 
| CimTrak.Objects.objectStatus | number | Object Status | 
| CimTrak.Objects.objectSubType | number | object subtype | 
| CimTrak.Objects.objectType | number | object type | 
| CimTrak.Objects.parentId | number | Parent ID | 
| CimTrak.Objects.revisions | number | Revisions | 
| CimTrak.Objects.templateId | number | Template Id | 
| CimTrak.Objects.securityAdd | boolean | Security add | 
| CimTrak.Objects.securityEdit | boolean | Security edit | 
| CimTrak.Objects.securityLock | boolean | Security lock | 
| CimTrak.Objects.securityReport | boolean | Security report | 
| CimTrak.Objects.securityUnlock | boolean | Security unlock | 
| CimTrak.Objects.securityView | boolean | Security view | 
| CimTrak.Objects.warnMinutes | number | Warn minutes | 
| CimTrak.Objects.contact | string | Contact | 
| CimTrak.Objects.createDate | string | Create date | 
| CimTrak.Objects.location | string | Location | 
| CimTrak.Objects.url | string | Url | 
| CimTrak.Objects.parentName | string | Parent name | 
| CimTrak.Objects.children | number | Children | 
| CimTrak.Objects.agentVersion | string | Agent version | 
| CimTrak.Objects.agentBuild | number | Agent build | 
| CimTrak.Objects.agentOsVersion | string | Agent Os version | 
| CimTrak.Objects.agentIp | string | agent Ip | 
| CimTrak.Objects.agentName | string | Agent name | 
| CimTrak.Objects.agentInstalled | boolean | Agent installed | 
### get-agent-info

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectId | number | Object ID to retrieve compliance items | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.AgentInfo.objectData | string | Object data | 
| CimTrak.AgentInfo.objectsCustom | string | Object custom | 
| CimTrak.AgentInfo.agentData | string | Agent data | 
| CimTrak.AgentInfo.state | string | State | 
### get-compliance-archive-details

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectId | number | Object ID to retrieve compliance items | 
| ComplianceScanId | number | Compliance Scan ID to retrieve compliance items | 
| Filter | json | Filter array to limit results IE: [{name: id, operator:>, value:5}] | 
| Start | number | Starting number of record to get | 
| End | number | Ending number of record to get | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Compliance.testdate | string | Test Date | 
| CimTrak.Compliance.datatype | string | Data Type | 
| CimTrak.Compliance.scanid | number | Scan id | 
| CimTrak.Compliance.ipaddress | string | IP address | 
| CimTrak.Compliance.lobjectid | number | Object Id | 
| CimTrak.Compliance.alternatesystemid | string | Alternate System ID | 
| CimTrak.Compliance.agentuuid | string | Agent uuid | 
| CimTrak.Compliance.agentname | string | Agent name | 
| CimTrak.Compliance.objectpath | string | Object path | 
| CimTrak.Compliance.benchmark | string | Benchmark | 
| CimTrak.Compliance.profile | string | Profile | 
| CimTrak.Compliance.test | string | Test | 
| CimTrak.Compliance.pass | boolean | Pass | 
| CimTrak.Compliance.iswaived | boolean | Is waived | 
| CimTrak.Compliance.adjustedscore | number | Adjusted score | 
| CimTrak.Compliance.possiblescore | number | Possible score | 
| CimTrak.Compliance.rawscore | number | Raws core | 
| CimTrak.Compliance.weight | number | Weight | 
| CimTrak.Compliance.testran | boolean | Test ran | 
| CimTrak.Compliance.remediation | string | Remediation | 
| CimTrak.Compliance.severity | string | Severity | 
| CimTrak.Compliance.version | string | Version | 
| CimTrak.Compliance.rationale | string | Rationale | 
| CimTrak.Compliance.description | string | Description | 
| CimTrak.Compliance.assessment | string | Assessment | 
| CimTrak.Compliance.disposition | string | Disposition | 
| CimTrak.Compliance.conjunction | string | Conjunction | 
| CimTrak.Compliance.negatatevalue | boolean | Negatate value | 
| CimTrak.Compliance.comment | string | Comment | 
| CimTrak.Compliance.controlversion | string | Controlversion | 
| CimTrak.Compliance.controlnumber | string | Control number | 
| CimTrak.Compliance.osversion | string | OS version | 
| CimTrak.Compliance.personality | string | Personality | 
| CimTrak.Compliance.objectid | number | Object id | 
| CimTrak.Compliance.userId | number | User id | 
| CimTrak.Compliance.block | boolean | Lock | 
| CimTrak.Compliance.bunlock | boolean | Unlock | 
| CimTrak.Compliance.bview | boolean | View | 
| CimTrak.Compliance.bedit | boolean | Edit | 
| CimTrak.Compliance.badd | boolean | Add | 
| CimTrak.Compliance.breports | boolean | Reports | 
| CimTrak.Compliance.blogon | boolean | Logon | 
| CimTrak.Compliance.isadmin | boolean | Is admin | 
### get-compliance-archive-summary

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectId | number | Object ID to retrieve compliance items | 
| ComplianceScanId | number | Compliance Scan ID to retrieve compliance items | 
| Filter | json | Filter array to limit results IE: [{name: id, operator:>, value:5}] | 
| Start | number | Starting number of record to get | 
| End | number | Ending number of record to get | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Compliance.testdate | string | Test Date | 
| CimTrak.Compliance.scanid | number | Scan id | 
| CimTrak.Compliance.ipaddress | string | IP address | 
| CimTrak.Compliance.datatype | string | Data Type | 
| CimTrak.Compliance.alternatesystemid | string | Alternate System ID | 
| CimTrak.Compliance.agentuuid | string | Agent uuid | 
| CimTrak.Compliance.agentname | string | Agent name | 
| CimTrak.Compliance.objectpath | string | Object path | 
| CimTrak.Compliance.lobjectid | number | Object Id | 
| CimTrak.Compliance.benchmark | string | Benchmark | 
| CimTrak.Compliance.profile | string | Profile | 
| CimTrak.Compliance.totalfailcount | number | Total fail count | 
| CimTrak.Compliance.totalpasscount | number | Total pass count | 
| CimTrak.Compliance.totaltestsskipped | number | Total tests skipped | 
| CimTrak.Compliance.totalwaivecount | number | Total waive count | 
| CimTrak.Compliance.pass | boolean | Pass | 
| CimTrak.Compliance.totaltestsran | number | Total tests ran | 
| CimTrak.Compliance.osversion | string | OS version | 
| CimTrak.Compliance.personality | string | Personality | 
| CimTrak.Compliance.userId | number | User id | 
| CimTrak.Compliance.objectid | number | Object id | 
| CimTrak.Compliance.block | boolean | Lock | 
| CimTrak.Compliance.bunlock | boolean | Unlock | 
| CimTrak.Compliance.bview | boolean | View | 
| CimTrak.Compliance.bedit | boolean | Edit | 
| CimTrak.Compliance.badd | boolean | Add | 
| CimTrak.Compliance.breports | boolean | Reports | 
| CimTrak.Compliance.blogon | boolean | Logon | 
### compliance-scan-children

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectParentId | number | Parent Object Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### compliance-scan-with-summary

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectId | number | Object Id | 
| retryCount | number | Number of times to retry to check if scan has completed | 
| retrySeconds | number | Number of seconds to wait before retry to check if scan completed | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Compliance.testdate | string | Test Date | 
| CimTrak.Compliance.scanid | number | Scan id | 
| CimTrak.Compliance.ipaddress | string | IP address | 
| CimTrak.Compliance.datatype | string | Data Type | 
| CimTrak.Compliance.alternatesystemid | string | Alternate System ID | 
| CimTrak.Compliance.agentuuid | string | Agent uuid | 
| CimTrak.Compliance.agentname | string | Agent name | 
| CimTrak.Compliance.objectpath | string | Object path | 
| CimTrak.Compliance.lobjectid | number | Object Id | 
| CimTrak.Compliance.benchmark | string | Benchmark | 
| CimTrak.Compliance.profile | string | Profile | 
| CimTrak.Compliance.totalfailcount | number | Total fail count | 
| CimTrak.Compliance.totalpasscount | number | Total pass count | 
| CimTrak.Compliance.totaltestsskipped | number | Total tests skipped | 
| CimTrak.Compliance.totalwaivecount | number | Total waive count | 
| CimTrak.Compliance.pass | boolean | Pass | 
| CimTrak.Compliance.totaltestsran | number | Total tests ran | 
| CimTrak.Compliance.osversion | string | OS version | 
| CimTrak.Compliance.personality | string | Personality | 
| CimTrak.Compliance.userId | number | User id | 
| CimTrak.Compliance.objectid | number | Object id | 
| CimTrak.Compliance.block | boolean | Lock | 
| CimTrak.Compliance.bunlock | boolean | Unlock | 
| CimTrak.Compliance.bview | boolean | View | 
| CimTrak.Compliance.bedit | boolean | Edit | 
| CimTrak.Compliance.badd | boolean | Add | 
| CimTrak.Compliance.breports | boolean | Reports | 
| CimTrak.Compliance.blogon | boolean | Logon | 
### get-agent-object-id-by-alternate-system-id

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alternateSystemId | string | Alternate system Id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Object.agentObjectId | number | Object Id of agent | 
### get-agent-object-by-name

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentName | string | Agent name | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Object.agentIsFilesystem | boolean | Agent Is Filesystem | 
| CimTrak.Object.cancel | boolean | Cancel | 
| CimTrak.Object.connected | boolean | Connected | 
| CimTrak.Object.logsByDays | boolean | Logs By Days | 
| CimTrak.Object.requireNotes | boolean | Require Notes | 
| CimTrak.Object.inService | string | In Service | 
| CimTrak.Object.children | number | Children | 
| CimTrak.Object.events | number | Events | 
| CimTrak.Object.intrusions | number | Intrusions | 
| CimTrak.Object.intrusionSize | number | Intrusion Size | 
| CimTrak.Object.objectId | number | Object Id | 
| CimTrak.Object.objectStatus | number | Object Status | 
| CimTrak.Object.objectSubType | number | Object SubType | 
| CimTrak.Object.objectType | number | Object Type | 
| CimTrak.Object.parentId | number | Parent Id | 
| CimTrak.Object.revisions | number | Revisions | 
| CimTrak.Object.templateId | number | Template Id | 
| CimTrak.Object.securityAdd | boolean | Security Add | 
| CimTrak.Object.securityEdit | boolean | Security Edit | 
| CimTrak.Object.securityLock | boolean | Security Lock | 
| CimTrak.Object.securityReport | boolean | Security Report | 
| CimTrak.Object.securityUnlock | boolean | Security Unlock | 
| CimTrak.Object.securityView | boolean | Security View | 
| CimTrak.Object.warnMinutes | number | Warn Minutes | 
| CimTrak.Object.contact | string | Contact | 
| CimTrak.Object.createDate | string | Create Date | 
| CimTrak.Object.description | string | Description | 
| CimTrak.Object.location | string | Location | 
| CimTrak.Object.name | string | Name | 
| CimTrak.Object.objectPath | string | Object Path | 
| CimTrak.Object.url | string | URL | 
| CimTrak.Object.agentObjectId | number | Agent Object Id | 
### get-agent-object-by-alternate-id

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alternateSystemId | string | Agent alternate id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Object.agentIsFilesystem | boolean | Agent Is Filesystem | 
| CimTrak.Object.cancel | boolean | Cancel | 
| CimTrak.Object.connected | boolean | Connected | 
| CimTrak.Object.logsByDays | boolean | Logs By Days | 
| CimTrak.Object.requireNotes | boolean | Require Notes | 
| CimTrak.Object.inService | string | In Service | 
| CimTrak.Object.children | number | Children | 
| CimTrak.Object.events | number | Events | 
| CimTrak.Object.intrusions | number | Intrusions | 
| CimTrak.Object.intrusionSize | number | Intrusion Size | 
| CimTrak.Object.objectId | number | Object Id | 
| CimTrak.Object.objectStatus | number | Object Status | 
| CimTrak.Object.objectSubType | number | Object SubType | 
| CimTrak.Object.objectType | number | Object Type | 
| CimTrak.Object.parentId | number | Parent Id | 
| CimTrak.Object.revisions | number | Revisions | 
| CimTrak.Object.templateId | number | Template Id | 
| CimTrak.Object.securityAdd | boolean | Security Add | 
| CimTrak.Object.securityEdit | boolean | Security Edit | 
| CimTrak.Object.securityLock | boolean | Security Lock | 
| CimTrak.Object.securityReport | boolean | Security Report | 
| CimTrak.Object.securityUnlock | boolean | Security Unlock | 
| CimTrak.Object.securityView | boolean | Security View | 
| CimTrak.Object.warnMinutes | number | Warn Minutes | 
| CimTrak.Object.contact | string | Contact | 
| CimTrak.Object.createDate | string | Create Date | 
| CimTrak.Object.description | string | Description | 
| CimTrak.Object.location | string | Location | 
| CimTrak.Object.name | string | Name | 
| CimTrak.Object.objectPath | string | Object Path | 
| CimTrak.Object.url | string | URL | 
| CimTrak.Object.agentObjectId | number | Agent Object Id | 
### get-agent-object-by-ip

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | string | Agent alternate id | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CimTrak.Object.agentIsFilesystem | boolean | Agent Is Filesystem | 
| CimTrak.Object.cancel | boolean | Cancel | 
| CimTrak.Object.connected | boolean | Connected | 
| CimTrak.Object.logsByDays | boolean | Logs By Days | 
| CimTrak.Object.requireNotes | boolean | Require Notes | 
| CimTrak.Object.inService | string | In Service | 
| CimTrak.Object.children | number | Children | 
| CimTrak.Object.events | number | Events | 
| CimTrak.Object.intrusions | number | Intrusions | 
| CimTrak.Object.intrusionSize | number | Intrusion Size | 
| CimTrak.Object.objectId | number | Object Id | 
| CimTrak.Object.objectStatus | number | Object Status | 
| CimTrak.Object.objectSubType | number | Object SubType | 
| CimTrak.Object.objectType | number | Object Type | 
| CimTrak.Object.parentId | number | Parent Id | 
| CimTrak.Object.revisions | number | Revisions | 
| CimTrak.Object.templateId | number | Template Id | 
| CimTrak.Object.securityAdd | boolean | Security Add | 
| CimTrak.Object.securityEdit | boolean | Security Edit | 
| CimTrak.Object.securityLock | boolean | Security Lock | 
| CimTrak.Object.securityReport | boolean | Security Report | 
| CimTrak.Object.securityUnlock | boolean | Security Unlock | 
| CimTrak.Object.securityView | boolean | Security View | 
| CimTrak.Object.warnMinutes | number | Warn Minutes | 
| CimTrak.Object.contact | string | Contact | 
| CimTrak.Object.createDate | string | Create Date | 
| CimTrak.Object.description | string | Description | 
| CimTrak.Object.location | string | Location | 
| CimTrak.Object.name | string | Name | 
| CimTrak.Object.objectPath | string | Object Path | 
| CimTrak.Object.url | string | URL | 
| CimTrak.Object.agentObjectId | number | Agent Object Id | 
