CRM Services
This integration was integrated and tested with version xx of SalesforceV2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-salesforce-v2).

## Configure Salesforce V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Instance URL |  | True |
    | Credentials |  | True |
    | Password |  | True |
    | Consumer Key |  | True |
    | Consumer Secret |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch type: cases/comments | Only fetch comments when using the SalesforceAskUser automation. | False |
    | Define a query to determine which objects to fetch. | E.g.: OwnerId='0056s000000wGoWAAX' | False |
    | Fields to Fetch (only for cases/comments) | Additional fields to fetch | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First Fetch Time | The First Fetch Time, e.g., 1 hour, 3 days | False |
    | Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Salesforce to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to ServiceNow\), or Incoming and Outgoing \(from/to Cortex XSOAR and Salesforce\). | False |
    | Comment Entry Tag | Choose the tag to add to an entry to mirror it as a comment in Salesforce. | False |
    | Close Mirrored XSOAR Incident | When selected, closing the Salesforce ticket is mirrored in Cortex XSOAR. | False |
    | Close Mirrored Salesforce case | When selected, closing the Cortex XSOAR incident is mirrored in Salesforce. | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### salesforce-search
***
Search records that contain values with the defined pattern.


#### Base Command

`salesforce-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern | The string or number to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The ID of the case object. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | The origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 
| SalesForce.Contact.ID | string | ID of the contact. | 
| SalesForce.Contact.Name | string | The name of the contact. | 
| SalesForce.Contact.Account | string | The account associated with the Contact information. | 
| SalesForce.Contact.Title | string | The title of the contact. | 
| SalesForce.Contact.Phone | string | The phone number of the contact. | 
| SalesForce.Contact.MobilePhone | string | The mobile number of the contact. | 
| SalesForce.Contact.Email | string | The email address of the contact. | 
| SalesForce.Contact.Owner | string | The owner of the contact. | 
| SalesForce.Lead.ID | string | The lead ID. | 
| SalesForce.Lead.Name | string | The lead name. | 
| SalesForce.Lead.Title | string | The title of the lead. | 
| SalesForce.Lead.Company | string | The lead company. | 
| SalesForce.Lead.Phone | string | The lead phone number. | 
| SalesForce.Lead.Mobile | string | The lead mobile number. | 
| SalesForce.Lead.Email | string | The lead email address. | 
| SalesForce.Lead.Owner | string | The lead owner. | 
| SalesForce.Lead.Status | string | The lead status. Can be: "New", "Nurturing", "Working", "Qualified", or "Unqualified". | 
| SalesForce.Task.ID | string | The ID of the task. | 
| SalesForce.Task.Subject | string | The subject of the task. | 
| SalesForce.Task.Lead | string | The leader of the task. | 
| SalesForce.Task.RelatedTo | string | The relevant account. | 
| SalesForce.Task.DueDate | date | The due date of the task. | 
| SalesForce.User.ID | string | The ID of the user. | 
| SalesForce.User.Name | string | The name of the user. | 
| SalesForce.User.Title | string | The title of the user. | 
| SalesForce.User.Phone | string | The phone number of the user. | 
| SalesForce.User.Email | string | The email address of the user. | 
| SalesForce.Case.IsEscalated | boolean | Whether the case is escalated. | 
| SalesForce.Case.SuppliedPhone | string | Case supplied phone number. | 
| SalesForce.Case.SuppliedCompany | string | Case supplied company. | 
| SalesForce.Case.ContactEmail | string | Case contact email address. | 
| SalesForce.Case.ContactId | string | Case contact ID. | 
| SalesForce.Case.AccountId | string | Case account ID. | 

### salesforce-query
***
Queries Salesforce in SOQL format.


#### Base Command

`salesforce-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query in SOQL format: "SELECT name from Account". | Required | 


#### Context Output

There is no context output for this command.
### salesforce-get-object
***
Returns an object by its path.


#### Base Command

`salesforce-get-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The object path. For example, "Case/5000Y000001EjzRQAS" for Object "Case" with ID "5000Y000001EjzRQAS". | Optional | 
| oid | Object ID (in case no path is given). For example, 5000Y000001EjzRQAS. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | Origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 
| SalesForce.Contact.ID | string | The ID of the contact. | 
| SalesForce.Contact.Name | string | The name of the contact. | 
| SalesForce.Contact.Account | string | The account associated with the contact information. | 
| SalesForce.Contact.Title | string | The title of the contact. | 
| SalesForce.Contact.Phone | string | The phone number of the contact. | 
| SalesForce.Contact.MobilePhone | string | The mobile number of the contact. | 
| SalesForce.Contact.Email | string | The email address of the contact. | 
| SalesForce.Contact.Owner | string | The owner of the contact. | 
| SalesForce.Lead.ID | string | The lead ID. | 
| SalesForce.Lead.Name | string | The lead name. | 
| SalesForce.Lead.Title | string | The title of the lead. | 
| SalesForce.Lead.Company | string | The lead company. | 
| SalesForce.Lead.Phone | string | The lead phone number. | 
| SalesForce.Lead.Mobile | string | The lead mobile number. | 
| SalesForce.Lead.Email | string | The lead email address. | 
| SalesForce.Lead.Owner | string | The lead owner. | 
| SalesForce.Lead.Status | string | The lead status. Can be: "New", "Nurturing", "Working", "Qualified", or "Unqualified". | 
| SalesForce.Task.ID | string | The ID of the task. | 
| SalesForce.Task.Subject | string | The subject of the task. | 
| SalesForce.Task.Lead | string | The leader of the task. | 
| SalesForce.Task.RelatedTo | string | The relevant account of the task. | 
| SalesForce.Task.DueDate | date | The due date of the task. | 
| SalesForce.User.ID | string | The ID of the user. | 
| SalesForce.User.Name | string | The name of the user. | 
| SalesForce.User.Title | string | The title of the user. | 
| SalesForce.User.Phone | string | The phone number of the user. | 
| SalesForce.User.Email | string | The email address of the user. | 

### salesforce-update-object
***
Updates object fields.


#### Base Command

`salesforce-update-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The object path. For example, "Case/5000Y000001EjzRQAS" for Object "Case" with ID "5000Y000001EjzRQAS". | Required | 
| json | The JSON file with fields and values of the object to be updated. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure time of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | The origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 
| SalesForce.Contact.ID | string | The ID of the contact. | 
| SalesForce.Contact.Name | string | The name of the contact. | 
| SalesForce.Contact.Account | string | The account associated with the contact information. | 
| SalesForce.Contact.Title | string | The title of the contact. | 
| SalesForce.Contact.Phone | string | The phone number of the contact. | 
| SalesForce.Contact.MobilePhone | string | The mobile number of the contact. | 
| SalesForce.Contact.Email | string | The email address of the contact. | 
| SalesForce.Contact.Owner | string | The owner of the contact. | 
| SalesForce.Lead.ID | string | The lead ID. | 
| SalesForce.Lead.Name | string | The lead name. | 
| SalesForce.Lead.Title | string | The title of the lead. | 
| SalesForce.Lead.Company | string | The lead company. | 
| SalesForce.Lead.Phone | string | The lead phone number. | 
| SalesForce.Lead.Mobile | string | The lead mobile number. | 
| SalesForce.Lead.Email | string | The lead email address. | 
| SalesForce.Lead.Owner | string | The lead owner. | 
| SalesForce.Lead.Status | string | The lead status. Can be: "New", "Nurturing", "Working", "Qualified", or "Unqualified". | 
| SalesForce.Task.ID | string | The ID of the task. | 
| SalesForce.Task.Subject | string | The subject of the task. | 
| SalesForce.Task.Lead | string | The leader of the task. | 
| SalesForce.Task.RelatedTo | string | The relevant account. | 
| SalesForce.Task.DueDate | date | The due date of the task. | 
| SalesForce.User.ID | string | The ID of the user. | 
| SalesForce.User.Name | string | The name of the user. | 
| SalesForce.User.Title | string | The title of the user. | 
| SalesForce.User.Phone | string | The phone number of the user. | 
| SalesForce.User.Email | string | The email address of the user. | 

### salesforce-create-object
***
Creates a new object.


#### Base Command

`salesforce-create-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The object path. For example, "Case" for Object "Case". | Required | 
| json | The JSON file with fields and values of the object to be created. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", "High". | 
| SalesForce.Case.Origin | string | Origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 
| SalesForce.Contact.ID | string | The ID of the contact. | 
| SalesForce.Contact.Name | string | The name of the contact. | 
| SalesForce.Contact.Account | string | The account associated with the contact information. | 
| SalesForce.Contact.Title | string | The title of the contact. | 
| SalesForce.Contact.Phone | string | The phone number of the contact. | 
| SalesForce.Contact.MobilePhone | string | The mobile number of the contact. | 
| SalesForce.Contact.Email | string | The email address of the contact. | 
| SalesForce.Contact.Owner | string | The owner of the contact. | 
| SalesForce.Lead.ID | string | The lead ID. | 
| SalesForce.Lead.Name | string | The lead name. | 
| SalesForce.Lead.Title | string | The title of the lead. | 
| SalesForce.Lead.Company | string | The lead company. | 
| SalesForce.Lead.Phone | string | The lead phone number. | 
| SalesForce.Lead.Mobile | string | The lead mobile number. | 
| SalesForce.Lead.Email | string | The lead email address. | 
| SalesForce.Lead.Owner | string | The lead owner. | 
| SalesForce.Lead.Status | string | The lead status. Can be: "New", "Nurturing", "Working", "Qualified", or "Unqualified". | 
| SalesForce.Task.ID | string | The ID of the task. | 
| SalesForce.Task.Subject | string | The subject of the task. | 
| SalesForce.Task.Lead | string | The leader of the task. | 
| SalesForce.Task.RelatedTo | string | The relevant account of the task. | 
| SalesForce.Task.DueDate | date | The due date of the task. | 
| SalesForce.User.ID | string | The ID of the user. | 
| SalesForce.User.Name | string | The name of the user. | 
| SalesForce.User.Title | string | The title of the user. | 
| SalesForce.User.Phone | string | The phone number of the user. | 
| SalesForce.User.Email | string | The email address of the user. | 

### salesforce-push-comment
***
Adds a comment to Chatter.


#### Base Command

`salesforce-push-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the subject. | Required | 
| text | Chat text. | Required | 
| link | Adds a link to the message. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Comment.Body | string | The body of the comment. | 
| SalesForce.Comment.CreatedDate | date | The date the comment was created. | 
| SalesForce.Comment.Title | string | The title of the comment. | 
| SalesForce.Comment.ParentType | string | The parent type of the comment. | 
| SalesForce.Comment.ParentName | string | The parent name of the comment. | 
| SalesForce.Comment.URL | string | The URL link of the comment. | 
| SalesForce.Comment.Visibility | string | The visibility of the comment. | 

### salesforce-get-case
***
Returns information on a case. All arguments are optional, but you must specify at least one argument for the command to execute successfully.


#### Base Command

`salesforce-get-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | Case number of the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | The origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 

### salesforce-create-case
***
Creates a new case.


#### Base Command

`salesforce-create-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subject | The case subject. | Required | 
| description | The case description. | Optional | 
| status | The case status. Possible values are: New, On Hold, Closed, Escalated. Default is New. | Required | 
| origin | The case origin. Possible values are: Email, Phone, Web. | Optional | 
| priority | The case priority. Possible values are: Low, Medium, High. Default is Low. | Optional | 
| type | The case type. Possible values are: Question, Problem, Feature Request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | The origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New", "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | The reason for the case creation. | 

### salesforce-update-case
***
Updates case fields.


#### Base Command

`salesforce-update-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | The case number. | Optional | 
| subject | The case subject. | Optional | 
| description | The case description. | Optional | 
| status | The case status. Possible values are: New, On Hold, Closed, Escalated. | Optional | 
| origin | The case origin. Possible values are: Email, Phone, Web. | Optional | 
| priority | The case priority. Possible values are: Low, Medium, High. | Optional | 
| type | The case type. Possible values are: Question, Problem, Feature Request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The number of the case. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | The description of the case. | 
| SalesForce.Case.CreateDate | date | The creation date of the case. | 
| SalesForce.Case.ClosedDate | date | The closure date of the case. | 
| SalesForce.Case.Owner | string | The owner of the case. | 
| SalesForce.Case.Priority | string | The priority of the case. Can be: "Low", "Medium", or "High". | 
| SalesForce.Case.Origin | string | Origin of the case. Can be: "Web", "Phone", or "Email". | 
| SalesForce.Case.Status | string | The status of the case. Can be: "New, "Escalated", "On Hold", or "Closed". | 
| SalesForce.Case.Reason | string | Reason for the case creation. | 

### salesforce-get-cases
***
Returns all cases.


#### Base Command

`salesforce-get-cases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### salesforce-close-case
***
Close a case


#### Base Command

`salesforce-close-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The case object ID. | Optional | 
| caseNumber | The case number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Case.ID | string | The object ID of the case. | 
| SalesForce.Case.CaseNumber | string | The case number. | 
| SalesForce.Case.Subject | string | The subject of the case. | 
| SalesForce.Case.Description | string | Case description. | 
| SalesForce.Case.CreateDate | date | Creation time of the case. | 
| SalesForce.Case.ClosedDate | date | Closure time of the case. | 
| SalesForce.Case.Owner | string | Case owner. | 
| SalesForce.Case.Priority | string | Priority of the case. Can be one of the following: "Low", "Medium", "High". | 
| SalesForce.Case.Origin | string | Origin of the case. Can be one of the following: "Web", "Phone", "Email". | 
| SalesForce.Case.Status | string | Case status. Can be one of the following: "New", "Escalated"," On Hold" or "Closed". | 
| SalesForce.Case.Reason | string | Reason the case was created. | 

### salesforce-push-comment-threads
***
Add the comment to the Chatter thread. Use this command only after salesforce-push-comment.


#### Base Command

`salesforce-push-comment-threads`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Chatter comment thread ID. | Required | 
| text | The comment text. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesForce.Comment.Reply.Body | string | Reply body. | 
| SalesForce.Comment.Reply.CreatedDate | date | Reply created date. | 
| SalesForce.Comment.Reply.URL | string | Reply URL link. | 

### salesforce-delete-case
***
Deletes a case.


#### Base Command

`salesforce-delete-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | The case number. | Optional | 


#### Context Output

There is no context output for this command.
### salesforce-get-casecomment
***
Returns a comment through the case number.


#### Base Command

`salesforce-get-casecomment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | The case number of the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ID | string | The ID of the case. | 
| ParentId | string | The ID of the parent case of the case comment. | 
| IsPublished | boolean | Whether the case comment is visible to customers in the Self-Service portal \(true\). This is the only CaseComment field that can be updated through the API. | 
| CommentBody | string | The text of the case body. Maximum size is 4,000 bytes. | 
| CreatedById | unknown | The created date by ID. | 
| CreatedDate | string | The created date. | 
| SystemModstamp | string | The SystemMod stamp. | 
| LastModifiedDate | string | The last modified date. | 
| LastModifiedById | string | The last modified date by ID. | 
| IsDeleted | boolean | Whether the object has been moved to the Recycle Bin \(true\). | 

### salesforce-post-casecomment
***
The post comment through the case number.


#### Base Command

`salesforce-post-casecomment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | The case number of the case. | Optional | 
| text | The text to add to the context. | Optional | 
| public | Whether to make the comment public (true or false). Default value is false. Possible values are: true, false. Default is false. | Required | 


#### Context Output

There is no context output for this command.
### salesforce-get-user
***
Returns the user name through the case number.


#### Base Command

`salesforce-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oid | The object ID of the case. | Optional | 
| caseNumber | The case number of the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ID | string | The ID of the case. | 
| Alias | string | The user's alias. For example, jsmith. | 
| CommunityNickname | string | The name used to identify the user in the Community application, which includes the ideas and answers features. | 
| CreatedById | string | Created by the ID. | 
| Email | string | The user's email address. Required. | 
| LastLoginDate | string | The time and date when the user last successfully logged in. This value is updated if 60 seconds have elapsed since the user's last login. | 
| LastModifiedDate | string | The last modified date. | 
| LastName | string | The user's last name. | 
| Name | string | Concatenation of FirstName and LastName. | 
| Username | string | Contains the name that a user enters to log in to the API or the user interface. | 
| UserRoleId | string | The ID of the user's UserRole. | 

### salesforce-get-org
***
Returns organization details from the case number.


#### Base Command

`salesforce-get-org`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseNumber | The case number of the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ID | string | The unique ID of the case. | 
| Name | string | Name of the account. If the account has a record type of Person Account, this value is the concatenation of the FirstName, MiddleName, LastName, and Suffix of the associated person contact. | 

### get-remote-data
***
Gets remote data from a remote incident. This method is only used for debugging purposes and will not update the current incident.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.
### get-modified-remote-data
***
Available from Cortex XSOAR version 6.1.0. This command queries for incidents that were modified since the last update. This method is only used for debugging purposes.


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | . | Required | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***
Returns the list of fields for an incident type.


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### salesforce-describe-sobject-field
***
Describe Salesforce object field.


#### Base Command

`salesforce-describe-sobject-field`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sobject | Salesforce object name. For example, Case (default Case). Default is Case. | Required | 
| field | Field definition to return. | Required | 


#### Context Output

There is no context output for this command.
### salesforce-list-case-files
***
Return the list of files attached to the case.


#### Base Command

`salesforce-list-case-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseoId | Case object ID. | Optional | 
| caseNumber | Case number. | Optional | 


#### Context Output

There is no context output for this command.
### salesforce-get-case-file-by-id
***
Retrieve a case file by file ID.


#### Base Command

`salesforce-get-case-file-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseFileId | Case file ID. | Optional | 
| caseNumber | Case number. | Optional | 


#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Salesforce V2 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Salesforce V2 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Salesforce V2 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Salesforce V2 events will be reflected in both directions. |

3. Optional: You can go to the mirroring tags parameter and select the tags used to mark incident entries to be mirrored. Available tags are: Comment Entry Tag.
4. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Salesforce V2.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Salesforce V2.

## Breaking changes from the previous version of this integration - Salesforce V2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
