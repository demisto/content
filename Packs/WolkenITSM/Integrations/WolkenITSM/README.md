Use The Wolken IT Service Management (ITSM) solution to modernize the way you manage and deliver services to your users.
This integration was integrated and tested with version 1.0.0 of Wolken ITSM

## Configure Wolken ITSM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. api-brdcmitsmbst.wolkenservicedesk.com) | True |
| API Key | True |
| Client Id | True |
| Service Account | True |
| Domain | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Refresh Token | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wolken-add-internal-notes
***
Used to add Internal Notes in the specified incident


#### Base Command

`wolken-add-internal-notes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | pass incidentId. | Required | 
| Notes | Pass Internal Notes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-create-incident-requestv1
***
Creates new Wolken ITSM incident


#### Base Command

`wolken-create-incident-requestv1`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Subject | Pass Subject of the Incident. | Required | 
| Description | Pass Description of the Incident. | Required | 
| SubCategoryName | Pass Sub-Category of the Incident. | Required | 
| ItemName | Pass Item Name of the Incident. | Optional | 
| PriorityId | Pass Priority Id of the Incident. | Optional | 
| RequestorEmail | Pass Requester Email Id of the Incident. | Required | 
| PreferredContactModeNumber | Pass Contact Number of the Requester. | Optional | 
| ContactTypeId | Pass Contact Type Id of the Incident. | Optional | 
| Category | Pass Category of the incident. | Optional | 
| Sub_Category | Pass Sub Category of the Incident. | Optional | 
| TeamId | Pass required Team Id. | Optional | 
| Reminder | Pass Reminder of the incident. | Optional | 
| Reminder_Notes | Pass Remider Notes of the Incident. | Optional | 
| ImpactId | Pass Impact Id of the Incident. | Optional | 
| UrgencyId | Pass Urgency Id of the Incident. | Optional | 
| Location | Pass Location. | Optional | 
| Configuration_Item | Pass Configuration Item of the incident. | Optional | 
| file_name | Pass file name required to add in the incident. | Optional | 
| file_type | Pass file type required to add in the incident. | Optional | 
| file_entryId | Pass file entry Id required to add in the incident. | Optional | 
| SourceId | Pass SourceId required to add in the incident. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.CreateIncidents.status | String |  | 
| Wolken.CreateIncidents.message | String |  | 
| Wolken.CreateIncidents.data.requestId | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-get-access-token
***
Use to get access token and save it in integration context . Refresh Token saved in integration context will be used to create new access token after expiration.


#### Base Command

`wolken-get-access-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.Token.access_token | String |  | 
| Wolken.Token.token_type | String |  | 
| Wolken.Token.refresh_token | String |  | 
| Wolken.Token.expires_in | Number |  | 
| Wolken.Token.scope | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-get-incident-by-id
***
Find incident using the specified incident id


#### Base Command

`wolken-get-incident-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | Pass Incident Id required for searching. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.GetIncidents.status | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-post-api-v1-incidents-add-attachments
***
Add Attachment to the specified Incident Id using entry Id


#### Base Command

`wolken-post-api-v1-incidents-add-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | Pass Incident Id. | Required | 
| file_name | Pass file name required to add in the incident. | Optional | 
| file_type | Pass file type required to add in the incident. | Optional | 
| file_entryId | Pass file entry Id required to add in the incident. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-post-api-v1-incidents-add-outbound-notes
***
Add Outbound Notes to the specified Incident Id


#### Base Command

`wolken-post-api-v1-incidents-add-outbound-notes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | pass incidentId. | Required | 
| Notes | Pass Outbound Notes object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-post-api-v1-incidents-by-incident-id
***
Update an existing incident


#### Base Command

`wolken-post-api-v1-incidents-by-incident-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | Pass Incident Id. | Required | 
| SourceId | Pass incident 2Update object. | Required | 
| Subject | Pass the subject of the incident. | Required | 
| Description | Pass the description of the incident. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-post-api-v1-incidents-close
***
Close an Incident


#### Base Command

`wolken-post-api-v1-incidents-close`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | Pass Incident Id. | Required | 
| Resolution_Code | Pass the required Resolution code. | Required | 
| Resolution_Notes | Pass Resolution Notes . | Required | 
| Closure_Description | Pass Closure description while closing the incident. | Required | 
| StatusId | Pass Status Id of the incident . | Required | 
| SubStatusId | Pass Sub Status Id of the incident. | Required | 
| Owner | Pass Owner of the incident. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-put-api-v1-incidents-cancel
***
Cancel an Incident


#### Base Command

`wolken-put-api-v1-incidents-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | Pass Incident Id. | Required | 
| Description | Pass description for incident Cancellation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.UpdateIncidents.status | String |  | 
| Wolken.UpdateIncidents.message | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### wolken-search-incidents-by-params
***
Search in the list of incident using any parameters


#### Base Command

`wolken-search-incidents-by-params`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Pass limit. | Required | 
| offset | Pass offset. | Required | 
| userPsNo | Login User Id. | Optional | 
| statusId | Status Id. | Optional | 
| subStatusId | Sub Status Id. | Optional | 
| teamId | Team Id. | Optional | 
| unitId | Unit Id. | Optional | 
| creatorId | Creator Id. | Optional | 
| requesterId | Requester Id. | Optional | 
| itemId | Item Id. | Optional | 
| priorityId | Priority Id. | Optional | 
| assignedUserId | Assigned User Id. | Optional | 
| createdTimeGTE | Created Time Greater Than Equals. | Optional | 
| createdTimeLT | Created Time Less then. | Optional | 
| updatedTimeGTE | Updated Time Greater Then Equals. | Optional | 
| updatedTimeLT | Updated Time Less Then. | Optional | 
| updatedByUserId | Updated By User Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wolken.GetIncidents.status | String |  | 


#### Command Example
``` ```

#### Human Readable Output

