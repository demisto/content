Use this integration to manage Jira objects and attach files to Jira objects from Cortex XSOAR.
This integration was integrated and tested with version 5.4.15 of AtlassianJiraServiceManagement.

## Configure Atlassian Jira Service Management in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Token | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jira-asset-object-schema-list

***
List all object schemas.

#### Base Command

`jira-asset-object-schema-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum amount of schemas to retrieve. Cannot be used alongside the *page* and *page_size* arguments. | Optional | 
| all_results | Whether to retrieve all object schemas with no limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Schema.ID | Number | The ID of the object schema. | 
| JiraAsset.Schema.Name | String | The name of the object schema. | 
| JiraAsset.Schema.Key | String | The key of the object schema. | 
| JiraAsset.Schema.Status | String | The status of the object schema. | 
| JiraAsset.Schema.Created | Date | The date in which this object schema was created. | 
| JiraAsset.Schema.Updated | Date | The date in which this object schema was updated. | 
| JiraAsset.Schema.ObjectCount | Number | The number of objects in the schema. | 
| JiraAsset.Schema.ObjectTypeCount | Number | The number of different object types in the schema. | 

### jira-asset-object-type-list

***
List all object types.

#### Base Command

`jira-asset-object-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schema_id | The schema from which the command will retrieve object types. Values can be received by running the `jira-asset-object-schema-list` command. | Required | 
| exclude | Object types with that name will be excluded from the results. | Optional | 
| limit | The maximum amount of object types to retrieve. | Optional | 
| all_results | Whether to retrieve all object types with no limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.ObjectType.ID | Number | The ID of the object type. | 
| JiraAsset.ObjectType.Name | String | The name of the object type. | 
| JiraAsset.ObjectType.Type | Number | The type of the object type. | 
| JiraAsset.ObjectType.Position | Number | The position of the object type among other object types with the same level in the schema hierarchy. | 
| JiraAsset.ObjectType.Created | Date | The date the object type was created. | 
| JiraAsset.ObjectType.Updated | Date | The date the object type was last updated. | 
| JiraAsset.ObjectType.ObjectCount | Number | The amount of objects listed under this object type. | 
| JiraAsset.ObjectType.ObjectSchemaId | Number | The ID of the schema this object type is listed under. | 
| JiraAsset.ObjectType.Inherited | Boolean | Whether this object type inherits from a parent object type. | 
| JiraAsset.ObjectType.AbstractObjectType | Boolean | Is this object type abstract \(can only be inherited\). | 
| JiraAsset.ObjectType.ParentObjectTypeInherited | Boolean | Whether this object type inherits from a parent object type. | 

### jira-asset-object-type-attribute-list

***
List all attributes for an object type.

#### Base Command

`jira-asset-object-type-attribute-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type_id | The object type for which the command will retrieve attributes. Values can be received by running the `jira-asset-object-type-list` command. | Required | 
| is_editable | Whether to only return attributes that can be edited. Possible values are: true, false. | Optional | 
| order_by_name | Whether to sort the results by the attribute name. Possible values are: true, false. | Optional | 
| query | Query to filter on available object type attributes. Filter attributes that start with the query. | Optional | 
| include_value_exist | Should the response only include attributes where attribute values exists. Possible values are: true, false. | Optional | 
| exclude_parent_attributes | Should the response exclude parent attributes. Possible values are: true, false. | Optional | 
| include_children | Should the response include child attributes. Possible values are: true, false. | Optional | 
| order_by_required | Should the response be ordered by the number of required attributes. Possible values are: true, false. | Optional | 
| limit | The maximum amount of object types to retrieve. | Optional | 
| all_results | Whether to retrieve all object types with no limit. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Attribute.ID | Number | The ID of the attribute. | 
| JiraAsset.Attribute.Name | String | The name of the attribute. | 
| JiraAsset.Attribute.Label | Boolean | Whether this attribute is used as the label for objects of that type. | 
| JiraAsset.Attribute.Type | String | The type of the attribute \(Default, Reference, User, Project etc.\). | 
| JiraAsset.Attribute.DefaultType.id | Number | ID for the sub-type of the default type. | 
| JiraAsset.Attribute.DefaultType.name | String | Name for the sub-type of the default type. | 
| JiraAsset.Attribute.Editable | Boolean | Whether this attribute is editable. | 
| JiraAsset.Attribute.System | Boolean | Whether this attribute is a system attribute or a custom one. | 
| JiraAsset.Attribute.Sortable | Boolean | Can the objects be sorted by that attribute. | 
| JiraAsset.Attribute.Summable | Boolean | Can this attribute be summarized. | 
| JiraAsset.Attribute.Indexed | Boolean | Is this attribute indexed. | 
| JiraAsset.Attribute.MinimumCardinality | Number | The minimum amount of elements this attribute should populate. | 
| JiraAsset.Attribute.MaximumCardinality | Number | The maximum amount of elements this attribute should populate. | 
| JiraAsset.Attribute.Removable | Boolean | Whether this attribute can be removed from the object. | 
| JiraAsset.Attribute.Hidden | Boolean | Whether this attribute is a hidden attribute. | 
| JiraAsset.Attribute.IncludeChildObjectTypes | Boolean | Whether this attribute includes child object types. | 
| JiraAsset.Attribute.UniqueAttribute | Boolean | Whether this attribute is unique to its object. | 
| JiraAsset.Attribute.Options | String | Options for the attributes. | 
| JiraAsset.Attribute.Position | Number | The position of the attribute in relation to other object attributes. | 

### jira-asset-object-create

***
Create a new object of the specified object type ID. Either attributes or attributes_json must be provided.

#### Base Command

`jira-asset-object-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type_id | The object type for which a new object will be created. | Required | 
| attributes | Provide this field if attributes_json is not provided. A key-value map of object attributes. The structure of the field is: { "attributeId1": [ "value1", "value2"] , "attributeId2":["value1", "value2"] }. You can run the `jira-asset-object-type-attribute-list` command to retrieve the list of available attributes. | Optional | 
| attributes_json | Provide this field if attributes is not provided. A JSON string of object attributes to be added to the new object. Take a look at https://docs.atlassian.com/assets/REST/10.7.0/#object-createObject for the structure of this field. You can use the `jira-asset-object-type-attribute-list` command  to retrieve the list of available attributes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Object.ID | Number | ID of the newly created object. | 
| JiraAsset.Object.Label | String | The value of the attribute that is marked as Label for this object type. | 
| JiraAsset.Object.ObjectKey | String | The auto-generated object key. | 
| JiraAsset.Object.Avatar.objectId | Number | ID of the newly created object. | 
| JiraAsset.Object.Created | Date | The date in which this object was created. | 
| JiraAsset.Object.Updated | Date | The date in which this object was last updated. | 
| JiraAsset.Object.HasAvatar | Boolean | Does this object have an Avatar. | 
| JiraAsset.Object.Timestamp | Date | Epoch version of the object's creation date. | 
| JiraAsset.Object.Links.self | String | The link to view this object in the Jira web app. | 
| JiraAsset.Object.Name | String | The name of the newly created object. | 

### jira-asset-object-update

***
Updates an existing object of specified object type ID. Either attributes or attributes_json must be provided.

#### Base Command

`jira-asset-object-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that will be updated. | Required | 
| attributes | Provide this field if attributes_json is not provided. A key-value map of object attributes. The structure of the field is: { "attributeId1": [ "value1", "value2"] , "attributeId2":["value1", "value2"] }. You can use the `jira-asset-object-type-attribute-list` command to retrieve the list of available attributes. | Optional | 
| attributes_json | Provide this field if attributes is not provided. A JSON string of object attributes to be added to the new object. Take a look at https://docs.atlassian.com/assets/REST/10.7.0/#object-createObject for the structure of this field. You can use the `jira-asset-object-type-attribute-list` command to retrieve the list of available attributes. | Optional | 

#### Context Output

There is no context output for this command.
### jira-asset-object-delete

***
Deletes an existing object of the specified object ID.

#### Base Command

`jira-asset-object-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that will be deleted. | Required | 

#### Context Output

There is no context output for this command.
### jira-asset-object-get

***
Retrieves the object with the specified object ID.

#### Base Command

`jira-asset-object-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that will be retrieved. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Object.ID | Number | ID of the retrieved object. | 
| JiraAsset.Object.Label | String | The value of the attribute that is marked as Label for this object type. | 
| JiraAsset.Object.ObjectKey | String | The auto-generated object key. | 
| JiraAsset.Object.Created | Date | The date in which this object was created. | 
| JiraAsset.Object.Updated | Date | The date in which this object was last updated. | 
| JiraAsset.Object.HasAvatar | Boolean | Does this object have an Avatar. | 
| JiraAsset.Object.Timestamp | Date | Epoch version of the object's creation date. | 
| JiraAsset.Object.ExtendedInfo.openIssuesExists | Boolean | Does this object appear in any open issues. | 
| JiraAsset.Object.ExtendedInfo.attachmentsExists | Boolean | Does this object have any attachments. | 
| JiraAsset.Object.Links.self | String | The link to view this object in the Jira web app. | 
| JiraAsset.Object.Name | String | The name of the object. | 

### jira-asset-object-search

***
Searches for objects of the specified object type.

#### Base Command

`jira-asset-object-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ql_query | An aql query to search objects by. View https://support.atlassian.com/jira-service-management-cloud/docs/use-assets-query-language-aql/ for further details. | Required | 
| include_attributes | Whether to include the attributes structure in the response. Possible values are: true, false. | Optional | 
| page | Page number. | Optional | 
| page_size | Use this argument or limit, but not both. Size of the page. Defaults to 50. | Optional | 
| limit | Use this argument or a combination of page and page_size, but not both. Limit the number of entries returned by the command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Object.ID | Number | ID of the retrieved object. | 
| JiraAsset.Object.Label | String | The value of the attribute that is marked as Label for this object type. | 
| JiraAsset.Object.ObjectKey | String | The auto-generated object key. | 
| JiraAsset.Object.Created | Date | The date in which this object was created. | 
| JiraAsset.Object.Updated | Date | The date in which this object was last updated. | 
| JiraAsset.Object.HasAvatar | Boolean | Does this object have an Avatar. | 
| JiraAsset.Object.Timestamp | Date | Epoch version of the object's creation date. | 
| JiraAsset.Object.Attributes.id | Number | The ID of the attribute. | 
| JiraAsset.Object.Attributes.objectTypeAttributeId | Number | The ID of the attribute, not relative to the object type. | 
| JiraAsset.Object.Attributes.objectAttributeValues.value | String | The value of the specific attribute for this object. | 
| JiraAsset.Object.Attributes.objectAttributeValues.referencedType | Boolean | Whether this attribute is referenced by other types. | 
| JiraAsset.Object.Attributes.objectAttributeValues.displayValue | String | The display value for this attribute. | 
| JiraAsset.Object.Attributes.objectAttributeValues.searchValue | String | The search value for this attribute. | 
| JiraAsset.Object.Attributes.objectId | Number | The ID of the object this attribute is assigned to. | 
| JiraAsset.Object.Links.self | String | The link to view this object in the Jira web app. | 
| JiraAsset.Object.Name | String | The name of the object. | 

### jira-asset-attribute-json-create

***
Utility command used to create a JSON file with all attributes of the specified object type. All that is left is to fill in the values of each attribute.

#### Base Command

`jira-asset-attribute-json-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type_id | ID of the object type that attributes JSON will be created for. You could use the jira-asset-object-type-list command to find object types. | Required | 
| is_editable | Whether to fetch only editable attributes. Possible values are: true, false. | Optional | 
| is_required | Whether to fetch only required attributes. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 

### jira-asset-comment-create

***
Creates a comment for the specified object.

#### Base Command

`jira-asset-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that the comment will be added to. You could use the jira-asset-object-search command to find objects. | Required | 
| comment | Body of the comment that will be created. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Comment.Created | Date | The date in which this comment was created. | 
| JiraAsset.Comment.Updated | Date | The date in which this object was last updated. | 
| JiraAsset.Comment.Id | Number | The ID of the newly created comment. | 
| JiraAsset.Comment.Actor.AvatarUrl | String | URL to the avatar of the author of the comment. | 
| JiraAsset.Comment.Actor.DisplayName | String | Display name of the author of the comment. | 
| JiraAsset.Comment.Actor.Name | String | Name of the author of the comment. | 
| JiraAsset.Comment.Actor.Key | String | Key of the author of the comment. | 
| JiraAsset.Comment.Actor.RenderedLink | String | A link to the author's Jira profile. | 
| JiraAsset.Comment.Actor.IsDeleted | Boolean | Is the author of the comment deleted. | 
| JiraAsset.Comment.Role | Number | The role of the author of the comment. | 
| JiraAsset.Comment.Comment | String | The body of the comment that was newly added. | 
| JiraAsset.Comment.CommentOutput | String | The body of the comment that was newly added. | 
| JiraAsset.Comment.ObjectId | Number | The ID of the object the new comment was added to. | 
| JiraAsset.Comment.CanEdit | Boolean | Whether the comment is editable. | 
| JiraAsset.Comment.CanDelete | Boolean | Whether the comment can be deleted. | 

### jira-asset-connected-ticket-list

***
Returns a list of all connected tickets for the specified object.

#### Base Command

`jira-asset-connected-ticket-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object for which connected tickets will be fetched. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.ConnectedTicket.Tickets.Key | String | Key for the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.ID | Number | The ID of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Reporter | String | The user who reported the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Created | Date | The date in which this connected ticket was created. | 
| JiraAsset.ConnectedTicket.Tickets.Updated | Date | The date in which this connected ticket was last updated. | 
| JiraAsset.ConnectedTicket.Tickets.Title | String | Title of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Status.Name | String | The name of the status of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Status.Colorname | String | The color of the connected tikcet. | 
| JiraAsset.ConnectedTicket.Tickets.Type.Name | String | The type of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Type.Description | String | The description of the type of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Type.Iconurl | String | The URL to the icon representing the type of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Priority.Name | String | Priority of the connected ticket. | 
| JiraAsset.ConnectedTicket.Tickets.Priority.Iconurl | String | The URL to the icon representing the priority of the connected ticket. | 
| JiraAsset.ConnectedTicket.Allticketsquery | String | The query used to fetch the connected tickets. | 

### jira-asset-comment-list

***
Returns a list of comments for the specified object.

#### Base Command

`jira-asset-comment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that comments will be retrieved for. You could use the jira-asset-object-search command to find objects. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Comment.Created | Date | The date in which this comment was created. | 
| JiraAsset.Comment.Updated | Date | The date in which this object was last updated. | 
| JiraAsset.Comment.ID | Number | The ID of the newly created comment. | 
| JiraAsset.Comment.Role | Number | The role of the author of the comment. | 
| JiraAsset.Comment.Comment | String | The body of the comment that was newly added. | 
| JiraAsset.Comment.CommentOutput | String | The body of the comment that was newly added. | 
| JiraAsset.Comment.ObjectId | Number | The ID of the object the new comment was added to. | 
| JiraAsset.Comment.CanEdit | Boolean | Whether the comment is editable. | 
| JiraAsset.Comment.CanDelete | unknown | Whether the comment can be deleted. | 

### jira-asset-attachment-add

***
Uploads a file attachment to the specified object.

#### Base Command

`jira-asset-attachment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that the file will be attached to. | Required | 
| entry_id | ID of the file to upload. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Attachment.ID | Number | ID of the attachment. | 
| JiraAsset.Attachment.Author | String | Author of the attachment. | 
| JiraAsset.Attachment.MimeType | String | The file's MIME type. | 
| JiraAsset.Attachment.Filename | String | The file's name. | 
| JiraAsset.Attachment.Filesize | String | The size of the file. | 
| JiraAsset.Attachment.Created | Date | The date in which this attachment was created. | 
| JiraAsset.Attachment.Comment | String | The comment attached to the attachment, if there is one. | 
| JiraAsset.Attachment.CommentOutput | String | The comment output of the attachment, if there is one. | 
| JiraAsset.Attachment.Url | String | URL to the attachment. | 

### jira-asset-attachment-list

***
Returns a list of attachments for the specified object. You can also download the files in a zipped format.

#### Base Command

`jira-asset-attachment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object that attachments will be fetched for. | Required | 
| download_file | Whether to download the attachments for this object in a zipped format. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Attachment.ID | Number | ID of the attachment. | 
| JiraAsset.Attachment.Author | String | Author of the attachment. | 
| JiraAsset.Attachment.MimeType | String | The file's MIME type. | 
| JiraAsset.Attachment.Filename | String | The file's name. | 
| JiraAsset.Attachment.Filesize | String | The size of the file. | 
| JiraAsset.Attachment.Created | Date | The date in which this attachment was created. | 
| JiraAsset.Attachment.Comment | String | The comment attached to the attachment, if there is one. | 
| JiraAsset.Attachment.CommentOutput | String | The comment output of the attachment, if there is one. | 
| JiraAsset.Attachment.Url | String | URL to the attachment. | 

### jira-asset-attachment-remove

***
Removes an attachment from a specific object.

#### Base Command

`jira-asset-attachment-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the attachment that will be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JiraAsset.Attachment.ID | Number | ID of the attachment that was deleted. | 
| JiraAsset.Attachment.Author | String | Author of the attachment. | 
| JiraAsset.Attachment.MimeType | String | The file's MIME type. | 
| JiraAsset.Attachment.Filename | String | The file's name. | 
| JiraAsset.Attachment.Filesize | String | The size of the file. | 
| JiraAsset.Attachment.Created | Date | The date in which this attachment was created. | 
| JiraAsset.Attachment.Comment | String | The comment attached to the attachment, if there is one. | 
| JiraAsset.Attachment.CommentOutput | String | The comment output of the attachment, if there is one. | 
| JiraAsset.Attachment.Url | String | URL to the attachment. | 