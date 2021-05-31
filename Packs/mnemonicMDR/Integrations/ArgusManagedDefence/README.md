Rapidly detect, analyse and respond to security threats with mnemonic’s leading Managed Detection and Response (MDR) service.

This integration was integrated and tested with version 5.0.1 argus-toolbelt ([PyPi](https://pypi.org/project/argus-toolbelt)).
## Configure ArgusManagedDefence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ArgusManagedDefence.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | max_fetch | Maximum number of incidents per fetch | False |
    | api_key | API Key | True |
    | min_severity | Minimum severity of alerts to fetch | True |
    | first_fetch | First fetch time | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | api_url | API URL | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

**Note: all timestamps are in the millisecond format**

### argus_add_case_tag
***
Adds a key, value tag to an Argus case


#### Base Command

`argus-add-case-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to add tag to. | Required | 
| key | Key of tag to add to case. | Required | 
| value | Value of tag to add to case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | API response metadata, response code of this request | 
| Argus.Tags.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Tags.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Tags.count | Number | API response metadata, total number of results this query has | 
| Argus.Tags.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Tags.messages.message | String | Tag Messages Message | 
| Argus.Tags.messages.messageTemplate | String | Tag Messages Message Template | 
| Argus.Tags.messages.type | String | Tag Messages Type | 
| Argus.Tags.messages.field | String | Tag Messages Field | 
| Argus.Tags.messages.timestamp | Number | Tag Messages Timestamp | 
| Argus.Tags.data.id | String | Tag ID | 
| Argus.Tags.data.key | String | Tag Key | 
| Argus.Tags.data.value | String | Tag Value | 
| Argus.Tags.data.addedTimestamp | Number | Tag Added Timestamp | 
| Argus.Tags.data.addedByUser.id | Number | Tag Added By User ID | 
| Argus.Tags.data.addedByUser.customerID | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.id | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.name | String | Tag Added By User Customer Name | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Tag Added By User Customer Short Name | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Tag Added By User Customer Domain ID | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Tag Added By User Customer Domain Name | 
| Argus.Tags.data.addedByUser.domain.id | Number | Tag Added By User Domain ID | 
| Argus.Tags.data.addedByUser.domain.name | String | Tag Added By User Domain Name | 
| Argus.Tags.data.addedByUser.userName | String | Tag Added By User User Name | 
| Argus.Tags.data.addedByUser.name | String | Tag Added By User Name | 
| Argus.Tags.data.addedByUser.type | String | Tag Added By User Type | 
| Argus.Tags.data.flags | String | Tag Flags | 
| Argus.Tags.data.addedTime | String | Tag Added Time | 

#### Command Example
``` !argus-add-case-tag case_id=123 key=foo value=bar ```


### argus-list-case-tags
***
List tags attached to an Argus case


#### Base Command

`argus-list-case-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID . | Required | 
| limit | Limit the amount of fetched tags. (Default 25). | Optional | 
| offset | Skip a number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | API response metadata, response code of this request | 
| Argus.Tags.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Tags.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Tags.count | Number | API response metadata, total number of results this query has | 
| Argus.Tags.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Tags.messages.message | String | Tag Messages Message | 
| Argus.Tags.messages.messageTemplate | String | Tag Messages Message Template | 
| Argus.Tags.messages.type | String | Tag Messages Type | 
| Argus.Tags.messages.field | String | Tag Messages Field | 
| Argus.Tags.messages.timestamp | Number | Tag Messages Timestamp | 
| Argus.Tags.data.id | String | Tag ID | 
| Argus.Tags.data.key | String | Tag Key | 
| Argus.Tags.data.value | String | Tag Value | 
| Argus.Tags.data.addedTimestamp | Number | Tag Added Timestamp | 
| Argus.Tags.data.addedByUser.id | Number | Tag Added By User ID | 
| Argus.Tags.data.addedByUser.customerID | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.id | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.name | String | Tag Added By User Customer Name | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Tag Added By User Customer Short Name | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Tag Added By User Customer Domain ID | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Tag Added By User Customer Domain Name | 
| Argus.Tags.data.addedByUser.domain.id | Number | Tag Added By User Domain ID | 
| Argus.Tags.data.addedByUser.domain.name | String | Tag Added By User Domain Name | 
| Argus.Tags.data.addedByUser.userName | String | Tag Added By User User Name | 
| Argus.Tags.data.addedByUser.name | String | Tag Added By User Name | 
| Argus.Tags.data.addedByUser.type | String | Tag Added By User Type | 
| Argus.Tags.data.flags | String | Tag Flags | 
| Argus.Tags.data.addedTime | String | Tag Added Time | 


#### Command Example
``` !argus-list-case-tags case_id=123 ```


### argus-add-comment
***
Add comment to an Argus case


#### Base Command

`argus-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| comment | The comment to attach. | Required | 
| as_reply_to | ID of comment this comment will reply to. | Optional | 
| internal | Whether this comment will be shown to the customer. Possible values are: false, true. Default is false. | Optional | 
| origin_email_address | Define the e-mail address this comment originates from. | Optional | 
| associated_attachment_id | ID of case attachement this comment is related to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | API response metadata, response code of this request | 
| Argus.Comment.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Comment.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Comment.count | Number | API response metadata, total number of results this query has | 
| Argus.Comment.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Comment.messages.message | String | Comment Messages Message | 
| Argus.Comment.messages.messageTemplate | String | Comment Messages Message Template | 
| Argus.Comment.messages.type | String | Comment Messages Type | 
| Argus.Comment.messages.field | String | Comment Messages Field | 
| Argus.Comment.messages.timestamp | Number | Comment Messages Timestamp | 
| Argus.Comment.data.id | String | Comment ID | 
| Argus.Comment.data.addedTimestamp | Number | Comment Added Timestamp | 
| Argus.Comment.data.addedByUser.id | Number | Comment Added By User ID | 
| Argus.Comment.data.addedByUser.customerID | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.id | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.name | String | Comment Added By User Customer Name | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Comment Added By User Customer Short Name | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Comment Added By User Customer Domain ID | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Comment Added By User Customer Domain Name | 
| Argus.Comment.data.addedByUser.domain.id | Number | Comment Added By User Domain ID | 
| Argus.Comment.data.addedByUser.domain.name | String | Comment Added By User Domain Name | 
| Argus.Comment.data.addedByUser.userName | String | Comment Added By User User Name | 
| Argus.Comment.data.addedByUser.name | String | Comment Added By User Name | 
| Argus.Comment.data.addedByUser.type | String | Comment Added By User Type | 
| Argus.Comment.data.comment | String | Comment Comment | 
| Argus.Comment.data.flags | String | Comment Flags | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Comment Last Updated Timestamp | 
| Argus.Comment.data.status | String | Comment Status | 
| Argus.Comment.data.priority | String | Comment Priority | 
| Argus.Comment.data.originEmailAddress | String | Comment Origin Email Address | 
| Argus.Comment.data.associatedAttachments.id | String | Comment Associated Attachments ID | 
| Argus.Comment.data.associatedAttachments.name | String | Comment Associated Attachments Name | 
| Argus.Comment.data.references.type | String | Comment References Type | 
| Argus.Comment.data.references.commentID | String | Comment References Comment ID | 
| Argus.Comment.data.lastUpdatedTime | String | Comment Last Updated Time | 
| Argus.Comment.data.addedTime | String | Comment Added Time | 

#### Command Example
``` !argus-add-comment case_id=123 comment="this is a comment" ```

### argus-list-case-comments
***
List the comments of an Argus case


#### Base Command

`argus-list-case-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID of Argus case. | Required | 
| before_comment | Limit to comments before this comment ID (in sort order). Possible values are: . | Optional | 
| offset | Skip a number of results (default 0). | Optional | 
| limit | Maximum number of returned results (default 25). | Optional | 
| sort_by | Sort ordering. Default is ascending. Possible values are: ascending, descending. | Optional | 
| after_comment | Limit to comments after this comment ID (in sort order). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comments.responseCode | Number | API response metadata, response code of this request | 
| Argus.Comments.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Comments.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Comments.count | Number | API response metadata, total number of results this query has | 
| Argus.Comments.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Comments.messages.message | String | Comment Messages Message | 
| Argus.Comments.messages.messageTemplate | String | Comment Messages Message Template | 
| Argus.Comments.messages.type | String | Comment Messages Type | 
| Argus.Comments.messages.field | String | Comment Messages Field | 
| Argus.Comments.messages.timestamp | Number | Comment Messages Timestamp | 
| Argus.Comments.data.id | String | Comment ID | 
| Argus.Comments.data.addedTimestamp | Number | Comment Added Timestamp | 
| Argus.Comments.data.addedByUser.id | Number | Comment Added By User ID | 
| Argus.Comments.data.addedByUser.customerID | Number | Comment Added By User Customer ID | 
| Argus.Comments.data.addedByUser.customer.id | Number | Comment Added By User Customer ID | 
| Argus.Comments.data.addedByUser.customer.name | String | Comment Added By User Customer Name | 
| Argus.Comments.data.addedByUser.customer.shortName | String | Comment Added By User Customer Short Name | 
| Argus.Comments.data.addedByUser.customer.domain.id | Number | Comment Added By User Customer Domain ID | 
| Argus.Comments.data.addedByUser.customer.domain.name | String | Comment Added By User Customer Domain Name | 
| Argus.Comments.data.addedByUser.domain.id | Number | Comment Added By User Domain ID | 
| Argus.Comments.data.addedByUser.domain.name | String | Comment Added By User Domain Name | 
| Argus.Comments.data.addedByUser.userName | String | Comment Added By User User Name | 
| Argus.Comments.data.addedByUser.name | String | Comment Added By User Name | 
| Argus.Comments.data.addedByUser.type | String | Comment Added By User Type | 
| Argus.Comments.data.comment | String | Comment Comment | 
| Argus.Comments.data.flags | String | Comment Flags | 
| Argus.Comments.data.lastUpdatedTimestamp | Number | Comment Last Updated Timestamp | 
| Argus.Comments.data.status | String | Comment Status | 
| Argus.Comments.data.priority | String | Comment Priority | 
| Argus.Comments.data.originEmailAddress | String | Comment Origin Email Address | 
| Argus.Comments.data.associatedAttachments.id | String | Comment Associated Attachments ID | 
| Argus.Comments.data.associatedAttachments.name | String | Comment Associated Attachments Name | 
| Argus.Comments.data.references.type | String | Comment References Type | 
| Argus.Comments.data.references.commentID | String | Comment References Comment ID | 
| Argus.Comments.data.lastUpdatedTime | String | Comment Last Updated Time | 
| Argus.Comments.data.addedTime | String | Comment Added Time | 

#### Command Example
``` !argus_list_case_comments case_id=123 ```

### argus-advanced-case-search
***
Returns cases matching the defined case search criteria


#### Base Command

`argus-advanced-case-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_timestamp | Start timestamp. Possible values are: | Optional | 
| end_timestamp | End timestamp. | Optional | 
| limit | Set this value to set max number of results. By default, no restriction on result set size. | Optional | 
| offset | Set this value to skip the first (offset) objects. By default, return result from first object. | Optional | 
| include_deleted | Set to true to include deleted objects. By default, exclude deleted objects. Possible values are: true, false. Default is false. | Optional | 
| sub_criteria | Set additional criterias which are applied using a logical OR. | Optional | 
| exclude | Only relevant for subcriteria. If set to true, objects matching this subcriteria object will be excluded. Possible values are: true, false. | Optional | 
| required | Only relevant for subcriteria. If set to true, objects matching this subcriteria are required (AND-ed together with parent criteria). Possible values are: true, false. | Optional | 
| customer_id | Restrict search to data belonging to specified customers.  | Optional | 
| case_id | Restrict search to specific cases (by ID).  | Optional | 
| customer | Restrict search to specific customers (by ID or shortname).  | Optional | 
| case_type | Restrict search to entries of one of these types. | Optional | 
| service | Restrict search to entries of one of these services (by service shortname or ID).  | Optional | 
| category | Restrict search to entries of one of these categories (by category shortname or ID). | Optional | 
| status | Restrict search to entries of one of these statuses.  | Optional | 
| priority | Restrict search to entries with given priorties. | Optional | 
| asset_id | Restrict search to cases associated with specified assets (hosts, services or processes). | Optional | 
| tag | Restrict search to entries matching the given tag criteria.  | Optional | 
| workflow | Restrict search to entries matching the given workflow criteria.  | Optional | 
| field | Restrict search to entries matching the given field criteria.  | Optional | 
| keywords | Search for keywords. | Optional | 
| time_field_strategy | Defines which timestamps will be included in the search (default all).  | Optional | 
| time_match_strategy | Defines how strict to match against different timestamps (all/any) using start and end timestamp (default any). | Optional | 
| keyword_field_strategy | Defines which fields will be searched by keywords (default all supported fields).  | Optional | 
| keyword_match_strategy | Defines the MatchStrategy for keywords (default match all keywords).  | Optional | 
| user | Restrict search to cases associated with these users or user groups (by ID or shortname).  | Optional | 
| user_field_strategy | Defines which user fields will be searched (default match all user fields).  | Optional | 
| user_assigned | If set, limit search to cases where assignedUser field is set/unset. Possible values are: true, false. | Optional | 
| tech_assigned | If set, limit search to cases where assignedTech field is set/unset. Possible values are: true, false. | Optional | 
| include_workflows | If true, include list of workflows in result. Default is false (not present).  Possible values are: true, false. Default is false. | Optional | 
| include_description | If false, omit description from response. Default is true (description is present).  Possible values are: true, false. Default is true. | Optional | 
| access_mode | If set, only match cases which is set to one of these access modes. | Optional | 
| explicit_access | If set, only match cases which have explicit access grants matching the specified criteria. | Optional | 
| sort_by | List of properties to sort by (prefix with "-" to sort descending). | Optional | 
| include_flags | Only include objects which have includeFlags set.  | Optional | 
| exclude_flags | Exclude objects which have excludeFlags set.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Cases.responseCode | Number | API response metadata, response code of this request | 
| Argus.Cases.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Cases.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Cases.count | Number | API response metadata, total number of results this query has | 
| Argus.Cases.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Cases.messages.message | String | Case Messages Message | 
| Argus.Cases.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Cases.messages.type | String | Case Messages Type | 
| Argus.Cases.messages.field | String | Case Messages Field | 
| Argus.Cases.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Cases.data.id | Number | Case ID | 
| Argus.Cases.data.customer.id | Number | Case Customer ID | 
| Argus.Cases.data.customer.name | String | Case Customer Name | 
| Argus.Cases.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Cases.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Cases.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Cases.data.service.id | Number | Case Service ID | 
| Argus.Cases.data.service.name | String | Case Service Name | 
| Argus.Cases.data.service.shortName | String | Case Service Short Name | 
| Argus.Cases.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Cases.data.category.id | Number | Case Category ID | 
| Argus.Cases.data.category.name | String | Case Category Name | 
| Argus.Cases.data.category.shortName | String | Case Category Short Name | 
| Argus.Cases.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Cases.data.type | String | Case Type | 
| Argus.Cases.data.initialStatus | String | Case Initial Status | 
| Argus.Cases.data.status | String | Case Status | 
| Argus.Cases.data.initialPriority | String | Case Initial Priority | 
| Argus.Cases.data.priority | String | Case Priority | 
| Argus.Cases.data.subject | String | Case Subject | 
| Argus.Cases.data.description | String | Case Description | 
| Argus.Cases.data.customerReference | String | Case Customer Reference | 
| Argus.Cases.data.accessMode | String | Case Access Mode | 
| Argus.Cases.data.reporter.id | Number | Case Reporter ID | 
| Argus.Cases.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Cases.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Cases.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Cases.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Cases.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Cases.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Cases.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Cases.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Cases.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Cases.data.reporter.name | String | Case Reporter Name | 
| Argus.Cases.data.reporter.type | String | Case Reporter Type | 
| Argus.Cases.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Cases.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Cases.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Cases.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Cases.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Cases.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Cases.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Cases.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Cases.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Cases.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Cases.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Cases.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Cases.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Cases.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Cases.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Cases.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Cases.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Cases.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Cases.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Cases.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Cases.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Cases.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Cases.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Cases.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Cases.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Cases.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Cases.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Cases.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Cases.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Cases.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Cases.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Cases.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Cases.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Cases.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Cases.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Cases.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Cases.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Cases.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Cases.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Cases.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Cases.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Cases.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Cases.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Cases.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Cases.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Cases.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Cases.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Cases.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Cases.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Cases.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Cases.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Cases.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Cases.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Cases.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Cases.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Cases.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Cases.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Cases.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Cases.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Cases.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Cases.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Cases.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Cases.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Cases.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Cases.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Cases.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Cases.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Cases.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Cases.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Cases.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Cases.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Cases.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Cases.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Cases.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Cases.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Cases.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Cases.data.flags | String | Case Flags | 
| Argus.Cases.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Cases.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Cases.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Cases.data.workflows.state | String | Case Workflows State | 
| Argus.Cases.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Cases.data.createdTime | String | Case Created Time | 
| Argus.Cases.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Cases.data.closedTime | String | Case Closed Time | 
| Argus.Cases.data.publishedTime | String | Case Published Time | 


#### Command Example
``` !argus-advanced-case-search ```



### argus-close-case
***
Close an Argus case


#### Base Command

`argus-close-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID of Argus case. | Required | 
| comment | Attach a closing comment. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | API response metadata, response code of this request | 
| Argus.Case.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Case.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Case.count | Number | API response metadata, total number of results this query has | 
| Argus.Case.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Case.messages.message | String | Case Messages Message | 
| Argus.Case.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Case.messages.type | String | Case Messages Type | 
| Argus.Case.messages.field | String | Case Messages Field | 
| Argus.Case.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Case.data.id | Number | Case ID | 
| Argus.Case.data.customer.id | Number | Case Customer ID | 
| Argus.Case.data.customer.name | String | Case Customer Name | 
| Argus.Case.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Case.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Case.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Case.data.service.id | Number | Case Service ID | 
| Argus.Case.data.service.name | String | Case Service Name | 
| Argus.Case.data.service.shortName | String | Case Service Short Name | 
| Argus.Case.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Case.data.category.id | Number | Case Category ID | 
| Argus.Case.data.category.name | String | Case Category Name | 
| Argus.Case.data.category.shortName | String | Case Category Short Name | 
| Argus.Case.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Case.data.type | String | Case Type | 
| Argus.Case.data.initialStatus | String | Case Initial Status | 
| Argus.Case.data.status | String | Case Status | 
| Argus.Case.data.initialPriority | String | Case Initial Priority | 
| Argus.Case.data.priority | String | Case Priority | 
| Argus.Case.data.subject | String | Case Subject | 
| Argus.Case.data.description | String | Case Description | 
| Argus.Case.data.customerReference | String | Case Customer Reference | 
| Argus.Case.data.accessMode | String | Case Access Mode | 
| Argus.Case.data.reporter.id | Number | Case Reporter ID | 
| Argus.Case.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Case.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Case.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Case.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Case.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Case.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Case.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Case.data.reporter.name | String | Case Reporter Name | 
| Argus.Case.data.reporter.type | String | Case Reporter Type | 
| Argus.Case.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Case.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Case.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Case.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Case.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Case.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Case.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Case.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Case.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Case.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Case.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Case.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Case.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Case.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Case.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Case.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Case.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Case.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Case.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Case.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Case.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Case.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Case.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Case.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Case.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Case.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Case.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Case.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Case.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Case.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Case.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Case.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Case.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Case.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Case.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Case.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Case.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Case.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Case.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Case.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Case.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Case.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Case.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Case.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Case.data.flags | String | Case Flags | 
| Argus.Case.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Case.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Case.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Case.data.workflows.state | String | Case Workflows State | 
| Argus.Case.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Case.data.createdTime | String | Case Created Time | 
| Argus.Case.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Case.data.closedTime | String | Case Closed Time | 
| Argus.Case.data.publishedTime | String | Case Published Time | 


#### Command Example
``` !argus-close-case case_id=123 ```




### argus-create-case
***
Create Argus case


#### Base Command

`argus-create-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer | ID or shortname of customer to create case for. Defaults to current users customer. | Optional | 
| service | ID of service to create case for. Possible values are: ids, support, administrative, advisory, vulnscan. | Required | 
| category | If set, assign given category to new case (by category shortname).  Possible values are: network-testing, unauthorized-access, dos, data-leakage, exposed-malicious, malicious-infection, poor-practice, reconnaissance, misconfigured, vpn-down, sensor-malfunctioning, not-receiving-traffic, false-positive, suspected-targeted-attack, duplicate, problem-managed, problem-customer, adware, network-connection-lost, failed-authentication, missing-log-sources, no-threat, phishing, argus-improvement, argus-bug. | Optional | 
| type | Type of case to create. Possible values are: operationalIncident, change, securityIncident, informational. | Required | 
| status | Status of case to create. If not set, system will select automatically. Creating a new case with status closed is not permitted. . Possible values are: pendingCustomer, pendingSoc, pendingVendor, pendingClose, workingSoc, workingCustomer. | Optional | 
| tags | Tags to add on case creation.  (key,value,key,value, ...). | Optional | 
| subject | Subject of case to create. | Required | 
| description | Case description. May use HTML, which will be sanitized. . | Required | 
| customer_reference | Customer reference for case. | Optional | 
| priority | Priority of case to create. (default medium). Possible values are: low, medium, high, critical. Default is medium. | Optional | 
| access_mode | Access mode for new case. (default roleBased). | Optional | 
| origin_email_address | If case is created from an email, specify origin email address here. | Optional | 
| publish | Whether to publish new case. Creating an unpublished case requires special permission. (default true). Possible values are: true, false. Default is true. | Optional | 
| default_watchers | Whether to enable default watchers for this case. If set to false, default watchers will not be enabled, and will not be notified upon creation of this case. (default true). Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | API response metadata, response code of this request | 
| Argus.Case.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Case.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Case.count | Number | API response metadata, total number of results this query has | 
| Argus.Case.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Case.messages.message | String | Case Messages Message | 
| Argus.Case.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Case.messages.type | String | Case Messages Type | 
| Argus.Case.messages.field | String | Case Messages Field | 
| Argus.Case.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Case.data.id | Number | Case ID | 
| Argus.Case.data.customer.id | Number | Case Customer ID | 
| Argus.Case.data.customer.name | String | Case Customer Name | 
| Argus.Case.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Case.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Case.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Case.data.service.id | Number | Case Service ID | 
| Argus.Case.data.service.name | String | Case Service Name | 
| Argus.Case.data.service.shortName | String | Case Service Short Name | 
| Argus.Case.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Case.data.category.id | Number | Case Category ID | 
| Argus.Case.data.category.name | String | Case Category Name | 
| Argus.Case.data.category.shortName | String | Case Category Short Name | 
| Argus.Case.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Case.data.type | String | Case Type | 
| Argus.Case.data.initialStatus | String | Case Initial Status | 
| Argus.Case.data.status | String | Case Status | 
| Argus.Case.data.initialPriority | String | Case Initial Priority | 
| Argus.Case.data.priority | String | Case Priority | 
| Argus.Case.data.subject | String | Case Subject | 
| Argus.Case.data.description | String | Case Description | 
| Argus.Case.data.customerReference | String | Case Customer Reference | 
| Argus.Case.data.accessMode | String | Case Access Mode | 
| Argus.Case.data.reporter.id | Number | Case Reporter ID | 
| Argus.Case.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Case.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Case.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Case.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Case.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Case.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Case.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Case.data.reporter.name | String | Case Reporter Name | 
| Argus.Case.data.reporter.type | String | Case Reporter Type | 
| Argus.Case.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Case.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Case.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Case.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Case.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Case.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Case.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Case.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Case.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Case.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Case.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Case.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Case.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Case.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Case.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Case.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Case.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Case.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Case.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Case.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Case.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Case.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Case.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Case.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Case.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Case.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Case.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Case.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Case.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Case.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Case.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Case.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Case.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Case.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Case.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Case.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Case.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Case.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Case.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Case.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Case.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Case.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Case.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Case.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Case.data.flags | String | Case Flags | 
| Argus.Case.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Case.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Case.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Case.data.workflows.state | String | Case Workflows State | 
| Argus.Case.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Case.data.createdTime | String | Case Created Time | 
| Argus.Case.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Case.data.closedTime | String | Case Closed Time | 
| Argus.Case.data.publishedTime | String | Case Published Time | 

#### Command Example
``` !argus-create-case subject="test case title" description="test case details" service=administrative type=informational ```

### argus-delete-case
***
Mark existing case as deleted


#### Base Command

`argus-delete-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case to mark as deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | API response metadata, response code of this request | 
| Argus.Case.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Case.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Case.count | Number | API response metadata, total number of results this query has | 
| Argus.Case.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Case.messages.message | String | Case Messages Message | 
| Argus.Case.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Case.messages.type | String | Case Messages Type | 
| Argus.Case.messages.field | String | Case Messages Field | 
| Argus.Case.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Case.data.id | Number | Case ID | 
| Argus.Case.data.customer.id | Number | Case Customer ID | 
| Argus.Case.data.customer.name | String | Case Customer Name | 
| Argus.Case.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Case.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Case.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Case.data.service.id | Number | Case Service ID | 
| Argus.Case.data.service.name | String | Case Service Name | 
| Argus.Case.data.service.shortName | String | Case Service Short Name | 
| Argus.Case.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Case.data.category.id | Number | Case Category ID | 
| Argus.Case.data.category.name | String | Case Category Name | 
| Argus.Case.data.category.shortName | String | Case Category Short Name | 
| Argus.Case.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Case.data.type | String | Case Type | 
| Argus.Case.data.initialStatus | String | Case Initial Status | 
| Argus.Case.data.status | String | Case Status | 
| Argus.Case.data.initialPriority | String | Case Initial Priority | 
| Argus.Case.data.priority | String | Case Priority | 
| Argus.Case.data.subject | String | Case Subject | 
| Argus.Case.data.description | String | Case Description | 
| Argus.Case.data.customerReference | String | Case Customer Reference | 
| Argus.Case.data.accessMode | String | Case Access Mode | 
| Argus.Case.data.reporter.id | Number | Case Reporter ID | 
| Argus.Case.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Case.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Case.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Case.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Case.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Case.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Case.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Case.data.reporter.name | String | Case Reporter Name | 
| Argus.Case.data.reporter.type | String | Case Reporter Type | 
| Argus.Case.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Case.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Case.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Case.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Case.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Case.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Case.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Case.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Case.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Case.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Case.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Case.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Case.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Case.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Case.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Case.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Case.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Case.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Case.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Case.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Case.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Case.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Case.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Case.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Case.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Case.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Case.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Case.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Case.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Case.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Case.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Case.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Case.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Case.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Case.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Case.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Case.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Case.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Case.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Case.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Case.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Case.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Case.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Case.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Case.data.flags | String | Case Flags | 
| Argus.Case.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Case.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Case.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Case.data.workflows.state | String | Case Workflows State | 
| Argus.Case.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Case.data.createdTime | String | Case Created Time | 
| Argus.Case.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Case.data.closedTime | String | Case Closed Time | 
| Argus.Case.data.publishedTime | String | Case Published Time | 

#### Command Example
``` !argus-delete-case case_id=123 ```

### argus-delete-comment
***
Mark existing comment as deleted


#### Base Command

`argus-delete-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case where comment exists. | Required | 
| comment_id | ID of comment to mark as deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | API response metadata, response code of this request | 
| Argus.Comment.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Comment.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Comment.count | Number | API response metadata, total number of results this query has | 
| Argus.Comment.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Comment.messages.message | String | Comment Messages Message | 
| Argus.Comment.messages.messageTemplate | String | Comment Messages Message Template | 
| Argus.Comment.messages.type | String | Comment Messages Type | 
| Argus.Comment.messages.field | String | Comment Messages Field | 
| Argus.Comment.messages.timestamp | Number | Comment Messages Timestamp | 
| Argus.Comment.data.id | String | Comment ID | 
| Argus.Comment.data.addedTimestamp | Number | Comment Added Timestamp | 
| Argus.Comment.data.addedByUser.id | Number | Comment Added By User ID | 
| Argus.Comment.data.addedByUser.customerID | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.id | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.name | String | Comment Added By User Customer Name | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Comment Added By User Customer Short Name | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Comment Added By User Customer Domain ID | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Comment Added By User Customer Domain Name | 
| Argus.Comment.data.addedByUser.domain.id | Number | Comment Added By User Domain ID | 
| Argus.Comment.data.addedByUser.domain.name | String | Comment Added By User Domain Name | 
| Argus.Comment.data.addedByUser.userName | String | Comment Added By User User Name | 
| Argus.Comment.data.addedByUser.name | String | Comment Added By User Name | 
| Argus.Comment.data.addedByUser.type | String | Comment Added By User Type | 
| Argus.Comment.data.comment | String | Comment Comment | 
| Argus.Comment.data.flags | String | Comment Flags | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Comment Last Updated Timestamp | 
| Argus.Comment.data.status | String | Comment Status | 
| Argus.Comment.data.priority | String | Comment Priority | 
| Argus.Comment.data.originEmailAddress | String | Comment Origin Email Address | 
| Argus.Comment.data.associatedAttachments.id | String | Comment Associated Attachments ID | 
| Argus.Comment.data.associatedAttachments.name | String | Comment Associated Attachments Name | 
| Argus.Comment.data.references.type | String | Comment References Type | 
| Argus.Comment.data.references.commentID | String | Comment References Comment ID | 
| Argus.Comment.data.lastUpdatedTime | String | Comment Last Updated Time | 
| Argus.Comment.data.addedTime | String | Comment Added Time | 

#### Command Example
``` !argus-delete-comment case_id=123 comment_id=123456 ```


### argus-edit-comment
***
Edit existing comment


#### Base Command

`argus-edit-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case where comment exists. | Required | 
| comment_id | ID of comment to edit. | Required | 
| comment | Comment text which will replace the current text. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | API response metadata, response code of this request | 
| Argus.Comment.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Comment.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Comment.count | Number | API response metadata, total number of results this query has | 
| Argus.Comment.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Comment.messages.message | String | Comment Messages Message | 
| Argus.Comment.messages.messageTemplate | String | Comment Messages Message Template | 
| Argus.Comment.messages.type | String | Comment Messages Type | 
| Argus.Comment.messages.field | String | Comment Messages Field | 
| Argus.Comment.messages.timestamp | Number | Comment Messages Timestamp | 
| Argus.Comment.data.id | String | Comment ID | 
| Argus.Comment.data.addedTimestamp | Number | Comment Added Timestamp | 
| Argus.Comment.data.addedByUser.id | Number | Comment Added By User ID | 
| Argus.Comment.data.addedByUser.customerID | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.id | Number | Comment Added By User Customer ID | 
| Argus.Comment.data.addedByUser.customer.name | String | Comment Added By User Customer Name | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Comment Added By User Customer Short Name | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Comment Added By User Customer Domain ID | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Comment Added By User Customer Domain Name | 
| Argus.Comment.data.addedByUser.domain.id | Number | Comment Added By User Domain ID | 
| Argus.Comment.data.addedByUser.domain.name | String | Comment Added By User Domain Name | 
| Argus.Comment.data.addedByUser.userName | String | Comment Added By User User Name | 
| Argus.Comment.data.addedByUser.name | String | Comment Added By User Name | 
| Argus.Comment.data.addedByUser.type | String | Comment Added By User Type | 
| Argus.Comment.data.comment | String | Comment Comment | 
| Argus.Comment.data.flags | String | Comment Flags | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Comment Last Updated Timestamp | 
| Argus.Comment.data.status | String | Comment Status | 
| Argus.Comment.data.priority | String | Comment Priority | 
| Argus.Comment.data.originEmailAddress | String | Comment Origin Email Address | 
| Argus.Comment.data.associatedAttachments.id | String | Comment Associated Attachments ID | 
| Argus.Comment.data.associatedAttachments.name | String | Comment Associated Attachments Name | 
| Argus.Comment.data.references.type | String | Comment References Type | 
| Argus.Comment.data.references.commentID | String | Comment References Comment ID | 
| Argus.Comment.data.lastUpdatedTime | String | Comment Last Updated Time | 
| Argus.Comment.data.addedTime | String | Comment Added Time | 

#### Command Example
``` !argus-edit-comment case_id=123 comment_id=123456 comment="comment content" ```

### argus-get-case-metadata-by-id
***
Returns the basic case descriptor for the case identified by ID


#### Base Command

`argus-get-case-metadata-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| skip_redirect | If true, skip automatic redirect (for merged cases). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | API response metadata, response code of this request | 
| Argus.Case.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Case.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Case.count | Number | API response metadata, total number of results this query has | 
| Argus.Case.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Case.messages.message | String | Case Messages Message | 
| Argus.Case.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Case.messages.type | String | Case Messages Type | 
| Argus.Case.messages.field | String | Case Messages Field | 
| Argus.Case.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Case.data.id | Number | Case ID | 
| Argus.Case.data.customer.id | Number | Case Customer ID | 
| Argus.Case.data.customer.name | String | Case Customer Name | 
| Argus.Case.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Case.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Case.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Case.data.service.id | Number | Case Service ID | 
| Argus.Case.data.service.name | String | Case Service Name | 
| Argus.Case.data.service.shortName | String | Case Service Short Name | 
| Argus.Case.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Case.data.category.id | Number | Case Category ID | 
| Argus.Case.data.category.name | String | Case Category Name | 
| Argus.Case.data.category.shortName | String | Case Category Short Name | 
| Argus.Case.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Case.data.type | String | Case Type | 
| Argus.Case.data.initialStatus | String | Case Initial Status | 
| Argus.Case.data.status | String | Case Status | 
| Argus.Case.data.initialPriority | String | Case Initial Priority | 
| Argus.Case.data.priority | String | Case Priority | 
| Argus.Case.data.subject | String | Case Subject | 
| Argus.Case.data.description | String | Case Description | 
| Argus.Case.data.customerReference | String | Case Customer Reference | 
| Argus.Case.data.accessMode | String | Case Access Mode | 
| Argus.Case.data.reporter.id | Number | Case Reporter ID | 
| Argus.Case.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Case.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Case.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Case.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Case.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Case.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Case.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Case.data.reporter.name | String | Case Reporter Name | 
| Argus.Case.data.reporter.type | String | Case Reporter Type | 
| Argus.Case.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Case.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Case.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Case.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Case.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Case.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Case.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Case.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Case.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Case.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Case.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Case.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Case.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Case.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Case.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Case.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Case.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Case.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Case.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Case.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Case.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Case.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Case.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Case.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Case.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Case.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Case.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Case.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Case.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Case.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Case.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Case.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Case.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Case.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Case.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Case.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Case.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Case.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Case.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Case.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Case.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Case.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Case.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Case.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Case.data.flags | String | Case Flags | 
| Argus.Case.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Case.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Case.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Case.data.workflows.state | String | Case Workflows State | 
| Argus.Case.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Case.data.createdTime | String | Case Created Time | 
| Argus.Case.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Case.data.closedTime | String | Case Closed Time | 
| Argus.Case.data.publishedTime | String | Case Published Time | 

#### Command Example
``` !argus-get-case_metadata_by_id case_id=123 ```

### argus-list-case-attachments
***
List attachments for an existing case


#### Base Command

`argus-list-case-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| limit | Maximum number of returned results. | Optional | 
| offset | Skip a number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Attachments.responseCode | Number | API response metadata, response code of this request | 
| Argus.Attachments.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Attachments.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Attachments.count | Number | API response metadata, total number of results this query has | 
| Argus.Attachments.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Attachments.messages.message | String | Attachment Messages Message | 
| Argus.Attachments.messages.messageTemplate | String | Attachment Messages Message Template | 
| Argus.Attachments.messages.type | String | Attachment Messages Type | 
| Argus.Attachments.messages.field | String | Attachment Messages Field | 
| Argus.Attachments.messages.timestamp | Number | Attachment Messages Timestamp | 
| Argus.Attachments.data.id | String | Attachment ID | 
| Argus.Attachments.data.addedTimestamp | Number | Attachment Added Timestamp | 
| Argus.Attachments.data.addedByUser.id | Number | Attachment Added By User ID | 
| Argus.Attachments.data.addedByUser.customerID | Number | Attachment Added By User Customer ID | 
| Argus.Attachments.data.addedByUser.customer.id | Number | Attachment Added By User Customer ID | 
| Argus.Attachments.data.addedByUser.customer.name | String | Attachment Added By User Customer Name | 
| Argus.Attachments.data.addedByUser.customer.shortName | String | Attachment Added By User Customer Short Name | 
| Argus.Attachments.data.addedByUser.customer.domain.id | Number | Attachment Added By User Customer Domain ID | 
| Argus.Attachments.data.addedByUser.customer.domain.name | String | Attachment Added By User Customer Domain Name | 
| Argus.Attachments.data.addedByUser.domain.id | Number | Attachment Added By User Domain ID | 
| Argus.Attachments.data.addedByUser.domain.name | String | Attachment Added By User Domain Name | 
| Argus.Attachments.data.addedByUser.userName | String | Attachment Added By User User Name | 
| Argus.Attachments.data.addedByUser.name | String | Attachment Added By User Name | 
| Argus.Attachments.data.addedByUser.type | String | Attachment Added By User Type | 
| Argus.Attachments.data.name | String | Attachment Name | 
| Argus.Attachments.data.mimeType | String | Attachment Mime Type | 
| Argus.Attachments.data.flags | String | Attachment Flags | 
| Argus.Attachments.data.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Attachments.data.originEmailAddress | String | Attachment Origin Email Address | 
| Argus.Attachments.data.addedTime | String | Attachment Added Time | 

#### Command Example
``` !argus-list-case-attachments case_id=123 ```

### argus-remove-case-tag-by-id
***
Remove existing tag by tag ID


#### Base Command

`argus-remove-case-tag-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| tag_id | ID of tag to remove. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | API response metadata, response code of this request | 
| Argus.Tags.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Tags.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Tags.count | Number | API response metadata, total number of results this query has | 
| Argus.Tags.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Tags.messages.message | String | Tag Messages Message | 
| Argus.Tags.messages.messageTemplate | String | Tag Messages Message Template | 
| Argus.Tags.messages.type | String | Tag Messages Type | 
| Argus.Tags.messages.field | String | Tag Messages Field | 
| Argus.Tags.messages.timestamp | Number | Tag Messages Timestamp | 
| Argus.Tags.data.id | String | Tag ID | 
| Argus.Tags.data.key | String | Tag Key | 
| Argus.Tags.data.value | String | Tag Value | 
| Argus.Tags.data.addedTimestamp | Number | Tag Added Timestamp | 
| Argus.Tags.data.addedByUser.id | Number | Tag Added By User ID | 
| Argus.Tags.data.addedByUser.customerID | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.id | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.name | String | Tag Added By User Customer Name | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Tag Added By User Customer Short Name | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Tag Added By User Customer Domain ID | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Tag Added By User Customer Domain Name | 
| Argus.Tags.data.addedByUser.domain.id | Number | Tag Added By User Domain ID | 
| Argus.Tags.data.addedByUser.domain.name | String | Tag Added By User Domain Name | 
| Argus.Tags.data.addedByUser.userName | String | Tag Added By User User Name | 
| Argus.Tags.data.addedByUser.name | String | Tag Added By User Name | 
| Argus.Tags.data.addedByUser.type | String | Tag Added By User Type | 
| Argus.Tags.data.flags | String | Tag Flags | 
| Argus.Tags.data.addedTime | String | Tag Added Time | 

#### Command Example
``` !argus-remove-case-tag-by-id case_id=123 tag_id=123456 ```

### argus-remove-case-tag-by-key-value
***
Remove existing tag with key, value matching


#### Base Command

`argus-remove-case-tag-by-key-value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| key | Key of tag to remove. | Required | 
| value | Value of tag to remove. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | API response metadata, response code of this request | 
| Argus.Tags.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Tags.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Tags.count | Number | API response metadata, total number of results this query has | 
| Argus.Tags.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Tags.messages.message | String | Tag Messages Message | 
| Argus.Tags.messages.messageTemplate | String | Tag Messages Message Template | 
| Argus.Tags.messages.type | String | Tag Messages Type | 
| Argus.Tags.messages.field | String | Tag Messages Field | 
| Argus.Tags.messages.timestamp | Number | Tag Messages Timestamp | 
| Argus.Tags.data.id | String | Tag ID | 
| Argus.Tags.data.key | String | Tag Key | 
| Argus.Tags.data.value | String | Tag Value | 
| Argus.Tags.data.addedTimestamp | Number | Tag Added Timestamp | 
| Argus.Tags.data.addedByUser.id | Number | Tag Added By User ID | 
| Argus.Tags.data.addedByUser.customerID | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.id | Number | Tag Added By User Customer ID | 
| Argus.Tags.data.addedByUser.customer.name | String | Tag Added By User Customer Name | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Tag Added By User Customer Short Name | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Tag Added By User Customer Domain ID | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Tag Added By User Customer Domain Name | 
| Argus.Tags.data.addedByUser.domain.id | Number | Tag Added By User Domain ID | 
| Argus.Tags.data.addedByUser.domain.name | String | Tag Added By User Domain Name | 
| Argus.Tags.data.addedByUser.userName | String | Tag Added By User User Name | 
| Argus.Tags.data.addedByUser.name | String | Tag Added By User Name | 
| Argus.Tags.data.addedByUser.type | String | Tag Added By User Type | 
| Argus.Tags.data.flags | String | Tag Flags | 
| Argus.Tags.data.addedTime | String | Tag Added Time | 

#### Command Example
``` !argus-remove-case-tag-by-key-value case_id=123 key=foo value=bar ```

### argus-update-case
***
Request changes to basic fields of an existing case.


#### Base Command

`argus-update-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case to update. | Required | 
| subject | If set, change subject of case. | Optional | 
| description | If set, change description of case. May use HTML, will be sanitized. . | Optional | 
| status | If set, change status of case Possible values are: pendingCustomer, pendingSoc, pendingVendor, pendingClose, workingSoc, workingCustomer. | Optional | 
| priority | If set, change priority of case.  Possible values are: low, medium, high, critical. | Optional | 
| category | If set, assign given category to specified category (by category shortname). Set value to empty string to unset category. Possible values are: network-testing, unauthorized-access, dos, data-leakage, exposed-malicious, malicious-infection, poor-practice, reconnaissance, misconfigured, vpn-down, sensor-malfunctioning, not-receiving-traffic, false-positive, suspected-targeted-attack, duplicate, problem-managed, problem-customer, adware, network-connection-lost, failed-authentication, missing-log-sources, no-threat, phishing, argus-improvement, argus-bug. | Optional | 
| reporter | If set, set given user as reporter for case (by ID or shortname). Shortname will be resolved in the current users domain.  | Optional | 
| assigned_user | If set, assign given user to case (by ID or shortname). Shortname will be resolved in the current users domain. If blank, this will unset assignedUser. . | Optional | 
| assigned_tech | If set, assign given technical user (solution engineer) to case (by ID or shortname). Shortname will be resolved in the current users domain. If blank, this will unset assignedTech. | Optional | 
| customer_reference | If set, change customer reference for case.  | Optional | 
| comment | If set, add comment to case. May use HTML, will be sanitized.  | Optional | 
| origin_email_address | If update is made from an email, specify origin email address here. | Optional | 
| has_events | f set, update the hasEvents flag for this case, signalling that this case may have events associated to it. . Possible values are: true, false. | Optional | 
| internal_comment | If true, add comment as internal. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | API response metadata, response code of this request | 
| Argus.Case.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Case.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Case.count | Number | API response metadata, total number of results this query has | 
| Argus.Case.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Case.messages.message | String | Case Messages Message | 
| Argus.Case.messages.messageTemplate | String | Case Messages Message Template | 
| Argus.Case.messages.type | String | Case Messages Type | 
| Argus.Case.messages.field | String | Case Messages Field | 
| Argus.Case.messages.timestamp | Number | Case Messages Timestamp | 
| Argus.Case.data.id | Number | Case ID | 
| Argus.Case.data.customer.id | Number | Case Customer ID | 
| Argus.Case.data.customer.name | String | Case Customer Name | 
| Argus.Case.data.customer.shortName | String | Case Customer Short Name | 
| Argus.Case.data.customer.domain.id | Number | Case Customer Domain ID | 
| Argus.Case.data.customer.domain.name | String | Case Customer Domain Name | 
| Argus.Case.data.service.id | Number | Case Service ID | 
| Argus.Case.data.service.name | String | Case Service Name | 
| Argus.Case.data.service.shortName | String | Case Service Short Name | 
| Argus.Case.data.service.localizedName | String | Case Service Localized Name | 
| Argus.Case.data.category.id | Number | Case Category ID | 
| Argus.Case.data.category.name | String | Case Category Name | 
| Argus.Case.data.category.shortName | String | Case Category Short Name | 
| Argus.Case.data.category.localizedName | String | Case Category Localized Name | 
| Argus.Case.data.type | String | Case Type | 
| Argus.Case.data.initialStatus | String | Case Initial Status | 
| Argus.Case.data.status | String | Case Status | 
| Argus.Case.data.initialPriority | String | Case Initial Priority | 
| Argus.Case.data.priority | String | Case Priority | 
| Argus.Case.data.subject | String | Case Subject | 
| Argus.Case.data.description | String | Case Description | 
| Argus.Case.data.customerReference | String | Case Customer Reference | 
| Argus.Case.data.accessMode | String | Case Access Mode | 
| Argus.Case.data.reporter.id | Number | Case Reporter ID | 
| Argus.Case.data.reporter.customerID | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.id | Number | Case Reporter Customer ID | 
| Argus.Case.data.reporter.customer.name | String | Case Reporter Customer Name | 
| Argus.Case.data.reporter.customer.shortName | String | Case Reporter Customer Short Name | 
| Argus.Case.data.reporter.customer.domain.id | Number | Case Reporter Customer Domain ID | 
| Argus.Case.data.reporter.customer.domain.name | String | Case Reporter Customer Domain Name | 
| Argus.Case.data.reporter.domain.id | Number | Case Reporter Domain ID | 
| Argus.Case.data.reporter.domain.name | String | Case Reporter Domain Name | 
| Argus.Case.data.reporter.userName | String | Case Reporter User Name | 
| Argus.Case.data.reporter.name | String | Case Reporter Name | 
| Argus.Case.data.reporter.type | String | Case Reporter Type | 
| Argus.Case.data.assignedUser.id | Number | Case Assigned User ID | 
| Argus.Case.data.assignedUser.customerID | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.id | Number | Case Assigned User Customer ID | 
| Argus.Case.data.assignedUser.customer.name | String | Case Assigned User Customer Name | 
| Argus.Case.data.assignedUser.customer.shortName | String | Case Assigned User Customer Short Name | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Case Assigned User Customer Domain ID | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Case Assigned User Customer Domain Name | 
| Argus.Case.data.assignedUser.domain.id | Number | Case Assigned User Domain ID | 
| Argus.Case.data.assignedUser.domain.name | String | Case Assigned User Domain Name | 
| Argus.Case.data.assignedUser.userName | String | Case Assigned User User Name | 
| Argus.Case.data.assignedUser.name | String | Case Assigned User Name | 
| Argus.Case.data.assignedUser.type | String | Case Assigned User Type | 
| Argus.Case.data.assignedTech.id | Number | Case Assigned Tech ID | 
| Argus.Case.data.assignedTech.customerID | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.id | Number | Case Assigned Tech Customer ID | 
| Argus.Case.data.assignedTech.customer.name | String | Case Assigned Tech Customer Name | 
| Argus.Case.data.assignedTech.customer.shortName | String | Case Assigned Tech Customer Short Name | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Case Assigned Tech Customer Domain ID | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Case Assigned Tech Customer Domain Name | 
| Argus.Case.data.assignedTech.domain.id | Number | Case Assigned Tech Domain ID | 
| Argus.Case.data.assignedTech.domain.name | String | Case Assigned Tech Domain Name | 
| Argus.Case.data.assignedTech.userName | String | Case Assigned Tech User Name | 
| Argus.Case.data.assignedTech.name | String | Case Assigned Tech Name | 
| Argus.Case.data.assignedTech.type | String | Case Assigned Tech Type | 
| Argus.Case.data.createdTimestamp | Number | Case Created Timestamp | 
| Argus.Case.data.createdByUser.id | Number | Case Created By User ID | 
| Argus.Case.data.createdByUser.customerID | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.id | Number | Case Created By User Customer ID | 
| Argus.Case.data.createdByUser.customer.name | String | Case Created By User Customer Name | 
| Argus.Case.data.createdByUser.customer.shortName | String | Case Created By User Customer Short Name | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Case Created By User Customer Domain ID | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Case Created By User Customer Domain Name | 
| Argus.Case.data.createdByUser.domain.id | Number | Case Created By User Domain ID | 
| Argus.Case.data.createdByUser.domain.name | String | Case Created By User Domain Name | 
| Argus.Case.data.createdByUser.userName | String | Case Created By User User Name | 
| Argus.Case.data.createdByUser.name | String | Case Created By User Name | 
| Argus.Case.data.createdByUser.type | String | Case Created By User Type | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Case Last Updated Timestamp | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Case Last Updated By User ID | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Case Last Updated By User Customer ID | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Case Last Updated By User Customer Name | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Case Last Updated By User Customer Short Name | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Case Last Updated By User Customer Domain ID | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Case Last Updated By User Customer Domain Name | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Case Last Updated By User Domain ID | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Case Last Updated By User Domain Name | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Case Last Updated By User User Name | 
| Argus.Case.data.lastUpdatedByUser.name | String | Case Last Updated By User Name | 
| Argus.Case.data.lastUpdatedByUser.type | String | Case Last Updated By User Type | 
| Argus.Case.data.closedTimestamp | Number | Case Closed Timestamp | 
| Argus.Case.data.closedByUser.id | Number | Case Closed By User ID | 
| Argus.Case.data.closedByUser.customerID | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.id | Number | Case Closed By User Customer ID | 
| Argus.Case.data.closedByUser.customer.name | String | Case Closed By User Customer Name | 
| Argus.Case.data.closedByUser.customer.shortName | String | Case Closed By User Customer Short Name | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Case Closed By User Customer Domain ID | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Case Closed By User Customer Domain Name | 
| Argus.Case.data.closedByUser.domain.id | Number | Case Closed By User Domain ID | 
| Argus.Case.data.closedByUser.domain.name | String | Case Closed By User Domain Name | 
| Argus.Case.data.closedByUser.userName | String | Case Closed By User User Name | 
| Argus.Case.data.closedByUser.name | String | Case Closed By User Name | 
| Argus.Case.data.closedByUser.type | String | Case Closed By User Type | 
| Argus.Case.data.publishedTimestamp | Number | Case Published Timestamp | 
| Argus.Case.data.publishedByUser.id | Number | Case Published By User ID | 
| Argus.Case.data.publishedByUser.customerID | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.id | Number | Case Published By User Customer ID | 
| Argus.Case.data.publishedByUser.customer.name | String | Case Published By User Customer Name | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Case Published By User Customer Short Name | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Case Published By User Customer Domain ID | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Case Published By User Customer Domain Name | 
| Argus.Case.data.publishedByUser.domain.id | Number | Case Published By User Domain ID | 
| Argus.Case.data.publishedByUser.domain.name | String | Case Published By User Domain Name | 
| Argus.Case.data.publishedByUser.userName | String | Case Published By User User Name | 
| Argus.Case.data.publishedByUser.name | String | Case Published By User Name | 
| Argus.Case.data.publishedByUser.type | String | Case Published By User Type | 
| Argus.Case.data.flags | String | Case Flags | 
| Argus.Case.data.currentUserAccess.level | String | Case Current User Access Level | 
| Argus.Case.data.currentUserAccess.role | String | Case Current User Access Role | 
| Argus.Case.data.workflows.workflow | String | Case Workflows Workflow | 
| Argus.Case.data.workflows.state | String | Case Workflows State | 
| Argus.Case.data.originEmailAddress | String | Case Origin Email Address | 
| Argus.Case.data.createdTime | String | Case Created Time | 
| Argus.Case.data.lastUpdatedTime | String | Case Last Updated Time | 
| Argus.Case.data.closedTime | String | Case Closed Time | 
| Argus.Case.data.publishedTime | String | Case Published Time | 

#### Command Example
``` !argus-update-case case_id=123 ```

### argus-get-attachment
***
Fetch specific attachment metadata


#### Base Command

`argus-get-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| attachment_id | ID of attachement. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Attachment.responseCode | Number | API response metadata, response code of this request | 
| Argus.Attachment.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Attachment.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Attachment.count | Number | API response metadata, total number of results this query has | 
| Argus.Attachment.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Attachment.messages.message | String | Attachment Messages Message | 
| Argus.Attachment.messages.messageTemplate | String | Attachment Messages Message Template | 
| Argus.Attachment.messages.type | String | Attachment Messages Type | 
| Argus.Attachment.messages.field | String | Attachment Messages Field | 
| Argus.Attachment.messages.timestamp | Number | Attachment Messages Timestamp | 
| Argus.Attachment.data.id | String | Attachment ID | 
| Argus.Attachment.data.addedTimestamp | Number | Attachment Added Timestamp | 
| Argus.Attachment.data.addedByUser.id | Number | Attachment Added By User ID | 
| Argus.Attachment.data.addedByUser.customerID | Number | Attachment Added By User Customer ID | 
| Argus.Attachment.data.addedByUser.customer.id | Number | Attachment Added By User Customer ID | 
| Argus.Attachment.data.addedByUser.customer.name | String | Attachment Added By User Customer Name | 
| Argus.Attachment.data.addedByUser.customer.shortName | String | Attachment Added By User Customer Short Name | 
| Argus.Attachment.data.addedByUser.customer.domain.id | Number | Attachment Added By User Customer Domain ID | 
| Argus.Attachment.data.addedByUser.customer.domain.name | String | Attachment Added By User Customer Domain Name | 
| Argus.Attachment.data.addedByUser.domain.id | Number | Attachment Added By User Domain ID | 
| Argus.Attachment.data.addedByUser.domain.name | String | Attachment Added By User Domain Name | 
| Argus.Attachment.data.addedByUser.userName | String | Attachment Added By User User Name | 
| Argus.Attachment.data.addedByUser.name | String | Attachment Added By User Name | 
| Argus.Attachment.data.addedByUser.type | String | Attachment Added By User Type | 
| Argus.Attachment.data.name | String | Attachment Name | 
| Argus.Attachment.data.mimeType | String | Attachment Mime Type | 
| Argus.Attachment.data.flags | String | Attachment Flags | 
| Argus.Attachment.data.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Attachment.data.originEmailAddress | String | Attachment Origin Email Address | 
| Argus.Attachment.data.addedTime | String | Attachment Added Time | 

#### Command Example
``` !argus-get-attachment case_id=123 attachment_id=123456 ```

### argus-download-attachment
***
Download specific attachment contents.


#### Base Command

`argus-download-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| attachment_id | ID of attachment to download. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command Example
``` !argus-download-attachment case_id=123 attachment_id=123456 ```


### argus-get-events-for-case
***
Fetch events associated with specified case.


#### Base Command

`argus-get-events-for-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case. | Required | 
| limit | Maximum number of returned results (default 25). | Optional | 
| offset | Skip a number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Events.responseCode | Number | API response metadata, response code of this request | 
| Argus.Events.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Events.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Events.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Events.messages.message | String | Event Messages Message | 
| Argus.Events.messages.messageTemplate | String | Event Messages Message Template | 
| Argus.Events.messages.type | String | Event Messages Type | 
| Argus.Events.messages.field | String | Event Messages Field | 
| Argus.Events.messages.timestamp | Number | Event Messages Timestamp | 
| Argus.Events.data.customerInfo.id | Number | Event Customer Info ID | 
| Argus.Events.data.customerInfo.name | String | Event Customer Info Name | 
| Argus.Events.data.customerInfo.shortName | String | Event Customer Info Short Name | 
| Argus.Events.data.customerInfo.domain.id | Number | Event Customer Info Domain ID | 
| Argus.Events.data.customerInfo.domain.name | String | Event Customer Info Domain Name | 
| Argus.Events.data.properties.additionalProp1 | String | Event Properties Additional Prop 1 | 
| Argus.Events.data.properties.additionalProp2 | String | Event Properties Additional Prop 2 | 
| Argus.Events.data.properties.additionalProp3 | String | Event Properties Additional Prop 3 | 
| Argus.Events.data.comments.timestamp | Number | Event Comments Timestamp | 
| Argus.Events.data.comments.user.id | Number | Event Comments User ID | 
| Argus.Events.data.comments.user.customerID | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.id | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.name | String | Event Comments User Customer Name | 
| Argus.Events.data.comments.user.customer.shortName | String | Event Comments User Customer Short Name | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Event Comments User Customer Domain ID | 
| Argus.Events.data.comments.user.customer.domain.name | String | Event Comments User Customer Domain Name | 
| Argus.Events.data.comments.user.domain.id | Number | Event Comments User Domain ID | 
| Argus.Events.data.comments.user.domain.name | String | Event Comments User Domain Name | 
| Argus.Events.data.comments.user.userName | String | Event Comments User User Name | 
| Argus.Events.data.comments.user.name | String | Event Comments User Name | 
| Argus.Events.data.comments.user.type | String | Event Comments User Type | 
| Argus.Events.data.comments.comment | String | Event Comments Comment | 
| Argus.Events.data.associatedCase.id | Number | Event Associated Case ID | 
| Argus.Events.data.associatedCase.subject | String | Event Associated Case Subject | 
| Argus.Events.data.associatedCase.categoryID | Number | Event Associated Case Category ID | 
| Argus.Events.data.associatedCase.categoryName | String | Event Associated Case Category Name | 
| Argus.Events.data.associatedCase.service | String | Event Associated Case Service | 
| Argus.Events.data.associatedCase.status | String | Event Associated Case Status | 
| Argus.Events.data.associatedCase.priority | String | Event Associated Case Priority | 
| Argus.Events.data.location.shortName | String | Event Location Short Name | 
| Argus.Events.data.location.name | String | Event Location Name | 
| Argus.Events.data.location.timeZone | String | Event Location Time Zone | 
| Argus.Events.data.location.id | Number | Event Location ID | 
| Argus.Events.data.attackInfo.alarmID | Number | Event Attack Info Alarm ID | 
| Argus.Events.data.attackInfo.alarmDescription | String | Event Attack Info Alarm Description | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Event Attack Info Attack Category ID | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Event Attack Info Attack Category Name | 
| Argus.Events.data.attackInfo.signature | String | Event Attack Info Signature | 
| Argus.Events.data.domain.fqdn | String | Event Domain Fqdn | 
| Argus.Events.data.uri | String | Event Uri | 
| Argus.Events.data.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.data.source.port | Number | Event Source Port | 
| Argus.Events.data.source.geoLocation.countryCode | String | Event Source Geo Location Country Code | 
| Argus.Events.data.source.geoLocation.countryName | String | Event Source Geo Location Country Name | 
| Argus.Events.data.source.geoLocation.locationName | String | Event Source Geo Location Location Name | 
| Argus.Events.data.source.geoLocation.latitude | Number | Event Source Geo Location Latitude | 
| Argus.Events.data.source.geoLocation.longitude | Number | Event Source Geo Location Longitude | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Event Source Network Address Ipv 6 | 
| Argus.Events.data.source.networkAddress.public | Boolean | Event Source Network Address Public | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Event Source Network Address Mask Bits | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Event Source Network Address Multicast | 
| Argus.Events.data.source.networkAddress.host | Boolean | Event Source Network Address Host | 
| Argus.Events.data.source.networkAddress.address | String | Event Source Network Address Address | 
| Argus.Events.data.destination.port | Number | Event Destination Port | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Event Destination Geo Location Country Code | 
| Argus.Events.data.destination.geoLocation.countryName | String | Event Destination Geo Location Country Name | 
| Argus.Events.data.destination.geoLocation.locationName | String | Event Destination Geo Location Location Name | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Event Destination Geo Location Latitude | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Event Destination Geo Location Longitude | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Event Destination Network Address Ipv 6 | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Event Destination Network Address Public | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Event Destination Network Address Mask Bits | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Event Destination Network Address Multicast | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Event Destination Network Address Host | 
| Argus.Events.data.destination.networkAddress.address | String | Event Destination Network Address Address | 
| Argus.Events.data.protocol | String | Event Protocol | 
| Argus.Events.data.timestamp | Number | Event Timestamp | 
| Argus.Events.data.startTimestamp | Number | Event Start Timestamp | 
| Argus.Events.data.endTimestamp | Number | Event End Timestamp | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Event Last Updated Timestamp | 
| Argus.Events.data.flags | String | Event Flags | 
| Argus.Events.data.detailedEventIDS | String | Event Detailed Event IDS | 
| Argus.Events.data.severity | String | Event Severity | 
| Argus.Events.data.id | String | Event ID | 

#### Command Example
``` !argus_get_events_for_case case_id=123 ```

### argus-list-aggregated-events
***
List aggregated events


#### Base Command

`argus-list-aggregated-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Limit to customerID. | Optional | 
| signature | Limit to signature. | Optional | 
| ip | Limit to ip/network. | Optional | 
| start_timestamp | Limit to events after this timestamp (default is last 24 hours). | Optional | 
| end_timestamp | Limit to events before this timestamp. Defaults to now. | Optional | 
| limit | Limit results (default 25). | Optional | 
| offset | Skip a number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Events.responseCode | Number | API response metadata, response code of this request | 
| Argus.Events.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Events.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Events.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Events.messages.message | String | Event Messages Message | 
| Argus.Events.messages.messageTemplate | String | Event Messages Message Template | 
| Argus.Events.messages.type | String | Event Messages Type | 
| Argus.Events.messages.field | String | Event Messages Field | 
| Argus.Events.messages.timestamp | Number | Event Messages Timestamp | 
| Argus.Events.data.customerInfo.id | Number | Event Customer Info ID | 
| Argus.Events.data.customerInfo.name | String | Event Customer Info Name | 
| Argus.Events.data.customerInfo.shortName | String | Event Customer Info Short Name | 
| Argus.Events.data.customerInfo.domain.id | Number | Event Customer Info Domain ID | 
| Argus.Events.data.customerInfo.domain.name | String | Event Customer Info Domain Name | 
| Argus.Events.data.properties.additionalProp1 | String | Event Properties Additional Prop 1 | 
| Argus.Events.data.properties.additionalProp2 | String | Event Properties Additional Prop 2 | 
| Argus.Events.data.properties.additionalProp3 | String | Event Properties Additional Prop 3 | 
| Argus.Events.data.comments.timestamp | Number | Event Comments Timestamp | 
| Argus.Events.data.comments.user.id | Number | Event Comments User ID | 
| Argus.Events.data.comments.user.customerID | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.id | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.name | String | Event Comments User Customer Name | 
| Argus.Events.data.comments.user.customer.shortName | String | Event Comments User Customer Short Name | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Event Comments User Customer Domain ID | 
| Argus.Events.data.comments.user.customer.domain.name | String | Event Comments User Customer Domain Name | 
| Argus.Events.data.comments.user.domain.id | Number | Event Comments User Domain ID | 
| Argus.Events.data.comments.user.domain.name | String | Event Comments User Domain Name | 
| Argus.Events.data.comments.user.userName | String | Event Comments User User Name | 
| Argus.Events.data.comments.user.name | String | Event Comments User Name | 
| Argus.Events.data.comments.user.type | String | Event Comments User Type | 
| Argus.Events.data.comments.comment | String | Event Comments Comment | 
| Argus.Events.data.associatedCase.id | Number | Event Associated Case ID | 
| Argus.Events.data.associatedCase.subject | String | Event Associated Case Subject | 
| Argus.Events.data.associatedCase.categoryID | Number | Event Associated Case Category ID | 
| Argus.Events.data.associatedCase.categoryName | String | Event Associated Case Category Name | 
| Argus.Events.data.associatedCase.service | String | Event Associated Case Service | 
| Argus.Events.data.associatedCase.status | String | Event Associated Case Status | 
| Argus.Events.data.associatedCase.priority | String | Event Associated Case Priority | 
| Argus.Events.data.location.shortName | String | Event Location Short Name | 
| Argus.Events.data.location.name | String | Event Location Name | 
| Argus.Events.data.location.timeZone | String | Event Location Time Zone | 
| Argus.Events.data.location.id | Number | Event Location ID | 
| Argus.Events.data.attackInfo.alarmID | Number | Event Attack Info Alarm ID | 
| Argus.Events.data.attackInfo.alarmDescription | String | Event Attack Info Alarm Description | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Event Attack Info Attack Category ID | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Event Attack Info Attack Category Name | 
| Argus.Events.data.attackInfo.signature | String | Event Attack Info Signature | 
| Argus.Events.data.domain.fqdn | String | Event Domain Fqdn | 
| Argus.Events.data.uri | String | Event Uri | 
| Argus.Events.data.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.data.source.port | Number | Event Source Port | 
| Argus.Events.data.source.geoLocation.countryCode | String | Event Source Geo Location Country Code | 
| Argus.Events.data.source.geoLocation.countryName | String | Event Source Geo Location Country Name | 
| Argus.Events.data.source.geoLocation.locationName | String | Event Source Geo Location Location Name | 
| Argus.Events.data.source.geoLocation.latitude | Number | Event Source Geo Location Latitude | 
| Argus.Events.data.source.geoLocation.longitude | Number | Event Source Geo Location Longitude | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Event Source Network Address Ipv 6 | 
| Argus.Events.data.source.networkAddress.public | Boolean | Event Source Network Address Public | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Event Source Network Address Mask Bits | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Event Source Network Address Multicast | 
| Argus.Events.data.source.networkAddress.host | Boolean | Event Source Network Address Host | 
| Argus.Events.data.source.networkAddress.address | String | Event Source Network Address Address | 
| Argus.Events.data.destination.port | Number | Event Destination Port | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Event Destination Geo Location Country Code | 
| Argus.Events.data.destination.geoLocation.countryName | String | Event Destination Geo Location Country Name | 
| Argus.Events.data.destination.geoLocation.locationName | String | Event Destination Geo Location Location Name | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Event Destination Geo Location Latitude | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Event Destination Geo Location Longitude | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Event Destination Network Address Ipv 6 | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Event Destination Network Address Public | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Event Destination Network Address Mask Bits | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Event Destination Network Address Multicast | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Event Destination Network Address Host | 
| Argus.Events.data.destination.networkAddress.address | String | Event Destination Network Address Address | 
| Argus.Events.data.protocol | String | Event Protocol | 
| Argus.Events.data.timestamp | Number | Event Timestamp | 
| Argus.Events.data.startTimestamp | Number | Event Start Timestamp | 
| Argus.Events.data.endTimestamp | Number | Event End Timestamp | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Event Last Updated Timestamp | 
| Argus.Events.data.flags | String | Event Flags | 
| Argus.Events.data.detailedEventIDS | String | Event Detailed Event IDS | 
| Argus.Events.data.severity | String | Event Severity | 
| Argus.Events.data.id | String | Event ID | 


#### Command Example
``` !argus_list_aggregated_events  ```



### argus-find-aggregated-events
***
Search for aggregated events (OSB! advanced method: look in API doc)


#### Base Command

`argus-find-aggregated-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip_future_events | Skip future events. Possible values are: true, false. | Optional | 
| exclude | Exclude parameter. Possible values are: true, false. | Optional | 
| event_identifier | (as list). | Optional | 
| location_id | (as list). | Optional | 
| severity | (as list). | Optional | 
| customer | (as list). | Optional | 
| alarm_id | (as list). | Optional | 
| attack_category_id | (as list). | Optional | 
| source_geo_country | (as list). | Optional | 
| destination_geo_country | (as list). | Optional | 
| geo_country | (as list). | Optional | 
| properties | (as dict: key,value). | Optional | 
| exact_match_properties | Exact matching flag. Possible values are: true, false. | Optional | 
| sub_criteria | (as list). | Optional | 
| signature | (as list). | Optional | 
| last_updated_timestamp | Last updated timestamp. | Optional | 
| index_start_time | Index start time. | Optional | 
| index_end_time | Index end time. | Optional | 
| destination_ip | (as list). | Optional | 
| source_ip | (as list). | Optional | 
| ip | (as list). | Optional | 
| destination_port | (as list). | Optional | 
| source_port | (as list). | Optional | 
| port | (as lst). | Optional | 
| min_severity | Minimum severity. | Optional | 
| max_severity | Maximum severity. | Optional | 
| limit | Limit results (default 25). | Optional | 
| offset | Skip number of results. | Optional | 
| include_deleted | Include deleted events. Possible values are: true, false. | Optional | 
| min_count | Minimum count. | Optional | 
| associated_case_id | (as list). | Optional | 
| source_ip_min_bits | Source IP minimum bits. | Optional | 
| destination_ip_min_bits | Destination IP minimum bits. | Optional | 
| start_timestamp | Start timestamp. | Optional | 
| end_timestamp | End timestamp. | Optional | 
| sort_by | Order results by these properties (prefix with - to sort descending) (as list). | Optional | 
| include_flags | Search objects with these flags set  (as list). | Optional | 
| exclude_flags | Exclude objects with these flags set (as list). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Events.responseCode | Number | API response metadata, response code of this request | 
| Argus.Events.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Events.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Events.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Events.messages.message | String | Event Messages Message | 
| Argus.Events.messages.messageTemplate | String | Event Messages Message Template | 
| Argus.Events.messages.type | String | Event Messages Type | 
| Argus.Events.messages.field | String | Event Messages Field | 
| Argus.Events.messages.timestamp | Number | Event Messages Timestamp | 
| Argus.Events.data.customerInfo.id | Number | Event Customer Info ID | 
| Argus.Events.data.customerInfo.name | String | Event Customer Info Name | 
| Argus.Events.data.customerInfo.shortName | String | Event Customer Info Short Name | 
| Argus.Events.data.customerInfo.domain.id | Number | Event Customer Info Domain ID | 
| Argus.Events.data.customerInfo.domain.name | String | Event Customer Info Domain Name | 
| Argus.Events.data.properties.additionalProp1 | String | Event Properties Additional Prop 1 | 
| Argus.Events.data.properties.additionalProp2 | String | Event Properties Additional Prop 2 | 
| Argus.Events.data.properties.additionalProp3 | String | Event Properties Additional Prop 3 | 
| Argus.Events.data.comments.timestamp | Number | Event Comments Timestamp | 
| Argus.Events.data.comments.user.id | Number | Event Comments User ID | 
| Argus.Events.data.comments.user.customerID | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.id | Number | Event Comments User Customer ID | 
| Argus.Events.data.comments.user.customer.name | String | Event Comments User Customer Name | 
| Argus.Events.data.comments.user.customer.shortName | String | Event Comments User Customer Short Name | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Event Comments User Customer Domain ID | 
| Argus.Events.data.comments.user.customer.domain.name | String | Event Comments User Customer Domain Name | 
| Argus.Events.data.comments.user.domain.id | Number | Event Comments User Domain ID | 
| Argus.Events.data.comments.user.domain.name | String | Event Comments User Domain Name | 
| Argus.Events.data.comments.user.userName | String | Event Comments User User Name | 
| Argus.Events.data.comments.user.name | String | Event Comments User Name | 
| Argus.Events.data.comments.user.type | String | Event Comments User Type | 
| Argus.Events.data.comments.comment | String | Event Comments Comment | 
| Argus.Events.data.associatedCase.id | Number | Event Associated Case ID | 
| Argus.Events.data.associatedCase.subject | String | Event Associated Case Subject | 
| Argus.Events.data.associatedCase.categoryID | Number | Event Associated Case Category ID | 
| Argus.Events.data.associatedCase.categoryName | String | Event Associated Case Category Name | 
| Argus.Events.data.associatedCase.service | String | Event Associated Case Service | 
| Argus.Events.data.associatedCase.status | String | Event Associated Case Status | 
| Argus.Events.data.associatedCase.priority | String | Event Associated Case Priority | 
| Argus.Events.data.location.shortName | String | Event Location Short Name | 
| Argus.Events.data.location.name | String | Event Location Name | 
| Argus.Events.data.location.timeZone | String | Event Location Time Zone | 
| Argus.Events.data.location.id | Number | Event Location ID | 
| Argus.Events.data.attackInfo.alarmID | Number | Event Attack Info Alarm ID | 
| Argus.Events.data.attackInfo.alarmDescription | String | Event Attack Info Alarm Description | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Event Attack Info Attack Category ID | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Event Attack Info Attack Category Name | 
| Argus.Events.data.attackInfo.signature | String | Event Attack Info Signature | 
| Argus.Events.data.domain.fqdn | String | Event Domain Fqdn | 
| Argus.Events.data.uri | String | Event Uri | 
| Argus.Events.data.count | Number | API response metadata, total number of results this query has | 
| Argus.Events.data.source.port | Number | Event Source Port | 
| Argus.Events.data.source.geoLocation.countryCode | String | Event Source Geo Location Country Code | 
| Argus.Events.data.source.geoLocation.countryName | String | Event Source Geo Location Country Name | 
| Argus.Events.data.source.geoLocation.locationName | String | Event Source Geo Location Location Name | 
| Argus.Events.data.source.geoLocation.latitude | Number | Event Source Geo Location Latitude | 
| Argus.Events.data.source.geoLocation.longitude | Number | Event Source Geo Location Longitude | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Event Source Network Address Ipv 6 | 
| Argus.Events.data.source.networkAddress.public | Boolean | Event Source Network Address Public | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Event Source Network Address Mask Bits | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Event Source Network Address Multicast | 
| Argus.Events.data.source.networkAddress.host | Boolean | Event Source Network Address Host | 
| Argus.Events.data.source.networkAddress.address | String | Event Source Network Address Address | 
| Argus.Events.data.destination.port | Number | Event Destination Port | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Event Destination Geo Location Country Code | 
| Argus.Events.data.destination.geoLocation.countryName | String | Event Destination Geo Location Country Name | 
| Argus.Events.data.destination.geoLocation.locationName | String | Event Destination Geo Location Location Name | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Event Destination Geo Location Latitude | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Event Destination Geo Location Longitude | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Event Destination Network Address Ipv 6 | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Event Destination Network Address Public | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Event Destination Network Address Mask Bits | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Event Destination Network Address Multicast | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Event Destination Network Address Host | 
| Argus.Events.data.destination.networkAddress.address | String | Event Destination Network Address Address | 
| Argus.Events.data.protocol | String | Event Protocol | 
| Argus.Events.data.timestamp | Number | Event Timestamp | 
| Argus.Events.data.startTimestamp | Number | Event Start Timestamp | 
| Argus.Events.data.endTimestamp | Number | Event End Timestamp | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Event Last Updated Timestamp | 
| Argus.Events.data.flags | String | Event Flags | 
| Argus.Events.data.detailedEventIDS | String | Event Detailed Event IDS | 
| Argus.Events.data.severity | String | Event Severity | 
| Argus.Events.data.id | String | Event ID | 


#### Command Example
``` !argus-find-aggregated-events ```


### argus-get-payload
***
Fetch specified event payload


#### Base Command

`argus-get-payload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Event type. Possible values are: NIDS, AGGR, AGGRATTACK. | Required | 
| timestamp | Timestamp of event. | Required | 
| customer_id | ID of customer. | Required | 
| event_id | ID of related event. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Payload.responseCode | Number | API response metadata, response code of this request | 
| Argus.Payload.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Payload.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Payload.count | Number | API response metadata, total number of results this query has | 
| Argus.Payload.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Payload.messages.message | String | Payload Messages Message | 
| Argus.Payload.messages.messageTemplate | String | Payload Messages Message Template | 
| Argus.Payload.messages.type | String | Payload Messages Type | 
| Argus.Payload.messages.field | String | Payload Messages Field | 
| Argus.Payload.messages.timestamp | Number | Payload Messages Timestamp | 
| Argus.Payload.data.id | String | Payload ID | 
| Argus.Payload.data.type | String | Payload Type | 
| Argus.Payload.data.payload | String | Payload Payload | 


#### Command Example
``` !argus-get-payload customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```




### argus-get-pcap
***
Fetch specified event payload as PCAP.


#### Base Command

`argus-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Event type. Possible values are: NIDS, AGGR, AGGRATTACK. | Required | 
| timestamp | Timestamp of event. | Required | 
| customer_id | ID of customer. | Required | 
| event_id | ID of related event. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !argus-get-pcap customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```



### argus-get-event
***
Fetch specified event.


#### Base Command

`argus-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of event. Possible values are: NIDS, AGGR, AGGRATTACK. | Required | 
| timestamp | Timestamp of event. | Required | 
| customer_id | Customer ID related to event. | Required | 
| event_id | ID of event. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Event.responseCode | Number | API response metadata, response code of this request | 
| Argus.Event.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.Event.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.Event.count | Number | API response metadata, total number of results this query has | 
| Argus.Event.size | Number | API response metadata, the number of results returned in this request | 
| Argus.Event.messages.message | String | Event Messages Message | 
| Argus.Event.messages.messageTemplate | String | Event Messages Message Template | 
| Argus.Event.messages.type | String | Event Messages Type | 
| Argus.Event.messages.field | String | Event Messages Field | 
| Argus.Event.messages.timestamp | Number | Event Messages Timestamp | 
| Argus.Event.data.timestamp | Number | Event Timestamp | 
| Argus.Event.data.flags | Number | Event Flags | 
| Argus.Event.data.customerID | Number | Event Customer ID | 
| Argus.Event.data.aggregationKey | String | Event Aggregation Key | 
| Argus.Event.data.sourceType | String | Event Source Type | 
| Argus.Event.data.customerInfo.id | Number | Event Customer Info ID | 
| Argus.Event.data.customerInfo.name | String | Event Customer Info Name | 
| Argus.Event.data.customerInfo.shortName | String | Event Customer Info Short Name | 
| Argus.Event.data.customerInfo.domain.id | Number | Event Customer Info Domain ID | 
| Argus.Event.data.customerInfo.domain.name | String | Event Customer Info Domain Name | 
| Argus.Event.data.update | Boolean | Event Update | 
| Argus.Event.data.aggregated | Boolean | Event Aggregated | 
| Argus.Event.data.encodedFlags | String | Event Encoded Flags | 


#### Command Example
``` !argus-get-event customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```



### argus-list-nids-events
***
Simple search for NIDS events.


#### Base Command

`argus-list-nids-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Limit to customerID. | Optional | 
| signature | Limit to signature. | Optional | 
| ip | Limit to ip/network. | Optional | 
| start_timestamp | Limit to events after this timestamp (default is last 24 hours). | Optional | 
| end_timestamp | Limit to events before this timestamp (default: now). | Optional | 
| limit | Limit results (default: 25). | Optional | 
| offset | Skip a number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.NIDS.responseCode | Number | API response metadata, response code of this request | 
| Argus.NIDS.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.NIDS.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.NIDS.count | Number | API response metadata, total number of results this query has | 
| Argus.NIDS.size | Number | API response metadata, the number of results returned in this request | 
| Argus.NIDS.messages.message | String | NIDS Messages Message | 
| Argus.NIDS.messages.messageTemplate | String | NIDS Messages Message Template | 
| Argus.NIDS.messages.type | String | NIDS Messages Type | 
| Argus.NIDS.messages.field | String | NIDS Messages Field | 
| Argus.NIDS.messages.timestamp | Number | NIDS Messages Timestamp | 
| Argus.NIDS.data.customerInfo.id | Number | NIDS Customer Info ID | 
| Argus.NIDS.data.customerInfo.name | String | NIDS Customer Info Name | 
| Argus.NIDS.data.customerInfo.shortName | String | NIDS Customer Info Short Name | 
| Argus.NIDS.data.customerInfo.domain.id | Number | NIDS Customer Info Domain ID | 
| Argus.NIDS.data.customerInfo.domain.name | String | NIDS Customer Info Domain Name | 
| Argus.NIDS.data.properties.additionalProp1 | String | NIDS Properties Additional Prop 1 | 
| Argus.NIDS.data.properties.additionalProp2 | String | NIDS Properties Additional Prop 2 | 
| Argus.NIDS.data.properties.additionalProp3 | String | NIDS Properties Additional Prop 3 | 
| Argus.NIDS.data.comments.timestamp | Number | NIDS Comments Timestamp | 
| Argus.NIDS.data.comments.user.id | Number | NIDS Comments User ID | 
| Argus.NIDS.data.comments.user.customerID | Number | NIDS Comments User Customer ID | 
| Argus.NIDS.data.comments.user.customer.id | Number | NIDS Comments User Customer ID | 
| Argus.NIDS.data.comments.user.customer.name | String | NIDS Comments User Customer Name | 
| Argus.NIDS.data.comments.user.customer.shortName | String | NIDS Comments User Customer Short Name | 
| Argus.NIDS.data.comments.user.customer.domain.id | Number | NIDS Comments User Customer Domain ID | 
| Argus.NIDS.data.comments.user.customer.domain.name | String | NIDS Comments User Customer Domain Name | 
| Argus.NIDS.data.comments.user.domain.id | Number | NIDS Comments User Domain ID | 
| Argus.NIDS.data.comments.user.domain.name | String | NIDS Comments User Domain Name | 
| Argus.NIDS.data.comments.user.userName | String | NIDS Comments User User Name | 
| Argus.NIDS.data.comments.user.name | String | NIDS Comments User Name | 
| Argus.NIDS.data.comments.user.type | String | NIDS Comments User Type | 
| Argus.NIDS.data.comments.comment | String | NIDS Comments Comment | 
| Argus.NIDS.data.sensor.sensorID | Number | NIDS Sensor Sensor ID | 
| Argus.NIDS.data.sensor.hostName | String | NIDS Sensor Host Name | 
| Argus.NIDS.data.sensor.hostIpAddress.host | Boolean | NIDS Sensor Host Ip Address Host | 
| Argus.NIDS.data.sensor.hostIpAddress.ipv6 | Boolean | NIDS Sensor Host Ip Address Ipv 6 | 
| Argus.NIDS.data.sensor.hostIpAddress.public | Boolean | NIDS Sensor Host Ip Address Public | 
| Argus.NIDS.data.sensor.hostIpAddress.maskBits | Number | NIDS Sensor Host Ip Address Mask Bits | 
| Argus.NIDS.data.sensor.hostIpAddress.multicast | Boolean | NIDS Sensor Host Ip Address Multicast | 
| Argus.NIDS.data.sensor.hostIpAddress.address | String | NIDS Sensor Host Ip Address Address | 
| Argus.NIDS.data.sensor.hostIpString | String | NIDS Sensor Host Ip String | 
| Argus.NIDS.data.location.shortName | String | NIDS Location Short Name | 
| Argus.NIDS.data.location.name | String | NIDS Location Name | 
| Argus.NIDS.data.location.timeZone | String | NIDS Location Time Zone | 
| Argus.NIDS.data.location.id | Number | NIDS Location ID | 
| Argus.NIDS.data.attackInfo.alarmID | Number | NIDS Attack Info Alarm ID | 
| Argus.NIDS.data.attackInfo.alarmDescription | String | NIDS Attack Info Alarm Description | 
| Argus.NIDS.data.attackInfo.attackCategoryID | Number | NIDS Attack Info Attack Category ID | 
| Argus.NIDS.data.attackInfo.attackCategoryName | String | NIDS Attack Info Attack Category Name | 
| Argus.NIDS.data.attackInfo.signature | String | NIDS Attack Info Signature | 
| Argus.NIDS.data.count | Number | API response metadata, total number of results this query has | 
| Argus.NIDS.data.engineTimestamp | Number | NIDS Engine Timestamp | 
| Argus.NIDS.data.protocolID | Number | NIDS Protocol ID | 
| Argus.NIDS.data.domain.fqdn | String | NIDS Domain Fqdn | 
| Argus.NIDS.data.uri | String | NIDS Uri | 
| Argus.NIDS.data.source.port | Number | NIDS Source Port | 
| Argus.NIDS.data.source.geoLocation.countryCode | String | NIDS Source Geo Location Country Code | 
| Argus.NIDS.data.source.geoLocation.countryName | String | NIDS Source Geo Location Country Name | 
| Argus.NIDS.data.source.geoLocation.locationName | String | NIDS Source Geo Location Location Name | 
| Argus.NIDS.data.source.geoLocation.latitude | Number | NIDS Source Geo Location Latitude | 
| Argus.NIDS.data.source.geoLocation.longitude | Number | NIDS Source Geo Location Longitude | 
| Argus.NIDS.data.source.networkAddress.ipv6 | Boolean | NIDS Source Network Address Ipv 6 | 
| Argus.NIDS.data.source.networkAddress.public | Boolean | NIDS Source Network Address Public | 
| Argus.NIDS.data.source.networkAddress.maskBits | Number | NIDS Source Network Address Mask Bits | 
| Argus.NIDS.data.source.networkAddress.multicast | Boolean | NIDS Source Network Address Multicast | 
| Argus.NIDS.data.source.networkAddress.host | Boolean | NIDS Source Network Address Host | 
| Argus.NIDS.data.source.networkAddress.address | String | NIDS Source Network Address Address | 
| Argus.NIDS.data.destination.port | Number | NIDS Destination Port | 
| Argus.NIDS.data.destination.geoLocation.countryCode | String | NIDS Destination Geo Location Country Code | 
| Argus.NIDS.data.destination.geoLocation.countryName | String | NIDS Destination Geo Location Country Name | 
| Argus.NIDS.data.destination.geoLocation.locationName | String | NIDS Destination Geo Location Location Name | 
| Argus.NIDS.data.destination.geoLocation.latitude | Number | NIDS Destination Geo Location Latitude | 
| Argus.NIDS.data.destination.geoLocation.longitude | Number | NIDS Destination Geo Location Longitude | 
| Argus.NIDS.data.destination.networkAddress.ipv6 | Boolean | NIDS Destination Network Address Ipv 6 | 
| Argus.NIDS.data.destination.networkAddress.public | Boolean | NIDS Destination Network Address Public | 
| Argus.NIDS.data.destination.networkAddress.maskBits | Number | NIDS Destination Network Address Mask Bits | 
| Argus.NIDS.data.destination.networkAddress.multicast | Boolean | NIDS Destination Network Address Multicast | 
| Argus.NIDS.data.destination.networkAddress.host | Boolean | NIDS Destination Network Address Host | 
| Argus.NIDS.data.destination.networkAddress.address | String | NIDS Destination Network Address Address | 
| Argus.NIDS.data.timestamp | Number | NIDS Timestamp | 
| Argus.NIDS.data.severity | String | NIDS Severity | 
| Argus.NIDS.data.flags | String | NIDS Flags | 
| Argus.NIDS.data.id | String | NIDS ID | 


#### Command Example
``` !argus-list-nids-events  ```


### argus-find-nids-events
***
Search for NIDS events.


#### Base Command

`argus-find-nids-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip_future_events | Skip future evnts. Possible values are: true, false. | Optional | 
| exclude | Exclude. Possible values are: true, false. | Optional | 
| event_identifier | (as comma-separated list). | Optional | 
| location_id | (as comma-separated list). | Optional | 
| severity | (as comma-separated list). | Optional | 
| customer | (as comma-separated list). | Optional | 
| alarm_id | (as comma-separated list). | Optional | 
| attack_category_id | (as comma-separated list). | Optional | 
| source_geo_country | (as comma-separated list). | Optional | 
| destination_geo_country | (as comma-separated list). | Optional | 
| geo_country | (as comma-separated list). | Optional | 
| properties | As [key,value,key,value, ...] l. | Optional | 
| exact_match_properties | Use exact matching. Possible values are: true, false. | Optional | 
| sensor_id | (as comma-separated list). | Optional | 
| sub_criteria | (as comma-separated list). | Optional | 
| signature | (as comma-separated list). | Optional | 
| last_updated_timestamp | Last updated timestamp. | Optional | 
| index_start_time | Index start time. | Optional | 
| index_end_time | Index end time. | Optional | 
| destination_ip | (as comma-separated list). | Optional | 
| source_ip | (as comma-separated list). | Optional | 
| ip | (as comma-separated list). | Optional | 
| destination_port | (as comma-separated list). | Optional | 
| source_port | (as comma-separated list). | Optional | 
| port | source_port. | Optional | 
| min_severity | Minimum severity. | Optional | 
| max_severity | Maximum severity. | Optional | 
| limit | Limit number of results (default 25). | Optional | 
| offset | Skip a number of results. | Optional | 
| include_deleted | Inclide deleted events. Possible values are: true, false. | Optional | 
| start_timestamp | Search objects from this timestamp (default: -24hours). | Optional | 
| end_timestamp | Search objects until this timestamp  (default: now). | Optional | 
| sort_by | Order results by these properties (prefix with - to sort descending) (as comma-separated list). | Optional | 
| include_flags | (as comma-separated list). | Optional | 
| exclude_flags | (as comma-separated list). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.NIDS.responseCode | Number | API response metadata, response code of this request | 
| Argus.NIDS.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.NIDS.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.NIDS.count | Number | API response metadata, total number of results this query has | 
| Argus.NIDS.size | Number | API response metadata, the number of results returned in this request | 
| Argus.NIDS.messages.message | String | NIDS Messages Message | 
| Argus.NIDS.messages.messageTemplate | String | NIDS Messages Message Template | 
| Argus.NIDS.messages.type | String | NIDS Messages Type | 
| Argus.NIDS.messages.field | String | NIDS Messages Field | 
| Argus.NIDS.messages.timestamp | Number | NIDS Messages Timestamp | 
| Argus.NIDS.data.customerInfo.id | Number | NIDS Customer Info ID | 
| Argus.NIDS.data.customerInfo.name | String | NIDS Customer Info Name | 
| Argus.NIDS.data.customerInfo.shortName | String | NIDS Customer Info Short Name | 
| Argus.NIDS.data.customerInfo.domain.id | Number | NIDS Customer Info Domain ID | 
| Argus.NIDS.data.customerInfo.domain.name | String | NIDS Customer Info Domain Name | 
| Argus.NIDS.data.properties.additionalProp1 | String | NIDS Properties Additional Prop 1 | 
| Argus.NIDS.data.properties.additionalProp2 | String | NIDS Properties Additional Prop 2 | 
| Argus.NIDS.data.properties.additionalProp3 | String | NIDS Properties Additional Prop 3 | 
| Argus.NIDS.data.comments.timestamp | Number | NIDS Comments Timestamp | 
| Argus.NIDS.data.comments.user.id | Number | NIDS Comments User ID | 
| Argus.NIDS.data.comments.user.customerID | Number | NIDS Comments User Customer ID | 
| Argus.NIDS.data.comments.user.customer.id | Number | NIDS Comments User Customer ID | 
| Argus.NIDS.data.comments.user.customer.name | String | NIDS Comments User Customer Name | 
| Argus.NIDS.data.comments.user.customer.shortName | String | NIDS Comments User Customer Short Name | 
| Argus.NIDS.data.comments.user.customer.domain.id | Number | NIDS Comments User Customer Domain ID | 
| Argus.NIDS.data.comments.user.customer.domain.name | String | NIDS Comments User Customer Domain Name | 
| Argus.NIDS.data.comments.user.domain.id | Number | NIDS Comments User Domain ID | 
| Argus.NIDS.data.comments.user.domain.name | String | NIDS Comments User Domain Name | 
| Argus.NIDS.data.comments.user.userName | String | NIDS Comments User User Name | 
| Argus.NIDS.data.comments.user.name | String | NIDS Comments User Name | 
| Argus.NIDS.data.comments.user.type | String | NIDS Comments User Type | 
| Argus.NIDS.data.comments.comment | String | NIDS Comments Comment | 
| Argus.NIDS.data.sensor.sensorID | Number | NIDS Sensor Sensor ID | 
| Argus.NIDS.data.sensor.hostName | String | NIDS Sensor Host Name | 
| Argus.NIDS.data.sensor.hostIpAddress.host | Boolean | NIDS Sensor Host Ip Address Host | 
| Argus.NIDS.data.sensor.hostIpAddress.ipv6 | Boolean | NIDS Sensor Host Ip Address Ipv 6 | 
| Argus.NIDS.data.sensor.hostIpAddress.public | Boolean | NIDS Sensor Host Ip Address Public | 
| Argus.NIDS.data.sensor.hostIpAddress.maskBits | Number | NIDS Sensor Host Ip Address Mask Bits | 
| Argus.NIDS.data.sensor.hostIpAddress.multicast | Boolean | NIDS Sensor Host Ip Address Multicast | 
| Argus.NIDS.data.sensor.hostIpAddress.address | String | NIDS Sensor Host Ip Address Address | 
| Argus.NIDS.data.sensor.hostIpString | String | NIDS Sensor Host Ip String | 
| Argus.NIDS.data.location.shortName | String | NIDS Location Short Name | 
| Argus.NIDS.data.location.name | String | NIDS Location Name | 
| Argus.NIDS.data.location.timeZone | String | NIDS Location Time Zone | 
| Argus.NIDS.data.location.id | Number | NIDS Location ID | 
| Argus.NIDS.data.attackInfo.alarmID | Number | NIDS Attack Info Alarm ID | 
| Argus.NIDS.data.attackInfo.alarmDescription | String | NIDS Attack Info Alarm Description | 
| Argus.NIDS.data.attackInfo.attackCategoryID | Number | NIDS Attack Info Attack Category ID | 
| Argus.NIDS.data.attackInfo.attackCategoryName | String | NIDS Attack Info Attack Category Name | 
| Argus.NIDS.data.attackInfo.signature | String | NIDS Attack Info Signature | 
| Argus.NIDS.data.count | Number | API response metadata, total number of results this query has | 
| Argus.NIDS.data.engineTimestamp | Number | NIDS Engine Timestamp | 
| Argus.NIDS.data.protocolID | Number | NIDS Protocol ID | 
| Argus.NIDS.data.domain.fqdn | String | NIDS Domain Fqdn | 
| Argus.NIDS.data.uri | String | NIDS Uri | 
| Argus.NIDS.data.source.port | Number | NIDS Source Port | 
| Argus.NIDS.data.source.geoLocation.countryCode | String | NIDS Source Geo Location Country Code | 
| Argus.NIDS.data.source.geoLocation.countryName | String | NIDS Source Geo Location Country Name | 
| Argus.NIDS.data.source.geoLocation.locationName | String | NIDS Source Geo Location Location Name | 
| Argus.NIDS.data.source.geoLocation.latitude | Number | NIDS Source Geo Location Latitude | 
| Argus.NIDS.data.source.geoLocation.longitude | Number | NIDS Source Geo Location Longitude | 
| Argus.NIDS.data.source.networkAddress.ipv6 | Boolean | NIDS Source Network Address Ipv 6 | 
| Argus.NIDS.data.source.networkAddress.public | Boolean | NIDS Source Network Address Public | 
| Argus.NIDS.data.source.networkAddress.maskBits | Number | NIDS Source Network Address Mask Bits | 
| Argus.NIDS.data.source.networkAddress.multicast | Boolean | NIDS Source Network Address Multicast | 
| Argus.NIDS.data.source.networkAddress.host | Boolean | NIDS Source Network Address Host | 
| Argus.NIDS.data.source.networkAddress.address | String | NIDS Source Network Address Address | 
| Argus.NIDS.data.destination.port | Number | NIDS Destination Port | 
| Argus.NIDS.data.destination.geoLocation.countryCode | String | NIDS Destination Geo Location Country Code | 
| Argus.NIDS.data.destination.geoLocation.countryName | String | NIDS Destination Geo Location Country Name | 
| Argus.NIDS.data.destination.geoLocation.locationName | String | NIDS Destination Geo Location Location Name | 
| Argus.NIDS.data.destination.geoLocation.latitude | Number | NIDS Destination Geo Location Latitude | 
| Argus.NIDS.data.destination.geoLocation.longitude | Number | NIDS Destination Geo Location Longitude | 
| Argus.NIDS.data.destination.networkAddress.ipv6 | Boolean | NIDS Destination Network Address Ipv 6 | 
| Argus.NIDS.data.destination.networkAddress.public | Boolean | NIDS Destination Network Address Public | 
| Argus.NIDS.data.destination.networkAddress.maskBits | Number | NIDS Destination Network Address Mask Bits | 
| Argus.NIDS.data.destination.networkAddress.multicast | Boolean | NIDS Destination Network Address Multicast | 
| Argus.NIDS.data.destination.networkAddress.host | Boolean | NIDS Destination Network Address Host | 
| Argus.NIDS.data.destination.networkAddress.address | String | NIDS Destination Network Address Address | 
| Argus.NIDS.data.timestamp | Number | NIDS Timestamp | 
| Argus.NIDS.data.severity | String | NIDS Severity | 
| Argus.NIDS.data.flags | String | NIDS Flags | 
| Argus.NIDS.data.id | String | NIDS ID | 


#### Command Example
``` !argus-find-nids-events ```



### argus-pdns-search-records
***
Search against PassiveDNS with criteria and return matching records.


#### Base Command

`argus-pdns-search-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Lookup query. | Required | 
| aggregate_result | Whether aggregate results (default true). Possible values are: true, false. | Optional | 
| include_anonymous_results | Whether include anonymous results (default true). Possible values are: true, false. | Optional | 
| rr_class | Lookup with specified record classes (as comma-separated list). | Optional | 
| rr_type | Lookup with specified record types (as comma-separated list). | Optional | 
| customer_id | Lookup for specified customer IDs  (as comma-separated list). | Optional | 
| tlp | Lookup with specified TLPs, public usage only TLP white allowed (as comma-separated list). Possible values are: white, green, amber, red. | Optional | 
| limit | Max number of results to be returned, default unset means default limit 25 will be used, 0 means unlimited. | Optional | 
| offset | Number of results to be skipped first (default 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.PDNS.responseCode | Number | API response metadata, response code of this request | 
| Argus.PDNS.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.PDNS.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.PDNS.count | Number | API response metadata, total number of results this query has | 
| Argus.PDNS.size | Number | API response metadata, the number of results returned in this request | 
| Argus.PDNS.messages.message | String | PDNS Messages Message | 
| Argus.PDNS.messages.messageTemplate | String | PDNS Messages Message Template | 
| Argus.PDNS.messages.type | String | PDNS Messages Type | 
| Argus.PDNS.messages.field | String | PDNS Messages Field | 
| Argus.PDNS.messages.timestamp | Number | PDNS Messages Timestamp | 
| Argus.PDNS.data.createdTimestamp | Number | PDNS Created Timestamp | 
| Argus.PDNS.data.lastUpdatedTimestamp | Number | PDNS Last Updated Timestamp | 
| Argus.PDNS.data.times | Number | PDNS Times | 
| Argus.PDNS.data.tlp | String | PDNS Tlp | 
| Argus.PDNS.data.query | String | PDNS Query | 
| Argus.PDNS.data.answer | String | PDNS Answer | 
| Argus.PDNS.data.minTtl | Number | PDNS Min Ttl | 
| Argus.PDNS.data.maxTtl | Number | PDNS Max Ttl | 
| Argus.PDNS.data.customer.id | Number | PDNS Customer ID | 
| Argus.PDNS.data.customer.name | String | PDNS Customer Name | 
| Argus.PDNS.data.customer.shortName | String | PDNS Customer Short Name | 
| Argus.PDNS.data.customer.domain.id | Number | PDNS Customer Domain ID | 
| Argus.PDNS.data.customer.domain.name | String | PDNS Customer Domain Name | 
| Argus.PDNS.data.lastSeenTimestamp | Number | PDNS Last Seen Timestamp | 
| Argus.PDNS.data.firstSeenTimestamp | Number | PDNS First Seen Timestamp | 
| Argus.PDNS.data.rrclass | String | PDNS Rrclass | 
| Argus.PDNS.data.rrtype | String | PDNS Rrtype | 


#### Command Example
``` !argus-pdns-search-records query=mnemonic.no ```



### argus-fetch-observations-for-domain
***
Look up reputation observations for the given domain


#### Base Command

`argus-fetch-observations-for-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fqdn | Domain to fetch observations for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.ObservationsDomain.responseCode | Number | API response metadata, response code of this request | 
| Argus.ObservationsDomain.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.ObservationsDomain.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.ObservationsDomain.count | Number | API response metadata, total number of results this query has | 
| Argus.ObservationsDomain.size | Number | API response metadata, the number of results returned in this request | 
| Argus.ObservationsDomain.messages.message | String | Observations Domain Messages Message | 
| Argus.ObservationsDomain.messages.messageTemplate | String | Observations Domain Messages Message Template | 
| Argus.ObservationsDomain.messages.type | String | Observations Domain Messages Type | 
| Argus.ObservationsDomain.messages.field | String | Observations Domain Messages Field | 
| Argus.ObservationsDomain.messages.timestamp | Number | Observations Domain Messages Timestamp | 
| Argus.ObservationsDomain.data.domainName.fqdn | String | Observations Domain Domain Name Fqdn | 
| Argus.ObservationsDomain.data.reason | String | Observations Domain Reason | 
| Argus.ObservationsDomain.data.override | Boolean | Observations Domain Override | 
| Argus.ObservationsDomain.data.value | Number | Observations Domain Value | 


#### Command Example
``` !argus-fetch-observations-for-domain fqdn=mnemonic.no ```



### argus-fetch-observations-for-ip
***
Look up reputation observations for the given IP


#### Base Command

`argus-fetch-observations-for-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to fetch observations for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.ObservationsIP.responseCode | Number | API response metadata, response code of this request | 
| Argus.ObservationsIP.limit | Number | API response metadata, limit of results this request ran with | 
| Argus.ObservationsIP.offset | Number | API response metadata, the offset into the result-set of this query | 
| Argus.ObservationsIP.count | Number | API response metadata, total number of results this query has | 
| Argus.ObservationsIP.size | Number | API response metadata, the number of results returned in this request | 
| Argus.ObservationsIP.messages.message | String | Observations IP Messages Message | 
| Argus.ObservationsIP.messages.messageTemplate | String | Observations IP Messages Message Template | 
| Argus.ObservationsIP.messages.type | String | Observations IP Messages Type | 
| Argus.ObservationsIP.messages.field | String | Observations IP Messages Field | 
| Argus.ObservationsIP.messages.timestamp | Number | Observations IP Messages Timestamp | 
| Argus.ObservationsIP.data.id | Number | Observations IP ID | 
| Argus.ObservationsIP.data.lastModified | Number | Observations IP Last Modified | 
| Argus.ObservationsIP.data.source.id | Number | Observations IP Source ID | 
| Argus.ObservationsIP.data.source.alias | String | Observations IP Source Alias | 
| Argus.ObservationsIP.data.source.name | String | Observations IP Source Name | 
| Argus.ObservationsIP.data.role.id | Number | Observations IP Role ID | 
| Argus.ObservationsIP.data.role.alias | String | Observations IP Role Alias | 
| Argus.ObservationsIP.data.role.name | String | Observations IP Role Name | 
| Argus.ObservationsIP.data.firstSeen | Number | Observations IP First Seen | 
| Argus.ObservationsIP.data.lastSeen | Number | Observations IP Last Seen | 
| Argus.ObservationsIP.data.numObservations | Number | Observations IP Num Observations | 
| Argus.ObservationsIP.data.state | Number | Observations IP State | 
| Argus.ObservationsIP.data.comment | String | Observations IP Comment | 
| Argus.ObservationsIP.data.address.host | Boolean | Observations IP Address Host | 
| Argus.ObservationsIP.data.address.ipv6 | Boolean | Observations IP Address Ipv 6 | 
| Argus.ObservationsIP.data.address.maskBits | Number | Observations IP Address Mask Bits | 
| Argus.ObservationsIP.data.address.multicast | Boolean | Observations IP Address Multicast | 
| Argus.ObservationsIP.data.address.public | Boolean | Observations IP Address Public | 
| Argus.ObservationsIP.data.address.address | String | Observations IP Address Address | 


#### Command Example
``` !argus-fetch-observations-for-ip ip=94.127.56.170 ```
