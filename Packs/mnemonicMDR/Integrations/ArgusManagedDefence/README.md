Rapidly detect, analyse and respond to security threats with mnemonic’s leading Managed Detection and Response (MDR) service.

This integration was integrated and tested with version 5.0.1 argus-toolbelt ([PyPi](https://pypi.org/project/argus-toolbelt)).
## Configure ArgusManagedDefence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for mnemonic MDR.
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

`argus_add_case_tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to add tag to | Required | 
| key | Key of tag to add to case | Required | 
| value | Value of tag to add to case | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | Argus | 
| Argus.Tags.limit | Number | Argus | 
| Argus.Tags.offset | Number | Argus | 
| Argus.Tags.count | Number | Argus | 
| Argus.Tags.size | Number | Argus | 
| Argus.Tags.messages.message | String | Argus | 
| Argus.Tags.messages.messageTemplate | String | Argus | 
| Argus.Tags.messages.type | String | Argus | 
| Argus.Tags.messages.field | String | Argus | 
| Argus.Tags.messages.timestamp | Number | Argus | 
| Argus.Tags.data.id | String | Argus | 
| Argus.Tags.data.key | String | Argus | 
| Argus.Tags.data.value | String | Argus | 
| Argus.Tags.data.addedTimestamp | Number | Argus | 
| Argus.Tags.data.addedByUser.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customerID | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.name | String | Argus | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.userName | String | Argus | 
| Argus.Tags.data.addedByUser.name | String | Argus | 
| Argus.Tags.data.addedByUser.type | String | Argus | 
| Argus.Tags.data.flags | String | Argus | 
| Argus.Tags.data.addedTime | String | Argus | 


#### Command Example
``` !argus_add_case_tag case_id=123 key=foo value=bar ```



### argus_list_case_tags
***
List tags attached to an Argus case


#### Base Command

`argus_list_case_tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID  | Required | 
| limit | Limit the amount of fetched tags. (Default 25) | Optional | 
| offset | Skip a number of results | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | Argus | 
| Argus.Tags.limit | Number | Argus | 
| Argus.Tags.offset | Number | Argus | 
| Argus.Tags.count | Number | Argus | 
| Argus.Tags.size | Number | Argus | 
| Argus.Tags.messages.message | String | Argus | 
| Argus.Tags.messages.messageTemplate | String | Argus | 
| Argus.Tags.messages.type | String | Argus | 
| Argus.Tags.messages.field | String | Argus | 
| Argus.Tags.messages.timestamp | Number | Argus | 
| Argus.Tags.data.id | String | Argus | 
| Argus.Tags.data.key | String | Argus | 
| Argus.Tags.data.value | String | Argus | 
| Argus.Tags.data.addedTimestamp | Number | Argus | 
| Argus.Tags.data.addedByUser.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customerID | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.name | String | Argus | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.userName | String | Argus | 
| Argus.Tags.data.addedByUser.name | String | Argus | 
| Argus.Tags.data.addedByUser.type | String | Argus | 
| Argus.Tags.data.flags | String | Argus | 
| Argus.Tags.data.addedTime | String | Argus | 


#### Command Example
``` !argus_list_case_tags case_id=123 ```



### argus_add_comment
***
Add comment to an Argus case


#### Base Command

`argus_add_comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID | Required | 
| comment | The comment to attach | Required | 
| as_reply_to | ID of comment this comment will reply to | Optional | 
| internal | Whether this comment will be shown to the customer | Optional | 
| origin_email_address | Define the e-mail address this comment originates from | Optional | 
| associated_attachment_id | ID of case attachement this comment is related to | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | Argus | 
| Argus.Comment.limit | Number | Argus | 
| Argus.Comment.offset | Number | Argus | 
| Argus.Comment.count | Number | Argus | 
| Argus.Comment.size | Number | Argus | 
| Argus.Comment.messages.message | String | Argus | 
| Argus.Comment.messages.messageTemplate | String | Argus | 
| Argus.Comment.messages.type | String | Argus | 
| Argus.Comment.messages.field | String | Argus | 
| Argus.Comment.messages.timestamp | Number | Argus | 
| Argus.Comment.data.id | String | Argus | 
| Argus.Comment.data.addedTimestamp | Number | Argus | 
| Argus.Comment.data.addedByUser.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customerID | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.name | String | Argus | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.userName | String | Argus | 
| Argus.Comment.data.addedByUser.name | String | Argus | 
| Argus.Comment.data.addedByUser.type | String | Argus | 
| Argus.Comment.data.comment | String | Argus | 
| Argus.Comment.data.flags | String | Argus | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Comment.data.status | String | Argus | 
| Argus.Comment.data.priority | String | Argus | 
| Argus.Comment.data.originEmailAddress | String | Argus | 
| Argus.Comment.data.associatedAttachments.id | String | Argus | 
| Argus.Comment.data.associatedAttachments.name | String | Argus | 
| Argus.Comment.data.references.type | String | Argus | 
| Argus.Comment.data.references.commentID | String | Argus | 
| Argus.Comment.data.lastUpdatedTime | String | Argus | 
| Argus.Comment.data.addedTime | String | Argus | 


#### Command Example
``` !argus_add_comment case_id=123 comment="this is a comment" ```



### argus_list_case_comments
***
List the comments of an Argus case


#### Base Command

`argus_list_case_comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID of Argus case | Required | 
| before_comment | Limit to comments before this comment ID (in sort order) | Optional | 
| offset | Skip a number of results (default 0) | Optional | 
| limit | Maximum number of returned results (default 25) | Optional | 
| sort_by | Sort ordering. Default is ascending | Optional | 
| after_comment | Limit to comments after this comment ID (in sort order) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comments.responseCode | Number | Argus | 
| Argus.Comments.limit | Number | Argus | 
| Argus.Comments.offset | Number | Argus | 
| Argus.Comments.count | Number | Argus | 
| Argus.Comments.size | Number | Argus | 
| Argus.Comments.messages.message | String | Argus | 
| Argus.Comments.messages.messageTemplate | String | Argus | 
| Argus.Comments.messages.type | String | Argus | 
| Argus.Comments.messages.field | String | Argus | 
| Argus.Comments.messages.timestamp | Number | Argus | 
| Argus.Comments.data.id | String | Argus | 
| Argus.Comments.data.addedTimestamp | Number | Argus | 
| Argus.Comments.data.addedByUser.id | Number | Argus | 
| Argus.Comments.data.addedByUser.customerID | Number | Argus | 
| Argus.Comments.data.addedByUser.customer.id | Number | Argus | 
| Argus.Comments.data.addedByUser.customer.name | String | Argus | 
| Argus.Comments.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Comments.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Comments.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Comments.data.addedByUser.domain.id | Number | Argus | 
| Argus.Comments.data.addedByUser.domain.name | String | Argus | 
| Argus.Comments.data.addedByUser.userName | String | Argus | 
| Argus.Comments.data.addedByUser.name | String | Argus | 
| Argus.Comments.data.addedByUser.type | String | Argus | 
| Argus.Comments.data.comment | String | Argus | 
| Argus.Comments.data.flags | String | Argus | 
| Argus.Comments.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Comments.data.status | String | Argus | 
| Argus.Comments.data.priority | String | Argus | 
| Argus.Comments.data.originEmailAddress | String | Argus | 
| Argus.Comments.data.associatedAttachments.id | String | Argus | 
| Argus.Comments.data.associatedAttachments.name | String | Argus | 
| Argus.Comments.data.references.type | String | Argus | 
| Argus.Comments.data.references.commentID | String | Argus | 
| Argus.Comments.data.lastUpdatedTime | String | Argus | 
| Argus.Comments.data.addedTime | String | Argus | 


#### Command Example
``` !argus_list_case_comments case_id=123 ```



### argus_advanced_case_search
***
Returns cases matching the defined case search criteria


#### Base Command

`argus_advanced_case_search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_timestamp | Start timestamp | Optional | 
| end_timestamp | End timestamp | Optional | 
| limit | Set this value to set max number of results. By default, no restriction on result set size. | Optional | 
| offset | Set this value to skip the first (offset) objects. By default, return result from first object.  | Optional | 
| include_deleted | Set to true to include deleted objects. By default, exclude deleted objects. | Optional | 
| sub_criteria | Set additional criterias which are applied using a logical OR. | Optional | 
| exclude | Only relevant for subcriteria. If set to true, objects matching this subcriteria object will be excluded.  | Optional | 
| required | Only relevant for subcriteria. If set to true, objects matching this subcriteria are required (AND-ed together with parent criteria).  | Optional | 
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
| user_assigned | If set, limit search to cases where assignedUser field is set/unset. | Optional | 
| tech_assigned | If set, limit search to cases where assignedTech field is set/unset. | Optional | 
| include_workflows | If true, include list of workflows in result. Default is false (not present).  | Optional | 
| include_description | If false, omit description from response. Default is true (description is present).  | Optional | 
| access_mode | If set, only match cases which is set to one of these access modes. | Optional | 
| explicit_access | If set, only match cases which have explicit access grants matching the specified criteria. | Optional | 
| sort_by | List of properties to sort by (prefix with "-" to sort descending). | Optional | 
| include_flags | Only include objects which have includeFlags set.  | Optional | 
| exclude_flags | Exclude objects which have excludeFlags set.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Cases.responseCode | Number | Argus | 
| Argus.Cases.limit | Number | Argus | 
| Argus.Cases.offset | Number | Argus | 
| Argus.Cases.count | Number | Argus | 
| Argus.Cases.size | Number | Argus | 
| Argus.Cases.messages.message | String | Argus | 
| Argus.Cases.messages.messageTemplate | String | Argus | 
| Argus.Cases.messages.type | String | Argus | 
| Argus.Cases.messages.field | String | Argus | 
| Argus.Cases.messages.timestamp | Number | Argus | 
| Argus.Cases.data.id | Number | Argus | 
| Argus.Cases.data.customer.id | Number | Argus | 
| Argus.Cases.data.customer.name | String | Argus | 
| Argus.Cases.data.customer.shortName | String | Argus | 
| Argus.Cases.data.customer.domain.id | Number | Argus | 
| Argus.Cases.data.customer.domain.name | String | Argus | 
| Argus.Cases.data.service.id | Number | Argus | 
| Argus.Cases.data.service.name | String | Argus | 
| Argus.Cases.data.service.shortName | String | Argus | 
| Argus.Cases.data.service.localizedName | String | Argus | 
| Argus.Cases.data.category.id | Number | Argus | 
| Argus.Cases.data.category.name | String | Argus | 
| Argus.Cases.data.category.shortName | String | Argus | 
| Argus.Cases.data.category.localizedName | String | Argus | 
| Argus.Cases.data.type | String | Argus | 
| Argus.Cases.data.initialStatus | String | Argus | 
| Argus.Cases.data.status | String | Argus | 
| Argus.Cases.data.initialPriority | String | Argus | 
| Argus.Cases.data.priority | String | Argus | 
| Argus.Cases.data.subject | String | Argus | 
| Argus.Cases.data.description | String | Argus | 
| Argus.Cases.data.customerReference | String | Argus | 
| Argus.Cases.data.accessMode | String | Argus | 
| Argus.Cases.data.reporter.id | Number | Argus | 
| Argus.Cases.data.reporter.customerID | Number | Argus | 
| Argus.Cases.data.reporter.customer.id | Number | Argus | 
| Argus.Cases.data.reporter.customer.name | String | Argus | 
| Argus.Cases.data.reporter.customer.shortName | String | Argus | 
| Argus.Cases.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Cases.data.reporter.customer.domain.name | String | Argus | 
| Argus.Cases.data.reporter.domain.id | Number | Argus | 
| Argus.Cases.data.reporter.domain.name | String | Argus | 
| Argus.Cases.data.reporter.userName | String | Argus | 
| Argus.Cases.data.reporter.name | String | Argus | 
| Argus.Cases.data.reporter.type | String | Argus | 
| Argus.Cases.data.assignedUser.id | Number | Argus | 
| Argus.Cases.data.assignedUser.customerID | Number | Argus | 
| Argus.Cases.data.assignedUser.customer.id | Number | Argus | 
| Argus.Cases.data.assignedUser.customer.name | String | Argus | 
| Argus.Cases.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Cases.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Cases.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Cases.data.assignedUser.domain.id | Number | Argus | 
| Argus.Cases.data.assignedUser.domain.name | String | Argus | 
| Argus.Cases.data.assignedUser.userName | String | Argus | 
| Argus.Cases.data.assignedUser.name | String | Argus | 
| Argus.Cases.data.assignedUser.type | String | Argus | 
| Argus.Cases.data.assignedTech.id | Number | Argus | 
| Argus.Cases.data.assignedTech.customerID | Number | Argus | 
| Argus.Cases.data.assignedTech.customer.id | Number | Argus | 
| Argus.Cases.data.assignedTech.customer.name | String | Argus | 
| Argus.Cases.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Cases.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Cases.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Cases.data.assignedTech.domain.id | Number | Argus | 
| Argus.Cases.data.assignedTech.domain.name | String | Argus | 
| Argus.Cases.data.assignedTech.userName | String | Argus | 
| Argus.Cases.data.assignedTech.name | String | Argus | 
| Argus.Cases.data.assignedTech.type | String | Argus | 
| Argus.Cases.data.createdTimestamp | Number | Argus | 
| Argus.Cases.data.createdByUser.id | Number | Argus | 
| Argus.Cases.data.createdByUser.customerID | Number | Argus | 
| Argus.Cases.data.createdByUser.customer.id | Number | Argus | 
| Argus.Cases.data.createdByUser.customer.name | String | Argus | 
| Argus.Cases.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Cases.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Cases.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Cases.data.createdByUser.domain.id | Number | Argus | 
| Argus.Cases.data.createdByUser.domain.name | String | Argus | 
| Argus.Cases.data.createdByUser.userName | String | Argus | 
| Argus.Cases.data.createdByUser.name | String | Argus | 
| Argus.Cases.data.createdByUser.type | String | Argus | 
| Argus.Cases.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Cases.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Cases.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Cases.data.closedTimestamp | Number | Argus | 
| Argus.Cases.data.closedByUser.id | Number | Argus | 
| Argus.Cases.data.closedByUser.customerID | Number | Argus | 
| Argus.Cases.data.closedByUser.customer.id | Number | Argus | 
| Argus.Cases.data.closedByUser.customer.name | String | Argus | 
| Argus.Cases.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Cases.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Cases.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Cases.data.closedByUser.domain.id | Number | Argus | 
| Argus.Cases.data.closedByUser.domain.name | String | Argus | 
| Argus.Cases.data.closedByUser.userName | String | Argus | 
| Argus.Cases.data.closedByUser.name | String | Argus | 
| Argus.Cases.data.closedByUser.type | String | Argus | 
| Argus.Cases.data.publishedTimestamp | Number | Argus | 
| Argus.Cases.data.publishedByUser.id | Number | Argus | 
| Argus.Cases.data.publishedByUser.customerID | Number | Argus | 
| Argus.Cases.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Cases.data.publishedByUser.customer.name | String | Argus | 
| Argus.Cases.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Cases.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Cases.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Cases.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Cases.data.publishedByUser.domain.name | String | Argus | 
| Argus.Cases.data.publishedByUser.userName | String | Argus | 
| Argus.Cases.data.publishedByUser.name | String | Argus | 
| Argus.Cases.data.publishedByUser.type | String | Argus | 
| Argus.Cases.data.flags | String | Argus | 
| Argus.Cases.data.currentUserAccess.level | String | Argus | 
| Argus.Cases.data.currentUserAccess.role | String | Argus | 
| Argus.Cases.data.workflows.workflow | String | Argus | 
| Argus.Cases.data.workflows.state | String | Argus | 
| Argus.Cases.data.originEmailAddress | String | Argus | 
| Argus.Cases.data.createdTime | String | Argus | 
| Argus.Cases.data.lastUpdatedTime | String | Argus | 
| Argus.Cases.data.closedTime | String | Argus | 
| Argus.Cases.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_advanced_case_search ```


### argus_close_case
***
Close an Argus case


#### Base Command

`argus_close_case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID of Argus case | Required | 
| comment | Attach a closing comment | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | Argus | 
| Argus.Case.limit | Number | Argus | 
| Argus.Case.offset | Number | Argus | 
| Argus.Case.count | Number | Argus | 
| Argus.Case.size | Number | Argus | 
| Argus.Case.messages.message | String | Argus | 
| Argus.Case.messages.messageTemplate | String | Argus | 
| Argus.Case.messages.type | String | Argus | 
| Argus.Case.messages.field | String | Argus | 
| Argus.Case.messages.timestamp | Number | Argus | 
| Argus.Case.data.id | Number | Argus | 
| Argus.Case.data.customer.id | Number | Argus | 
| Argus.Case.data.customer.name | String | Argus | 
| Argus.Case.data.customer.shortName | String | Argus | 
| Argus.Case.data.customer.domain.id | Number | Argus | 
| Argus.Case.data.customer.domain.name | String | Argus | 
| Argus.Case.data.service.id | Number | Argus | 
| Argus.Case.data.service.name | String | Argus | 
| Argus.Case.data.service.shortName | String | Argus | 
| Argus.Case.data.service.localizedName | String | Argus | 
| Argus.Case.data.category.id | Number | Argus | 
| Argus.Case.data.category.name | String | Argus | 
| Argus.Case.data.category.shortName | String | Argus | 
| Argus.Case.data.category.localizedName | String | Argus | 
| Argus.Case.data.type | String | Argus | 
| Argus.Case.data.initialStatus | String | Argus | 
| Argus.Case.data.status | String | Argus | 
| Argus.Case.data.initialPriority | String | Argus | 
| Argus.Case.data.priority | String | Argus | 
| Argus.Case.data.subject | String | Argus | 
| Argus.Case.data.description | String | Argus | 
| Argus.Case.data.customerReference | String | Argus | 
| Argus.Case.data.accessMode | String | Argus | 
| Argus.Case.data.reporter.id | Number | Argus | 
| Argus.Case.data.reporter.customerID | Number | Argus | 
| Argus.Case.data.reporter.customer.id | Number | Argus | 
| Argus.Case.data.reporter.customer.name | String | Argus | 
| Argus.Case.data.reporter.customer.shortName | String | Argus | 
| Argus.Case.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Case.data.reporter.customer.domain.name | String | Argus | 
| Argus.Case.data.reporter.domain.id | Number | Argus | 
| Argus.Case.data.reporter.domain.name | String | Argus | 
| Argus.Case.data.reporter.userName | String | Argus | 
| Argus.Case.data.reporter.name | String | Argus | 
| Argus.Case.data.reporter.type | String | Argus | 
| Argus.Case.data.assignedUser.id | Number | Argus | 
| Argus.Case.data.assignedUser.customerID | Number | Argus | 
| Argus.Case.data.assignedUser.customer.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.name | String | Argus | 
| Argus.Case.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.userName | String | Argus | 
| Argus.Case.data.assignedUser.name | String | Argus | 
| Argus.Case.data.assignedUser.type | String | Argus | 
| Argus.Case.data.assignedTech.id | Number | Argus | 
| Argus.Case.data.assignedTech.customerID | Number | Argus | 
| Argus.Case.data.assignedTech.customer.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.name | String | Argus | 
| Argus.Case.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.userName | String | Argus | 
| Argus.Case.data.assignedTech.name | String | Argus | 
| Argus.Case.data.assignedTech.type | String | Argus | 
| Argus.Case.data.createdTimestamp | Number | Argus | 
| Argus.Case.data.createdByUser.id | Number | Argus | 
| Argus.Case.data.createdByUser.customerID | Number | Argus | 
| Argus.Case.data.createdByUser.customer.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.name | String | Argus | 
| Argus.Case.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.userName | String | Argus | 
| Argus.Case.data.createdByUser.name | String | Argus | 
| Argus.Case.data.createdByUser.type | String | Argus | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Case.data.closedTimestamp | Number | Argus | 
| Argus.Case.data.closedByUser.id | Number | Argus | 
| Argus.Case.data.closedByUser.customerID | Number | Argus | 
| Argus.Case.data.closedByUser.customer.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.name | String | Argus | 
| Argus.Case.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.userName | String | Argus | 
| Argus.Case.data.closedByUser.name | String | Argus | 
| Argus.Case.data.closedByUser.type | String | Argus | 
| Argus.Case.data.publishedTimestamp | Number | Argus | 
| Argus.Case.data.publishedByUser.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customerID | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.name | String | Argus | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.userName | String | Argus | 
| Argus.Case.data.publishedByUser.name | String | Argus | 
| Argus.Case.data.publishedByUser.type | String | Argus | 
| Argus.Case.data.flags | String | Argus | 
| Argus.Case.data.currentUserAccess.level | String | Argus | 
| Argus.Case.data.currentUserAccess.role | String | Argus | 
| Argus.Case.data.workflows.workflow | String | Argus | 
| Argus.Case.data.workflows.state | String | Argus | 
| Argus.Case.data.originEmailAddress | String | Argus | 
| Argus.Case.data.createdTime | String | Argus | 
| Argus.Case.data.lastUpdatedTime | String | Argus | 
| Argus.Case.data.closedTime | String | Argus | 
| Argus.Case.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_close_case case_id=123 ```



### argus_create_case
***
Create Argus case


#### Base Command

`argus_create_case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer | ID or shortname of customer to create case for. Defaults to current users customer. | Optional | 
| service | ID of service to create case for | Required | 
| category | If set, assign given category to new case (by category shortname).  | Optional | 
| type | Type of case to create  | Required | 
| status | Status of case to create. If not set, system will select automatically. Creating a new case with status closed is not permitted.  | Optional | 
| tags | Tags to add on case creation.  (key,value,key,value, ...) | Optional | 
| subject | Subject of case to create. | Required | 
| description | Case description. May use HTML, which will be sanitized.  | Required | 
| customer_reference | Customer reference for case. | Optional | 
| priority | Priority of case to create. (default medium) | Optional | 
| access_mode | Access mode for new case. (default roleBased) | Optional | 
| origin_email_address | If case is created from an email, specify origin email address here. | Optional | 
| publish | Whether to publish new case. Creating an unpublished case requires special permission. (default true) | Optional | 
| default_watchers | Whether to enable default watchers for this case. If set to false, default watchers will not be enabled, and will not be notified upon creation of this case. (default true) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | Argus | 
| Argus.Case.limit | Number | Argus | 
| Argus.Case.offset | Number | Argus | 
| Argus.Case.count | Number | Argus | 
| Argus.Case.size | Number | Argus | 
| Argus.Case.messages.message | String | Argus | 
| Argus.Case.messages.messageTemplate | String | Argus | 
| Argus.Case.messages.type | String | Argus | 
| Argus.Case.messages.field | String | Argus | 
| Argus.Case.messages.timestamp | Number | Argus | 
| Argus.Case.data.id | Number | Argus | 
| Argus.Case.data.customer.id | Number | Argus | 
| Argus.Case.data.customer.name | String | Argus | 
| Argus.Case.data.customer.shortName | String | Argus | 
| Argus.Case.data.customer.domain.id | Number | Argus | 
| Argus.Case.data.customer.domain.name | String | Argus | 
| Argus.Case.data.service.id | Number | Argus | 
| Argus.Case.data.service.name | String | Argus | 
| Argus.Case.data.service.shortName | String | Argus | 
| Argus.Case.data.service.localizedName | String | Argus | 
| Argus.Case.data.category.id | Number | Argus | 
| Argus.Case.data.category.name | String | Argus | 
| Argus.Case.data.category.shortName | String | Argus | 
| Argus.Case.data.category.localizedName | String | Argus | 
| Argus.Case.data.type | String | Argus | 
| Argus.Case.data.initialStatus | String | Argus | 
| Argus.Case.data.status | String | Argus | 
| Argus.Case.data.initialPriority | String | Argus | 
| Argus.Case.data.priority | String | Argus | 
| Argus.Case.data.subject | String | Argus | 
| Argus.Case.data.description | String | Argus | 
| Argus.Case.data.customerReference | String | Argus | 
| Argus.Case.data.accessMode | String | Argus | 
| Argus.Case.data.reporter.id | Number | Argus | 
| Argus.Case.data.reporter.customerID | Number | Argus | 
| Argus.Case.data.reporter.customer.id | Number | Argus | 
| Argus.Case.data.reporter.customer.name | String | Argus | 
| Argus.Case.data.reporter.customer.shortName | String | Argus | 
| Argus.Case.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Case.data.reporter.customer.domain.name | String | Argus | 
| Argus.Case.data.reporter.domain.id | Number | Argus | 
| Argus.Case.data.reporter.domain.name | String | Argus | 
| Argus.Case.data.reporter.userName | String | Argus | 
| Argus.Case.data.reporter.name | String | Argus | 
| Argus.Case.data.reporter.type | String | Argus | 
| Argus.Case.data.assignedUser.id | Number | Argus | 
| Argus.Case.data.assignedUser.customerID | Number | Argus | 
| Argus.Case.data.assignedUser.customer.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.name | String | Argus | 
| Argus.Case.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.userName | String | Argus | 
| Argus.Case.data.assignedUser.name | String | Argus | 
| Argus.Case.data.assignedUser.type | String | Argus | 
| Argus.Case.data.assignedTech.id | Number | Argus | 
| Argus.Case.data.assignedTech.customerID | Number | Argus | 
| Argus.Case.data.assignedTech.customer.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.name | String | Argus | 
| Argus.Case.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.userName | String | Argus | 
| Argus.Case.data.assignedTech.name | String | Argus | 
| Argus.Case.data.assignedTech.type | String | Argus | 
| Argus.Case.data.createdTimestamp | Number | Argus | 
| Argus.Case.data.createdByUser.id | Number | Argus | 
| Argus.Case.data.createdByUser.customerID | Number | Argus | 
| Argus.Case.data.createdByUser.customer.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.name | String | Argus | 
| Argus.Case.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.userName | String | Argus | 
| Argus.Case.data.createdByUser.name | String | Argus | 
| Argus.Case.data.createdByUser.type | String | Argus | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Case.data.closedTimestamp | Number | Argus | 
| Argus.Case.data.closedByUser.id | Number | Argus | 
| Argus.Case.data.closedByUser.customerID | Number | Argus | 
| Argus.Case.data.closedByUser.customer.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.name | String | Argus | 
| Argus.Case.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.userName | String | Argus | 
| Argus.Case.data.closedByUser.name | String | Argus | 
| Argus.Case.data.closedByUser.type | String | Argus | 
| Argus.Case.data.publishedTimestamp | Number | Argus | 
| Argus.Case.data.publishedByUser.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customerID | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.name | String | Argus | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.userName | String | Argus | 
| Argus.Case.data.publishedByUser.name | String | Argus | 
| Argus.Case.data.publishedByUser.type | String | Argus | 
| Argus.Case.data.flags | String | Argus | 
| Argus.Case.data.currentUserAccess.level | String | Argus | 
| Argus.Case.data.currentUserAccess.role | String | Argus | 
| Argus.Case.data.workflows.workflow | String | Argus | 
| Argus.Case.data.workflows.state | String | Argus | 
| Argus.Case.data.originEmailAddress | String | Argus | 
| Argus.Case.data.createdTime | String | Argus | 
| Argus.Case.data.lastUpdatedTime | String | Argus | 
| Argus.Case.data.closedTime | String | Argus | 
| Argus.Case.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_create_case subject="test case title" description="test case details" service=administrative type=informational ```


### argus_delete_case
***
Mark existing case as deleted


#### Base Command

`argus_delete_case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case to mark as deleted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | Argus | 
| Argus.Case.limit | Number | Argus | 
| Argus.Case.offset | Number | Argus | 
| Argus.Case.count | Number | Argus | 
| Argus.Case.size | Number | Argus | 
| Argus.Case.messages.message | String | Argus | 
| Argus.Case.messages.messageTemplate | String | Argus | 
| Argus.Case.messages.type | String | Argus | 
| Argus.Case.messages.field | String | Argus | 
| Argus.Case.messages.timestamp | Number | Argus | 
| Argus.Case.data.id | Number | Argus | 
| Argus.Case.data.customer.id | Number | Argus | 
| Argus.Case.data.customer.name | String | Argus | 
| Argus.Case.data.customer.shortName | String | Argus | 
| Argus.Case.data.customer.domain.id | Number | Argus | 
| Argus.Case.data.customer.domain.name | String | Argus | 
| Argus.Case.data.service.id | Number | Argus | 
| Argus.Case.data.service.name | String | Argus | 
| Argus.Case.data.service.shortName | String | Argus | 
| Argus.Case.data.service.localizedName | String | Argus | 
| Argus.Case.data.category.id | Number | Argus | 
| Argus.Case.data.category.name | String | Argus | 
| Argus.Case.data.category.shortName | String | Argus | 
| Argus.Case.data.category.localizedName | String | Argus | 
| Argus.Case.data.type | String | Argus | 
| Argus.Case.data.initialStatus | String | Argus | 
| Argus.Case.data.status | String | Argus | 
| Argus.Case.data.initialPriority | String | Argus | 
| Argus.Case.data.priority | String | Argus | 
| Argus.Case.data.subject | String | Argus | 
| Argus.Case.data.description | String | Argus | 
| Argus.Case.data.customerReference | String | Argus | 
| Argus.Case.data.accessMode | String | Argus | 
| Argus.Case.data.reporter.id | Number | Argus | 
| Argus.Case.data.reporter.customerID | Number | Argus | 
| Argus.Case.data.reporter.customer.id | Number | Argus | 
| Argus.Case.data.reporter.customer.name | String | Argus | 
| Argus.Case.data.reporter.customer.shortName | String | Argus | 
| Argus.Case.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Case.data.reporter.customer.domain.name | String | Argus | 
| Argus.Case.data.reporter.domain.id | Number | Argus | 
| Argus.Case.data.reporter.domain.name | String | Argus | 
| Argus.Case.data.reporter.userName | String | Argus | 
| Argus.Case.data.reporter.name | String | Argus | 
| Argus.Case.data.reporter.type | String | Argus | 
| Argus.Case.data.assignedUser.id | Number | Argus | 
| Argus.Case.data.assignedUser.customerID | Number | Argus | 
| Argus.Case.data.assignedUser.customer.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.name | String | Argus | 
| Argus.Case.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.userName | String | Argus | 
| Argus.Case.data.assignedUser.name | String | Argus | 
| Argus.Case.data.assignedUser.type | String | Argus | 
| Argus.Case.data.assignedTech.id | Number | Argus | 
| Argus.Case.data.assignedTech.customerID | Number | Argus | 
| Argus.Case.data.assignedTech.customer.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.name | String | Argus | 
| Argus.Case.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.userName | String | Argus | 
| Argus.Case.data.assignedTech.name | String | Argus | 
| Argus.Case.data.assignedTech.type | String | Argus | 
| Argus.Case.data.createdTimestamp | Number | Argus | 
| Argus.Case.data.createdByUser.id | Number | Argus | 
| Argus.Case.data.createdByUser.customerID | Number | Argus | 
| Argus.Case.data.createdByUser.customer.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.name | String | Argus | 
| Argus.Case.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.userName | String | Argus | 
| Argus.Case.data.createdByUser.name | String | Argus | 
| Argus.Case.data.createdByUser.type | String | Argus | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Case.data.closedTimestamp | Number | Argus | 
| Argus.Case.data.closedByUser.id | Number | Argus | 
| Argus.Case.data.closedByUser.customerID | Number | Argus | 
| Argus.Case.data.closedByUser.customer.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.name | String | Argus | 
| Argus.Case.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.userName | String | Argus | 
| Argus.Case.data.closedByUser.name | String | Argus | 
| Argus.Case.data.closedByUser.type | String | Argus | 
| Argus.Case.data.publishedTimestamp | Number | Argus | 
| Argus.Case.data.publishedByUser.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customerID | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.name | String | Argus | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.userName | String | Argus | 
| Argus.Case.data.publishedByUser.name | String | Argus | 
| Argus.Case.data.publishedByUser.type | String | Argus | 
| Argus.Case.data.flags | String | Argus | 
| Argus.Case.data.currentUserAccess.level | String | Argus | 
| Argus.Case.data.currentUserAccess.role | String | Argus | 
| Argus.Case.data.workflows.workflow | String | Argus | 
| Argus.Case.data.workflows.state | String | Argus | 
| Argus.Case.data.originEmailAddress | String | Argus | 
| Argus.Case.data.createdTime | String | Argus | 
| Argus.Case.data.lastUpdatedTime | String | Argus | 
| Argus.Case.data.closedTime | String | Argus | 
| Argus.Case.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_delete_case case_id=123 ```



### argus_delete_comment
***
Mark existing comment as deleted


#### Base Command

`argus_delete_comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case where comment exists | Required | 
| comment_id | ID of comment to mark as deleted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | Argus | 
| Argus.Comment.limit | Number | Argus | 
| Argus.Comment.offset | Number | Argus | 
| Argus.Comment.count | Number | Argus | 
| Argus.Comment.size | Number | Argus | 
| Argus.Comment.messages.message | String | Argus | 
| Argus.Comment.messages.messageTemplate | String | Argus | 
| Argus.Comment.messages.type | String | Argus | 
| Argus.Comment.messages.field | String | Argus | 
| Argus.Comment.messages.timestamp | Number | Argus | 
| Argus.Comment.data.id | String | Argus | 
| Argus.Comment.data.addedTimestamp | Number | Argus | 
| Argus.Comment.data.addedByUser.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customerID | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.name | String | Argus | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.userName | String | Argus | 
| Argus.Comment.data.addedByUser.name | String | Argus | 
| Argus.Comment.data.addedByUser.type | String | Argus | 
| Argus.Comment.data.comment | String | Argus | 
| Argus.Comment.data.flags | String | Argus | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Comment.data.status | String | Argus | 
| Argus.Comment.data.priority | String | Argus | 
| Argus.Comment.data.originEmailAddress | String | Argus | 
| Argus.Comment.data.associatedAttachments.id | String | Argus | 
| Argus.Comment.data.associatedAttachments.name | String | Argus | 
| Argus.Comment.data.references.type | String | Argus | 
| Argus.Comment.data.references.commentID | String | Argus | 
| Argus.Comment.data.lastUpdatedTime | String | Argus | 
| Argus.Comment.data.addedTime | String | Argus | 


#### Command Example
``` !argus_delete_comment case_id=123 comment_id=123456 ```



### argus_edit_comment
***
Edit existing comment


#### Base Command

`argus_edit_comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case where comment exists | Required | 
| comment_id | ID of comment to edit | Required | 
| comment | Comment text which will replace the current text | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Comment.responseCode | Number | Argus | 
| Argus.Comment.limit | Number | Argus | 
| Argus.Comment.offset | Number | Argus | 
| Argus.Comment.count | Number | Argus | 
| Argus.Comment.size | Number | Argus | 
| Argus.Comment.messages.message | String | Argus | 
| Argus.Comment.messages.messageTemplate | String | Argus | 
| Argus.Comment.messages.type | String | Argus | 
| Argus.Comment.messages.field | String | Argus | 
| Argus.Comment.messages.timestamp | Number | Argus | 
| Argus.Comment.data.id | String | Argus | 
| Argus.Comment.data.addedTimestamp | Number | Argus | 
| Argus.Comment.data.addedByUser.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customerID | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.name | String | Argus | 
| Argus.Comment.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.domain.id | Number | Argus | 
| Argus.Comment.data.addedByUser.domain.name | String | Argus | 
| Argus.Comment.data.addedByUser.userName | String | Argus | 
| Argus.Comment.data.addedByUser.name | String | Argus | 
| Argus.Comment.data.addedByUser.type | String | Argus | 
| Argus.Comment.data.comment | String | Argus | 
| Argus.Comment.data.flags | String | Argus | 
| Argus.Comment.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Comment.data.status | String | Argus | 
| Argus.Comment.data.priority | String | Argus | 
| Argus.Comment.data.originEmailAddress | String | Argus | 
| Argus.Comment.data.associatedAttachments.id | String | Argus | 
| Argus.Comment.data.associatedAttachments.name | String | Argus | 
| Argus.Comment.data.references.type | String | Argus | 
| Argus.Comment.data.references.commentID | String | Argus | 
| Argus.Comment.data.lastUpdatedTime | String | Argus | 
| Argus.Comment.data.addedTime | String | Argus | 


#### Command Example
``` !argus_edit_comment case_id=123 comment_id=123456 comment="comment content" ```



### argus_get_case_metadata_by_id
***
Returns the basic case descriptor for the case identified by ID


#### Base Command

`argus_get_case_metadata_by_id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| skip_redirect | If true, skip automatic redirect (for merged cases) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | Argus | 
| Argus.Case.limit | Number | Argus | 
| Argus.Case.offset | Number | Argus | 
| Argus.Case.count | Number | Argus | 
| Argus.Case.size | Number | Argus | 
| Argus.Case.messages.message | String | Argus | 
| Argus.Case.messages.messageTemplate | String | Argus | 
| Argus.Case.messages.type | String | Argus | 
| Argus.Case.messages.field | String | Argus | 
| Argus.Case.messages.timestamp | Number | Argus | 
| Argus.Case.data.id | Number | Argus | 
| Argus.Case.data.customer.id | Number | Argus | 
| Argus.Case.data.customer.name | String | Argus | 
| Argus.Case.data.customer.shortName | String | Argus | 
| Argus.Case.data.customer.domain.id | Number | Argus | 
| Argus.Case.data.customer.domain.name | String | Argus | 
| Argus.Case.data.service.id | Number | Argus | 
| Argus.Case.data.service.name | String | Argus | 
| Argus.Case.data.service.shortName | String | Argus | 
| Argus.Case.data.service.localizedName | String | Argus | 
| Argus.Case.data.category.id | Number | Argus | 
| Argus.Case.data.category.name | String | Argus | 
| Argus.Case.data.category.shortName | String | Argus | 
| Argus.Case.data.category.localizedName | String | Argus | 
| Argus.Case.data.type | String | Argus | 
| Argus.Case.data.initialStatus | String | Argus | 
| Argus.Case.data.status | String | Argus | 
| Argus.Case.data.initialPriority | String | Argus | 
| Argus.Case.data.priority | String | Argus | 
| Argus.Case.data.subject | String | Argus | 
| Argus.Case.data.description | String | Argus | 
| Argus.Case.data.customerReference | String | Argus | 
| Argus.Case.data.accessMode | String | Argus | 
| Argus.Case.data.reporter.id | Number | Argus | 
| Argus.Case.data.reporter.customerID | Number | Argus | 
| Argus.Case.data.reporter.customer.id | Number | Argus | 
| Argus.Case.data.reporter.customer.name | String | Argus | 
| Argus.Case.data.reporter.customer.shortName | String | Argus | 
| Argus.Case.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Case.data.reporter.customer.domain.name | String | Argus | 
| Argus.Case.data.reporter.domain.id | Number | Argus | 
| Argus.Case.data.reporter.domain.name | String | Argus | 
| Argus.Case.data.reporter.userName | String | Argus | 
| Argus.Case.data.reporter.name | String | Argus | 
| Argus.Case.data.reporter.type | String | Argus | 
| Argus.Case.data.assignedUser.id | Number | Argus | 
| Argus.Case.data.assignedUser.customerID | Number | Argus | 
| Argus.Case.data.assignedUser.customer.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.name | String | Argus | 
| Argus.Case.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.userName | String | Argus | 
| Argus.Case.data.assignedUser.name | String | Argus | 
| Argus.Case.data.assignedUser.type | String | Argus | 
| Argus.Case.data.assignedTech.id | Number | Argus | 
| Argus.Case.data.assignedTech.customerID | Number | Argus | 
| Argus.Case.data.assignedTech.customer.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.name | String | Argus | 
| Argus.Case.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.userName | String | Argus | 
| Argus.Case.data.assignedTech.name | String | Argus | 
| Argus.Case.data.assignedTech.type | String | Argus | 
| Argus.Case.data.createdTimestamp | Number | Argus | 
| Argus.Case.data.createdByUser.id | Number | Argus | 
| Argus.Case.data.createdByUser.customerID | Number | Argus | 
| Argus.Case.data.createdByUser.customer.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.name | String | Argus | 
| Argus.Case.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.userName | String | Argus | 
| Argus.Case.data.createdByUser.name | String | Argus | 
| Argus.Case.data.createdByUser.type | String | Argus | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Case.data.closedTimestamp | Number | Argus | 
| Argus.Case.data.closedByUser.id | Number | Argus | 
| Argus.Case.data.closedByUser.customerID | Number | Argus | 
| Argus.Case.data.closedByUser.customer.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.name | String | Argus | 
| Argus.Case.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.userName | String | Argus | 
| Argus.Case.data.closedByUser.name | String | Argus | 
| Argus.Case.data.closedByUser.type | String | Argus | 
| Argus.Case.data.publishedTimestamp | Number | Argus | 
| Argus.Case.data.publishedByUser.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customerID | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.name | String | Argus | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.userName | String | Argus | 
| Argus.Case.data.publishedByUser.name | String | Argus | 
| Argus.Case.data.publishedByUser.type | String | Argus | 
| Argus.Case.data.flags | String | Argus | 
| Argus.Case.data.currentUserAccess.level | String | Argus | 
| Argus.Case.data.currentUserAccess.role | String | Argus | 
| Argus.Case.data.workflows.workflow | String | Argus | 
| Argus.Case.data.workflows.state | String | Argus | 
| Argus.Case.data.originEmailAddress | String | Argus | 
| Argus.Case.data.createdTime | String | Argus | 
| Argus.Case.data.lastUpdatedTime | String | Argus | 
| Argus.Case.data.closedTime | String | Argus | 
| Argus.Case.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_get_case_metadata_by_id case_id=123 ```



### argus_list_case_attachments
***
List attachments for an existing case


#### Base Command

`argus_list_case_attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| limit | Maximum number of returned results | Optional | 
| offset | Skip a number of results | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Attachments.responseCode | Number | Argus | 
| Argus.Attachments.limit | Number | Argus | 
| Argus.Attachments.offset | Number | Argus | 
| Argus.Attachments.count | Number | Argus | 
| Argus.Attachments.size | Number | Argus | 
| Argus.Attachments.messages.message | String | Argus | 
| Argus.Attachments.messages.messageTemplate | String | Argus | 
| Argus.Attachments.messages.type | String | Argus | 
| Argus.Attachments.messages.field | String | Argus | 
| Argus.Attachments.messages.timestamp | Number | Argus | 
| Argus.Attachments.data.id | String | Argus | 
| Argus.Attachments.data.addedTimestamp | Number | Argus | 
| Argus.Attachments.data.addedByUser.id | Number | Argus | 
| Argus.Attachments.data.addedByUser.customerID | Number | Argus | 
| Argus.Attachments.data.addedByUser.customer.id | Number | Argus | 
| Argus.Attachments.data.addedByUser.customer.name | String | Argus | 
| Argus.Attachments.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Attachments.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Attachments.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Attachments.data.addedByUser.domain.id | Number | Argus | 
| Argus.Attachments.data.addedByUser.domain.name | String | Argus | 
| Argus.Attachments.data.addedByUser.userName | String | Argus | 
| Argus.Attachments.data.addedByUser.name | String | Argus | 
| Argus.Attachments.data.addedByUser.type | String | Argus | 
| Argus.Attachments.data.name | String | Argus | 
| Argus.Attachments.data.mimeType | String | Argus | 
| Argus.Attachments.data.flags | String | Argus | 
| Argus.Attachments.data.size | Number | Argus | 
| Argus.Attachments.data.originEmailAddress | String | Argus | 
| Argus.Attachments.data.addedTime | String | Argus | 


#### Command Example
``` !argus_list_case_attachments case_id=123 ```



### argus_remove_case_tag_by_id
***
Remove existing tag by tag ID


#### Base Command

`argus_remove_case_tag_by_id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| tag_id | ID of tag to remove | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | Argus | 
| Argus.Tags.limit | Number | Argus | 
| Argus.Tags.offset | Number | Argus | 
| Argus.Tags.count | Number | Argus | 
| Argus.Tags.size | Number | Argus | 
| Argus.Tags.messages.message | String | Argus | 
| Argus.Tags.messages.messageTemplate | String | Argus | 
| Argus.Tags.messages.type | String | Argus | 
| Argus.Tags.messages.field | String | Argus | 
| Argus.Tags.messages.timestamp | Number | Argus | 
| Argus.Tags.data.id | String | Argus | 
| Argus.Tags.data.key | String | Argus | 
| Argus.Tags.data.value | String | Argus | 
| Argus.Tags.data.addedTimestamp | Number | Argus | 
| Argus.Tags.data.addedByUser.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customerID | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.name | String | Argus | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.userName | String | Argus | 
| Argus.Tags.data.addedByUser.name | String | Argus | 
| Argus.Tags.data.addedByUser.type | String | Argus | 
| Argus.Tags.data.flags | String | Argus | 
| Argus.Tags.data.addedTime | String | Argus | 


#### Command Example
``` !argus_remove_case_tag_by_id case_id=123 tag_id=123456 ```


### argus_remove_case_tag_by_key_value
***
Remove existing tag with key, value matching


#### Base Command

`argus_remove_case_tag_by_key_value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| key | Key of tag to remove | Required | 
| value | Value of tag to remove | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Tags.responseCode | Number | Argus | 
| Argus.Tags.limit | Number | Argus | 
| Argus.Tags.offset | Number | Argus | 
| Argus.Tags.count | Number | Argus | 
| Argus.Tags.size | Number | Argus | 
| Argus.Tags.messages.message | String | Argus | 
| Argus.Tags.messages.messageTemplate | String | Argus | 
| Argus.Tags.messages.type | String | Argus | 
| Argus.Tags.messages.field | String | Argus | 
| Argus.Tags.messages.timestamp | Number | Argus | 
| Argus.Tags.data.id | String | Argus | 
| Argus.Tags.data.key | String | Argus | 
| Argus.Tags.data.value | String | Argus | 
| Argus.Tags.data.addedTimestamp | Number | Argus | 
| Argus.Tags.data.addedByUser.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customerID | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.name | String | Argus | 
| Argus.Tags.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.domain.id | Number | Argus | 
| Argus.Tags.data.addedByUser.domain.name | String | Argus | 
| Argus.Tags.data.addedByUser.userName | String | Argus | 
| Argus.Tags.data.addedByUser.name | String | Argus | 
| Argus.Tags.data.addedByUser.type | String | Argus | 
| Argus.Tags.data.flags | String | Argus | 
| Argus.Tags.data.addedTime | String | Argus | 


#### Command Example
``` !argus_remove_case_tag_by_key_value case_id=123 key=foo value=bar ```



### argus_update_case
***
Request changes to basic fields of an existing case.


#### Base Command

`argus_update_case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case to update | Required | 
| subject | If set, change subject of case. | Optional | 
| description | If set, change description of case. May use HTML, will be sanitized.  | Optional | 
| status | If set, change status of case  | Optional | 
| priority | If set, change priority of case.  | Optional | 
| category | If set, assign given category to specified category (by category shortname). Set value to empty string to unset category.  | Optional | 
| reporter | If set, set given user as reporter for case (by ID or shortname). Shortname will be resolved in the current users domain.  | Optional | 
| assigned_user | If set, assign given user to case (by ID or shortname). Shortname will be resolved in the current users domain. If blank, this will unset assignedUser.  | Optional | 
| assigned_tech | If set, assign given technical user (solution engineer) to case (by ID or shortname). Shortname will be resolved in the current users domain. If blank, this will unset assignedTech. | Optional | 
| customer_reference | If set, change customer reference for case.  | Optional | 
| comment | If set, add comment to case. May use HTML, will be sanitized.  | Optional | 
| origin_email_address | If update is made from an email, specify origin email address here | Optional | 
| has_events | f set, update the hasEvents flag for this case, signalling that this case may have events associated to it.  | Optional | 
| internal_comment | If true, add comment as internal. (default false) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Case.responseCode | Number | Argus | 
| Argus.Case.limit | Number | Argus | 
| Argus.Case.offset | Number | Argus | 
| Argus.Case.count | Number | Argus | 
| Argus.Case.size | Number | Argus | 
| Argus.Case.messages.message | String | Argus | 
| Argus.Case.messages.messageTemplate | String | Argus | 
| Argus.Case.messages.type | String | Argus | 
| Argus.Case.messages.field | String | Argus | 
| Argus.Case.messages.timestamp | Number | Argus | 
| Argus.Case.data.id | Number | Argus | 
| Argus.Case.data.customer.id | Number | Argus | 
| Argus.Case.data.customer.name | String | Argus | 
| Argus.Case.data.customer.shortName | String | Argus | 
| Argus.Case.data.customer.domain.id | Number | Argus | 
| Argus.Case.data.customer.domain.name | String | Argus | 
| Argus.Case.data.service.id | Number | Argus | 
| Argus.Case.data.service.name | String | Argus | 
| Argus.Case.data.service.shortName | String | Argus | 
| Argus.Case.data.service.localizedName | String | Argus | 
| Argus.Case.data.category.id | Number | Argus | 
| Argus.Case.data.category.name | String | Argus | 
| Argus.Case.data.category.shortName | String | Argus | 
| Argus.Case.data.category.localizedName | String | Argus | 
| Argus.Case.data.type | String | Argus | 
| Argus.Case.data.initialStatus | String | Argus | 
| Argus.Case.data.status | String | Argus | 
| Argus.Case.data.initialPriority | String | Argus | 
| Argus.Case.data.priority | String | Argus | 
| Argus.Case.data.subject | String | Argus | 
| Argus.Case.data.description | String | Argus | 
| Argus.Case.data.customerReference | String | Argus | 
| Argus.Case.data.accessMode | String | Argus | 
| Argus.Case.data.reporter.id | Number | Argus | 
| Argus.Case.data.reporter.customerID | Number | Argus | 
| Argus.Case.data.reporter.customer.id | Number | Argus | 
| Argus.Case.data.reporter.customer.name | String | Argus | 
| Argus.Case.data.reporter.customer.shortName | String | Argus | 
| Argus.Case.data.reporter.customer.domain.id | Number | Argus | 
| Argus.Case.data.reporter.customer.domain.name | String | Argus | 
| Argus.Case.data.reporter.domain.id | Number | Argus | 
| Argus.Case.data.reporter.domain.name | String | Argus | 
| Argus.Case.data.reporter.userName | String | Argus | 
| Argus.Case.data.reporter.name | String | Argus | 
| Argus.Case.data.reporter.type | String | Argus | 
| Argus.Case.data.assignedUser.id | Number | Argus | 
| Argus.Case.data.assignedUser.customerID | Number | Argus | 
| Argus.Case.data.assignedUser.customer.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.name | String | Argus | 
| Argus.Case.data.assignedUser.customer.shortName | String | Argus | 
| Argus.Case.data.assignedUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.domain.id | Number | Argus | 
| Argus.Case.data.assignedUser.domain.name | String | Argus | 
| Argus.Case.data.assignedUser.userName | String | Argus | 
| Argus.Case.data.assignedUser.name | String | Argus | 
| Argus.Case.data.assignedUser.type | String | Argus | 
| Argus.Case.data.assignedTech.id | Number | Argus | 
| Argus.Case.data.assignedTech.customerID | Number | Argus | 
| Argus.Case.data.assignedTech.customer.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.name | String | Argus | 
| Argus.Case.data.assignedTech.customer.shortName | String | Argus | 
| Argus.Case.data.assignedTech.customer.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.customer.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.domain.id | Number | Argus | 
| Argus.Case.data.assignedTech.domain.name | String | Argus | 
| Argus.Case.data.assignedTech.userName | String | Argus | 
| Argus.Case.data.assignedTech.name | String | Argus | 
| Argus.Case.data.assignedTech.type | String | Argus | 
| Argus.Case.data.createdTimestamp | Number | Argus | 
| Argus.Case.data.createdByUser.id | Number | Argus | 
| Argus.Case.data.createdByUser.customerID | Number | Argus | 
| Argus.Case.data.createdByUser.customer.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.name | String | Argus | 
| Argus.Case.data.createdByUser.customer.shortName | String | Argus | 
| Argus.Case.data.createdByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.domain.id | Number | Argus | 
| Argus.Case.data.createdByUser.domain.name | String | Argus | 
| Argus.Case.data.createdByUser.userName | String | Argus | 
| Argus.Case.data.createdByUser.name | String | Argus | 
| Argus.Case.data.createdByUser.type | String | Argus | 
| Argus.Case.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customerID | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.id | Number | Argus | 
| Argus.Case.data.lastUpdatedByUser.domain.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.userName | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.name | String | Argus | 
| Argus.Case.data.lastUpdatedByUser.type | String | Argus | 
| Argus.Case.data.closedTimestamp | Number | Argus | 
| Argus.Case.data.closedByUser.id | Number | Argus | 
| Argus.Case.data.closedByUser.customerID | Number | Argus | 
| Argus.Case.data.closedByUser.customer.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.name | String | Argus | 
| Argus.Case.data.closedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.closedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.domain.id | Number | Argus | 
| Argus.Case.data.closedByUser.domain.name | String | Argus | 
| Argus.Case.data.closedByUser.userName | String | Argus | 
| Argus.Case.data.closedByUser.name | String | Argus | 
| Argus.Case.data.closedByUser.type | String | Argus | 
| Argus.Case.data.publishedTimestamp | Number | Argus | 
| Argus.Case.data.publishedByUser.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customerID | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.name | String | Argus | 
| Argus.Case.data.publishedByUser.customer.shortName | String | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.customer.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.domain.id | Number | Argus | 
| Argus.Case.data.publishedByUser.domain.name | String | Argus | 
| Argus.Case.data.publishedByUser.userName | String | Argus | 
| Argus.Case.data.publishedByUser.name | String | Argus | 
| Argus.Case.data.publishedByUser.type | String | Argus | 
| Argus.Case.data.flags | String | Argus | 
| Argus.Case.data.currentUserAccess.level | String | Argus | 
| Argus.Case.data.currentUserAccess.role | String | Argus | 
| Argus.Case.data.workflows.workflow | String | Argus | 
| Argus.Case.data.workflows.state | String | Argus | 
| Argus.Case.data.originEmailAddress | String | Argus | 
| Argus.Case.data.createdTime | String | Argus | 
| Argus.Case.data.lastUpdatedTime | String | Argus | 
| Argus.Case.data.closedTime | String | Argus | 
| Argus.Case.data.publishedTime | String | Argus | 


#### Command Example
``` !argus_update_case case_id=123 ```


### argus_get_attachment
***
Fetch specific attachment metadata


#### Base Command

`argus_get_attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| attachment_id | ID of attachement | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Attachment.responseCode | Number | Argus | 
| Argus.Attachment.limit | Number | Argus | 
| Argus.Attachment.offset | Number | Argus | 
| Argus.Attachment.count | Number | Argus | 
| Argus.Attachment.size | Number | Argus | 
| Argus.Attachment.messages.message | String | Argus | 
| Argus.Attachment.messages.messageTemplate | String | Argus | 
| Argus.Attachment.messages.type | String | Argus | 
| Argus.Attachment.messages.field | String | Argus | 
| Argus.Attachment.messages.timestamp | Number | Argus | 
| Argus.Attachment.data.id | String | Argus | 
| Argus.Attachment.data.addedTimestamp | Number | Argus | 
| Argus.Attachment.data.addedByUser.id | Number | Argus | 
| Argus.Attachment.data.addedByUser.customerID | Number | Argus | 
| Argus.Attachment.data.addedByUser.customer.id | Number | Argus | 
| Argus.Attachment.data.addedByUser.customer.name | String | Argus | 
| Argus.Attachment.data.addedByUser.customer.shortName | String | Argus | 
| Argus.Attachment.data.addedByUser.customer.domain.id | Number | Argus | 
| Argus.Attachment.data.addedByUser.customer.domain.name | String | Argus | 
| Argus.Attachment.data.addedByUser.domain.id | Number | Argus | 
| Argus.Attachment.data.addedByUser.domain.name | String | Argus | 
| Argus.Attachment.data.addedByUser.userName | String | Argus | 
| Argus.Attachment.data.addedByUser.name | String | Argus | 
| Argus.Attachment.data.addedByUser.type | String | Argus | 
| Argus.Attachment.data.name | String | Argus | 
| Argus.Attachment.data.mimeType | String | Argus | 
| Argus.Attachment.data.flags | String | Argus | 
| Argus.Attachment.data.size | Number | Argus | 
| Argus.Attachment.data.originEmailAddress | String | Argus | 
| Argus.Attachment.data.addedTime | String | Argus | 


#### Command Example
``` !argus_get_attachment case_id=123 attachment_id=123456 ```


### argus_download_attachment
***
Download specific attachment contents.


#### Base Command

`argus_download_attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| attachment_id | ID of attachment to download | Required | 


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
``` !argus_download_attachment case_id=123 attachment_id=123456 ```



### argus_get_events_for_case
***
Fetch events associated with specified case.


#### Base Command

`argus_get_events_for_case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of Argus case | Required | 
| limit | Maximum number of returned results (default 25) | Optional | 
| offset | Skip a number of results | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Events.responseCode | Number | Argus | 
| Argus.Events.limit | Number | Argus | 
| Argus.Events.offset | Number | Argus | 
| Argus.Events.count | Number | Argus | 
| Argus.Events.size | Number | Argus | 
| Argus.Events.messages.message | String | Argus | 
| Argus.Events.messages.messageTemplate | String | Argus | 
| Argus.Events.messages.type | String | Argus | 
| Argus.Events.messages.field | String | Argus | 
| Argus.Events.messages.timestamp | Number | Argus | 
| Argus.Events.data.customerInfo.id | Number | Argus | 
| Argus.Events.data.customerInfo.name | String | Argus | 
| Argus.Events.data.customerInfo.shortName | String | Argus | 
| Argus.Events.data.customerInfo.domain.id | Number | Argus | 
| Argus.Events.data.customerInfo.domain.name | String | Argus | 
| Argus.Events.data.properties.additionalProp1 | String | Argus | 
| Argus.Events.data.properties.additionalProp2 | String | Argus | 
| Argus.Events.data.properties.additionalProp3 | String | Argus | 
| Argus.Events.data.comments.timestamp | Number | Argus | 
| Argus.Events.data.comments.user.id | Number | Argus | 
| Argus.Events.data.comments.user.customerID | Number | Argus | 
| Argus.Events.data.comments.user.customer.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.name | String | Argus | 
| Argus.Events.data.comments.user.customer.shortName | String | Argus | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.domain.name | String | Argus | 
| Argus.Events.data.comments.user.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.domain.name | String | Argus | 
| Argus.Events.data.comments.user.userName | String | Argus | 
| Argus.Events.data.comments.user.name | String | Argus | 
| Argus.Events.data.comments.user.type | String | Argus | 
| Argus.Events.data.comments.comment | String | Argus | 
| Argus.Events.data.associatedCase.id | Number | Argus | 
| Argus.Events.data.associatedCase.subject | String | Argus | 
| Argus.Events.data.associatedCase.categoryID | Number | Argus | 
| Argus.Events.data.associatedCase.categoryName | String | Argus | 
| Argus.Events.data.associatedCase.service | String | Argus | 
| Argus.Events.data.associatedCase.status | String | Argus | 
| Argus.Events.data.associatedCase.priority | String | Argus | 
| Argus.Events.data.location.shortName | String | Argus | 
| Argus.Events.data.location.name | String | Argus | 
| Argus.Events.data.location.timeZone | String | Argus | 
| Argus.Events.data.location.id | Number | Argus | 
| Argus.Events.data.attackInfo.alarmID | Number | Argus | 
| Argus.Events.data.attackInfo.alarmDescription | String | Argus | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Argus | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Argus | 
| Argus.Events.data.attackInfo.signature | String | Argus | 
| Argus.Events.data.domain.fqdn | String | Argus | 
| Argus.Events.data.uri | String | Argus | 
| Argus.Events.data.count | Number | Argus | 
| Argus.Events.data.source.port | Number | Argus | 
| Argus.Events.data.source.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.source.geoLocation.countryName | String | Argus | 
| Argus.Events.data.source.geoLocation.locationName | String | Argus | 
| Argus.Events.data.source.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.source.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.address | String | Argus | 
| Argus.Events.data.destination.port | Number | Argus | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.destination.geoLocation.countryName | String | Argus | 
| Argus.Events.data.destination.geoLocation.locationName | String | Argus | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.address | String | Argus | 
| Argus.Events.data.protocol | String | Argus | 
| Argus.Events.data.timestamp | Number | Argus | 
| Argus.Events.data.startTimestamp | Number | Argus | 
| Argus.Events.data.endTimestamp | Number | Argus | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Events.data.flags | String | Argus | 
| Argus.Events.data.detailedEventIDS | String | Argus | 
| Argus.Events.data.severity | String | Argus | 
| Argus.Events.data.id | String | Argus | 


#### Command Example
``` !argus_get_events_for_case case_id=123 ```



### argus_list_aggregated_events
***
List aggregated events


#### Base Command

`argus_list_aggregated_events`
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
| Argus.Events.responseCode | Number | Argus | 
| Argus.Events.limit | Number | Argus | 
| Argus.Events.offset | Number | Argus | 
| Argus.Events.count | Number | Argus | 
| Argus.Events.size | Number | Argus | 
| Argus.Events.messages.message | String | Argus | 
| Argus.Events.messages.messageTemplate | String | Argus | 
| Argus.Events.messages.type | String | Argus | 
| Argus.Events.messages.field | String | Argus | 
| Argus.Events.messages.timestamp | Number | Argus | 
| Argus.Events.data.customerInfo.id | Number | Argus | 
| Argus.Events.data.customerInfo.name | String | Argus | 
| Argus.Events.data.customerInfo.shortName | String | Argus | 
| Argus.Events.data.customerInfo.domain.id | Number | Argus | 
| Argus.Events.data.customerInfo.domain.name | String | Argus | 
| Argus.Events.data.properties.additionalProp1 | String | Argus | 
| Argus.Events.data.properties.additionalProp2 | String | Argus | 
| Argus.Events.data.properties.additionalProp3 | String | Argus | 
| Argus.Events.data.comments.timestamp | Number | Argus | 
| Argus.Events.data.comments.user.id | Number | Argus | 
| Argus.Events.data.comments.user.customerID | Number | Argus | 
| Argus.Events.data.comments.user.customer.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.name | String | Argus | 
| Argus.Events.data.comments.user.customer.shortName | String | Argus | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.domain.name | String | Argus | 
| Argus.Events.data.comments.user.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.domain.name | String | Argus | 
| Argus.Events.data.comments.user.userName | String | Argus | 
| Argus.Events.data.comments.user.name | String | Argus | 
| Argus.Events.data.comments.user.type | String | Argus | 
| Argus.Events.data.comments.comment | String | Argus | 
| Argus.Events.data.associatedCase.id | Number | Argus | 
| Argus.Events.data.associatedCase.subject | String | Argus | 
| Argus.Events.data.associatedCase.categoryID | Number | Argus | 
| Argus.Events.data.associatedCase.categoryName | String | Argus | 
| Argus.Events.data.associatedCase.service | String | Argus | 
| Argus.Events.data.associatedCase.status | String | Argus | 
| Argus.Events.data.associatedCase.priority | String | Argus | 
| Argus.Events.data.location.shortName | String | Argus | 
| Argus.Events.data.location.name | String | Argus | 
| Argus.Events.data.location.timeZone | String | Argus | 
| Argus.Events.data.location.id | Number | Argus | 
| Argus.Events.data.attackInfo.alarmID | Number | Argus | 
| Argus.Events.data.attackInfo.alarmDescription | String | Argus | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Argus | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Argus | 
| Argus.Events.data.attackInfo.signature | String | Argus | 
| Argus.Events.data.domain.fqdn | String | Argus | 
| Argus.Events.data.uri | String | Argus | 
| Argus.Events.data.count | Number | Argus | 
| Argus.Events.data.source.port | Number | Argus | 
| Argus.Events.data.source.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.source.geoLocation.countryName | String | Argus | 
| Argus.Events.data.source.geoLocation.locationName | String | Argus | 
| Argus.Events.data.source.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.source.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.address | String | Argus | 
| Argus.Events.data.destination.port | Number | Argus | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.destination.geoLocation.countryName | String | Argus | 
| Argus.Events.data.destination.geoLocation.locationName | String | Argus | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.address | String | Argus | 
| Argus.Events.data.protocol | String | Argus | 
| Argus.Events.data.timestamp | Number | Argus | 
| Argus.Events.data.startTimestamp | Number | Argus | 
| Argus.Events.data.endTimestamp | Number | Argus | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Events.data.flags | String | Argus | 
| Argus.Events.data.detailedEventIDS | String | Argus | 
| Argus.Events.data.severity | String | Argus | 
| Argus.Events.data.id | String | Argus | 


#### Command Example
``` !argus_list_aggregated_events  ```


### argus_find_aggregated_events
***
Search for aggregated events (OSB! advanced method: look in API doc)


#### Base Command

`argus_find_aggregated_events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip_future_events | Skip future events | Optional | 
| exclude | Exclude parameter | Optional | 
| event_identifier | (as list) | Optional | 
| location_id | (as list) | Optional | 
| severity | (as list) | Optional | 
| customer | (as list) | Optional | 
| alarm_id | (as list) | Optional | 
| attack_category_id | (as list) | Optional | 
| source_geo_country | (as list) | Optional | 
| destination_geo_country | (as list) | Optional | 
| geo_country | (as list) | Optional | 
| properties | (as dict: key,value) | Optional | 
| exact_match_properties | Exact matching flag | Optional | 
| sub_criteria | (as list) | Optional | 
| signature | (as list) | Optional | 
| last_updated_timestamp | Last updated timestamp | Optional | 
| index_start_time | Index start time | Optional | 
| index_end_time | Index end time | Optional | 
| destination_ip | (as list) | Optional | 
| source_ip | (as list) | Optional | 
| ip | (as list) | Optional | 
| destination_port | (as list) | Optional | 
| source_port | (as list) | Optional | 
| port | (as lst) | Optional | 
| min_severity | Minimum severity | Optional | 
| max_severity | Maximum severity | Optional | 
| limit | Limit results (default 25) | Optional | 
| offset | Skip number of results | Optional | 
| include_deleted | Include deleted events | Optional | 
| min_count | Minimum count | Optional | 
| associated_case_id | (as list) | Optional | 
| source_ip_min_bits | Source IP minimum bits | Optional | 
| destination_ip_min_bits | Destination IP minimum bits | Optional | 
| start_timestamp | Start timestamp | Optional | 
| end_timestamp | End timestamp | Optional | 
| sort_by | Order results by these properties (prefix with - to sort descending) (as list) | Optional | 
| include_flags | Search objects with these flags set  (as list) | Optional | 
| exclude_flags | Exclude objects with these flags set (as list) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Events.responseCode | Number | Argus | 
| Argus.Events.limit | Number | Argus | 
| Argus.Events.offset | Number | Argus | 
| Argus.Events.count | Number | Argus | 
| Argus.Events.size | Number | Argus | 
| Argus.Events.messages.message | String | Argus | 
| Argus.Events.messages.messageTemplate | String | Argus | 
| Argus.Events.messages.type | String | Argus | 
| Argus.Events.messages.field | String | Argus | 
| Argus.Events.messages.timestamp | Number | Argus | 
| Argus.Events.data.customerInfo.id | Number | Argus | 
| Argus.Events.data.customerInfo.name | String | Argus | 
| Argus.Events.data.customerInfo.shortName | String | Argus | 
| Argus.Events.data.customerInfo.domain.id | Number | Argus | 
| Argus.Events.data.customerInfo.domain.name | String | Argus | 
| Argus.Events.data.properties.additionalProp1 | String | Argus | 
| Argus.Events.data.properties.additionalProp2 | String | Argus | 
| Argus.Events.data.properties.additionalProp3 | String | Argus | 
| Argus.Events.data.comments.timestamp | Number | Argus | 
| Argus.Events.data.comments.user.id | Number | Argus | 
| Argus.Events.data.comments.user.customerID | Number | Argus | 
| Argus.Events.data.comments.user.customer.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.name | String | Argus | 
| Argus.Events.data.comments.user.customer.shortName | String | Argus | 
| Argus.Events.data.comments.user.customer.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.customer.domain.name | String | Argus | 
| Argus.Events.data.comments.user.domain.id | Number | Argus | 
| Argus.Events.data.comments.user.domain.name | String | Argus | 
| Argus.Events.data.comments.user.userName | String | Argus | 
| Argus.Events.data.comments.user.name | String | Argus | 
| Argus.Events.data.comments.user.type | String | Argus | 
| Argus.Events.data.comments.comment | String | Argus | 
| Argus.Events.data.associatedCase.id | Number | Argus | 
| Argus.Events.data.associatedCase.subject | String | Argus | 
| Argus.Events.data.associatedCase.categoryID | Number | Argus | 
| Argus.Events.data.associatedCase.categoryName | String | Argus | 
| Argus.Events.data.associatedCase.service | String | Argus | 
| Argus.Events.data.associatedCase.status | String | Argus | 
| Argus.Events.data.associatedCase.priority | String | Argus | 
| Argus.Events.data.location.shortName | String | Argus | 
| Argus.Events.data.location.name | String | Argus | 
| Argus.Events.data.location.timeZone | String | Argus | 
| Argus.Events.data.location.id | Number | Argus | 
| Argus.Events.data.attackInfo.alarmID | Number | Argus | 
| Argus.Events.data.attackInfo.alarmDescription | String | Argus | 
| Argus.Events.data.attackInfo.attackCategoryID | Number | Argus | 
| Argus.Events.data.attackInfo.attackCategoryName | String | Argus | 
| Argus.Events.data.attackInfo.signature | String | Argus | 
| Argus.Events.data.domain.fqdn | String | Argus | 
| Argus.Events.data.uri | String | Argus | 
| Argus.Events.data.count | Number | Argus | 
| Argus.Events.data.source.port | Number | Argus | 
| Argus.Events.data.source.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.source.geoLocation.countryName | String | Argus | 
| Argus.Events.data.source.geoLocation.locationName | String | Argus | 
| Argus.Events.data.source.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.source.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.source.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.source.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.source.networkAddress.address | String | Argus | 
| Argus.Events.data.destination.port | Number | Argus | 
| Argus.Events.data.destination.geoLocation.countryCode | String | Argus | 
| Argus.Events.data.destination.geoLocation.countryName | String | Argus | 
| Argus.Events.data.destination.geoLocation.locationName | String | Argus | 
| Argus.Events.data.destination.geoLocation.latitude | Number | Argus | 
| Argus.Events.data.destination.geoLocation.longitude | Number | Argus | 
| Argus.Events.data.destination.networkAddress.ipv6 | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.public | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.maskBits | Number | Argus | 
| Argus.Events.data.destination.networkAddress.multicast | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.host | Boolean | Argus | 
| Argus.Events.data.destination.networkAddress.address | String | Argus | 
| Argus.Events.data.protocol | String | Argus | 
| Argus.Events.data.timestamp | Number | Argus | 
| Argus.Events.data.startTimestamp | Number | Argus | 
| Argus.Events.data.endTimestamp | Number | Argus | 
| Argus.Events.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.Events.data.flags | String | Argus | 
| Argus.Events.data.detailedEventIDS | String | Argus | 
| Argus.Events.data.severity | String | Argus | 
| Argus.Events.data.id | String | Argus | 


#### Command Example
``` !argus_find_aggregated_events ```


### argus_get_payload
***
Fetch specified event payload


#### Base Command

`argus_get_payload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Event type. | Required | 
| timestamp | Timestamp of event | Required | 
| customer_id | ID of customer | Required | 
| event_id | ID of related event | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Payload.responseCode | Number | Argus | 
| Argus.Payload.limit | Number | Argus | 
| Argus.Payload.offset | Number | Argus | 
| Argus.Payload.count | Number | Argus | 
| Argus.Payload.size | Number | Argus | 
| Argus.Payload.messages.message | String | Argus | 
| Argus.Payload.messages.messageTemplate | String | Argus | 
| Argus.Payload.messages.type | String | Argus | 
| Argus.Payload.messages.field | String | Argus | 
| Argus.Payload.messages.timestamp | Number | Argus | 
| Argus.Payload.data.id | String | Argus | 
| Argus.Payload.data.type | String | Argus | 
| Argus.Payload.data.payload | String | Argus | 


#### Command Example
``` !argus_get_payload customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```



### argus_get_pcap
***
Fetch specified event payload as PCAP.


#### Base Command

`argus_get_pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Event type. | Required | 
| timestamp | Timestamp of event | Required | 
| customer_id | ID of customer | Required | 
| event_id | ID of related event | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !argus_get_pcap customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```



### argus_get_event
***
Fetch specified event.


#### Base Command

`argus_get_event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of event | Required | 
| timestamp | Timestamp of event | Required | 
| customer_id | Customer ID related to event | Required | 
| event_id | ID of event | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.Event.responseCode | Number | Argus | 
| Argus.Event.limit | Number | Argus | 
| Argus.Event.offset | Number | Argus | 
| Argus.Event.count | Number | Argus | 
| Argus.Event.size | Number | Argus | 
| Argus.Event.messages.message | String | Argus | 
| Argus.Event.messages.messageTemplate | String | Argus | 
| Argus.Event.messages.type | String | Argus | 
| Argus.Event.messages.field | String | Argus | 
| Argus.Event.messages.timestamp | Number | Argus | 
| Argus.Event.data.timestamp | Number | Argus | 
| Argus.Event.data.flags | Number | Argus | 
| Argus.Event.data.customerID | Number | Argus | 
| Argus.Event.data.aggregationKey | String | Argus | 
| Argus.Event.data.sourceType | String | Argus | 
| Argus.Event.data.customerInfo.id | Number | Argus | 
| Argus.Event.data.customerInfo.name | String | Argus | 
| Argus.Event.data.customerInfo.shortName | String | Argus | 
| Argus.Event.data.customerInfo.domain.id | Number | Argus | 
| Argus.Event.data.customerInfo.domain.name | String | Argus | 
| Argus.Event.data.update | Boolean | Argus | 
| Argus.Event.data.aggregated | Boolean | Argus | 
| Argus.Event.data.encodedFlags | String | Argus | 


#### Command Example
``` !argus_get_event customer_id=123 event_id=123456 timestamp=123456789 type=NIDS ```



### argus_list_nids_events
***
Simple search for NIDS events.


#### Base Command

`argus_list_nids_events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Limit to customerID | Optional | 
| signature | Limit to signature | Optional | 
| ip | Limit to ip/network | Optional | 
| start_timestamp | Limit to events after this timestamp (default is last 24 hours). | Optional | 
| end_timestamp | Limit to events before this timestamp (default: now). | Optional | 
| limit | Limit results (default: 25). | Optional | 
| offset | Skip a number of results | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.NIDS.responseCode | Number | Argus | 
| Argus.NIDS.limit | Number | Argus | 
| Argus.NIDS.offset | Number | Argus | 
| Argus.NIDS.count | Number | Argus | 
| Argus.NIDS.size | Number | Argus | 
| Argus.NIDS.messages.message | String | Argus | 
| Argus.NIDS.messages.messageTemplate | String | Argus | 
| Argus.NIDS.messages.type | String | Argus | 
| Argus.NIDS.messages.field | String | Argus | 
| Argus.NIDS.messages.timestamp | Number | Argus | 
| Argus.NIDS.data.customerInfo.id | Number | Argus | 
| Argus.NIDS.data.customerInfo.name | String | Argus | 
| Argus.NIDS.data.customerInfo.shortName | String | Argus | 
| Argus.NIDS.data.customerInfo.domain.id | Number | Argus | 
| Argus.NIDS.data.customerInfo.domain.name | String | Argus | 
| Argus.NIDS.data.properties.additionalProp1 | String | Argus | 
| Argus.NIDS.data.properties.additionalProp2 | String | Argus | 
| Argus.NIDS.data.properties.additionalProp3 | String | Argus | 
| Argus.NIDS.data.comments.timestamp | Number | Argus | 
| Argus.NIDS.data.comments.user.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customerID | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.name | String | Argus | 
| Argus.NIDS.data.comments.user.customer.shortName | String | Argus | 
| Argus.NIDS.data.comments.user.customer.domain.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.domain.name | String | Argus | 
| Argus.NIDS.data.comments.user.domain.id | Number | Argus | 
| Argus.NIDS.data.comments.user.domain.name | String | Argus | 
| Argus.NIDS.data.comments.user.userName | String | Argus | 
| Argus.NIDS.data.comments.user.name | String | Argus | 
| Argus.NIDS.data.comments.user.type | String | Argus | 
| Argus.NIDS.data.comments.comment | String | Argus | 
| Argus.NIDS.data.sensor.sensorID | Number | Argus | 
| Argus.NIDS.data.sensor.hostName | String | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.host | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.public | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.address | String | Argus | 
| Argus.NIDS.data.sensor.hostIpString | String | Argus | 
| Argus.NIDS.data.location.shortName | String | Argus | 
| Argus.NIDS.data.location.name | String | Argus | 
| Argus.NIDS.data.location.timeZone | String | Argus | 
| Argus.NIDS.data.location.id | Number | Argus | 
| Argus.NIDS.data.attackInfo.alarmID | Number | Argus | 
| Argus.NIDS.data.attackInfo.alarmDescription | String | Argus | 
| Argus.NIDS.data.attackInfo.attackCategoryID | Number | Argus | 
| Argus.NIDS.data.attackInfo.attackCategoryName | String | Argus | 
| Argus.NIDS.data.attackInfo.signature | String | Argus | 
| Argus.NIDS.data.count | Number | Argus | 
| Argus.NIDS.data.engineTimestamp | Number | Argus | 
| Argus.NIDS.data.protocolID | Number | Argus | 
| Argus.NIDS.data.domain.fqdn | String | Argus | 
| Argus.NIDS.data.uri | String | Argus | 
| Argus.NIDS.data.source.port | Number | Argus | 
| Argus.NIDS.data.source.geoLocation.countryCode | String | Argus | 
| Argus.NIDS.data.source.geoLocation.countryName | String | Argus | 
| Argus.NIDS.data.source.geoLocation.locationName | String | Argus | 
| Argus.NIDS.data.source.geoLocation.latitude | Number | Argus | 
| Argus.NIDS.data.source.geoLocation.longitude | Number | Argus | 
| Argus.NIDS.data.source.networkAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.public | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.source.networkAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.host | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.address | String | Argus | 
| Argus.NIDS.data.destination.port | Number | Argus | 
| Argus.NIDS.data.destination.geoLocation.countryCode | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.countryName | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.locationName | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.latitude | Number | Argus | 
| Argus.NIDS.data.destination.geoLocation.longitude | Number | Argus | 
| Argus.NIDS.data.destination.networkAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.public | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.destination.networkAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.host | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.address | String | Argus | 
| Argus.NIDS.data.timestamp | Number | Argus | 
| Argus.NIDS.data.severity | String | Argus | 
| Argus.NIDS.data.flags | String | Argus | 
| Argus.NIDS.data.id | String | Argus | 


#### Command Example
``` !argus_list_nids_events  ```



### argus_find_nids_events
***
Search for NIDS events.


#### Base Command

`argus_find_nids_events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip_future_events | Skip future evnts | Optional | 
| exclude | Exclude | Optional | 
| event_identifier | (as comma-separated list) | Optional | 
| location_id | (as comma-separated list) | Optional | 
| severity | (as comma-separated list) | Optional | 
| customer | (as comma-separated list) | Optional | 
| alarm_id | (as comma-separated list) | Optional | 
| attack_category_id | (as comma-separated list) | Optional | 
| source_geo_country | (as comma-separated list) | Optional | 
| destination_geo_country | (as comma-separated list) | Optional | 
| geo_country | (as comma-separated list) | Optional | 
| properties | As [key,value,key,value, ...] l | Optional | 
| exact_match_properties | Use exact matching | Optional | 
| sensor_id | (as comma-separated list) | Optional | 
| sub_criteria | (as comma-separated list) | Optional | 
| signature | (as comma-separated list) | Optional | 
| last_updated_timestamp | Last updated timestamp | Optional | 
| index_start_time | Index start time | Optional | 
| index_end_time | Index end time | Optional | 
| destination_ip | (as comma-separated list) | Optional | 
| source_ip | (as comma-separated list) | Optional | 
| ip | (as comma-separated list) | Optional | 
| destination_port | (as comma-separated list) | Optional | 
| source_port | (as comma-separated list) | Optional | 
| port | source_port | Optional | 
| min_severity | Minimum severity | Optional | 
| max_severity | Maximum severity | Optional | 
| limit | Limit number of results (default 25). | Optional | 
| offset | Skip a number of results | Optional | 
| include_deleted | Inclide deleted events | Optional | 
| start_timestamp | Search objects from this timestamp (default: -24hours). | Optional | 
| end_timestamp | Search objects until this timestamp  (default: now) | Optional | 
| sort_by | Order results by these properties (prefix with - to sort descending) (as comma-separated list) | Optional | 
| include_flags | (as comma-separated list) | Optional | 
| exclude_flags | (as comma-separated list) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.NIDS.responseCode | Number | Argus | 
| Argus.NIDS.limit | Number | Argus | 
| Argus.NIDS.offset | Number | Argus | 
| Argus.NIDS.count | Number | Argus | 
| Argus.NIDS.size | Number | Argus | 
| Argus.NIDS.messages.message | String | Argus | 
| Argus.NIDS.messages.messageTemplate | String | Argus | 
| Argus.NIDS.messages.type | String | Argus | 
| Argus.NIDS.messages.field | String | Argus | 
| Argus.NIDS.messages.timestamp | Number | Argus | 
| Argus.NIDS.data.customerInfo.id | Number | Argus | 
| Argus.NIDS.data.customerInfo.name | String | Argus | 
| Argus.NIDS.data.customerInfo.shortName | String | Argus | 
| Argus.NIDS.data.customerInfo.domain.id | Number | Argus | 
| Argus.NIDS.data.customerInfo.domain.name | String | Argus | 
| Argus.NIDS.data.properties.additionalProp1 | String | Argus | 
| Argus.NIDS.data.properties.additionalProp2 | String | Argus | 
| Argus.NIDS.data.properties.additionalProp3 | String | Argus | 
| Argus.NIDS.data.comments.timestamp | Number | Argus | 
| Argus.NIDS.data.comments.user.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customerID | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.name | String | Argus | 
| Argus.NIDS.data.comments.user.customer.shortName | String | Argus | 
| Argus.NIDS.data.comments.user.customer.domain.id | Number | Argus | 
| Argus.NIDS.data.comments.user.customer.domain.name | String | Argus | 
| Argus.NIDS.data.comments.user.domain.id | Number | Argus | 
| Argus.NIDS.data.comments.user.domain.name | String | Argus | 
| Argus.NIDS.data.comments.user.userName | String | Argus | 
| Argus.NIDS.data.comments.user.name | String | Argus | 
| Argus.NIDS.data.comments.user.type | String | Argus | 
| Argus.NIDS.data.comments.comment | String | Argus | 
| Argus.NIDS.data.sensor.sensorID | Number | Argus | 
| Argus.NIDS.data.sensor.hostName | String | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.host | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.public | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.sensor.hostIpAddress.address | String | Argus | 
| Argus.NIDS.data.sensor.hostIpString | String | Argus | 
| Argus.NIDS.data.location.shortName | String | Argus | 
| Argus.NIDS.data.location.name | String | Argus | 
| Argus.NIDS.data.location.timeZone | String | Argus | 
| Argus.NIDS.data.location.id | Number | Argus | 
| Argus.NIDS.data.attackInfo.alarmID | Number | Argus | 
| Argus.NIDS.data.attackInfo.alarmDescription | String | Argus | 
| Argus.NIDS.data.attackInfo.attackCategoryID | Number | Argus | 
| Argus.NIDS.data.attackInfo.attackCategoryName | String | Argus | 
| Argus.NIDS.data.attackInfo.signature | String | Argus | 
| Argus.NIDS.data.count | Number | Argus | 
| Argus.NIDS.data.engineTimestamp | Number | Argus | 
| Argus.NIDS.data.protocolID | Number | Argus | 
| Argus.NIDS.data.domain.fqdn | String | Argus | 
| Argus.NIDS.data.uri | String | Argus | 
| Argus.NIDS.data.source.port | Number | Argus | 
| Argus.NIDS.data.source.geoLocation.countryCode | String | Argus | 
| Argus.NIDS.data.source.geoLocation.countryName | String | Argus | 
| Argus.NIDS.data.source.geoLocation.locationName | String | Argus | 
| Argus.NIDS.data.source.geoLocation.latitude | Number | Argus | 
| Argus.NIDS.data.source.geoLocation.longitude | Number | Argus | 
| Argus.NIDS.data.source.networkAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.public | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.source.networkAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.host | Boolean | Argus | 
| Argus.NIDS.data.source.networkAddress.address | String | Argus | 
| Argus.NIDS.data.destination.port | Number | Argus | 
| Argus.NIDS.data.destination.geoLocation.countryCode | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.countryName | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.locationName | String | Argus | 
| Argus.NIDS.data.destination.geoLocation.latitude | Number | Argus | 
| Argus.NIDS.data.destination.geoLocation.longitude | Number | Argus | 
| Argus.NIDS.data.destination.networkAddress.ipv6 | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.public | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.maskBits | Number | Argus | 
| Argus.NIDS.data.destination.networkAddress.multicast | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.host | Boolean | Argus | 
| Argus.NIDS.data.destination.networkAddress.address | String | Argus | 
| Argus.NIDS.data.timestamp | Number | Argus | 
| Argus.NIDS.data.severity | String | Argus | 
| Argus.NIDS.data.flags | String | Argus | 
| Argus.NIDS.data.id | String | Argus | 


#### Command Example
``` !argus_find_nids_events ```


### argus_pdns_search_records
***
Search against PassiveDNS with criteria and return matching records.


#### Base Command

`argus_pdns_search_records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Lookup query | Required | 
| aggregate_result | Whether aggregate results (default true) . | Optional | 
| include_anonymous_results | Whether include anonymous results (default true)  | Optional | 
| rr_class | Lookup with specified record classes (as comma-separated list). | Optional | 
| rr_type | Lookup with specified record types (as comma-separated list) | Optional | 
| customer_id | Lookup for specified customer IDs  (as comma-separated list) | Optional | 
| tlp | Lookup with specified TLPs, public usage only TLP white allowed (as comma-separated list) | Optional | 
| limit | Max number of results to be returned, default unset means default limit 25 will be used, 0 means unlimited. | Optional | 
| offset | Number of results to be skipped first (default 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.PDNS.responseCode | Number | Argus | 
| Argus.PDNS.limit | Number | Argus | 
| Argus.PDNS.offset | Number | Argus | 
| Argus.PDNS.count | Number | Argus | 
| Argus.PDNS.size | Number | Argus | 
| Argus.PDNS.messages.message | String | Argus | 
| Argus.PDNS.messages.messageTemplate | String | Argus | 
| Argus.PDNS.messages.type | String | Argus | 
| Argus.PDNS.messages.field | String | Argus | 
| Argus.PDNS.messages.timestamp | Number | Argus | 
| Argus.PDNS.data.createdTimestamp | Number | Argus | 
| Argus.PDNS.data.lastUpdatedTimestamp | Number | Argus | 
| Argus.PDNS.data.times | Number | Argus | 
| Argus.PDNS.data.tlp | String | Argus | 
| Argus.PDNS.data.query | String | Argus | 
| Argus.PDNS.data.answer | String | Argus | 
| Argus.PDNS.data.minTtl | Number | Argus | 
| Argus.PDNS.data.maxTtl | Number | Argus | 
| Argus.PDNS.data.customer.id | Number | Argus | 
| Argus.PDNS.data.customer.name | String | Argus | 
| Argus.PDNS.data.customer.shortName | String | Argus | 
| Argus.PDNS.data.customer.domain.id | Number | Argus | 
| Argus.PDNS.data.customer.domain.name | String | Argus | 
| Argus.PDNS.data.lastSeenTimestamp | Number | Argus | 
| Argus.PDNS.data.firstSeenTimestamp | Number | Argus | 
| Argus.PDNS.data.rrclass | String | Argus | 
| Argus.PDNS.data.rrtype | String | Argus | 


#### Command Example
``` !argus_pdns_search_records query=mnemonic.no ```


### argus_fetch_observations_for_domain
***
Look up reputation observations for the given domain


#### Base Command

`argus_fetch_observations_for_domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fqdn | Domain to fetch observations for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.ObservationsDomain.responseCode | Number | Argus | 
| Argus.ObservationsDomain.limit | Number | Argus | 
| Argus.ObservationsDomain.offset | Number | Argus | 
| Argus.ObservationsDomain.count | Number | Argus | 
| Argus.ObservationsDomain.size | Number | Argus | 
| Argus.ObservationsDomain.messages.message | String | Argus | 
| Argus.ObservationsDomain.messages.messageTemplate | String | Argus | 
| Argus.ObservationsDomain.messages.type | String | Argus | 
| Argus.ObservationsDomain.messages.field | String | Argus | 
| Argus.ObservationsDomain.messages.timestamp | Number | Argus | 
| Argus.ObservationsDomain.data.domainName.fqdn | String | Argus | 
| Argus.ObservationsDomain.data.reason | String | Argus | 
| Argus.ObservationsDomain.data.override | Boolean | Argus | 
| Argus.ObservationsDomain.data.value | Number | Argus | 


#### Command Example
``` !argus_fetch_observations_for_domain fqdn=mnemonic.no ```


### argus_fetch_observations_for_ip
***
Look up reputation observations for the given IP


#### Base Command

`argus_fetch_observations_for_ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to fetch observations for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Argus.ObservationsIP.responseCode | Number | Argus | 
| Argus.ObservationsIP.limit | Number | Argus | 
| Argus.ObservationsIP.offset | Number | Argus | 
| Argus.ObservationsIP.count | Number | Argus | 
| Argus.ObservationsIP.size | Number | Argus | 
| Argus.ObservationsIP.messages.message | String | Argus | 
| Argus.ObservationsIP.messages.messageTemplate | String | Argus | 
| Argus.ObservationsIP.messages.type | String | Argus | 
| Argus.ObservationsIP.messages.field | String | Argus | 
| Argus.ObservationsIP.messages.timestamp | Number | Argus | 
| Argus.ObservationsIP.data.id | Number | Argus | 
| Argus.ObservationsIP.data.lastModified | Number | Argus | 
| Argus.ObservationsIP.data.source.id | Number | Argus | 
| Argus.ObservationsIP.data.source.alias | String | Argus | 
| Argus.ObservationsIP.data.source.name | String | Argus | 
| Argus.ObservationsIP.data.role.id | Number | Argus | 
| Argus.ObservationsIP.data.role.alias | String | Argus | 
| Argus.ObservationsIP.data.role.name | String | Argus | 
| Argus.ObservationsIP.data.firstSeen | Number | Argus | 
| Argus.ObservationsIP.data.lastSeen | Number | Argus | 
| Argus.ObservationsIP.data.numObservations | Number | Argus | 
| Argus.ObservationsIP.data.state | Number | Argus | 
| Argus.ObservationsIP.data.comment | String | Argus | 
| Argus.ObservationsIP.data.address.host | Boolean | Argus | 
| Argus.ObservationsIP.data.address.ipv6 | Boolean | Argus | 
| Argus.ObservationsIP.data.address.maskBits | Number | Argus | 
| Argus.ObservationsIP.data.address.multicast | Boolean | Argus | 
| Argus.ObservationsIP.data.address.public | Boolean | Argus | 
| Argus.ObservationsIP.data.address.address | String | Argus | 


#### Command Example
``` !argus_fetch_observations_for_ip ip=94.127.56.170 ```
