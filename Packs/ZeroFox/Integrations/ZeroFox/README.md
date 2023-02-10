The ZeroFox Platform delivers proactive intelligence to disrupt phishing, impersonations,
malicious domains and data leakage across the public, deep and dark web.

This integration was integrated and tested with api version 1.0 of ZeroFox

## Configure ZeroFox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ZeroFox.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | URL (e.g., https://api.zerofox.com/1.0) | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Fetch Limit | True |
    | Fetch incidents | False |
    | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### zerofox-get-alert
***
Fetches an alert by ID.


#### Base Command

`zerofox-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved by running the zerofox-list-alerts command. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.AlertType | String | The type of an alert. |
| ZeroFox.Alert.OffendingContentURL | String | The URL to the site containing content that triggered an alert. |
| ZeroFox.Alert.Assignee | String | The user to which an alert is assigned. |
| ZeroFox.Alert.Entity.ID | Number | The ID of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Name | String | The name of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Image | String | The URL to the profile image of the entity on which an alert was created. |
| ZeroFox.Alert.EntityTerm.ID | Number | The ID of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Name | String | The name of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Deleted | Boolean | Whether an entity term was deleted. |
| ZeroFox.Alert.ContentCreatedAt | Date | The date-time string indicating when the alerted content was created, in ISO-8601 format. |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.RiskRating | Number | The risk rating of an alert. Can be "Critical", "High", "Medium", "Low", or "Info". |
| ZeroFox.Alert.Perpetrator.Name | String | For account, post, or page alerts, the perpetrator's social network account display name or the account from which the content was posted. |
| ZeroFox.Alert.Perpetrator.URL | String | The URL at which you can view the basic details of the perpetrator. |
| ZeroFox.Alert.Perpetrator.Timestamp | Date | The timestamp of a post created by a perpetrator. |
| ZeroFox.Alert.Perpetrator.Type | String | The type of perpetrator on which an alert was created. Can be an account, page, or post. |
| ZeroFox.Alert.Perpetrator.ID | Number | The ZeroFox resource ID of the alert perpetrator. |
| ZeroFox.Alert.Perpetrator.Network | String | The network containing the offending content. |
| ZeroFox.Alert.RuleGroupID | Number | The ID of the rule group. |
| ZeroFox.Alert.Status | String | The status of an alert. Can be "Open", "Closed", "Takedown:Accepted", "Takedown:Denied", "Takedown:Requested", or "Whitelisted". |
| ZeroFox.Alert.Timestamp | Date | The date-time string when an the alert was created, in ISO-8601 format. |
| ZeroFox.Alert.RuleName | String | The name of the rule on which an alert was created. Outputs "null" if the rule was deleted. |
| ZeroFox.Alert.LastModified | Date | The date and time at which an alert was last modified. |
| ZeroFox.Alert.DarkwebTerm | String | Details about the dark web term on which an alert was created. Outputs "null" if the alert has no details. |
| ZeroFox.Alert.Reviewed | Boolean | Whether an alert was reviewed. |
| ZeroFox.Alert.Escalated | Boolean | Whether an alert was escalated. |
| ZeroFox.Alert.Network | String | The network on which an alert was created. |
| ZeroFox.Alert.ProtectedSocialObject | String | The protected object corresponding to an alert. If the alert occurred on an entity term, the protected object will be an entity term name. If the alert occurred on a protected account, \(account information or an incoming or outgoing content\), and it was network defined, the protected object will be an account username. If the alert was not network-defined, the protected object will default to the account's display name. Otherwise, the protected account will be an account display name. For impersonation alerts, the protected object is null. |
| ZeroFox.Alert.Notes | String | Notes made on an alert by the user. |
| ZeroFox.Alert.RuleID | Number | The ID of the rule on which an alert was created. Outputs "null" if the rule has been deleted. |
| ZeroFox.Alert.Tags | String | A list of an alert's tags. |
| ZeroFox.Alert.EntityAccount | String | The account associated with the entity. |

### zerofox-alert-user-assignment
***
Assigns an alert to a user.


#### Base Command

`zerofox-alert-user-assignment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved by running the zerofox-list-alerts command. | Required |
| username | The name of the user to which an alert is assigned. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.Assignee | String | The user to which an alert is assigned. |

### zerofox-close-alert
***
Closes an alert.


#### Base Command

`zerofox-close-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved by running the zerofox-list-alerts command. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.Status | String | The status of an alert. |

### zerofox-alert-request-takedown
***
Requests a takedown of a specified alert.


#### Base Command

`zerofox-alert-request-takedown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved by running the zerofox-list-alerts command. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.Status | String | The status of an alert. |

### zerofox-modify-alert-tags
***
Adds tags to and or removes tags from a specified alert.


#### Base Command

`zerofox-modify-alert-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Adds or removes tags. Possible values are: add, remove. Default is add. | Optional |
| alert_id | The ID of an alert. Can be retrieved by running the zerofox-list-alerts command. | Required |
| tags | A CSV of tags to be added to or removed from an alert. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.AlertType | String | The type of an alert. |
| ZeroFox.Alert.OffendingContentURL | String | The URL to the site containing content that triggered an alert. |
| ZeroFox.Alert.Assignee | String | The user to which an alert is assigned. |
| ZeroFox.Alert.Entity.ID | Number | The ID of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Name | String | The name of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Image | String | The URL to the profile image of the entity on which an alert was created. |
| ZeroFox.Alert.EntityTerm.ID | Number | The ID of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Name | String | The name of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Deleted | Boolean | Whether an entity term was deleted. |
| ZeroFox.Alert.ContentCreatedAt | Date | The date-time string indicating when the alerted content was created, in ISO-8601 format. |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.RiskRating | Number | The risk rating of an alert. Can be "Critical", "High", "Medium", "Low", or "Info". |
| ZeroFox.Alert.Perpetrator.Name | String | For account, post, or page alerts, the perpetrator's social network account display name or the account from which the content was posted. |
| ZeroFox.Alert.Perpetrator.URL | String | The URL at which you can view the basic details of the perpetrator. |
| ZeroFox.Alert.Perpetrator.Timestamp | Date | The timestamp of a post created by a perpetrator. |
| ZeroFox.Alert.Perpetrator.Type | String | The type of perpetrator on which an alert was created. Can be an account, page, or post. |
| ZeroFox.Alert.Perpetrator.ID | Number | The ZeroFox resource ID of the alert perpetrator. |
| ZeroFox.Alert.Perpetrator.Network | String | The network containing the offending content. |
| ZeroFox.Alert.RuleGroupID | Number | The ID of the rule group. |
| ZeroFox.Alert.Status | String | The status of an alert. Can be "Open", "Closed", "Takedown:Accepted", "Takedown:Denied", "Takedown:Requested", or "Whitelisted". |
| ZeroFox.Alert.Timestamp | Date | The date-time string when an alert was created, in ISO-8601 format. |
| ZeroFox.Alert.RuleName | String | The name of the rule on which an alert was created. Outputs "null" if the rule has been deleted. |
| ZeroFox.Alert.LastModified | Date | The date and time at which an alert was last modified. |
| ZeroFox.Alert.DarkwebTerm | String | Details about the dark web term on which an alert was created. Outputs "null" if the alert has no details. |
| ZeroFox.Alert.Reviewed | Boolean | Whether an alert was reviewed. |
| ZeroFox.Alert.Escalated | Boolean | Whether an alert was escalated. |
| ZeroFox.Alert.Network | String | The network on which an alert was created. |
| ZeroFox.Alert.ProtectedSocialObject | String | The protected object corresponding to an alert. If the alert occurred on an entity term, the protected object will be an entity term name. If the alert occurred on a protected account, \(account information or an incoming or outgoing content\), and it was network defined, the protected object will be an account username. If the alert was not network-defined, the protected object will default to the account's display name. Otherwise, the protected account will be an account display name. For impersonation alerts, the protected object is null. |
| ZeroFox.Alert.Notes | String | Notes made on an alert. |
| ZeroFox.Alert.RuleID | Number | The ID of the rule on which an alert was created. Outputs "null" if the rule has been deleted. |
| ZeroFox.Alert.Tags | String | A list of an alert's tags. |
| ZeroFox.Alert.EntityAccount | String | The account associated with the entity. |

### zerofox-list-alerts
***
Returns alerts that match user-defined or default filters and parameters. By default, no filters are applied and the results are sorted by timestamp.


#### Base Command

`zerofox-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account | The account number of the social network (unique ID). | Optional |
| alert_type | A CSV list of alert types. Possible values are: account_information, entity_discovery_content, entity_discovery_profile, impersonating_account, impersonating_comment, impersonating_post, incoming_comment, incoming_post, incoming_private_message, outgoing_private_message, self_comment, self_post, search_query, location, email. | Optional |
| assignee | The name of the user assigned to an alert. | Optional |
| entity | The ID of the ZeroFox entity. | Optional |
| entity_term | The term ID of the ZeroFox entity. | Optional |
| last_modified | The amount of time (in seconds) since an alert was last modified. | Optional |
| limit | The maximum number of alerts to retrieve (0 - 100). Default is 10. | Optional |
| max_timestamp | The ending date-time string (in ISO-8601 format) by which to filter alerts. | Optional |
| min_timestamp | The starting date-time string (in ISO-8601 format) by which to filter alerts. | Optional |
| network | Filters results by the specified network names. | Optional |
| offset | Used for pagination. Starts response with the first filtered alert. | Optional |
| page_id | CSV list of the ZeroFox page IDs. | Optional |
| page_url | The URL to the website or social media content that triggered an alert. | Optional |
| pages | The encoded JSON array of strings used for filtering alerts. | Optional |
| post | The unique post number of the social network. | Optional |
| rule_id | CSV list of the ZeroFox rule IDs. | Optional |
| rule_name | CSV list of the ZeroFox rule names. | Optional |
| entity_search | The matched substring of the protected entity. | Optional |
| perpetrator_search | The substring used to filter alerts by the username or display name of a perpetrator. | Optional |
| pro_social_obj_search | The substring used to filter alerts by the username, display name, or entity term name of protected social objects. | Optional |
| alert_id | CSV list of alert IDs. | Optional |
| risk_rating | Risk rating of alert. Possible values are: Critical, High, Medium, Low, Info. | Optional |
| sort_direction | Sorts results in ascending or descending order. Possible values are: asc, desc. | Optional |
| sort_field | Field used for defining alert filter for sorting. Possible values are: alert_id, alert_status, alert_type, assigned_user, perpetrator, protected_entity, protected_social_object, rule, severity, social_network, timestamp, escalated. | Optional |
| status | The alert status. Possible values are: closed, open, takedown_accepted, takedown_denied, takedown_requested, whitelisted. | Optional |
| escalated | If true, returns only escalated alerts. Possible values are: true, false. | Optional |
| tags | Alert tags. Returns alerts containing at least of the tags in the provided CSV list. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.AlertType | String | The type of an alert. |
| ZeroFox.Alert.OffendingContentURL | String | The URL to the site containing content that triggered an alert. |
| ZeroFox.Alert.Assignee | String | The user to which an alert is assigned. |
| ZeroFox.Alert.Entity.ID | Number | The ID of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Name | String | The name of the entity corresponding to the triggered alert. |
| ZeroFox.Alert.Entity.Image | String | The URL to the profile image of the entity on which an alert was created. |
| ZeroFox.Alert.EntityTerm.ID | Number | The ID of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Name | String | The name of the entity term corresponding to the triggered alert. |
| ZeroFox.Alert.EntityTerm.Deleted | Boolean | Whether an entity term was deleted. |
| ZeroFox.Alert.ContentCreatedAt | Date | The date-time string indicating when the alerted content was created, in ISO-8601 format. |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.RiskRating | Number | The risk rating of an alert. Can be "Critical", "High", "Medium", "Low", or "Info". |
| ZeroFox.Alert.Perpetrator.Name | String | For account, post, or page alerts, the perpetrator's social network account display name or the account from which the content was posted. |
| ZeroFox.Alert.Perpetrator.URL | String | The URL at which you can view the basic details of the perpetrator. |
| ZeroFox.Alert.Perpetrator.Timestamp | Date | The timestamp of a post created by a perpetrator. |
| ZeroFox.Alert.Perpetrator.Type | String | The type of perpetrator on which an alert was created. Can be an account, page, or post. |
| ZeroFox.Alert.Perpetrator.ID | Number | The ZeroFox resource ID of the alert perpetrator. |
| ZeroFox.Alert.Perpetrator.Network | String | The network containing the offending content. |
| ZeroFox.Alert.RuleGroupID | Number | The ID of the rule group. |
| ZeroFox.Alert.Status | String | The status of an alert. Can be "Open", "Closed", "Takedown:Accepted", "Takedown:Denied", "Takedown:Requested" and "Whitelisted". |
| ZeroFox.Alert.Timestamp | Date | The date-time string when an alert was created, in ISO-8601 format. |
| ZeroFox.Alert.RuleName | String | The name of the rule on which an alert was created. Outputs "null" if the rule has been deleted. |
| ZeroFox.Alert.LastModified | Date | The date and time at which an alert was last modified. |
| ZeroFox.Alert.DarkwebTerm | String | Details about the dark web term on which an alert was created. Outputs "null" if the alert has no details. |
| ZeroFox.Alert.Reviewed | Boolean | Whether an alert was reviewed. |
| ZeroFox.Alert.Escalated | Boolean | Whether an alert was escalated. |
| ZeroFox.Alert.Network | String | The network on which an alert was created. |
| ZeroFox.Alert.ProtectedSocialObject | String | The protected object corresponding to an alert. If the alert occurred on an entity term, the protected object will be an entity term name. If the alert occurred on a protected account, \(account information or an incoming or outgoing content\), and it was network defined, the protected object will be an account username. If the alert was not network-defined, the protected object will default to the account's display name. Otherwise, the protected account will be an account display name. For impersonation alerts, the protected object is null. |
| ZeroFox.Alert.Notes | String | Notes made on an alert. |
| ZeroFox.Alert.RuleID | Number | The ID of the rule on which an alert was created. Outputs "null" if the rule has been deleted. |
| ZeroFox.Alert.Tags | String | A list of an alert's tags. |
| ZeroFox.Alert.EntityAccount | String | The account associated with the entity. |

### zerofox-create-entity
***
Creates a new entity associated with the company of the authorized user.


#### Base Command

`zerofox-create-entity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the entity (may be non-unique). | Required |
| strict_name_matching | Indicates the type of string matching used for comparing entity names to impersonator names. | Optional |
| tags | Comma-separated list of string tags for tagging the entity. <br/>For example:<br/>label1,label2,label3. | Optional |
| policy_id | The ID of the policy to assign to the new entity. Can be retrieved running the zerofox-get-policy-types command. | Optional |
| organization | The name of the organization associated with the entity. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Entity.Name | String | The name of the entity. |
| ZeroFox.Entity.ID | Number | The ID of the entity. |
| ZeroFox.StrictNameMatching | Boolean | Indicates the type of string matching used for comparing entity names to impersonator names. |
| ZeroFox.Entity.Tags | String | The list of string tags that can be used for tagging the entity. |
| ZeroFox.Entity.PolicyID | String | The policy ID of the entity. |
| ZeroFox.Entity.Organization | String | The name of the organization associated with the entity. |

### zerofox-alert-cancel-takedown
***
Cancels a takedown of a specified alert.


#### Base Command

`zerofox-alert-cancel-takedown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved running the zerofox-list-alerts command. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.Status | String | The status of an alert. |

### zerofox-open-alert
***
Opens an alert.


#### Base Command

`zerofox-open-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of an alert. Can be retrieved running the zerofox-list-alerts command. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Alert.ID | Number | The ID of an alert. |
| ZeroFox.Alert.Status | String | The status of an alert. |

### zerofox-list-entities
***
Lists all entities associated with the company of the authorized user.


#### Base Command

`zerofox-list-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Filters by matching email_address substrings. | Optional |
| group | Filters by entity group ID. Can be filtered by multiple group parameters. | Optional |
| label | Filters by entity label ID. Can be filtered by multiple label parameters. | Optional |
| network | Filters by entities with network accounts using an ID. Can be filtered by multiple network parameters. | Optional |
| networks | Filters by entities with network accounts using a CSV of network names. | Optional |
| page | The index of page to fetch. | Optional |
| policy | Filters by entity policy ID. Can be filtered by multiple policy parameters. Can be retrieved running the zerofox-get-policy-types command. | Optional |
| type | Filters by an entity type ID. Can be filtered by multiple type parameters. Can be retrieved running the zerofox-get-entity-types command. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroFox.Entity.ID | Number | The ID of the entity. |
| ZeroFox.Entity.Name | String | The name of the entity. |
| ZeroFox.Entity.EmailAddress | String | The email address associated with the entity. |
| ZeroFox.Entity.Organization | String | The organization associated with the entity. |
| ZeroFox.Entity.Tags | String | A list of tags of the entity |
| ZeroFox.Entity.StrictNameMatching | Boolean | Indicates the type of string matching used for comparing entity names to impersonator names. |
| ZeroFox.Entity.PolicyID | Number | The policy ID of the entity. |
| ZeroFox.Entity.Profile | String | A link to a profile resource, if applicable. |
| ZeroFox.Entity.EntityGroupID | Number | The ID of the entity group. |
| ZeroFox.Entity.EntityGroupName | String | The name of the entity group. |
| ZeroFox.Entity.TypeID | Number | The ID of the type of entity. |
| ZeroFox.Entity.TypeName | String | The name of the type of entity |

### zerofox-get-entity-types
***
Shows a table of all entity type names and IDs in the War Room.


#### Base Command

`zerofox-get-entity-types`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### zerofox-get-policy-types
***
Shows a table of all policy type names and IDs in the War Room.


#### Base Command

`zerofox-get-policy-types`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
