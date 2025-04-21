Use the CrowdStrike OpenAPI integration to interact with CrowdStrike APIs that do not have dedicated integrations in Cortex XSOAR, for example, CrowdStrike FalconX, etc.

To use the CrowdStrike OpenAPI integration, you need the ID and secret of an API client that has right scopes granted to it.

For more details, refer to the [CrowdStrike OAuth2-Based APIs documentation](https://falcon.crowdstrike.com/support/documentation/46/crowdstrike-oauth2-based-apis).

*Note:* The integration is in ***beta*** as it was auto generated from the CrowdStrike Falcon OpenAPI specification and is not fully tested.

## Configure CrowdStrike OpenAPI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Cloud Base URL | True |
| Client ID | True |
| Client Secret | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |
### cs-add-role

***
Assign new MSSP Role(s) between User Group and CID Group. It does not revoke existing role(s) between User Group and CID Group. User Group ID and CID Group ID have to be specified in request. 

#### Base Command

`cs-add-role`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_mssprolerequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainMSSPRoleResponseV1.errors.code | Number |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.message | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.user_group_id | String |  | 
### cs-add-user-group-members

***
Add new User Group member. Maximum 500 members allowed per User Group.

#### Base Command

`cs-add-user-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_usergroupmembersrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.resources.user_group_id | String |  | 
### cs-addcid-group-members

***
Add new CID Group member.

#### Base Command

`cs-addcid-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_cidgroupmembersrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.resources.cid_group_id | String |  | 
### cs-aggregate-allow-list

***
Retrieve aggregate allowlist ticket values based on the matched filter.

#### Base Command

`cs-aggregate-allow-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-block-list

***
Retrieve aggregate block list ticket values based on the matched filter.

#### Base Command

`cs-aggregate-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-detections

***
Retrieve aggregate detection values based on the matched filter.

#### Base Command

`cs-aggregate-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-device-count-collection

***
Retrieve aggregate host/devices count based on the matched filter.

#### Base Command

`cs-aggregate-device-count-collection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-escalations

***
Retrieve aggregate escalation ticket values based on the matched filter.

#### Base Command

`cs-aggregate-escalations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-notificationsv1

***
Get notification aggregates as specified via JSON in request body.

#### Base Command

`cs-aggregate-notificationsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.field | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.id | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.name | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregate-remediations

***
Retrieve aggregate remediation ticket values based on the matched filter.

#### Base Command

`cs-aggregate-remediations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregateevents

***
Aggregate events for customer.

#### Base Command

`cs-aggregateevents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fwmgr_msa_aggregatequeryrequest_date_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_field |  | Required | 
| fwmgr_msa_aggregatequeryrequest_filter |  | Required | 
| fwmgr_msa_aggregatequeryrequest_interval |  | Required | 
| fwmgr_msa_aggregatequeryrequest_min_doc_count |  | Required | 
| fwmgr_msa_aggregatequeryrequest_missing |  | Required | 
| fwmgr_msa_aggregatequeryrequest_name |  | Required | 
| fwmgr_msa_aggregatequeryrequest_q |  | Required | 
| fwmgr_msa_aggregatequeryrequest_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_size |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sort |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| fwmgr_msa_aggregatequeryrequest_time_zone |  | Required | 
| fwmgr_msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregatefc-incidents

***
Retrieve aggregate incident values based on the matched filter.

#### Base Command

`cs-aggregatefc-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregatepolicyrules

***
Aggregate rules within a policy for customer.

#### Base Command

`cs-aggregatepolicyrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fwmgr_msa_aggregatequeryrequest_date_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_field |  | Required | 
| fwmgr_msa_aggregatequeryrequest_filter |  | Required | 
| fwmgr_msa_aggregatequeryrequest_interval |  | Required | 
| fwmgr_msa_aggregatequeryrequest_min_doc_count |  | Required | 
| fwmgr_msa_aggregatequeryrequest_missing |  | Required | 
| fwmgr_msa_aggregatequeryrequest_name |  | Required | 
| fwmgr_msa_aggregatequeryrequest_q |  | Required | 
| fwmgr_msa_aggregatequeryrequest_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_size |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sort |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| fwmgr_msa_aggregatequeryrequest_time_zone |  | Required | 
| fwmgr_msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregaterulegroups

***
Aggregate rule groups for customer.

#### Base Command

`cs-aggregaterulegroups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fwmgr_msa_aggregatequeryrequest_date_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_field |  | Required | 
| fwmgr_msa_aggregatequeryrequest_filter |  | Required | 
| fwmgr_msa_aggregatequeryrequest_interval |  | Required | 
| fwmgr_msa_aggregatequeryrequest_min_doc_count |  | Required | 
| fwmgr_msa_aggregatequeryrequest_missing |  | Required | 
| fwmgr_msa_aggregatequeryrequest_name |  | Required | 
| fwmgr_msa_aggregatequeryrequest_q |  | Required | 
| fwmgr_msa_aggregatequeryrequest_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_size |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sort |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| fwmgr_msa_aggregatequeryrequest_time_zone |  | Required | 
| fwmgr_msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregaterules

***
Aggregate rules for customer.

#### Base Command

`cs-aggregaterules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fwmgr_msa_aggregatequeryrequest_date_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_field |  | Required | 
| fwmgr_msa_aggregatequeryrequest_filter |  | Required | 
| fwmgr_msa_aggregatequeryrequest_interval |  | Required | 
| fwmgr_msa_aggregatequeryrequest_min_doc_count |  | Required | 
| fwmgr_msa_aggregatequeryrequest_missing |  | Required | 
| fwmgr_msa_aggregatequeryrequest_name |  | Required | 
| fwmgr_msa_aggregatequeryrequest_q |  | Required | 
| fwmgr_msa_aggregatequeryrequest_ranges |  | Required | 
| fwmgr_msa_aggregatequeryrequest_size |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sort |  | Required | 
| fwmgr_msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| fwmgr_msa_aggregatequeryrequest_time_zone |  | Required | 
| fwmgr_msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregates-detections-global-counts

***
Get the total number of detections pushed across all customers.

#### Base Command

`cs-aggregates-detections-global-counts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | An FQL filter string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaFacetsResponse.errors.code | Number |  | 
| CrowdStrike.msaFacetsResponse.errors.id | String |  | 
| CrowdStrike.msaFacetsResponse.errors.message | String |  | 
| CrowdStrike.msaFacetsResponse.resources.count | Number |  | 
| CrowdStrike.msaFacetsResponse.resources.facet | String |  | 
| CrowdStrike.msaFacetsResponse.resources.label | String |  | 
| CrowdStrike.msaFacetsResponse.resources.term | String |  | 
### cs-aggregates-events

***
Get aggregate OverWatch detection event info by providing an aggregate query.

#### Base Command

`cs-aggregates-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregates-events-collections

***
Get OverWatch detection event collection info by providing an aggregate query.

#### Base Command

`cs-aggregates-events-collections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-aggregates-incidents-global-counts

***
Get the total number of incidents pushed across all customers.

#### Base Command

`cs-aggregates-incidents-global-counts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | An FQL filter string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaFacetsResponse.errors.code | Number |  | 
| CrowdStrike.msaFacetsResponse.errors.id | String |  | 
| CrowdStrike.msaFacetsResponse.errors.message | String |  | 
| CrowdStrike.msaFacetsResponse.resources.count | Number |  | 
| CrowdStrike.msaFacetsResponse.resources.facet | String |  | 
| CrowdStrike.msaFacetsResponse.resources.label | String |  | 
| CrowdStrike.msaFacetsResponse.resources.term | String |  | 
### cs-aggregatesow-events-global-counts

***
Get the total number of OverWatch events across all customers.

#### Base Command

`cs-aggregatesow-events-global-counts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | An FQL filter string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaFacetsResponse.errors.code | Number |  | 
| CrowdStrike.msaFacetsResponse.errors.id | String |  | 
| CrowdStrike.msaFacetsResponse.errors.message | String |  | 
| CrowdStrike.msaFacetsResponse.resources.count | Number |  | 
| CrowdStrike.msaFacetsResponse.resources.facet | String |  | 
| CrowdStrike.msaFacetsResponse.resources.label | String |  | 
| CrowdStrike.msaFacetsResponse.resources.term | String |  | 
### cs-apipreemptproxypostgraphql

***
Identity Protection GraphQL API. Allows to retrieve entities, timeline activities, identity-based incidents and security assessment. Allows to perform actions on entities and identity-based incidents.

#### Base Command

`cs-apipreemptproxypostgraphql`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Authorization | Authorization Header. | Required | 

#### Context Output

There is no context output for this command.
### cs-auditeventsquery

***
Search for audit events by providing an FQL filter and paging details.

#### Base Command

`cs-auditeventsquery`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-1000]. Defaults to 50. | Optional | 
| sort | The property to sort by (e.g. timestamp.desc). | Optional | 
| filter_ | The filter expression that should be used to limit the results (e.g., `action:'token_create'`). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-auditeventsread

***
Gets the details of one or more audit events by id.

#### Base Command

`cs-auditeventsread`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of audit events to retrieve details for. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiauditEventDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.action | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.actor | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.description | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.id | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.timestamp | String |  | 
| CrowdStrike.apiauditEventDetailsResponseV1.resources.token_id | String |  | 
### cs-batch-active-responder-cmd

***
Batch executes a RTR active-responder command across the hosts mapped to the given batch ID.

#### Base Command

`cs-batch-active-responder-cmd`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchexecutecommandrequest_base_command |  | Required | 
| domain_batchexecutecommandrequest_batch_id |  | Required | 
| domain_batchexecutecommandrequest_command_string |  | Required | 
| domain_batchexecutecommandrequest_optional_hosts |  | Optional | 
| domain_batchexecutecommandrequest_persist_all |  | Required | 

#### Context Output

There is no context output for this command.
### cs-batch-admin-cmd

***
Batch executes a RTR administrator command across the hosts mapped to the given batch ID.

#### Base Command

`cs-batch-admin-cmd`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchexecutecommandrequest_base_command |  | Required | 
| domain_batchexecutecommandrequest_batch_id |  | Required | 
| domain_batchexecutecommandrequest_command_string |  | Required | 
| domain_batchexecutecommandrequest_optional_hosts |  | Optional | 
| domain_batchexecutecommandrequest_persist_all |  | Required | 

#### Context Output

There is no context output for this command.
### cs-batch-cmd

***
Batch executes a RTR read-only command across the hosts mapped to the given batch ID.

#### Base Command

`cs-batch-cmd`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchexecutecommandrequest_base_command |  | Required | 
| domain_batchexecutecommandrequest_batch_id |  | Required | 
| domain_batchexecutecommandrequest_command_string |  | Required | 
| domain_batchexecutecommandrequest_optional_hosts |  | Optional | 
| domain_batchexecutecommandrequest_persist_all |  | Required | 

#### Context Output

There is no context output for this command.
### cs-batch-get-cmd

***
Batch executes `get` command across hosts to retrieve files. After this call is made `GET /real-time-response/combined/batch-get-command/v1` is used to query for the results.

#### Base Command

`cs-batch-get-cmd`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchgetcommandrequest_batch_id |  | Required | 
| domain_batchgetcommandrequest_file_path |  | Required | 
| domain_batchgetcommandrequest_optional_hosts |  | Optional | 

#### Context Output

There is no context output for this command.
### cs-batch-get-cmd-status

***
Retrieves the status of the specified batch get command.  Will return successful files when they are finished processing.

#### Base Command

`cs-batch-get-cmd-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| batch_get_cmd_req_id | Batch Get Command Request ID received from `/real-time-response/combined/get-command/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainBatchGetCmdStatusResponse.errors.code | Number |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.errors.id | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.errors.message | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.cloud_request_id | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.created_at | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.deleted_at | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.id | Number |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.name | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.session_id | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.sha256 | String |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.size | Number |  | 
| CrowdStrike.domainBatchGetCmdStatusResponse.resources.updated_at | String |  | 
### cs-batch-init-sessions

***
Batch initialize a RTR session on multiple hosts.  Before any RTR commands can be used, an active session is needed on the host.

#### Base Command

`cs-batch-init-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchinitsessionrequest_existing_batch_id |  | Optional | 
| domain_batchinitsessionrequest_host_ids |  | Required | 
| domain_batchinitsessionrequest_queue_offline |  | Required | 

#### Context Output

There is no context output for this command.
### cs-batch-refresh-sessions

***
Batch refresh a RTR session on multiple hosts. RTR sessions will expire after 10 minutes unless refreshed.

#### Base Command

`cs-batch-refresh-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 10 minutes. | Optional | 
| timeout_duration | Timeout duration for for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 10 minutes. | Optional | 
| domain_batchrefreshsessionrequest_batch_id |  | Required | 
| domain_batchrefreshsessionrequest_hosts_to_remove |  | Required | 

#### Context Output

There is no context output for this command.
### cs-create-actionsv1

***
Create actions for a monitoring rule. Accepts a list of actions that will be attached to the monitoring rule.

#### Base Command

`cs-create-actionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_registeractionsrequest_actions |  | Required | 
| domain_registeractionsrequest_rule_id |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainActionEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.cid | String | The ID of the customer who created the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.created_timestamp | String | The date when the action was created. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.frequency | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.id | String | The ID of the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.rule_id | String | The ID of the rule on which this action is attached. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.status | String | The action status. It can be either 'enabled' or 'muted'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.type | String | The action type. The only type currently supported is 'email'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.updated_timestamp | String | The date when the action was updated. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.user_uuid | String | The UUID of the user who created the action. | 
### cs-create-device-control-policies

***
Create Device Control Policies by specifying details about the policy to create.

#### Base Command

`cs-create-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_createdevicecontrolpoliciesv1_resources | A collection of policies to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-create-firewall-policies

***
Create Firewall Policies by specifying details about the policy to create.

#### Base Command

`cs-create-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_createfirewallpoliciesv1_resources | A collection of policies to create. | Required | 
| clone_id | The policy ID to be cloned from. | Optional | 

#### Context Output

There is no context output for this command.
### cs-create-host-groups

***
Create Host Groups by specifying details about the group to create.

#### Base Command

`cs-create-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_creategroupsv1_resources | A collection of device groups to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-create-or-updateaws-settings

***
Create or update Global Settings which are applicable to all provisioned AWS accounts.

#### Base Command

`cs-create-or-updateaws-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| models_modifyawscustomersettingsv1_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-create-prevention-policies

***
Create Prevention Policies by specifying details about the policy to create.

#### Base Command

`cs-create-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_createpreventionpoliciesv1_resources | A collection of policies to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-create-rulesv1

***
Create monitoring rules.

#### Base Command

`cs-create-rulesv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| sadomain_createrulerequestv1_filter | The filter to be used for searching. | Required | 
| sadomain_createrulerequestv1_name | The name of a particular rule. | Required | 
| sadomain_createrulerequestv1_permissions | The permissions for a particular rule which specifies the rule's access by other users. Possible values: [public private]. | Required | 
| sadomain_createrulerequestv1_priority | The priority for a particular rule. Possible values: [medium high low]. | Required | 
| sadomain_createrulerequestv1_topic | The topic of a given rule. Possible values: [SA_THIRD_PARTY SA_CVE SA_ALIAS SA_AUTHOR SA_BRAND_PRODUCT SA_VIP SA_IP SA_BIN SA_DOMAIN SA_EMAIL SA_CUSTOM]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRulesEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.cid | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.created_timestamp | String | The creation time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.filter | String | The FQL filter contained in a rule and used for searching. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.id | String | The ID of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.name | String | The name for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.permissions | String | The permissions of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.priority | String | The priority of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status | String | The status of a rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status_message | String | The detailed status message. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.topic | String | The topic of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.updated_timestamp | String | The last updated time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_id | String | The user ID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_name | String | The user name of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_uuid | String | The UUID of the user that created a given rule. | 
### cs-create-sensor-update-policies

***
Create Sensor Update Policies by specifying details about the policy to create.

#### Base Command

`cs-create-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_createsensorupdatepoliciesv1_resources | A collection of policies to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-create-sensor-update-policiesv2

***
Create Sensor Update Policies by specifying details about the policy to create with additional support for uninstall protection.

#### Base Command

`cs-create-sensor-update-policiesv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_createsensorupdatepoliciesv2_resources | A collection of policies to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-create-user

***
Create a new user. After creating a user, assign one or more roles with POST /user-roles/entities/user-roles/v1.

#### Base Command

`cs-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_usercreaterequest_firstname |  | Optional | 
| domain_usercreaterequest_lastname |  | Optional | 
| domain_usercreaterequest_password |  | Optional | 
| domain_usercreaterequest_uid |  | Optional | 

#### Context Output

There is no context output for this command.
### cs-create-user-groups

***
Create new User Group(s). Maximum 500 User Group(s) allowed per customer.

#### Base Command

`cs-create-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_usergroupsrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.user_group_id | String |  | 
### cs-createaws-account

***
Creates a new AWS account in our system for a customer and generates the installation script.

#### Base Command

`cs-createaws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| k8sreg_createawsaccreq_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createcid-groups

***
Create new CID Group(s). Maximum 500 CID Group(s) allowed.

#### Base Command

`cs-createcid-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_cidgroupsrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.name | String |  | 
### cs-createcspm-aws-account

***
Creates a new account in our system for a customer and generates a script for them to run in their AWS cloud environment to grant us access.

#### Base Command

`cs-createcspm-aws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_awsaccountcreaterequestextv2_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createcspmgcp-account

***
Creates a new account in our system for a customer and generates a new service account for them to add access to in their GCP environment to grant us access.

#### Base Command

`cs-createcspmgcp-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_gcpaccountcreaterequestextv1_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createml-exclusionsv1

***
Create the ML exclusions.

#### Base Command

`cs-createml-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_mlexclusioncreatereqv1_comment |  | Optional | 
| requests_mlexclusioncreatereqv1_excluded_from |  | Optional | 
| requests_mlexclusioncreatereqv1_groups |  | Optional | 
| requests_mlexclusioncreatereqv1_value |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
### cs-creatert-response-policies

***
Create Response Policies by specifying details about the policy to create.

#### Base Command

`cs-creatert-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_creatertresponsepoliciesv1_resources | A collection of policies to create. | Required | 

#### Context Output

There is no context output for this command.
### cs-createrule

***
Create a rule within a rule group. Returns the rule.

#### Base Command

`cs-createrule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_rulecreatev1_comment |  | Required | 
| api_rulecreatev1_description |  | Required | 
| api_rulecreatev1_disposition_id |  | Required | 
| api_rulecreatev1_field_values |  | Required | 
| api_rulecreatev1_name |  | Required | 
| api_rulecreatev1_pattern_severity |  | Required | 
| api_rulecreatev1_rulegroup_id |  | Required | 
| api_rulecreatev1_ruletype_id |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createrulegroup

***
Create new rule group on a platform for a customer with a name and description, and return the ID.

#### Base Command

`cs-createrulegroup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The user id. | Required | 
| clone_id | A rule group ID from which to copy rules. If this is provided then the 'rules' property of the body is ignored. | Optional | 
| li_ary | If this flag is set to true then the rules will be cloned from the clone_id from the CrowdStrike Firewal Rule Groups Li ary. | Optional | 
| comment | Audit log comment for this action. | Optional | 
| fwmgr_api_rulegroupcreaterequestv1_description |  | Required | 
| fwmgr_api_rulegroupcreaterequestv1_enabled |  | Required | 
| fwmgr_api_rulegroupcreaterequestv1_name |  | Required | 
| fwmgr_api_rulegroupcreaterequestv1_rules |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createrulegroup-mixin0

***
Create a rule group for a platform with a name and an optional description. Returns the rule group.

#### Base Command

`cs-createrulegroup-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_rulegroupcreaterequestv1_comment |  | Required | 
| api_rulegroupcreaterequestv1_description |  | Required | 
| api_rulegroupcreaterequestv1_name |  | Required | 
| api_rulegroupcreaterequestv1_platform |  | Required | 

#### Context Output

There is no context output for this command.
### cs-createsv-exclusionsv1

***
Create the sensor visibility exclusions.

#### Base Command

`cs-createsv-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_svexclusioncreatereqv1_comment |  | Optional | 
| requests_svexclusioncreatereqv1_groups |  | Optional | 
| requests_svexclusioncreatereqv1_value |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
### cs-crowd-score

***
Query environment wide CrowdScore and return the entity data.

#### Base Command

`cs-crowd-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | The maximum records to return. [1-2500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". Possible values are: score.asc, score.desc, timestamp.asc, timestamp.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaEnvironmentScoreResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaEnvironmentScoreResponse.errors.id | String |  | 
| CrowdStrike.apiMsaEnvironmentScoreResponse.errors.message | String |  | 
| CrowdStrike.apiMsaEnvironmentScoreResponse.resources.id | String |  | 
| CrowdStrike.apiMsaEnvironmentScoreResponse.resources.score | Number |  | 
| CrowdStrike.apiMsaEnvironmentScoreResponse.resources.timestamp | String |  | 
### cs-customersettingsread

***
Check current installation token settings.

#### Base Command

`cs-customersettingsread`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apicustomerSettingsResponseV1.errors.code | Number |  | 
| CrowdStrike.apicustomerSettingsResponseV1.errors.id | String |  | 
| CrowdStrike.apicustomerSettingsResponseV1.errors.message | String |  | 
| CrowdStrike.apicustomerSettingsResponseV1.resources.max_active_tokens | Number |  | 
| CrowdStrike.apicustomerSettingsResponseV1.resources.tokens_required | Boolean |  | 
### cs-delete-actionv1

***
Delete an action from a monitoring rule based on the action ID.

#### Base Command

`cs-delete-actionv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ID of the action. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainQueryResponse.errors.code | Number |  | 
| CrowdStrike.domainQueryResponse.errors.details.field | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.id | String |  | 
| CrowdStrike.domainQueryResponse.errors.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.message_key | String |  | 
### cs-delete-device-control-policies

***
Delete a set of Device Control Policies by specifying their IDs.

#### Base Command

`cs-delete-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Device Control Policies to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-firewall-policies

***
Delete a set of Firewall Policies by specifying their IDs.

#### Base Command

`cs-delete-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Firewall Policies to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-host-groups

***
Delete a set of Host Groups by specifying their IDs.

#### Base Command

`cs-delete-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Host Groups to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-notificationsv1

***
Delete notifications based on IDs. Notifications cannot be recovered after they are deleted.

#### Base Command

`cs-delete-notificationsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Notifications IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationIDResponse.errors.code | Number |  | 
| CrowdStrike.domainNotificationIDResponse.errors.details.field | String |  | 
| CrowdStrike.domainNotificationIDResponse.errors.details.message | String |  | 
| CrowdStrike.domainNotificationIDResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationIDResponse.errors.id | String |  | 
| CrowdStrike.domainNotificationIDResponse.errors.message | String |  | 
| CrowdStrike.domainNotificationIDResponse.errors.message_key | String |  | 
### cs-delete-prevention-policies

***
Delete a set of Prevention Policies by specifying their IDs.

#### Base Command

`cs-delete-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Prevention Policies to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-report

***
Delete report based on the report ID. Operation can be checked for success by polling for the report ID on the report-summaries endpoint.

#### Base Command

`cs-delete-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a report. | Required | 

#### Context Output

There is no context output for this command.
### cs-delete-rulesv1

***
Delete monitoring rules.

#### Base Command

`cs-delete-rulesv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | IDs of rules. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRuleQueryResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.id | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message_key | String |  | 
### cs-delete-samplev2

***
Removes a sample, including file, meta and submissions from the collection.

#### Base Command

`cs-delete-samplev2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | The file SHA256. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-samplev3

***
Removes a sample, including file, meta and submissions from the collection.

#### Base Command

`cs-delete-samplev3`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | The file SHA256. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-sensor-update-policies

***
Delete a set of Sensor Update Policies by specifying their IDs.

#### Base Command

`cs-delete-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Sensor Update Policies to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-sensor-visibility-exclusionsv1

***
Delete the sensor visibility exclusions by id.

#### Base Command

`cs-delete-sensor-visibility-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to delete. | Required | 
| comment | Explains why this exclusions was deleted. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-delete-user

***
Delete a user permanently.

#### Base Command

`cs-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-delete-user-group-members

***
Delete User Group members entry.

#### Base Command

`cs-delete-user-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_usergroupmembersrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.resources.user_group_id | String |  | 
### cs-delete-user-groups

***
Delete User Group(s) by ID(s).

#### Base Command

`cs-delete-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_group_ids | User Group IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaEntitiesResponse.errors.message | String |  | 
### cs-deleteaws-accounts

***
Delete a set of AWS Accounts by specifying their IDs.

#### Base Command

`cs-deleteaws-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of accounts to remove. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsBaseResponseV1.errors.code | Number |  | 
| CrowdStrike.modelsBaseResponseV1.errors.id | String |  | 
| CrowdStrike.modelsBaseResponseV1.errors.message | String |  | 
### cs-deleteaws-accounts-mixin0

***
Delete AWS accounts.

#### Base Command

`cs-deleteaws-accounts-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | AWS Account IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaMetaInfo.powered_by | String |  | 
| CrowdStrike.msaMetaInfo.query_time | Unknown |  | 
| CrowdStrike.msaMetaInfo.trace_id | String |  | 
| CrowdStrike.msaMetaInfo.powered_by | String |  | 
| CrowdStrike.msaMetaInfo.query_time | Unknown |  | 
| CrowdStrike.msaMetaInfo.trace_id | String |  | 
### cs-deletecid-group-members

***
Delete CID Group members entry.

#### Base Command

`cs-deletecid-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_cidgroupmembersrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.resources.cid_group_id | String |  | 
### cs-deletecid-groups

***
Delete CID Group(s) by ID(s).

#### Base Command

`cs-deletecid-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid_group_ids | CID group ids to be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaEntitiesResponse.errors.message | String |  | 
### cs-deletecspm-aws-account

***
Deletes an existing AWS account or organization in our system.

#### Base Command

`cs-deletecspm-aws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | AWS account IDs to remove. | Optional | 
| organization_ids | AWS organization IDs to remove. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationBaseResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationBaseResponseV1.errors.id | String |  | 
| CrowdStrike.registrationBaseResponseV1.errors.message | String |  | 
### cs-deletecspm-azure-account

***
Deletes an Azure subscription from the system.

#### Base Command

`cs-deletecspm-azure-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Azure subscription IDs to remove. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationBaseResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationBaseResponseV1.errors.id | String |  | 
| CrowdStrike.registrationBaseResponseV1.errors.message | String |  | 
### cs-deleted-roles

***
Delete MSSP Role assignment(s) between User Group and CID Group. User Group ID and CID Group ID have to be specified in request. Only specified roles are removed if specified in request payload, else association between User Group and CID Group is dissolved completely (if no roles specified).

#### Base Command

`cs-deleted-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_mssprolerequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainMSSPRoleResponseV1.errors.code | Number |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.message | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.user_group_id | String |  | 
### cs-deleteioa-exclusionsv1

***
Delete the IOA exclusions by id.

#### Base Command

`cs-deleteioa-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to delete. | Required | 
| comment | Explains why this exclusions was deleted. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-deleteml-exclusionsv1

***
Delete the ML exclusions by id.

#### Base Command

`cs-deleteml-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to delete. | Required | 
| comment | Explains why this exclusions was deleted. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
### cs-deletert-response-policies

***
Delete a set of Response Policies by specifying their IDs.

#### Base Command

`cs-deletert-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Response Policies to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-deleterulegroups

***
Delete rule group entities by ID.

#### Base Command

`cs-deleterulegroups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The user id. | Required | 
| ids | The IDs of the rule groups to be deleted. | Required | 
| comment | Audit log comment for this action. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-deleterulegroups-mixin0

***
Delete rule groups by ID.

#### Base Command

`cs-deleterulegroups-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Explains why the entity is being deleted. | Optional | 
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-deleterules

***
Delete rules from a rule group by ID.

#### Base Command

`cs-deleterules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_group_id | The parent rule group. | Required | 
| comment | Explains why the entity is being deleted. | Optional | 
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-devices-count

***
Number of hosts in your customer account that have observed a given custom IOC.

#### Base Command

`cs-devices-count`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type_ |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Required | 
| value | The string representation of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyIOCDevicesCount.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.resources.device_count | Number |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.resources.id | String |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.resources.limit_exceeded | Boolean |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.resources.type | String |  | 
| CrowdStrike.apiMsaReplyIOCDevicesCount.resources.value | String |  | 
### cs-devices-ran-on

***
Find hosts that have observed a given custom IOC. For details about those hosts, use GET /devices/entities/devices/v2.

#### Base Command

`cs-devices-ran-on`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type_ |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Required | 
| value | The string representation of the indicator. | Required | 
| limit | The first process to return, where 0 is the latest offset. Use with the offset  meter to manage pagination of results. | Optional | 
| offset | The first process to return, where 0 is the latest offset. Use with the limit  meter to manage pagination of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyDevicesRanOn.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyDevicesRanOn.errors.id | String |  | 
| CrowdStrike.apiMsaReplyDevicesRanOn.errors.message | String |  | 
### cs-download-sensor-installer-by-id

***
Download sensor installer by SHA256 ID.

#### Base Command

`cs-download-sensor-installer-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | SHA256 of the installer to download. | Required | 

#### Context Output

There is no context output for this command.
### cs-entitiesprocesses

***
For the provided ProcessID retrieve the process details.

#### Base Command

`cs-entitiesprocesses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ProcessID for the running process you want to lookup. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaProcessDetailResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaProcessDetailResponse.errors.id | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.errors.message | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.command_line | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.device_id | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.file_name | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.process_id | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.process_id_local | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.start_timestamp | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.start_timestamp_raw | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.stop_timestamp | String |  | 
| CrowdStrike.apiMsaProcessDetailResponse.resources.stop_timestamp_raw | String |  | 
### cs-get-actionsv1

***
Get actions based on their IDs. IDs can be retrieved using the GET /queries/actions/v1 endpoint.

#### Base Command

`cs-get-actionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Action IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainActionEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.cid | String | The ID of the customer who created the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.created_timestamp | String | The date when the action was created. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.frequency | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.id | String | The ID of the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.rule_id | String | The ID of the rule on which this action is attached. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.status | String | The action status. It can be either 'enabled' or 'muted'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.type | String | The action type. The only type currently supported is 'email'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.updated_timestamp | String | The date when the action was updated. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.user_uuid | String | The UUID of the user who created the action. | 
### cs-get-aggregate-detects

***
Get detect aggregates as specified via json in request body.

#### Base Command

`cs-get-aggregate-detects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-get-artifacts

***
Download IOC packs, PCAP files, and other analysis artifacts.

#### Base Command

`cs-get-artifacts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ID of an artifact, such as an IOC pack, PCAP file, or actor image. Find an artifact ID in a report or summary. | Required | 
| name | The name given to your downloaded file. | Optional | 
| Accept_Encoding | Format used to compress your downloaded file. Currently, you must provide the value `gzip`, the only valid format. | Optional | 

#### Context Output

There is no context output for this command.
### cs-get-assessmentv1

***
Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID) and a customer ID (CID).

#### Base Command

`cs-get-assessmentv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | One or more agent IDs, which you can find in the data.zta file, or the Falcon console. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainAssessmentsResponse.errors.code | Number |  | 
| CrowdStrike.domainAssessmentsResponse.errors.id | String |  | 
| CrowdStrike.domainAssessmentsResponse.errors.message | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.aid | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.cid | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.event_platform | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.modified_time | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.product_type_desc | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.sensor_file_status | String |  | 
| CrowdStrike.domainAssessmentsResponse.resources.system_serial_number | String |  | 
### cs-get-available-role-ids

***
Show role IDs for all roles available in your customer account. For more information on each role, provide the role ID to `/customer/entities/roles/v1`.

#### Base Command

`cs-get-available-role-ids`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-get-behaviors

***
Get details on behaviors by providing behavior IDs.

#### Base Command

`cs-get-behaviors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaExternalBehaviorResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.errors.id | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.errors.message | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.aid | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.behavior_id | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.cid | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.cmdline | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.compound_tto | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.detection_id | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.domain | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.filepath | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.incident_id | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.ioc_source | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.ioc_type | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.ioc_value | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.objective | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.pattern_disposition | Number |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.pattern_id | Number |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.sha256 | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.tactic | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.technique | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.template_instance_id | Number |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.timestamp | String |  | 
| CrowdStrike.apiMsaExternalBehaviorResponse.resources.user_name | String |  | 
### cs-get-children

***
Get link to child customer by child CID(s).

#### Base Command

`cs-get-children`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | CID of a child customer. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainChildrenResponseV1.resources.checksum | String |  | 
| CrowdStrike.domainChildrenResponseV1.resources.child_cid | String |  | 
| CrowdStrike.domainChildrenResponseV1.resources.child_gcid | String |  | 
| CrowdStrike.domainChildrenResponseV1.resources.child_of | String |  | 
| CrowdStrike.domainChildrenResponseV1.resources.name | String |  | 
| CrowdStrike.domainChildrenResponseV1.resources.status | String |  | 
### cs-get-cloudconnectazure-entities-account-v1

***
Return information about Azure account registration.

#### Base Command

`cs-get-cloudconnectazure-entities-account-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned. | Optional | 
| scan_type | Type of scan, dry or full, to perform on selected accounts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAzureAccountResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureAccountResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.CreatedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.DeletedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.ID | Number |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.status | String | Account registration status. | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.subscription_id | String | Azure Subscription ID. | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.tenant_id | String | Azure Tenant ID to use. | 
### cs-get-cloudconnectazure-entities-userscriptsdownload-v1

***
Return a script for customer to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment.

#### Base Command

`cs-get-cloudconnectazure-entities-userscriptsdownload-v1`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.resources.bash | String |  | 
### cs-get-cloudconnectcspmazure-entities-account-v1

***
Return information about Azure account registration.

#### Base Command

`cs-get-cloudconnectcspmazure-entities-account-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | SubscriptionIDs of accounts to select for this status operation. If this is empty then all accounts are returned. | Optional | 
| scan_type | Type of scan, dry or full, to perform on selected accounts. | Optional | 
| status | Account status to filter results by. | Optional | 
| limit | The maximum records to return. Defaults to 100. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAzureAccountResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureAccountResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.CreatedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.DeletedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.ID | Number |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.status | String | Account registration status. | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.subscription_id | String | Azure Subscription ID. | 
| CrowdStrike.registrationAzureAccountResponseV1.resources.tenant_id | String | Azure Tenant ID to use. | 
### cs-get-cloudconnectcspmazure-entities-userscriptsdownload-v1

***
Return a script for customer to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment.

#### Base Command

`cs-get-cloudconnectcspmazure-entities-userscriptsdownload-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | Tenant ID to generate script for. Defaults to most recently registered tenant. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.resources.bash | String |  | 
### cs-get-clusters

***
Provides the clusters acknowledged by the Kubernetes Protection service.

#### Base Command

`cs-get-clusters`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_names | Cluster name. For EKS it will be cluster ARN. | Optional | 
| account_ids | Cluster Account id. For EKS it will be AWS account ID. | Optional | 
| locations | Cloud location. | Optional | 
| cluster_service | Cluster Service. Possible values are: eks. | Optional | 
| limit | Limit returned accounts. | Optional | 
| offset | Offset returned accounts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.k8sregGetClustersResp.errors.code | Number |  | 
| CrowdStrike.k8sregGetClustersResp.errors.id | String |  | 
| CrowdStrike.k8sregGetClustersResp.errors.message | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.account_id | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.cid | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.cluster_id | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.cluster_name | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.cluster_service | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.created_at | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.last_heartbeat_at | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.location | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.status | String |  | 
| CrowdStrike.k8sregGetClustersResp.resources.updated_at | String |  | 
### cs-get-combined-sensor-installers-by-query

***
Get sensor installer details by provided query.

#### Base Command

`cs-get-combined-sensor-installers-by-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The first item to return, where 0 is the latest item. Use with the limit  meter to manage pagination of results. | Optional | 
| limit | The number of items to return in this response (default: 100, max: 500). Use with the offset  meter to manage pagination of results. | Optional | 
| sort | Sort items using their properties. Common sort options include:   ul  li version\|asc /li  li release_date\|desc /li  /ul. | Optional | 
| filter_ | Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard   includes all results.  Common filter options include:  ul  li platform:"windows" /li  li version: "5.2" /li  /ul. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainSensorInstallersV1.errors.code | Number |  | 
| CrowdStrike.domainSensorInstallersV1.errors.id | String |  | 
| CrowdStrike.domainSensorInstallersV1.errors.message | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.description | String | installer description. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_size | Number | file size. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_type | String | file type. | 
| CrowdStrike.domainSensorInstallersV1.resources.name | String | installer file name. | 
| CrowdStrike.domainSensorInstallersV1.resources.os | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.os_version | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.platform | String | supported platform. | 
| CrowdStrike.domainSensorInstallersV1.resources.release_date | String | release date. | 
| CrowdStrike.domainSensorInstallersV1.resources.sha256 | String | sha256. | 
| CrowdStrike.domainSensorInstallersV1.resources.version | String | version of the installer. | 
### cs-get-detect-summaries

***
View information about detections.

#### Base Command

`cs-get-detect-summaries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainMsaDetectSummariesResponse.errors.code | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.errors.id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.errors.message | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.assigned_to_name | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.assigned_to_uid | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.alleged_filetype | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.behavior_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.cmdline | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.confidence | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.container_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.control_graph_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.description | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.device_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.display_name | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.filename | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.filepath | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.ioc_description | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.ioc_source | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.ioc_type | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.ioc_value | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.md5 | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.objective | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.pattern_disposition | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.rule_instance_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.rule_instance_version | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.scenario | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.severity | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.sha256 | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.tactic | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.tactic_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.technique | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.technique_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.template_instance_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.timestamp | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.triggering_process_graph_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.user_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.behaviors.user_name | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.cid | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.created_timestamp | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.detection_id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.email_sent | Boolean |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.first_behavior | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.last_behavior | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.max_confidence | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.max_severity | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.max_severity_displayname | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.overwatch_notes | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.quarantined_files.id | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.quarantined_files.paths | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.quarantined_files.sha256 | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.quarantined_files.state | String |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.seconds_to_resolved | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.seconds_to_triaged | Number |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.show_in_ui | Boolean |  | 
| CrowdStrike.domainMsaDetectSummariesResponse.resources.status | String |  | 
### cs-get-device-control-policies

***
Retrieve a set of Device Control Policies by specifying their IDs.

#### Base Command

`cs-get-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Device Control Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-get-device-count-collection-queries-by-filter

***
Retrieve device count collection Ids that match the provided FQL filter, criteria with scrolling enabled.

#### Base Command

`cs-get-device-count-collection-queries-by-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-get-device-details

***
Get details on one or more hosts by providing agent IDs (AID). You can get a host's agent IDs (AIDs) from the /devices/queries/devices/v1 endpoint, the Falcon console or the Streaming API.

#### Base Command

`cs-get-device-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The host agentIDs used to get details on. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainDeviceDetailsResponseSwagger.errors.code | Number |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.errors.id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.errors.message | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.agent_load_flags | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.agent_local_time | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.agent_version | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.bios_manufacturer | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.bios_version | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.build_number | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.cid | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.config_id_base | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.config_id_build | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.config_id_platform | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.cpu_signature | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.detection_suppression_status | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.device_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.email | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.external_ip | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.first_login_timestamp | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.first_seen | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.group_hash | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.host_hidden_status | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.hostname | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.instance_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.last_login_timestamp | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.last_seen | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.local_ip | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.mac_address | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.machine_domain | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.major_version | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.minor_version | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.modified_timestamp | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.os_version | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.platform_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.platform_name | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_host_ip4 | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_host_ip6 | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_hostname | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_ip4 | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_ip6 | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_name | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_namespace | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pod_service_account_name | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.pointer_size | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.applied | Boolean |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.applied_date | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.assigned_date | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.policy_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.policy_type | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.rule_set_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.settings_hash | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.product_type | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.product_type_desc | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.provision_status | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.release_group | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.serial_number | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.service_pack_major | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.service_pack_minor | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.service_provider | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.service_provider_account_id | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.site_name | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.status | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.system_manufacturer | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.system_product_name | String |  | 
| CrowdStrike.domainDeviceDetailsResponseSwagger.resources.zone_group | String |  | 
### cs-get-firewall-policies

***
Retrieve a set of Firewall Policies by specifying their IDs.

#### Base Command

`cs-get-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Firewall Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
### cs-get-helm-values-yaml

***
Provides a sample Helm values.yaml file for a customer to install alongside the agent Helm chart.

#### Base Command

`cs-get-helm-values-yaml`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Cluster name. For EKS it will be cluster ARN. | Required | 

#### Context Output

There is no context output for this command.
### cs-get-host-groups

***
Retrieve a set of Host Groups by specifying their IDs.

#### Base Command

`cs-get-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Host Groups to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
### cs-get-incidents

***
Get details on incidents by providing incident IDs.

#### Base Command

`cs-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaExternalIncidentResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.errors.id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.errors.message | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.assigned_to | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.assigned_to_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.cid | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.created | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.description | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.end | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.count | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.has_detect | Boolean |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.has_overwatch | Boolean |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.has_prevented | Boolean |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.timestamp_max | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.events_histogram.timestamp_min | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.fine_score | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.agent_load_flags | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.agent_local_time | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.agent_version | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.bios_manufacturer | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.bios_version | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.cid | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.config_id_base | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.config_id_build | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.config_id_platform | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.device_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.external_ip | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.first_login_timestamp | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.first_login_user | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.first_seen | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.hostname | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.instance_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.last_login_timestamp | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.last_login_user | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.last_seen | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.local_ip | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.mac_address | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.machine_domain | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.major_version | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.minor_version | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.modified_timestamp | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.os_version | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.platform_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.platform_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.pod_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.pod_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.pod_namespace | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.pod_service_account_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.product_type | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.product_type_desc | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.release_group | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.service_provider | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.service_provider_account_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.site_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.status | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.system_manufacturer | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.hosts.system_product_name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.incident_id | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.incident_type | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.lm_hosts_capped | Boolean |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.modified_timestamp | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.name | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.start | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.state | String |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.status | Number |  | 
| CrowdStrike.apiMsaExternalIncidentResponse.resources.visibility | Number |  | 
### cs-get-intel-actor-entities

***
Retrieve specific actors using their actor IDs.

#### Base Command

`cs-get-intel-actor-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the actors you want to retrieve. | Required | 
| fields | The fields to return, or a predefined set of fields in the form of the collection name surrounded by two underscores like:  \_\_\ collection\ \_\_.  Ex: slug \_\_full\_\_.  Defaults to \_\_basic\_\_. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainActorsResponse.errors.id | String |  | 
| CrowdStrike.domainActorsResponse.errors.message | String |  | 
| CrowdStrike.domainActorsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.actor_type | String |  | 
| CrowdStrike.domainActorsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.description | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.first_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.known_as | String |  | 
| CrowdStrike.domainActorsResponse.resources.last_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.origins.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.origins.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.short_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.url | String |  | 
### cs-get-intel-indicator-entities

***
Retrieve specific indicators using their indicator IDs.

#### Base Command

`cs-get-intel-indicator-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainPublicIndicatorsV3Response.errors.code | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.message | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources._marker | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.deleted | Boolean |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.created_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.last_valid_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.name | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.last_updated | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.malicious_confidence | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.published_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.created_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.last_valid_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.type | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.type | String |  | 
### cs-get-intel-report-entities

***
Retrieve specific reports using their report IDs.

#### Base Command

`cs-get-intel-report-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the reports you want to retrieve. | Required | 
| fields | The fields to return, or a predefined set of fields in the form of the collection name surrounded by two underscores like:  \_\_\ collection\ \_\_.  Ex: slug \_\_full\_\_.  Defaults to \_\_basic\_\_. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNewsResponse.errors.code | Number |  | 
| CrowdStrike.domainNewsResponse.errors.id | String |  | 
| CrowdStrike.domainNewsResponse.errors.message | String |  | 
| CrowdStrike.domainNewsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.actors.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.actors.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.description | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.short_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.tags.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.url | String |  | 
### cs-get-intel-reportpdf

***
Return a Report PDF attachment.

#### Base Command

`cs-get-intel-reportpdf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the report you want to download as a PDF. | Required | 

#### Context Output

There is no context output for this command.
### cs-get-intel-rule-entities

***
Retrieve details for rule sets for the specified ids.

#### Base Command

`cs-get-intel-rule-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of rules to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRulesResponse.errors.code | Number |  | 
| CrowdStrike.domainRulesResponse.errors.id | String |  | 
| CrowdStrike.domainRulesResponse.errors.message | String |  | 
| CrowdStrike.domainRulesResponse.resources.created_date | Number |  | 
| CrowdStrike.domainRulesResponse.resources.description | String |  | 
| CrowdStrike.domainRulesResponse.resources.id | Number |  | 
| CrowdStrike.domainRulesResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainRulesResponse.resources.name | String |  | 
| CrowdStrike.domainRulesResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainRulesResponse.resources.short_description | String |  | 
| CrowdStrike.domainRulesResponse.resources.type | String |  | 
### cs-get-intel-rule-file

***
Download earlier rule sets.

#### Base Command

`cs-get-intel-rule-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Accept | Choose the format you want the rule set in. | Optional | 
| id_ | The ID of the rule set. | Required | 
| format | Choose the format you want the rule set in. Valid formats are zip and gzip. Defaults to zip. | Optional | 

#### Context Output

There is no context output for this command.
### cs-get-latest-intel-rule-file

***
Download the latest rule set.

#### Base Command

`cs-get-latest-intel-rule-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Accept | Choose the format you want the rule set in. | Optional | 
| type_ | The rule news report type. Accepted values:  snort-suricata-master  snort-suricata-update  snort-suricata-changelog  yara-master  yara-update  yara-changelog  common-event-format  netwitness. | Required | 
| format | Choose the format you want the rule set in. Valid formats are zip and gzip. Defaults to zip. | Optional | 

#### Context Output

There is no context output for this command.
### cs-get-locations

***
Provides the cloud locations acknowledged by the Kubernetes Protection service.

#### Base Command

`cs-get-locations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clouds | Cloud Provider. Possible values are: aws, azure, gcp. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.k8sregGetLocationsResp.errors.code | Number |  | 
| CrowdStrike.k8sregGetLocationsResp.errors.id | String |  | 
| CrowdStrike.k8sregGetLocationsResp.errors.message | String |  | 
| CrowdStrike.k8sregGetLocationsResp.resources.cloud | String |  | 
| CrowdStrike.k8sregGetLocationsResp.resources.location | String |  | 
### cs-get-mal-query-downloadv1

***
Download a file indexed by MalQuery. Specify the file using its SHA256. Only one file is supported at this time.

#### Base Command

`cs-get-mal-query-downloadv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The file SHA256. | Required | 

#### Context Output

There is no context output for this command.
### cs-get-mal-query-entities-samples-fetchv1

***
Fetch a zip archive with password 'infected' containing the samples. Call this once the /entities/samples-multidownload request has finished processing.

#### Base Command

`cs-get-mal-query-entities-samples-fetchv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Multidownload job id. | Required | 

#### Context Output

There is no context output for this command.
### cs-get-mal-query-metadatav1

***
Retrieve indexed files metadata by their hash.

#### Base Command

`cs-get-mal-query-metadatav1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The file SHA256. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malquerySampleMetadataResponse.errors.code | Number |  | 
| CrowdStrike.malquerySampleMetadataResponse.errors.id | String |  | 
| CrowdStrike.malquerySampleMetadataResponse.errors.message | String |  | 
| CrowdStrike.malquerySampleMetadataResponse.errors.type | String |  | 
| CrowdStrike.malquerySampleMetadataResponse.resources.family | String | Sample family. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.label | String | Sample label. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malquerySampleMetadataResponse.resources.sha256 | String | Sample SHA256. | 
### cs-get-mal-query-quotasv1

***
Get information about search and download quotas in your environment.

#### Base Command

`cs-get-mal-query-quotasv1`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryRateLimitsResponse.errors.code | Number |  | 
| CrowdStrike.malqueryRateLimitsResponse.errors.id | String |  | 
| CrowdStrike.malqueryRateLimitsResponse.errors.message | String |  | 
### cs-get-mal-query-requestv1

***
Check the status and results of an asynchronous request, such as hunt or exact-search. Supports a single request id at this time.

#### Base Command

`cs-get-mal-query-requestv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Identifier of a MalQuery request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryRequestResponse.errors.code | Number |  | 
| CrowdStrike.malqueryRequestResponse.errors.id | String |  | 
| CrowdStrike.malqueryRequestResponse.errors.message | String |  | 
| CrowdStrike.malqueryRequestResponse.errors.type | String |  | 
| CrowdStrike.malqueryRequestResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryRequestResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryRequestResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryRequestResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryRequestResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryRequestResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryRequestResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryRequestResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryRequestResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryRequestResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryRequestResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryRequestResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryRequestResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryRequestResponse.resources.yara_rule | String | Search YARA rule. | 
### cs-get-notifications-detailed-translatedv1

***
Get detailed notifications based on their IDs. These include the raw intelligence content that generated the match.This endpoint will return translated notification content. The only target language available is English. A single notification can be translated per request.

#### Base Command

`cs-get-notifications-detailed-translatedv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Notification IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message_key | String |  | 
### cs-get-notifications-detailedv1

***
Get detailed notifications based on their IDs. These include the raw intelligence content that generated the match.

#### Base Command

`cs-get-notifications-detailedv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Notification IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationDetailsResponseV1.errors.message_key | String |  | 
### cs-get-notifications-translatedv1

***
Get notifications based on their IDs. IDs can be retrieved using the GET /queries/notifications/v1 endpoint. This endpoint will return translated notification content. The only target language available is English.

#### Base Command

`cs-get-notifications-translatedv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Notification IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
### cs-get-notificationsv1

***
Get notifications based on their IDs. IDs can be retrieved using the GET /queries/notifications/v1 endpoint.

#### Base Command

`cs-get-notificationsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Notification IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
### cs-get-prevention-policies

***
Retrieve a set of Prevention Policies by specifying their IDs.

#### Base Command

`cs-get-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Prevention Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-get-reports

***
Get a full sandbox report.

#### Base Command

`cs-get-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a report. Find a report ID from the response when submitting a malware sample or search with `/falconx/queries/reports/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.falconxReportV1Response.errors.code | Number |  | 
| CrowdStrike.falconxReportV1Response.errors.id | String |  | 
| CrowdStrike.falconxReportV1Response.errors.message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.cid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.first_activity_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.image_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.known_as | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.last_activity_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.short_description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.thumbnail_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.updated_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_csv_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_json_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_maec_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_stix_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_csv_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_json_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_maec_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_stix_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.errors.code | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.errors.message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.input | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.family | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.file_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.first_seen_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.label | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.md5 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.sha1 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.verdict | String |  | 
| CrowdStrike.falconxReportV1Response.resources.origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.architecture | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.address | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.associated_runtime.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.associated_runtime.pid | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.compromised | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.country | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.protocol | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.address | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.compromised | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.country | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.domain | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_creation_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_name_servers | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_organization | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.environment_description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_available_to_download | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.md5 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.runtime_process | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.sha1 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.threat_level | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.threat_level_readable | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.filename | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.process | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.source | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_imports.module | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.header | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host_ip | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host_port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.method | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.response_code | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.response_phrase | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.incidents.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.ioc_report_broad_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.ioc_report_strict_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_forensics.stream_uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_forensics.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_strings_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.attack_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.tactic | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.technique | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.packer | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.pcap_report_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.command_line | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.mask | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.icon_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.normalized_path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.parent_uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.pid | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.process_flags.data | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.process_flags.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.key | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.operation | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.status | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.status_human_readable | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.cls_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.dispatch_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.argument_number | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.comment | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.meaning | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.result | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.status | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.executed | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.file_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.human_keywords | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.instructions_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.matched_signatures.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.matched_signatures.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.attack_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.category | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.identifier | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.relevance | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.threat_level | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.threat_level_human | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.type | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submission_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submit_url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.category | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.destination_ip | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.destination_port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.protocol | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.sid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.target_url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.threat_score | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.verdict | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.version_info.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.version_info.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_bitness | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_edition | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_service_pack | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_version | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_uuid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.verdict | String |  | 
| CrowdStrike.falconxReportV1Response.errors.code | Number |  | 
| CrowdStrike.falconxReportV1Response.errors.id | String |  | 
| CrowdStrike.falconxReportV1Response.errors.message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.cid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.first_activity_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.image_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.known_as | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.last_activity_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.origins.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.short_description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_countries.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.slug | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.target_industries.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.actors.thumbnail_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.created_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.updated_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.intel.related_indicators.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_csv_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_json_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_maec_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_broad_stix_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_csv_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_json_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_maec_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.ioc_report_strict_stix_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.errors.code | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.errors.message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.input | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.family | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.file_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.first_seen_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.label | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.md5 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.sha1 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.resources.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.malquery.verdict | String |  | 
| CrowdStrike.falconxReportV1Response.resources.origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.architecture | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.address | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.associated_runtime.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.associated_runtime.pid | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.compromised | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.country | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.contacted_hosts.protocol | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.address | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.compromised | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.country | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.domain | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_creation_timestamp | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_name_servers | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.dns_requests.registrar_organization | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.environment_description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_message | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.error_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_available_to_download | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.md5 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.runtime_process | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.sha1 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.threat_level | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_files.threat_level_readable | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.filename | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.process | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.source | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.extracted_interesting_strings.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_imports.module | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_size | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.file_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.header | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host_ip | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.host_port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.method | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.response_code | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.response_phrase | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.http_requests.url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.incidents.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.ioc_report_broad_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.ioc_report_strict_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_forensics.stream_uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_forensics.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.memory_strings_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.attack_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.tactic | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.mitre_attacks.technique | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.packer | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.pcap_report_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.command_line | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.mask | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.file_accesses.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.id | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.handles.type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.icon_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.normalized_path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.parent_uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.pid | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.process_flags.data | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.process_flags.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.key | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.operation | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.path | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.status | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.status_human_readable | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.registry.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.cls_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.dispatch_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.argument_number | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.comment | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.meaning | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.parameters.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.result | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.script_calls.status | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.executed | Boolean |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.file_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.human_keywords | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.instructions_artifact_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.matched_signatures.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.matched_signatures.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.streams.uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.processes.uid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.attack_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.category | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.identifier | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.origin | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.relevance | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.threat_level | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.threat_level_human | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.signatures.type | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submission_type | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.submit_url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.category | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.description | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.destination_ip | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.destination_port | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.protocol | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.suricata_alerts.sid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.target_url | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.threat_score | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.verdict | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.version_info.id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.version_info.value | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_bitness | Number |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_edition | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_service_pack | String |  | 
| CrowdStrike.falconxReportV1Response.resources.sandbox.windows_version_version | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxReportV1Response.resources.user_uuid | String |  | 
| CrowdStrike.falconxReportV1Response.resources.verdict | String |  | 
### cs-get-roles

***
Get info about a role.

#### Base Command

`cs-get-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a role. Find a role ID from `/customer/queries/roles/v1` or `/users/queries/roles/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserRoleResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleResponse.errors.message | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.cid | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.description | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.display_name | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.id | String |  | 
| CrowdStrike.domainUserRoleResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleResponse.errors.message | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.cid | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.description | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.display_name | String |  | 
| CrowdStrike.domainUserRoleResponse.resources.id | String |  | 
### cs-get-roles-byid

***
Get MSSP Role assignment(s). MSSP Role assignment is of the format :.

#### Base Command

`cs-get-roles-byid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | MSSP Role assignment is of the format  user_group_id : cid_group_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainMSSPRoleResponseV1.errors.code | Number |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.message | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.user_group_id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.code | Number |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.errors.message | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.id | String |  | 
| CrowdStrike.domainMSSPRoleResponseV1.resources.user_group_id | String |  | 
### cs-get-rulesv1

***
Get monitoring rules rules by provided IDs.

#### Base Command

`cs-get-rulesv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | IDs of rules. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRulesEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.cid | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.created_timestamp | String | The creation time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.filter | String | The FQL filter contained in a rule and used for searching. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.id | String | The ID of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.name | String | The name for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.permissions | String | The permissions of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.priority | String | The priority of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status | String | The status of a rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status_message | String | The detailed status message. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.topic | String | The topic of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.updated_timestamp | String | The last updated time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_id | String | The user ID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_name | String | The user name of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_uuid | String | The UUID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.cid | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.created_timestamp | String | The creation time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.filter | String | The FQL filter contained in a rule and used for searching. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.id | String | The ID of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.name | String | The name for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.permissions | String | The permissions of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.priority | String | The priority of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status | String | The status of a rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status_message | String | The detailed status message. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.topic | String | The topic of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.updated_timestamp | String | The last updated time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_id | String | The user ID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_name | String | The user name of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_uuid | String | The UUID of the user that created a given rule. | 
### cs-get-samplev2

***
Retrieves the file associated with the given ID (SHA256).

#### Base Command

`cs-get-samplev2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | The file SHA256. | Required | 
| password_protected | Flag whether the sample should be zipped and password protected with pass='infected'. | Optional | 

#### Context Output

There is no context output for this command.
### cs-get-samplev3

***
Retrieves the file associated with the given ID (SHA256).

#### Base Command

`cs-get-samplev3`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| ids | The file SHA256. | Required | 
| password_protected | Flag whether the sample should be zipped and password protected with pass='infected'. | Optional | 

#### Context Output

There is no context output for this command.
### cs-get-scans

***
Check the status of a volume scan. Time required for analysis increases with the number of samples in a volume but usually it should take less than 1 minute.

#### Base Command

`cs-get-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted scan. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.mlscannerScanV1Response.errors.code | Number |  | 
| CrowdStrike.mlscannerScanV1Response.errors.id | String |  | 
| CrowdStrike.mlscannerScanV1Response.errors.message | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.cid | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.id | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.error | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.sha256 | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.verdict | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.status | String |  | 
| CrowdStrike.mlscannerScanV1Response.errors.code | Number |  | 
| CrowdStrike.mlscannerScanV1Response.errors.id | String |  | 
| CrowdStrike.mlscannerScanV1Response.errors.message | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.cid | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.id | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.error | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.sha256 | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.samples.verdict | String |  | 
| CrowdStrike.mlscannerScanV1Response.resources.status | String |  | 
### cs-get-scans-aggregates

***
Get scans aggregations as specified via json in request body.

#### Base Command

`cs-get-scans-aggregates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

There is no context output for this command.
### cs-get-sensor-installers-by-query

***
Get sensor installer IDs by provided query.

#### Base Command

`cs-get-sensor-installers-by-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The first item to return, where 0 is the latest item. Use with the limit  meter to manage pagination of results. | Optional | 
| limit | The number of items to return in this response (default: 100, max: 500). Use with the offset  meter to manage pagination of results. | Optional | 
| sort | Sort items using their properties. Common sort options include:   ul  li version\|asc /li  li release_date\|desc /li  /ul. | Optional | 
| filter_ | Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard   includes all results.  Common filter options include:  ul  li platform:"windows" /li  li version: "5.2" /li  /ul. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-get-sensor-installers-entities

***
Get sensor installer details by provided SHA256 IDs.

#### Base Command

`cs-get-sensor-installers-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the installers. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainSensorInstallersV1.errors.code | Number |  | 
| CrowdStrike.domainSensorInstallersV1.errors.id | String |  | 
| CrowdStrike.domainSensorInstallersV1.errors.message | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.description | String | installer description. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_size | Number | file size. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_type | String | file type. | 
| CrowdStrike.domainSensorInstallersV1.resources.name | String | installer file name. | 
| CrowdStrike.domainSensorInstallersV1.resources.os | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.os_version | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.platform | String | supported platform. | 
| CrowdStrike.domainSensorInstallersV1.resources.release_date | String | release date. | 
| CrowdStrike.domainSensorInstallersV1.resources.sha256 | String | sha256. | 
| CrowdStrike.domainSensorInstallersV1.resources.version | String | version of the installer. | 
| CrowdStrike.domainSensorInstallersV1.errors.code | Number |  | 
| CrowdStrike.domainSensorInstallersV1.errors.id | String |  | 
| CrowdStrike.domainSensorInstallersV1.errors.message | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.description | String | installer description. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_size | Number | file size. | 
| CrowdStrike.domainSensorInstallersV1.resources.file_type | String | file type. | 
| CrowdStrike.domainSensorInstallersV1.resources.name | String | installer file name. | 
| CrowdStrike.domainSensorInstallersV1.resources.os | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.os_version | String |  | 
| CrowdStrike.domainSensorInstallersV1.resources.platform | String | supported platform. | 
| CrowdStrike.domainSensorInstallersV1.resources.release_date | String | release date. | 
| CrowdStrike.domainSensorInstallersV1.resources.sha256 | String | sha256. | 
| CrowdStrike.domainSensorInstallersV1.resources.version | String | version of the installer. | 
### cs-get-sensor-installersccid-by-query

***
Get CCID to use with sensor installers.

#### Base Command

`cs-get-sensor-installersccid-by-query`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-get-sensor-update-policies

***
Retrieve a set of Sensor Update Policies by specifying their IDs.

#### Base Command

`cs-get-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Sensor Update Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-get-sensor-update-policiesv2

***
Retrieve a set of Sensor Update Policies with additional support for uninstall protection by specifying their IDs.

#### Base Command

`cs-get-sensor-update-policiesv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the Sensor Update Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
### cs-get-sensor-visibility-exclusionsv1

***
Get a set of Sensor Visibility Exclusions by specifying their IDs.

#### Base Command

`cs-get-sensor-visibility-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSvExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value_hash | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value_hash | String |  | 
### cs-get-submissions

***
Check the status of a sandbox analysis. Time required for analysis varies but is usually less than 15 minutes.

#### Base Command

`cs-get-submissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with `/falconx/queries/submissions/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.falconxSubmissionV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.message | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.action_script | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.command_line | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.document_password | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.enable_tor | Boolean |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_date | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_time | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.url | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.state | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_uuid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.message | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.action_script | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.command_line | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.document_password | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.enable_tor | Boolean |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_date | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_time | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.url | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.state | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_uuid | String |  | 
### cs-get-summary-reports

***
Get a short summary version of a sandbox report.

#### Base Command

`cs-get-summary-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a summary. Find a summary ID from the response when submitting a malware sample or search with `/falconx/queries/reports/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.falconxSummaryReportV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.errors.id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.errors.message | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.id | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.slug | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_csv_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_json_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_maec_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_stix_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_csv_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_json_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_maec_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_stix_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.environment_description | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_message | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_origin | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.file_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.incidents.name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submission_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submit_url | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.threat_score | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.verdict | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.verdict | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.errors.id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.errors.message | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.id | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.intel.actors.slug | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_csv_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_json_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_maec_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_broad_stix_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_csv_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_json_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_maec_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.ioc_report_strict_stix_artifact_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.environment_description | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_message | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_origin | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.error_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.file_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.incidents.name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submission_type | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.submit_url | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.threat_score | Number |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.sandbox.verdict | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSummaryReportV1Response.resources.verdict | String |  | 
### cs-get-user-group-members-byid

***
Get User Group members by User Group ID(s).

#### Base Command

`cs-get-user-group-members-byid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_group_ids | User Group IDs to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.resources.user_group_id | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupMembersResponseV1.resources.user_group_id | String |  | 
### cs-get-user-groups-byid

***
Get User Group by ID(s).

#### Base Command

`cs-get-user-groups-byid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_group_ids | User Group IDs to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.user_group_id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.user_group_id | String |  | 
### cs-get-user-role-ids

***
Show role IDs of roles assigned to a user. For more information on each role, provide the role ID to `/customer/entities/roles/v1`.

#### Base Command

`cs-get-user-role-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-get-vulnerabilities

***
Get details on vulnerabilities by providing one or more IDs.

#### Base Command

`cs-get-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | One or more vulnerability IDs (max: 400). Find vulnerability IDs with GET /spotlight/queries/vulnerabilities/v1. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.code | Number |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.id | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.message | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.aid | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.cid | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.closed_timestamp | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.created_timestamp | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.id | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.status | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.updated_timestamp | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.code | Number |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.id | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.errors.message | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.aid | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.cid | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.closed_timestamp | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.created_timestamp | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.id | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.status | String |  | 
| CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2.resources.updated_timestamp | String |  | 
### cs-getaws-accounts

***
Retrieve a set of AWS Accounts by specifying their IDs.

#### Base Command

`cs-getaws-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of accounts to retrieve details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
### cs-getaws-accounts-mixin0

***
Provides a list of AWS accounts.

#### Base Command

`cs-getaws-accounts-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | AWS Account IDs. | Optional | 
| status | Filter by account status. | Optional | 
| limit | Limit returned accounts. | Optional | 
| offset | Offset returned accounts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.k8sregGetAWSAccountsResp.errors.code | Number |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.errors.id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.errors.message | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.account_id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.aws_permissions_status.name | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.aws_permissions_status.status | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.cid | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.cloudformation_url | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.created_at | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.from_cspm | Boolean |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.iam_role_arn | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.is_master | Boolean |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.organization_id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.region | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.status | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.updated_at | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.errors.code | Number |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.errors.id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.errors.message | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.account_id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.aws_permissions_status.name | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.aws_permissions_status.status | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.cid | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.cloudformation_url | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.created_at | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.from_cspm | Boolean |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.iam_role_arn | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.is_master | Boolean |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.organization_id | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.region | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.status | String |  | 
| CrowdStrike.k8sregGetAWSAccountsResp.resources.updated_at | String |  | 
### cs-getaws-settings

***
Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts.

#### Base Command

`cs-getaws-settings`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsCustomerConfigurationsV1.errors.code | Number |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.errors.id | String |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.errors.message | String |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the centralized S3 bucket containing cloudtrail logs for all accounts. | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.created_timestamp | String | Timestamp of when the settings were first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.last_modified_timestamp | String | Timestamp of when the settings were last modified. | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.static_external_id | String | By setting this value, all subsequent accounts that are provisioned will default to using this value as the external ID. | 
| CrowdStrike.modelsCustomerConfigurationsV1.errors.code | Number |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.errors.id | String |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.errors.message | String |  | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the centralized S3 bucket containing cloudtrail logs for all accounts. | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.created_timestamp | String | Timestamp of when the settings were first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.last_modified_timestamp | String | Timestamp of when the settings were last modified. | 
| CrowdStrike.modelsCustomerConfigurationsV1.resources.static_external_id | String | By setting this value, all subsequent accounts that are provisioned will default to using this value as the external ID. | 
### cs-getcid-group-by-id

***
Get CID Group(s) by ID(s).

#### Base Command

`cs-getcid-group-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid_group_ids | CID Group IDs to be searched on. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.name | String |  | 
### cs-getcid-group-members-by

***
Get CID Group members by CID Group IDs.

#### Base Command

`cs-getcid-group-members-by`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid_group_ids | CID Group IDs to be searched on. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupMembersResponseV1.resources.cid_group_id | String |  | 
### cs-getcspm-aws-account

***
Returns information about the current status of an AWS account.

#### Base Command

`cs-getcspm-aws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_type | Type of scan, dry or full, to perform on selected accounts. | Optional | 
| ids | AWS account IDs. | Optional | 
| organization_ids | AWS organization IDs. | Optional | 
| status | Account status to filter results by. | Optional | 
| limit | The maximum records to return. Defaults to 100. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| group_by | Field to group by. Possible values are: organization. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAWSAccountResponseV2.errors.code | Number |  | 
| CrowdStrike.registrationAWSAccountResponseV2.errors.id | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.errors.message | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.CreatedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.DeletedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.ID | Number |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.account_id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_cloudtrail_bucket_name | String | AWS CloudTrail bucket name to store logs. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_cloudtrail_region | String | AWS CloudTrail region. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_permissions_status.name | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_permissions_status.status | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.cid | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.cloudformation_url | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.eventbus_name | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.intermediate_role_arn | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.is_master | Boolean |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.organization_id | String | Up to 34 character AWS provided unique identifier for the organization. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.status | String | Account registration status. | 
| CrowdStrike.registrationAWSAccountResponseV2.errors.code | Number |  | 
| CrowdStrike.registrationAWSAccountResponseV2.errors.id | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.errors.message | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.CreatedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.DeletedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.ID | Number |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.account_id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_cloudtrail_bucket_name | String | AWS CloudTrail bucket name to store logs. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_cloudtrail_region | String | AWS CloudTrail region. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_permissions_status.name | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.aws_permissions_status.status | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.cid | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.cloudformation_url | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.eventbus_name | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.intermediate_role_arn | String |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.is_master | Boolean |  | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.organization_id | String | Up to 34 character AWS provided unique identifier for the organization. | 
| CrowdStrike.registrationAWSAccountResponseV2.resources.status | String | Account registration status. | 
### cs-getcspm-aws-account-scripts-attachment

***
Return a script for customer to run in their cloud environment to grant us access to their AWS environment as a downloadable attachment.

#### Base Command

`cs-getcspm-aws-account-scripts-attachment`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.code | Number |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.id | String |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.message | String |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.resources.bash | String |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.code | Number |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.id | String |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.errors.message | String |  | 
| CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2.resources.bash | String |  | 
### cs-getcspm-aws-console-setupur-ls

***
Return a URL for customer to visit in their cloud environment to grant us access to their AWS environment.

#### Base Command

`cs-getcspm-aws-console-setupur-ls`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAWSAccountConsoleURL.account_id | String |  | 
| CrowdStrike.registrationAWSAccountConsoleURL.url | String |  | 
| CrowdStrike.registrationAWSAccountConsoleURL.account_id | String |  | 
| CrowdStrike.registrationAWSAccountConsoleURL.url | String |  | 
### cs-getcspm-azure-user-scripts

***
Return a script for customer to run in their cloud environment to grant us access to their Azure environment.

#### Base Command

`cs-getcspm-azure-user-scripts`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.resources.bash | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1.resources.bash | String |  | 
### cs-getcspm-policy

***
Given a policy ID, returns detailed policy information.

#### Base Command

`cs-getcspm-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Policy ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationPolicyResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicyResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.CreatedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.DeletedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.ID | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.alert_logic | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.api_command | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cli_command | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_document | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_platform | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_platform_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_friendly | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.description | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.event_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.mitre_attack_cloud_matrix | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.mitre_attack_cloud_subtype | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_fail_query | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_pass_query | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_remediation | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_severity | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_statement | String |  | 
| CrowdStrike.registrationPolicyResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicyResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.CreatedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.DeletedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.ID | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.UpdatedAt | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.alert_logic | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.api_command | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cli_command | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_document | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_platform | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_platform_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_friendly | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.cloud_service_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.description | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.event_type | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.mitre_attack_cloud_matrix | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.mitre_attack_cloud_subtype | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_fail_query | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_pass_query | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_remediation | String |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_severity | Number |  | 
| CrowdStrike.registrationPolicyResponseV1.resources.policy_statement | String |  | 
### cs-getcspm-policy-settings

***
Returns information about current policy settings.

#### Base Command

`cs-getcspm-policy-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service | Service type to filter policy settings by. | Optional | 
| policy_id | Policy ID. | Optional | 
| cloud_platform | Cloud Platform (e.g.: aws\|azure\|gcp). Possible values are: aws, azure, gcp. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationPolicySettingsResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.name | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.account_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.enabled | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tag_excluded | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tenant_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_timestamp | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_type | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.name | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.account_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.enabled | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tag_excluded | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tenant_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_timestamp | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_type | String |  | 
### cs-getcspm-scan-schedule

***
Returns scan schedule configuration for one or more cloud platforms.

#### Base Command

`cs-getcspm-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cloud_platform | Cloud Platform. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationScanScheduleResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.id | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.message | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.cloud_platform | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.next_scan_timestamp | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.scan_schedule | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.id | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.message | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.cloud_platform | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.next_scan_timestamp | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.scan_schedule | String |  | 
### cs-getcspmcgp-account

***
Returns information about the current status of an GCP account.

#### Base Command

`cs-getcspmcgp-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_type | Type of scan, dry or full, to perform on selected accounts. | Optional | 
| ids | Parent IDs of accounts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationGCPAccountResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPAccountResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.parent_id | String | GCP ParentID. | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.status | String | Account registration status. | 
| CrowdStrike.registrationGCPAccountResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPAccountResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.parent_id | String | GCP ParentID. | 
| CrowdStrike.registrationGCPAccountResponseV1.resources.status | String | Account registration status. | 
### cs-getcspmgcp-user-scripts

***
Return a script for customer to run in their cloud environment to grant us access to their GCP environment.

#### Base Command

`cs-getcspmgcp-user-scripts`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.resources.bash | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.resources.bash | String |  | 
### cs-getcspmgcp-user-scripts-attachment

***
Return a script for customer to run in their cloud environment to grant us access to their GCP environment as a downloadable attachment.

#### Base Command

`cs-getcspmgcp-user-scripts-attachment`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.resources.bash | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.id | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.errors.message | String |  | 
| CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1.resources.bash | String |  | 
### cs-getevents

***
Get events entities by ID and optionally version.

#### Base Command

`cs-getevents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The events to retrieve, identified by ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiEventsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiEventsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.aid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.cid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.command_line | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.connection_direction | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.event_type | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.hidden | Boolean |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.host_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.icmp_code | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.icmp_type | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.image_file_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.ipv | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.local_address | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.local_port | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.match_count | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.match_count_since_last_event | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.network_profile | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.pid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.policy_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.policy_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.protocol | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.remote_address | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.remote_port | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_action | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_description | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_family_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_group_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.status | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.timestamp | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.tree_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiEventsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.aid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.cid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.command_line | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.connection_direction | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.event_type | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.hidden | Boolean |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.host_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.icmp_code | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.icmp_type | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.image_file_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.ipv | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.local_address | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.local_port | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.match_count | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.match_count_since_last_event | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.network_profile | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.pid | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.policy_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.policy_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.protocol | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.remote_address | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.remote_port | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_action | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_description | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_family_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_group_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_id | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.rule_name | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.status | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.timestamp | String |  | 
| CrowdStrike.fwmgrapiEventsResponse.resources.tree_id | String |  | 
### cs-getfirewallfields

***
Get the firewall field specifications by ID.

#### Base Command

`cs-getfirewallfields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the rule types to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.label | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.name | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.options.label | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.options.value | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.type | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.label | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.name | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.options.label | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.options.value | String |  | 
| CrowdStrike.fwmgrapiFirewallFieldsResponse.resources.platform_fields.type | String |  | 
### cs-getioa-events

***
For CSPM IOA events, gets list of IOA events.

#### Base Command

`cs-getioa-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| cloud_provider | Cloud Provider (e.g.: aws\|azure\|gcp). | Required | 
| account_id | Cloud account ID (e.g.: AWS accountID, Azure subscriptionID). | Optional | 
| azure_tenant_id | Azure tenantID. | Optional | 
| user_ids | user IDs. | Optional | 
| offset | Starting index of overall result set from which to return events. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationExternalIOAEventResponse.errors.code | Number |  | 
| CrowdStrike.registrationExternalIOAEventResponse.errors.id | String |  | 
| CrowdStrike.registrationExternalIOAEventResponse.errors.message | String |  | 
| CrowdStrike.registrationExternalIOAEventResponse.errors.code | Number |  | 
| CrowdStrike.registrationExternalIOAEventResponse.errors.id | String |  | 
| CrowdStrike.registrationExternalIOAEventResponse.errors.message | String |  | 
### cs-getioa-exclusionsv1

***
Get a set of IOA Exclusions by specifying their IDs.

#### Base Command

`cs-getioa-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesIoaExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.cl_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.description | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.detection_json | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.ifn_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.cl_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.description | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.detection_json | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.ifn_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_name | String |  | 
### cs-getioa-users

***
For CSPM IOA users, gets list of IOA users.

#### Base Command

`cs-getioa-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| cloud_provider | Cloud Provider (e.g.: aws\|azure\|gcp). | Required | 
| account_id | Cloud account ID (e.g.: AWS accountID, Azure subscriptionID). | Optional | 
| azure_tenant_id | Azure tenantID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationIOAUserResponse.errors.code | Number |  | 
| CrowdStrike.registrationIOAUserResponse.errors.id | String |  | 
| CrowdStrike.registrationIOAUserResponse.errors.message | String |  | 
| CrowdStrike.registrationIOAUserResponse.resources.user_id | String |  | 
| CrowdStrike.registrationIOAUserResponse.resources.user_name | String |  | 
| CrowdStrike.registrationIOAUserResponse.errors.code | Number |  | 
| CrowdStrike.registrationIOAUserResponse.errors.id | String |  | 
| CrowdStrike.registrationIOAUserResponse.errors.message | String |  | 
| CrowdStrike.registrationIOAUserResponse.resources.user_id | String |  | 
| CrowdStrike.registrationIOAUserResponse.resources.user_name | String |  | 
### cs-getioc

***
    DEPRECATED     Use the new IOC Management endpoint (GET /iocs/entities/indicators/v1).     Get an IOC by providing a type and value.

#### Base Command

`cs-getioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type_ |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Required | 
| value | The string representation of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyIOC.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOC.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.batch_id | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.description | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_days | Number |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.policy | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.share_level | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.source | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.type | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.value | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOC.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.batch_id | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.description | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_days | Number |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.policy | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.share_level | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.source | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.type | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.value | String |  | 
### cs-getml-exclusionsv1

***
Get a set of ML Exclusions by specifying their IDs.

#### Base Command

`cs-getml-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the exclusions to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
### cs-getpatterns

***
Get pattern severities by ID.

#### Base Command

`cs-getpatterns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiPatternsResponse.errors.code | Number |  | 
| CrowdStrike.apiPatternsResponse.errors.id | String |  | 
| CrowdStrike.apiPatternsResponse.errors.message | String |  | 
| CrowdStrike.apiPatternsResponse.resources.name | String |  | 
| CrowdStrike.apiPatternsResponse.resources.severity | String |  | 
| CrowdStrike.apiPatternsResponse.errors.code | Number |  | 
| CrowdStrike.apiPatternsResponse.errors.id | String |  | 
| CrowdStrike.apiPatternsResponse.errors.message | String |  | 
| CrowdStrike.apiPatternsResponse.resources.name | String |  | 
| CrowdStrike.apiPatternsResponse.resources.severity | String |  | 
### cs-getplatforms

***
Get platforms by ID, e.g., windows or mac or droid.

#### Base Command

`cs-getplatforms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the platforms to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiPlatformsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.resources.label | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiPlatformsResponse.resources.label | String |  | 
### cs-getplatforms-mixin0

***
Get platforms by ID.

#### Base Command

`cs-getplatforms-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiPlatformsResponse.errors.code | Number |  | 
| CrowdStrike.apiPlatformsResponse.errors.id | String |  | 
| CrowdStrike.apiPlatformsResponse.errors.message | String |  | 
| CrowdStrike.apiPlatformsResponse.resources.id | String |  | 
| CrowdStrike.apiPlatformsResponse.resources.label | String |  | 
| CrowdStrike.apiPlatformsResponse.errors.code | Number |  | 
| CrowdStrike.apiPlatformsResponse.errors.id | String |  | 
| CrowdStrike.apiPlatformsResponse.errors.message | String |  | 
| CrowdStrike.apiPlatformsResponse.resources.id | String |  | 
| CrowdStrike.apiPlatformsResponse.resources.label | String |  | 
### cs-getpolicycontainers

***
Get policy container entities by policy ID.

#### Base Command

`cs-getpolicycontainers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The policy container(s) to retrieve, identified by policy ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.default_inbound | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.default_outbound | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.enforce | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.is_default_policy | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.platform_id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.policy_id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.test_mode | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.tracking | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.default_inbound | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.default_outbound | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.enforce | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.is_default_policy | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.platform_id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.policy_id | String |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.test_mode | Boolean |  | 
| CrowdStrike.fwmgrapiPolicyContainersResponse.resources.tracking | String |  | 
### cs-getrt-response-policies

***
Retrieve a set of Response Policies by specifying their IDs.

#### Base Command

`cs-getrt-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the RTR Policies to return. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-getrulegroups

***
Get rule group entities by ID. These groups do not contain their rule entites, just the rule IDs in precedence order.

#### Base Command

`cs-getrulegroups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the rule groups to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.tracking | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiRuleGroupsResponse.resources.tracking | String |  | 
### cs-getrulegroups-mixin0

***
Get rule groups by ID.

#### Base Command

`cs-getrulegroups-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.action_label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.disposition_id | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.final_value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.type | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.magic_cookie | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_severity | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.rulegroup_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.action_label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.disposition_id | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.final_value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.type | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.magic_cookie | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_severity | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.rulegroup_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.version | Number |  | 
### cs-getrules

***
Get rule entities by ID (64-bit unsigned int as decimal string) or Family ID (32-character hexadecimal string).

#### Base Command

`cs-getrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The rules to retrieve, identified by ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiRulesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.action | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.address_family | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.description | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.direction | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.family | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.final_value | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.label | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.name | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.type | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.value | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_address.address | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_address.netmask | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_port.end | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_port.start | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.protocol | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_address.address | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_address.netmask | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_port.end | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_port.start | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.version | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.action | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.address_family | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.description | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.direction | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.family | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.final_value | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.label | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.name | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.type | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.fields.value | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.id | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_address.address | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_address.netmask | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_port.end | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.local_port.start | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.name | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.protocol | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_address.address | String |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_address.netmask | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_port.end | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.remote_port.start | Number |  | 
| CrowdStrike.fwmgrapiRulesResponse.resources.version | Number |  | 
### cs-getrules-mixin0

***
Get rules by ID and optionally version in the following format: `ID[:version]`. The max number of IDs is constrained by URL size.

#### Base Command

`cs-getrules-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
### cs-getrulesget

***
Get rules by ID and optionally version in the following format: `ID[:version]`.

#### Base Command

`cs-getrulesget`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_rulesgetrequestv1_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
### cs-getruletypes

***
Get rule types by ID.

#### Base Command

`cs-getruletypes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the entities. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRuleTypesResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleTypesResponse.errors.id | String |  | 
| CrowdStrike.apiRuleTypesResponse.errors.message | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.channel | Number |  | 
| CrowdStrike.apiRuleTypesResponse.resources.disposition_map.id | Number |  | 
| CrowdStrike.apiRuleTypesResponse.resources.disposition_map.label | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.fields.name | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.fields.value | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.id | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.long_desc | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.name | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.released | Boolean |  | 
| CrowdStrike.apiRuleTypesResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleTypesResponse.errors.id | String |  | 
| CrowdStrike.apiRuleTypesResponse.errors.message | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.channel | Number |  | 
| CrowdStrike.apiRuleTypesResponse.resources.disposition_map.id | Number |  | 
| CrowdStrike.apiRuleTypesResponse.resources.disposition_map.label | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.fields.name | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.fields.value | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.id | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.long_desc | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.name | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleTypesResponse.resources.released | Boolean |  | 
### cs-grant-user-role-ids

***
Assign one or more roles to a user.

#### Base Command

`cs-grant-user-role-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 
| domain_roleids_roleids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserRoleIDsResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.message | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.message | String |  | 
### cs-indicatorcombinedv1

***
Get Combined for Indicators.

#### Base Command

`cs-indicatorcombinedv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. Offset and After  ms are mutually exclusive. If none provided then scrolling will be used by default. | Optional | 
| limit | The maximum records to return. | Optional | 
| sort | The sort expression that should be used to sort the results. Possible values are: action, applied_globally, metadata.av_hits, metadata.company_name.raw, created_by, created_on, expiration, expired, metadata.filename.raw, modified_by, modified_on, metadata.original_filename.raw, metadata.product_name.raw, metadata.product_version, severity_number, source, type, value. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
### cs-indicatorcreatev1

***
Create Indicators.

#### Base Command

`cs-indicatorcreatev1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The username. | Optional | 
| retrodetects | Whether to submit to retrodetects. | Optional | 
| ignore_warnings | Set to true to ignore warnings and add all IOCs. | Optional | 
| api_indicatorcreatereqsv1_comment |  | Optional | 
| api_indicatorcreatereqsv1_indicators |  | Required | 

#### Context Output

There is no context output for this command.
### cs-indicatordeletev1

***
Delete Indicators by ids.

#### Base Command

`cs-indicatordeletev1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The FQL expression to delete Indicators in bulk. If both 'filter' and 'ids' are provided, then filter takes precedence and ignores ids. | Optional | 
| ids | The ids of the Indicators to delete. If both 'filter' and 'ids' are provided, then filter takes precedence and ignores ids. | Optional | 
| comment | The comment why these indicators were deleted. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiIndicatorQueryResponse.errors.code | Number |  | 
| CrowdStrike.apiIndicatorQueryResponse.errors.id | String |  | 
| CrowdStrike.apiIndicatorQueryResponse.errors.message | String |  | 
| CrowdStrike.apiIndicatorQueryResponse.errors.code | Number |  | 
| CrowdStrike.apiIndicatorQueryResponse.errors.id | String |  | 
| CrowdStrike.apiIndicatorQueryResponse.errors.message | String |  | 
### cs-indicatorgetv1

***
Get Indicators by ids.

#### Base Command

`cs-indicatorgetv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The ids of the Indicators to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
### cs-indicatorsearchv1

***
Search for Indicators.

#### Base Command

`cs-indicatorsearchv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. Offset and After  ms are mutually exclusive. If none provided then scrolling will be used by default. | Optional | 
| limit | The maximum records to return. | Optional | 
| sort | The sort expression that should be used to sort the results. Possible values are: action, applied_globally, metadata.av_hits, metadata.company_name.raw, created_by, created_on, expiration, expired, metadata.filename.raw, modified_by, modified_on, metadata.original_filename.raw, metadata.product_name.raw, metadata.product_version, severity_number, source, type, value. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiIndicatorQueryRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorQueryRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorQueryRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorQueryRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorQueryRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorQueryRespV1.errors.message | String |  | 
### cs-indicatorupdatev1

***
Update Indicators.

#### Base Command

`cs-indicatorupdatev1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The username. | Optional | 
| retrodetects | Whether to submit to retrodetects. | Optional | 
| ignore_warnings | Set to true to ignore warnings and add all IOCs. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_action | api_indicatorupdatereqsv1_bulk_update action. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_applied_globally | api_indicatorupdatereqsv1_bulk_update applied_globally. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_description | api_indicatorupdatereqsv1_bulk_update description. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_expiration | api_indicatorupdatereqsv1_bulk_update expiration. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_filter | api_indicatorupdatereqsv1_bulk_update filter. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_host_groups | api_indicatorupdatereqsv1_bulk_update host_groups. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_mobile_action | api_indicatorupdatereqsv1_bulk_update mobile_action. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_platforms | api_indicatorupdatereqsv1_bulk_update platforms. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_severity | api_indicatorupdatereqsv1_bulk_update severity. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_source | api_indicatorupdatereqsv1_bulk_update source. | Optional | 
| api_indicatorupdatereqsv1_bulk_update_tags | api_indicatorupdatereqsv1_bulk_update tags. | Optional | 
| api_indicatorupdatereqsv1_comment |  | Optional | 
| api_indicatorupdatereqsv1_indicators |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.code | Number |  | 
| CrowdStrike.apiIndicatorRespV1.errors.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.errors.message | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.created_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.deleted | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.description | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expiration | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.expired | Boolean |  | 
| CrowdStrike.apiIndicatorRespV1.resources.id | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.mobile_action | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_by | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.modified_on | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.severity | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.source | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.type | String |  | 
| CrowdStrike.apiIndicatorRespV1.resources.value | String |  | 
### cs-list-available-streamso-auth2

***
Discover all event streams in your environment.

#### Base Command

`cs-list-available-streamso-auth2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| appId | Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9). | Required | 
| format | Format for streaming events. Valid values: json, flatjson. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.maindiscoveryResponseV2.errors.code | Number |  | 
| CrowdStrike.maindiscoveryResponseV2.errors.id | String |  | 
| CrowdStrike.maindiscoveryResponseV2.errors.message | String |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.dataFeedURL | String |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.refreshActiveSessionInterval | Number |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.refreshActiveSessionURL | String |  | 
| CrowdStrike.maindiscoveryResponseV2.errors.code | Number |  | 
| CrowdStrike.maindiscoveryResponseV2.errors.id | String |  | 
| CrowdStrike.maindiscoveryResponseV2.errors.message | String |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.dataFeedURL | String |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.refreshActiveSessionInterval | Number |  | 
| CrowdStrike.maindiscoveryResponseV2.resources.refreshActiveSessionURL | String |  | 
### cs-oauth2-access-token

***
Generate an OAuth2 access token.

#### Base Command

`cs-oauth2-access-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_id | The API client ID to authenticate your API requests. For information on generating API clients, see [API documentation inside Falcon](https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers). | Required | 
| client_secret | The API client secret to authenticate your API requests. For information on generating API clients, see [API documentation inside Falcon](https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers). | Required | 
| member_cid | For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID. | Optional | 

#### Context Output

There is no context output for this command.
### cs-oauth2-revoke-token

***
Revoke a previously issued OAuth2 access token before the end of its standard 30-minute life .

#### Base Command

`cs-oauth2-revoke-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | The OAuth2 access token you want to revoke.  Include your API client ID and secret in basic auth format (`Authorization: basic  encoded API client ID and secret `) in your request header. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-patch-cloudconnectazure-entities-clientid-v1

***
Update an Azure service account in our system by with the user-created client_id created with the public key we've provided.

#### Base Command

`cs-patch-cloudconnectazure-entities-clientid-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ClientID to use for the Service Principal associated with the customer's Azure account. | Required | 

#### Context Output

There is no context output for this command.
### cs-patch-cloudconnectcspmazure-entities-clientid-v1

***
Update an Azure service account in our system by with the user-created client_id created with the public key we've provided.

#### Base Command

`cs-patch-cloudconnectcspmazure-entities-clientid-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ClientID to use for the Service Principal associated with the customer's Azure account. | Required | 
| tenant_id | Tenant ID to update client ID for. Required if multiple tenants are registered. | Optional | 

#### Context Output

There is no context output for this command.
### cs-patchcspm-aws-account

***
Patches a existing account in our system for a customer.

#### Base Command

`cs-patchcspm-aws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_awsaccountpatchrequest_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-perform-actionv2

***
Take various actions on the hosts in your environment. Contain or lift containment on a host. Delete or restore a host.

#### Base Command

`cs-perform-actionv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | Specify one of these actions:  - `contain` - This action contains the host, which stops any network communications to locations other than the CrowdStrike cloud and IPs specified in your [containment policy](https://falcon.crowdstrike.com/support/documentation/11/getting-started-guide#containmentpolicy) - `lift_containment`: This action lifts containment on the host, which returns its network communications to normal - `hide_host`: This action will delete a host. After the host is deleted, no new detections for that host will be reported via UI or APIs - `unhide_host`: This action will restore a host. Detection reporting will resume after the host is restored. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

There is no context output for this command.
### cs-perform-device-control-policies-action

***
Perform the specified action on the Device Control Policies specified in the request.

#### Base Command

`cs-perform-device-control-policies-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-host-group, disable, enable, remove-host-group. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-perform-firewall-policies-action

***
Perform the specified action on the Firewall Policies specified in the request.

#### Base Command

`cs-perform-firewall-policies-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-host-group, disable, enable, remove-host-group. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
### cs-perform-group-action

***
Perform the specified action on the Host Groups specified in the request.

#### Base Command

`cs-perform-group-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-hosts, remove-hosts. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
### cs-perform-incident-action

***
Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description.

#### Base Command

`cs-perform-incident-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-perform-prevention-policies-action

***
Perform the specified action on the Prevention Policies specified in the request.

#### Base Command

`cs-perform-prevention-policies-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-host-group, add-rule-group, disable, enable, remove-host-group, remove-rule-group. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-perform-sensor-update-policies-action

***
Perform the specified action on the Sensor Update Policies specified in the request.

#### Base Command

`cs-perform-sensor-update-policies-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-host-group, disable, enable, remove-host-group. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-performrt-response-policies-action

***
Perform the specified action on the Response Policies specified in the request.

#### Base Command

`cs-performrt-response-policies-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | The action to perform. Possible values are: add-host-group, add-rule-group, disable, enable, remove-host-group, remove-rule-group. | Required | 
| msa_entityactionrequestv2_action__meters |  | Optional | 
| msa_entityactionrequestv2_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-post-cloudconnectazure-entities-account-v1

***
Creates a new account in our system for a customer and generates a script for them to run in their cloud environment to grant us access.

#### Base Command

`cs-post-cloudconnectazure-entities-account-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_azureaccountcreaterequestexternalv1_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-post-cloudconnectcspmazure-entities-account-v1

***
Creates a new account in our system for a customer and generates a script for them to run in their cloud environment to grant us access.

#### Base Command

`cs-post-cloudconnectcspmazure-entities-account-v1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_azureaccountcreaterequestexternalv1_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-post-mal-query-entities-samples-multidownloadv1

***
Schedule samples for download. Use the result id with the /request endpoint to check if the download is ready after which you can call the /entities/samples-fetch to get the zip.

#### Base Command

`cs-post-mal-query-entities-samples-multidownloadv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malquery_multidownloadrequestv1_samples | List of sample sha256 ids. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
### cs-post-mal-query-exact-searchv1

***
Search Falcon MalQuery for a combination of hex patterns and strings in order to identify samples based upon file content at byte level granularity. You can filter results on criteria such as file type, file size and first seen date. Returns a request id which can be used with the /request endpoint.

#### Base Command

`cs-post-mal-query-exact-searchv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malquery_externalexactsearchparametersv1_options_filter_filetypes | malquery_externalexactsearchparametersv1_options filter_filetypes. | Optional | 
| malquery_externalexactsearchparametersv1_options_filter_meta | malquery_externalexactsearchparametersv1_options filter_meta. | Optional | 
| malquery_externalexactsearchparametersv1_options_limit | malquery_externalexactsearchparametersv1_options limit. | Optional | 
| malquery_externalexactsearchparametersv1_options_max_date | malquery_externalexactsearchparametersv1_options max_date. | Optional | 
| malquery_externalexactsearchparametersv1_options_max_size | malquery_externalexactsearchparametersv1_options max_size. | Optional | 
| malquery_externalexactsearchparametersv1_options_min_date | malquery_externalexactsearchparametersv1_options min_date. | Optional | 
| malquery_externalexactsearchparametersv1_options_min_size | malquery_externalexactsearchparametersv1_options min_size. | Optional | 
| malquery_externalexactsearchparametersv1_patterns | Patterns to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
### cs-post-mal-query-fuzzy-searchv1

***
Search Falcon MalQuery quickly, but with more potential for false positives. Search for a combination of hex patterns and strings in order to identify samples based upon file content at byte level granularity.

#### Base Command

`cs-post-mal-query-fuzzy-searchv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malquery_fuzzysearchparametersv1_options_filter_meta | malquery_fuzzysearchparametersv1_options filter_meta. | Optional | 
| malquery_fuzzysearchparametersv1_options_limit | malquery_fuzzysearchparametersv1_options limit. | Optional | 
| malquery_fuzzysearchparametersv1_patterns |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryFuzzySearchResponse.errors.code | Number |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.id | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.message | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.type | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.code | Number |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.id | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.message | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.errors.type | String |  | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryFuzzySearchResponse.resources.sha256 | String | Sample SHA256. | 
### cs-post-mal-query-huntv1

***
Schedule a YARA-based search for execution. Returns a request id which can be used with the /request endpoint.

#### Base Command

`cs-post-mal-query-huntv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malquery_externalhuntparametersv1_options_filter_filetypes | malquery_externalhuntparametersv1_options filter_filetypes. | Optional | 
| malquery_externalhuntparametersv1_options_filter_meta | malquery_externalhuntparametersv1_options filter_meta. | Optional | 
| malquery_externalhuntparametersv1_options_limit | malquery_externalhuntparametersv1_options limit. | Optional | 
| malquery_externalhuntparametersv1_options_max_date | malquery_externalhuntparametersv1_options max_date. | Optional | 
| malquery_externalhuntparametersv1_options_max_size | malquery_externalhuntparametersv1_options max_size. | Optional | 
| malquery_externalhuntparametersv1_options_min_date | malquery_externalhuntparametersv1_options min_date. | Optional | 
| malquery_externalhuntparametersv1_options_min_size | malquery_externalhuntparametersv1_options min_size. | Optional | 
| malquery_externalhuntparametersv1_yara_rule | A YARA rule that defines your search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
| CrowdStrike.malqueryExternalQueryResponse.errors.code | Number |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.id | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.message | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.errors.type | String |  | 
| CrowdStrike.malqueryExternalQueryResponse.resources.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.ignore_reason | String | Reason why the resource is ignored. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.label_confidence | String | Resource label confidence. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern | String | Search pattern. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.pattern_type | String | Search pattern type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.family | String | Sample family. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filesize | Number | Sample size. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.filetype | String | Sample file type. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.first_seen | String | Date when it was first seen. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.label | String | Sample label. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.md5 | String | Sample MD5. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.samples.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha1 | String | Sample SHA1. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.sha256 | String | Sample SHA256. | 
| CrowdStrike.malqueryExternalQueryResponse.resources.yara_rule | String | Search YARA rule. | 
### cs-preview-rulev1

***
Preview rules notification count and distribution. This will return aggregations on: channel, count, site.

#### Base Command

`cs-preview-rulev1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| domain_rulepreviewrequest_filter |  | Required | 
| domain_rulepreviewrequest_topic |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.field | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.id | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.name | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.sum_other_doc_count | Number |  | 
| CrowdStrike.domainAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.field | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.id | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message | String |  | 
| CrowdStrike.domainAggregatesResponse.errors.message_key | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.domainAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.name | String |  | 
| CrowdStrike.domainAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-processes-ran-on

***
Search for processes associated with a custom IOC.

#### Base Command

`cs-processes-ran-on`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type_ |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Required | 
| value | The string representation of the indicator. | Required | 
| device_id | Specify a host's ID to return only processes from that host. Get a host's ID from GET /devices/queries/devices/v1, the Falcon console, or the Streaming API. | Required | 
| limit | The first process to return, where 0 is the latest offset. Use with the offset  meter to manage pagination of results. | Optional | 
| offset | The first process to return, where 0 is the latest offset. Use with the limit  meter to manage pagination of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.id | String |  | 
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.message | String |  | 
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.id | String |  | 
| CrowdStrike.apiMsaReplyProcessesRanOn.errors.message | String |  | 
### cs-provisionaws-accounts

***
Provision AWS Accounts by specifying details about the accounts to provision.

#### Base Command

`cs-provisionaws-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mode | Mode for provisioning. Allowed values are `manual` or `cloudformation`. Defaults to manual if not defined. Possible values are: cloudformation, manual. | Optional | 
| models_createawsaccountsv1_resources |  | Required | 

#### Context Output

There is no context output for this command.
### cs-query-actionsv1

***
Query actions based on provided criteria. Use the IDs from this response to get the action entities on GET /entities/actions/v1.

#### Base Command

`cs-query-actionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 
| sort | Possible order by fields: created_timestamp, updated_timestamp. Ex: 'updated_timestamp\|desc'. | Optional | 
| filter_ | FQL query to filter actions by. Possible filter properties are: [id cid user_uuid rule_id type frequency recipients status created_timestamp updated_timestamp]. | Optional | 
| q | Free text search across all indexed fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainQueryResponse.errors.code | Number |  | 
| CrowdStrike.domainQueryResponse.errors.details.field | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.id | String |  | 
| CrowdStrike.domainQueryResponse.errors.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.code | Number |  | 
| CrowdStrike.domainQueryResponse.errors.details.field | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.id | String |  | 
| CrowdStrike.domainQueryResponse.errors.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.message_key | String |  | 
### cs-query-allow-list-filter

***
Retrieve allowlist tickets that match the provided filter criteria with scrolling enabled.

#### Base Command

`cs-query-allow-list-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-behaviors

***
Search for behaviors by providing an FQL filter, sorting, and paging details.

#### Base Command

`cs-query-behaviors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". Possible values are: timestamp.asc, timestamp.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-block-list-filter

***
Retrieve block listtickets that match the provided filter criteria with scrolling enabled.

#### Base Command

`cs-query-block-list-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-children

***
Query for customers linked as children.

#### Base Command

`cs-query-children`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-combined-device-control-policies

***
Search for Device Control Policies in your environment by providing an FQL filter and paging details. Returns a set of Device Control Policies which match the filter criteria.

#### Base Command

`cs-query-combined-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-query-combined-device-control-policy-members

***
Search for members of a Device Control Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combined-device-control-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Device Control Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
### cs-query-combined-firewall-policies

***
Search for Firewall Policies in your environment by providing an FQL filter and paging details. Returns a set of Firewall Policies which match the filter criteria.

#### Base Command

`cs-query-combined-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
### cs-query-combined-firewall-policy-members

***
Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combined-firewall-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Firewall Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
### cs-query-combined-group-members

***
Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combined-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Host Group to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesHostGroupMembersV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupMembersV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.bios_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.build_number | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.cid | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.device_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.email | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.external_ip | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_seen | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.group_hash | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.hostname | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.instance_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_seen | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.local_ip | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.mac_address | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.major_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.minor_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.os_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.platform_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.platform_name | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.product_type | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.provision_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.release_group | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_provider | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.site_name | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupMembersV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.agent_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.bios_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.build_number | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.cid | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.device_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.email | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.external_ip | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.first_seen | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.group_hash | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.hostname | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.instance_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.last_seen | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.local_ip | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.mac_address | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.major_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.minor_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.os_version | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.platform_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.platform_name | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.product_type | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.provision_status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.release_group | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_provider | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.site_name | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.status | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesHostGroupMembersV1.resources.system_product_name | String |  | 
### cs-query-combined-host-groups

***
Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of Host Groups which match the filter criteria.

#### Base Command

`cs-query-combined-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, group_type.asc, group_type.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
### cs-query-combined-prevention-policies

***
Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a set of Prevention Policies which match the filter criteria.

#### Base Command

`cs-query-combined-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-query-combined-prevention-policy-members

***
Search for members of a Prevention Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combined-prevention-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Prevention Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
### cs-query-combined-sensor-update-builds

***
Retrieve available builds for use with Sensor Update Policies.

#### Base Command

`cs-query-combined-sensor-update-builds`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| platform | The platform to return builds for. Possible values are: linux, mac, windows. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.resources.build | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.resources.platform | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.resources.build | String |  | 
| CrowdStrike.responsesSensorUpdateBuildsV1.resources.platform | String |  | 
### cs-query-combined-sensor-update-policies

***
Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter criteria.

#### Base Command

`cs-query-combined-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-query-combined-sensor-update-policiesv2

***
Search for Sensor Update Policies with additional support for uninstall protection in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter criteria.

#### Base Command

`cs-query-combined-sensor-update-policiesv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
### cs-query-combined-sensor-update-policy-members

***
Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combined-sensor-update-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Sensor Update Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
### cs-query-combinedrt-response-policies

***
Search for Response Policies in your environment by providing an FQL filter and paging details. Returns a set of Response Policies which match the filter criteria.

#### Base Command

`cs-query-combinedrt-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-query-combinedrt-response-policy-members

***
Search for members of a Response policy in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria.

#### Base Command

`cs-query-combinedrt-response-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Response policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.code | Number |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.errors.message | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_load_flags | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_local_time | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.agent_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.bios_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.build_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cid | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_base | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_build | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.config_id_platform | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.cpu_signature | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.detection_suppression_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.device_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.email | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.external_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.first_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.group_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.host_hidden_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.instance_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_login_user | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.last_seen | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.local_ip | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.mac_address | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.machine_domain | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.major_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.minor_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.os_version | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.platform_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_host_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_hostname | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip4 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_ip6 | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_namespace | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pod_service_account_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.pointer_size | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied | Boolean |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.applied_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.assigned_date | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.policy_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.rule_set_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.settings_hash | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.policies.uninstall_protection | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.product_type_desc | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.provision_status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.reduced_functionality_mode | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.release_group | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.serial_number | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_major | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_pack_minor | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.service_provider_account_id | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.site_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.slow_changing_modified_timestamp | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.status | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_manufacturer | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.system_product_name | String |  | 
| CrowdStrike.responsesPolicyMembersRespV1.resources.zone_group | String |  | 
### cs-query-detection-ids-by-filter

***
Retrieve DetectionsIds that match the provided FQL filter, criteria with scrolling enabled.

#### Base Command

`cs-query-detection-ids-by-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-detects

***
Search for detection IDs that match a given query.

#### Base Command

`cs-query-detects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The first detection to return, where `0` is the latest detection. Use with the `limit`  meter to manage pagination of results. | Optional | 
| limit | The maximum number of detections to return in this response (default: 9999; max: 9999). Use with the `offset`  meter to manage pagination of results. | Optional | 
| sort | Sort detections using these options:  - `first_behavior`: Timestamp of the first behavior associated with this detection - `last_behavior`: Timestamp of the last behavior associated with this detection - `max_severity`: Highest severity of the behaviors associated with this detection - `max_confidence`: Highest confidence of the behaviors associated with this detection - `adversary_id`: ID of the adversary associated with this detection, if any - `devices.hostname`: Hostname of the host where this detection was detected  Sort either `asc` (ascending) or `desc` (descending). For example: `last_behavior\|asc`. | Optional | 
| filter_ | Filter detections using a query in Falcon Query Language (FQL) An asterisk wildcard ` ` includes all results.   Common filter options include:  - `status` - `device.device_id` - `max_severity`  The full list of valid filter options is extensive. Review it in our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detections_fql). | Optional | 
| q | Search all detection metadata for the provided string. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-device-control-policies

***
Search for Device Control Policies in your environment by providing an FQL filter and paging details. Returns a set of Device Control Policy IDs which match the filter criteria.

#### Base Command

`cs-query-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-device-control-policy-members

***
Search for members of a Device Control Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-query-device-control-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Device Control Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-devices-by-filter

***
Search for hosts in your environment by platform, hostname, IP, and other criteria.

#### Base Command

`cs-query-devices-by-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by (e.g. status.desc or hostname.asc). | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-devices-by-filter-scroll

***
Search for hosts in your environment by platform, hostname, IP, and other criteria with continuous pagination capability (based on offset pointer which expires after 2 minutes with no maximum limit).

#### Base Command

`cs-query-devices-by-filter-scroll`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset to page from, for the next result set. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by (e.g. status.desc or hostname.asc). | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainDeviceResponse.errors.code | Number |  | 
| CrowdStrike.domainDeviceResponse.errors.id | String |  | 
| CrowdStrike.domainDeviceResponse.errors.message | String |  | 
| CrowdStrike.domainDeviceResponse.errors.code | Number |  | 
| CrowdStrike.domainDeviceResponse.errors.id | String |  | 
| CrowdStrike.domainDeviceResponse.errors.message | String |  | 
### cs-query-escalations-filter

***
Retrieve escalation tickets that match the provided filter criteria with scrolling enabled.

#### Base Command

`cs-query-escalations-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-firewall-policies

***
Search for Firewall Policies in your environment by providing an FQL filter and paging details. Returns a set of Firewall Policy IDs which match the filter criteria.

#### Base Command

`cs-query-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-firewall-policy-members

***
Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-query-firewall-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Firewall Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-group-members

***
Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-query-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Host Group to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-hidden-devices

***
Retrieve hidden hosts that match the provided filter criteria.

#### Base Command

`cs-query-hidden-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by (e.g. status.desc or hostname.asc). | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-host-groups

***
Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of Host Group IDs which match the filter criteria.

#### Base Command

`cs-query-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, group_type.asc, group_type.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-incident-ids-by-filter

***
Retrieve incidents that match the provided filter criteria with scrolling enabled.

#### Base Command

`cs-query-incident-ids-by-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-incidents

***
Search for incidents by providing an FQL filter, sorting, and paging details.

#### Base Command

`cs-query-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". Possible values are: assigned_to.asc, assigned_to.desc, assigned_to_name.asc, assigned_to_name.desc, end.asc, end.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, sort_score.asc, sort_score.desc, start.asc, start.desc, state.asc, state.desc, status.asc, status.desc. | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaIncidentQueryResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaIncidentQueryResponse.errors.id | String |  | 
| CrowdStrike.apiMsaIncidentQueryResponse.errors.message | String |  | 
| CrowdStrike.apiMsaIncidentQueryResponse.errors.code | Number |  | 
| CrowdStrike.apiMsaIncidentQueryResponse.errors.id | String |  | 
| CrowdStrike.apiMsaIncidentQueryResponse.errors.message | String |  | 
### cs-query-intel-actor-entities

***
Get info about actors that match provided FQL filters.

#### Base Command

`cs-query-intel-actor-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return actors from. Defaults to 0. | Optional | 
| limit | Set the number of actors to return. The value must be between 1 and 5000. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: created_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  actors, actors.id, actors.name, actors.slug, actors.url, created_date, description, id, last_modified_date, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, tags, tags.id, tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, type.name, type.slug, url. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 
| fields | The fields to return, or a predefined set of fields in the form of the collection name surrounded by two underscores like:  \_\_\ collection\ \_\_.  Ex: slug \_\_full\_\_.  Defaults to \_\_basic\_\_. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainActorsResponse.errors.code | Number |  | 
| CrowdStrike.domainActorsResponse.errors.id | String |  | 
| CrowdStrike.domainActorsResponse.errors.message | String |  | 
| CrowdStrike.domainActorsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.actor_type | String |  | 
| CrowdStrike.domainActorsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.description | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.first_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.known_as | String |  | 
| CrowdStrike.domainActorsResponse.resources.last_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.origins.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.origins.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.short_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.url | String |  | 
| CrowdStrike.domainActorsResponse.errors.code | Number |  | 
| CrowdStrike.domainActorsResponse.errors.id | String |  | 
| CrowdStrike.domainActorsResponse.errors.message | String |  | 
| CrowdStrike.domainActorsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.actor_type | String |  | 
| CrowdStrike.domainActorsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.description | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.first_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.known_as | String |  | 
| CrowdStrike.domainActorsResponse.resources.last_activity_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainActorsResponse.resources.origins.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.origins.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.origins.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.short_description | String |  | 
| CrowdStrike.domainActorsResponse.resources.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainActorsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainActorsResponse.resources.url | String |  | 
### cs-query-intel-actor-ids

***
Get actor IDs that match provided FQL filters.

#### Base Command

`cs-query-intel-actor-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return actors IDs from. Defaults to 0. | Optional | 
| limit | Set the number of actor IDs to return. The value must be between 1 and 5000. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: created_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  actors, actors.id, actors.name, actors.slug, actors.url, created_date, description, id, last_modified_date, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, tags, tags.id, tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, type.name, type.slug, url. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-intel-indicator-entities

***
Get info about indicators that match provided FQL filters.

#### Base Command

`cs-query-intel-indicator-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return indicators from. Defaults to 0. | Optional | 
| limit | Set the number of indicators to return. The number must be between 1 and 50000. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: published_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  _marker, actors, deleted, domain_types, id, indicator, ip_address_types, kill_chains, labels, labels.created_on, labels.last_valid_on, labels.name, last_updated, malicious_confidence, malware_families, published_date, reports, targets, threat_types, type, vulnerabilities. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 
| include_deleted | If true, include both published and deleted indicators in the response. Defaults to false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainPublicIndicatorsV3Response.errors.code | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.message | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources._marker | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.deleted | Boolean |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.created_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.last_valid_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.name | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.last_updated | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.malicious_confidence | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.published_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.created_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.last_valid_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.type | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.type | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.code | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.errors.message | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources._marker | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.deleted | Boolean |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.created_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.last_valid_on | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.labels.name | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.last_updated | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.malicious_confidence | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.published_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.created_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.id | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.indicator | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.last_valid_date | Number |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.relations.type | String |  | 
| CrowdStrike.domainPublicIndicatorsV3Response.resources.type | String |  | 
### cs-query-intel-indicator-ids

***
Get indicators IDs that match provided FQL filters.

#### Base Command

`cs-query-intel-indicator-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return indicator IDs from. Defaults to 0. | Optional | 
| limit | Set the number of indicator IDs to return. The number must be between 1 and 50000. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: published_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  _marker, actors, deleted, domain_types, id, indicator, ip_address_types, kill_chains, labels, labels.created_on, labels.last_valid_on, labels.name, last_updated, malicious_confidence, malware_families, published_date, reports, targets, threat_types, type, vulnerabilities. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 
| include_deleted | If true, include both published and deleted indicators in the response. Defaults to false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-intel-report-entities

***
Get info about reports that match provided FQL filters.

#### Base Command

`cs-query-intel-report-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return reports from. Defaults to 0. | Optional | 
| limit | Set the number of reports to return. The value must be between 1 and 5000. | Optional | 
| sort | Order fields in ascending or descending order. Ex: created_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  actors, actors.id, actors.name, actors.slug, actors.url, created_date, description, id, last_modified_date, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, tags, tags.id, tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, type.name, type.slug, url. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 
| fields | The fields to return, or a predefined set of fields in the form of the collection name surrounded by two underscores like:  \_\_\ collection\ \_\_.  Ex: slug \_\_full\_\_.  Defaults to \_\_basic\_\_. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNewsResponse.errors.code | Number |  | 
| CrowdStrike.domainNewsResponse.errors.id | String |  | 
| CrowdStrike.domainNewsResponse.errors.message | String |  | 
| CrowdStrike.domainNewsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.actors.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.actors.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.description | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.short_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.tags.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.url | String |  | 
| CrowdStrike.domainNewsResponse.errors.code | Number |  | 
| CrowdStrike.domainNewsResponse.errors.id | String |  | 
| CrowdStrike.domainNewsResponse.errors.message | String |  | 
| CrowdStrike.domainNewsResponse.resources.active | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.actors.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.actors.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.actors.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.attachments.url | String |  | 
| CrowdStrike.domainNewsResponse.resources.created_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.description | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.entitlements.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.last_modified_date | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.motivations.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.notify_users | Boolean |  | 
| CrowdStrike.domainNewsResponse.resources.rich_text_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.short_description | String |  | 
| CrowdStrike.domainNewsResponse.resources.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.tags.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.tags.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_countries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.id | Number |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.name | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.slug | String |  | 
| CrowdStrike.domainNewsResponse.resources.target_industries.value | String |  | 
| CrowdStrike.domainNewsResponse.resources.url | String |  | 
### cs-query-intel-report-ids

***
Get report IDs that match provided FQL filters.

#### Base Command

`cs-query-intel-report-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return report IDs from. Defaults to 0. | Optional | 
| limit | Set the number of report IDs to return. The value must be between 1 and 5000. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: created_date\|asc. | Optional | 
| filter_ | Filter your query by specifying FQL filter  meters. Filter  meters include:  actors, actors.id, actors.name, actors.slug, actors.url, created_date, description, id, last_modified_date, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, tags, tags.id, tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, type.name, type.slug, url. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-intel-rule-ids

***
Search for rule IDs that match provided filter criteria.

#### Base Command

`cs-query-intel-rule-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Set the starting row number to return reports from. Defaults to 0. | Optional | 
| limit | The number of rule IDs to return. Defaults to 10. | Optional | 
| sort | Order fields in ascending or descending order.  Ex: created_date\|asc. | Optional | 
| name | Search by rule title. | Optional | 
| type_ | The rule news report type. Accepted values:  snort-suricata-master  snort-suricata-update  snort-suricata-changelog  yara-master  yara-update  yara-changelog  common-event-format  netwitness. | Required | 
| description | Substring match on description field. | Optional | 
| tags | Search for rule tags. | Optional | 
| min_created_date | Filter results to those created on or after a certain date. | Optional | 
| max_created_date | Filter results to those created on or before a certain date. | Optional | 
| q | Perform a generic substring search across all fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-notificationsv1

***
Query notifications based on provided criteria. Use the IDs from this response to get the notification entities on GET /entities/notifications/v1 or GET /entities/notifications-detailed/v1.

#### Base Command

`cs-query-notificationsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 
| sort | Possible order by fields: created_date, updated_date. Ex: 'updated_date\|desc'. | Optional | 
| filter_ | FQL query to filter notifications by. Possible filter properties are: [id cid user_uuid status rule_id rule_name rule_topic rule_priority item_type created_date updated_date]. | Optional | 
| q | Free text search across all indexed fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainQueryResponse.errors.code | Number |  | 
| CrowdStrike.domainQueryResponse.errors.details.field | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.id | String |  | 
| CrowdStrike.domainQueryResponse.errors.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.code | Number |  | 
| CrowdStrike.domainQueryResponse.errors.details.field | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.details.message_key | String |  | 
| CrowdStrike.domainQueryResponse.errors.id | String |  | 
| CrowdStrike.domainQueryResponse.errors.message | String |  | 
| CrowdStrike.domainQueryResponse.errors.message_key | String |  | 
### cs-query-prevention-policies

***
Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a set of Prevention Policy IDs which match the filter criteria.

#### Base Command

`cs-query-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-prevention-policy-members

***
Search for members of a Prevention Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-query-prevention-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Prevention Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-remediations-filter

***
Retrieve remediation tickets that match the provided filter criteria with scrolling enabled.

#### Base Command

`cs-query-remediations-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc". | Optional | 
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-reports

***
Find sandbox reports by providing an FQL filter and paging details. Returns a set of report IDs that match your criteria.

#### Base Command

`cs-query-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | The offset to start retrieving reports from. | Optional | 
| limit | Maximum number of report IDs to return. Max: 5000. | Optional | 
| sort | Sort order: `asc` or `desc`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-roles

***
Query MSSP Role assignment. At least one of CID Group ID or User Group ID should also be provided. Role ID is optional.

#### Base Command

`cs-query-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_group_id | User Group ID to fetch MSSP role for. | Optional | 
| cid_group_id | CID Group ID to fetch MSSP role for. | Optional | 
| role_id | Role ID to fetch MSSP role for. | Optional | 
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-rulesv1

***
Query monitoring rules based on provided criteria. Use the IDs from this response to fetch the rules on /entities/rules/v1.

#### Base Command

`cs-query-rulesv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 
| sort | Possible order by fields: created_timestamp, last_updated_timestamp. Ex: 'last_updated_timestamp\|desc'. | Optional | 
| filter_ | FQL query to filter rules by. Possible filter properties are: [id cid user_uuid topic priority permissions filter status created_timestamp last_updated_timestamp]. | Optional | 
| q | Free text search across all indexed fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRuleQueryResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.id | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.id | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message | String |  | 
| CrowdStrike.domainRuleQueryResponseV1.errors.message_key | String |  | 
### cs-query-samplev1

***
Retrieves a list with sha256 of samples that exist and customer has rights to access them, maximum number of accepted items is 200.

#### Base Command

`cs-query-samplev1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| samplestore_querysamplesrequest_sha256s |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-sensor-update-policies

***
Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policy IDs which match the filter criteria.

#### Base Command

`cs-query-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-sensor-update-policy-members

***
Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-query-sensor-update-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Sensor Update Policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-sensor-visibility-exclusionsv1

***
Search for sensor visibility exclusions.

#### Base Command

`cs-query-sensor-visibility-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The sort expression that should be used to sort the results. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, value.asc, value.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-submissions

***
Find submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of submission IDs that match your criteria.

#### Base Command

`cs-query-submissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | The offset to start retrieving submissions from. | Optional | 
| limit | Maximum number of submission IDs to return. Max: 5000. | Optional | 
| sort | Sort order: `asc` or `desc`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-submissions-mixin0

***
Find IDs for submitted scans by providing an FQL filter and paging details. Returns a set of volume IDs that match your criteria.

#### Base Command

`cs-query-submissions-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | The offset to start retrieving submissions from. | Optional | 
| limit | Maximum number of volume IDs to return. Max: 5000. | Optional | 
| sort | Sort order: `asc` or `desc`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.mlscannerQueryResponse.errors.code | Number |  | 
| CrowdStrike.mlscannerQueryResponse.errors.id | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.message | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.code | Number |  | 
| CrowdStrike.mlscannerQueryResponse.errors.id | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.message | String |  | 
### cs-query-user-group-members

***
Query User Group member by User UUID.

#### Base Command

`cs-query-user-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | User UUID to lookup associated user group ID. | Required | 
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-user-groups

***
Query User Groups.

#### Base Command

`cs-query-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name to lookup groups for. | Optional | 
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp, name. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-query-vulnerabilities

***
Search for Vulnerabilities in your environment by providing an FQL filter and paging details. Returns a set of Vulnerability IDs which match the filter criteria.

#### Base Command

`cs-query-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| after | A pagination token used with the `limit`  meter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results. | Optional | 
| limit | The number of items to return in this response (default: 100, max: 400). Use with the after  meter to manage pagination of results. | Optional | 
| sort | Sort vulnerabilities by their properties. Common sort options include:   ul  li created_timestamp\|desc /li  li closed_timestamp\|asc /li  /ul. | Optional | 
| filter_ | Filter items using a query in Falcon Query Language (FQL). Wildcards   are unsupported.   Common filter options include:   ul  li created_timestamp: '2019-11-25T22:36:12Z' /li  li closed_timestamp: '2019-11-25T22:36:12Z' /li  li aid:'8e7656b27d8c49a34a1af416424d6231' /li  /ul. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.code | Number |  | 
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.id | String |  | 
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.message | String |  | 
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.code | Number |  | 
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.id | String |  | 
| CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse.errors.message | String |  | 
### cs-queryaws-accounts

***
Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS accounts which match the filter criteria.

#### Base Command

`cs-queryaws-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. Defaults to 100. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| sort | The property to sort by (e.g. alias.desc or state.asc). | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
### cs-queryaws-accounts-fori-ds

***
Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS account IDs which match the filter criteria.

#### Base Command

`cs-queryaws-accounts-fori-ds`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum records to return. [1-500]. Defaults to 100. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| sort | The property to sort by (e.g. alias.desc or state.asc). | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-querycid-group-members

***
Query a CID Groups members by associated CID.

#### Base Command

`cs-querycid-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | CID to lookup associated CID group ID. | Required | 
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp. | Optional | 
| offset | Starting index of overall result set from which to return id. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-querycid-groups

***
Query CID Groups.

#### Base Command

`cs-querycid-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name to lookup groups for. | Optional | 
| sort | The sort expression used to sort the results. Possible values are: last_modified_timestamp, name. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryevents

***
Find all event IDs matching the query with filter.

#### Base Command

`cs-queryevents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields:. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: enabled, platform, name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields, plus TODO. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| after | A pagination token used with the `limit`  meter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-queryfirewallfields

***
Get the firewall field specification IDs for the provided platform.

#### Base Command

`cs-queryfirewallfields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| platform_id | Get fields configuration for this platform. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrmsaQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.message | String |  | 
### cs-queryio-cs

***
    DEPRECATED     Use the new IOC Management endpoint (GET /iocs/queries/indicators/v1).     Search the custom IOCs in your customer account.

#### Base Command

`cs-queryio-cs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| types |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Optional | 
| values | The string representation of the indicator. | Optional | 
| from_expiration_timestamp | Find custom IOCs created after this time (RFC-3339 timestamp). | Optional | 
| to_expiration_timestamp | Find custom IOCs created before this time (RFC-3339 timestamp). | Optional | 
| policies | \ndetect: Find custom IOCs that produce notifications\n\nnone: Find custom IOCs the particular indicator has been detected on a host. This is equivalent to turning the indicator off. . | Optional | 
| sources | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limit 200 characters. | Optional | 
| share_levels | The level at which the indicator will be shared. Currently only red share level (not shared) is supported, indicating that the IOC isn't shared with other FH customers. | Optional | 
| created_by | created_by. | Optional | 
| deleted_by | The user or API client who deleted the custom IOC. | Optional | 
| include_deleted | true: Include deleted IOCs  false: Don't include deleted IOCs (default). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyIOCIDs.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOCIDs.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOCIDs.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOCIDs.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOCIDs.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOCIDs.errors.message | String |  | 
### cs-queryioa-exclusionsv1

***
Search for IOA exclusions.

#### Base Command

`cs-queryioa-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The sort expression that should be used to sort the results. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, name.asc, name.desc, pattern_id.asc, pattern_id.desc, pattern_name.asc, pattern_name.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryml-exclusionsv1

***
Search for ML exclusions.

#### Base Command

`cs-queryml-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-500]. | Optional | 
| sort | The sort expression that should be used to sort the results. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, value.asc, value.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-querypatterns

***
Get all pattern severity IDs.

#### Base Command

`cs-querypatterns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryplatforms

***
Get the list of platform names.

#### Base Command

`cs-queryplatforms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrmsaQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrmsaQueryResponse.errors.message | String |  | 
### cs-queryplatforms-mixin0

***
Get all platform IDs.

#### Base Command

`cs-queryplatforms-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-querypolicyrules

***
Find all firewall rule IDs matching the query with filter, and return them in precedence order.

#### Base Command

`cs-querypolicyrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the policy container within which to query. | Optional | 
| sort | Possible order by fields:. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: enabled, platform, name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields, plus TODO. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-queryrt-response-policies

***
Search for Response Policies in your environment by providing an FQL filter with sort and/or paging details. This returns a set of Response Policy IDs that match the given criteria.

#### Base Command

`cs-queryrt-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | The filter expression that should be used to determine the results. | Optional | 
| offset | The offset of the first record to retrieve from. | Optional | 
| limit | The maximum number of records to return [1-5000]. | Optional | 
| sort | The property to sort results by. Possible values are: created_by.asc, created_by.desc, created_timestamp.asc, created_timestamp.desc, enabled.asc, enabled.desc, modified_by.asc, modified_by.desc, modified_timestamp.asc, modified_timestamp.desc, name.asc, name.desc, platform_name.asc, platform_name.desc, precedence.asc, precedence.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryrt-response-policy-members

***
Search for members of a Response policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria.

#### Base Command

`cs-queryrt-response-policy-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The ID of the Response policy to search for members of. | Optional | 
| filter_ | The filter expression that should be used to limit the results. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-5000]. | Optional | 
| sort | The property to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryrulegroups

***
Find all rule group IDs matching the query with filter.

#### Base Command

`cs-queryrulegroups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields:. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: enabled, platform, name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields, plus TODO. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| after | A pagination token used with the `limit`  meter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-queryrulegroups-mixin0

***
Finds all rule group IDs matching the query with optional filter.

#### Base Command

`cs-queryrulegroups-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields: {created_by, created_on, modified_by, modified_on, enabled, name, description}. Possible values are: created_by, created_on, description, enabled, modified_by, modified_on, name. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: [enabled platform name description rules.action_label rules.name rules.description rules.pattern_severity rules.ruletype_name rules.enabled]. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryrulegroupsfull

***
Find all rule groups matching the query with optional filter.

#### Base Command

`cs-queryrulegroupsfull`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields: {created_by, created_on, modified_by, modified_on, enabled, name, description}. Possible values are: created_by, created_on, description, enabled, modified_by, modified_on, name. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: [enabled platform name description rules.action_label rules.name rules.description rules.pattern_severity rules.ruletype_name rules.enabled]. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryrules

***
Find all rule IDs matching the query with filter.

#### Base Command

`cs-queryrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields:. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: enabled, platform, name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields, plus TODO. | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| after | A pagination token used with the `limit`  meter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results. | Optional | 
| limit | Number of ids to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-queryrules-mixin0

***
Finds all rule IDs matching the query with optional filter.

#### Base Command

`cs-queryrules-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Possible order by fields: {rules.ruletype_name, rules.enabled, rules.created_by, rules.current_version.name, rules.current_version.modified_by, rules.created_on, rules.current_version.description, rules.current_version.pattern_severity, rules.current_version.action_label, rules.current_version.modified_on}. Possible values are: rules.created_by, rules.created_on, rules.current_version.action_label, rules.current_version.description, rules.current_version.modified_by, rules.current_version.modified_on, rules.current_version.name, rules.current_version.pattern_severity, rules.enabled, rules.ruletype_name. | Optional | 
| filter_ | FQL query specifying the filter  meters. Filter term criteria: [enabled platform name description rules.action_label rules.name rules.description rules.pattern_severity rules.ruletype_name rules.enabled]. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'. | Optional | 
| q | Match query criteria, which includes all the filter string fields. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-queryruletypes

***
Get all rule type IDs.

#### Base Command

`cs-queryruletypes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Number of IDs to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-refresh-active-stream-session

***
Refresh an active event stream. Use the URL shown in a GET /sensors/entities/datafeed/v2 response.

#### Base Command

`cs-refresh-active-stream-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_name | Action name. Allowed value is refresh_active_stream_session. | Required | 
| appId | Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9). | Required | 
| partition | Partition to request data for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-regenerateapi-key

***
Regenerate API key for docker registry integrations.

#### Base Command

`cs-regenerateapi-key`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.k8sregRegenAPIKeyResp.errors.code | Number |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.errors.id | String |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.errors.message | String |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.resources.api_key | String |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.errors.code | Number |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.errors.id | String |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.errors.message | String |  | 
| CrowdStrike.k8sregRegenAPIKeyResp.resources.api_key | String |  | 
### cs-retrieve-emails-bycid

***
List the usernames (usually an email address) for all users in your customer account.

#### Base Command

`cs-retrieve-emails-bycid`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-retrieve-user

***
Get info about a user.

#### Base Command

`cs-retrieve-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserMetaDataResponse.errors.code | Number |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.id | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.message | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.customer | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.firstName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.lastName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uuid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.code | Number |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.id | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.message | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.customer | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.firstName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.lastName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uuid | String |  | 
### cs-retrieve-useruui-ds-bycid

***
List user IDs for all users in your customer account. For more information on each user, provide the user ID to `/users/entities/user/v1`.

#### Base Command

`cs-retrieve-useruui-ds-bycid`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-retrieve-useruuid

***
Get a user's ID by providing a username (usually an email address).

#### Base Command

`cs-retrieve-useruuid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uid | A username. This is usually the user's email address, but may vary based on your configuration. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-reveal-uninstall-token

***
Reveals an uninstall token for a specific device. To retrieve the bulk maintenance token pass the value 'MAINTENANCE' as the value for 'device_id'.

#### Base Command

`cs-reveal-uninstall-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_revealuninstalltokenv1_audit_message | An optional message to append to the recorded audit log. | Optional | 
| requests_revealuninstalltokenv1_device_id | The id of the device to reveal the token for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.code | Number |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.id | String |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.message | String |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.device_id | String | The device the token belongs to. | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.seed_id | Number | The seedID of the uninstall token. | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.uninstall_token | String | The uninstall token. | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.code | Number |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.id | String |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.errors.message | String |  | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.device_id | String | The device the token belongs to. | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.seed_id | Number | The seedID of the uninstall token. | 
| CrowdStrike.responsesRevealUninstallTokenRespV1.resources.uninstall_token | String | The uninstall token. | 
### cs-revoke-user-role-ids

***
Revoke one or more roles from a user.

#### Base Command

`cs-revoke-user-role-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 
| ids | One or more role IDs to revoke. Find a role's ID from `/users/queries/roles/v1`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserRoleIDsResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.message | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.code | Number |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.id | String |  | 
| CrowdStrike.domainUserRoleIDsResponse.errors.message | String |  | 
### cs-rtr-aggregate-sessions

***
Get aggregates on session data.

#### Base Command

`cs-rtr-aggregate-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_aggregatequeryrequest_date_ranges |  | Required | 
| msa_aggregatequeryrequest_field |  | Required | 
| msa_aggregatequeryrequest_filter |  | Required | 
| msa_aggregatequeryrequest_interval |  | Required | 
| msa_aggregatequeryrequest_min_doc_count |  | Required | 
| msa_aggregatequeryrequest_missing |  | Required | 
| msa_aggregatequeryrequest_name |  | Required | 
| msa_aggregatequeryrequest_q |  | Required | 
| msa_aggregatequeryrequest_ranges |  | Required | 
| msa_aggregatequeryrequest_size |  | Required | 
| msa_aggregatequeryrequest_sort |  | Required | 
| msa_aggregatequeryrequest_sub_aggregates |  | Required | 
| msa_aggregatequeryrequest_time_zone |  | Required | 
| msa_aggregatequeryrequest_type |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.code | Number |  | 
| CrowdStrike.msaAggregatesResponse.errors.id | String |  | 
| CrowdStrike.msaAggregatesResponse.errors.message | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.count | Number |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.from | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.key_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_from | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.string_to | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.to | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value | Unknown |  | 
| CrowdStrike.msaAggregatesResponse.resources.buckets.value_as_string | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.name | String |  | 
| CrowdStrike.msaAggregatesResponse.resources.sum_other_doc_count | Number |  | 
### cs-rtr-check-active-responder-command-status

***
Get status of an executed active-responder command on a single host.

#### Base Command

`cs-rtr-check-active-responder-command-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cloud_request_id | Cloud Request ID of the executed command to query. | Required | 
| sequence_id | Sequence ID that we want to retrieve. Command responses are chunked across sequences. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
### cs-rtr-check-admin-command-status

***
Get status of an executed RTR administrator command on a single host.

#### Base Command

`cs-rtr-check-admin-command-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cloud_request_id | Cloud Request ID of the executed command to query. | Required | 
| sequence_id | Sequence ID that we want to retrieve. Command responses are chunked across sequences. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
### cs-rtr-check-command-status

***
Get status of an executed command on a single host.

#### Base Command

`cs-rtr-check-command-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cloud_request_id | Cloud Request ID of the executed command to query. | Required | 
| sequence_id | Sequence ID that we want to retrieve. Command responses are chunked across sequences. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.base_command | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.complete | Boolean |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.sequence_id | Number |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stderr | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.stdout | String |  | 
| CrowdStrike.domainStatusResponseWrapper.resources.task_id | String |  | 
### cs-rtr-create-put-files

***
Upload a new put-file to use for the RTR `put` command.

#### Base Command

`cs-rtr-create-put-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | put-file to upload. | Required | 
| description | File description. | Required | 
| name | File name (if different than actual file name). | Optional | 
| comments_for_audit_log | The audit log comment. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-rtr-create-scripts

***
Upload a new custom-script to use for the RTR `runscript` command.

#### Base Command

`cs-rtr-create-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | custom-script file to upload.  These should be powershell scripts. | Optional | 
| description | File description. | Required | 
| name | File name (if different than actual file name). | Optional | 
| comments_for_audit_log | The audit log comment. | Optional | 
| permission_type | Permission for the custom-script. Valid permission values:   - `private`, usable by only the user who uploaded it   - `group`, usable by all RTR Admins   - `public`, usable by all active-responders and RTR admins. | Required | 
| content | The script text that you want to use to upload. | Optional | 
| platform | Platforms for the file. Currently supports: windows, mac, linux, . If no platform is provided, it will default to 'windows'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-rtr-delete-file

***
Delete a RTR session file.

#### Base Command

`cs-rtr-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | RTR Session file id. | Required | 
| session_id | RTR Session id. | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-delete-put-files

***
Delete a put-file based on the ID given.  Can only delete one file at a time.

#### Base Command

`cs-rtr-delete-put-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | File id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-rtr-delete-queued-session

***
Delete a queued session command.

#### Base Command

`cs-rtr-delete-queued-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | RTR Session id. | Required | 
| cloud_request_id | Cloud Request ID of the executed command to query. | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-delete-scripts

***
Delete a custom-script based on the ID given.  Can only delete one script at a time.

#### Base Command

`cs-rtr-delete-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | File id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-rtr-delete-session

***
Delete a session.

#### Base Command

`cs-rtr-delete-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | RTR Session id. | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-execute-active-responder-command

***
Execute an active responder command on a single host.

#### Base Command

`cs-rtr-execute-active-responder-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_commandexecuterequest_base_command |  | Required | 
| domain_commandexecuterequest_command_string |  | Required | 
| domain_commandexecuterequest_device_id |  | Required | 
| domain_commandexecuterequest_id |  | Required | 
| domain_commandexecuterequest_persist |  | Required | 
| domain_commandexecuterequest_session_id |  | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-execute-admin-command

***
Execute a RTR administrator command on a single host.

#### Base Command

`cs-rtr-execute-admin-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_commandexecuterequest_base_command |  | Required | 
| domain_commandexecuterequest_command_string |  | Required | 
| domain_commandexecuterequest_device_id |  | Required | 
| domain_commandexecuterequest_id |  | Required | 
| domain_commandexecuterequest_persist |  | Required | 
| domain_commandexecuterequest_session_id |  | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-execute-command

***
Execute a command on a single host.

#### Base Command

`cs-rtr-execute-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_commandexecuterequest_base_command |  | Required | 
| domain_commandexecuterequest_command_string |  | Required | 
| domain_commandexecuterequest_device_id |  | Required | 
| domain_commandexecuterequest_id |  | Required | 
| domain_commandexecuterequest_persist |  | Required | 
| domain_commandexecuterequest_session_id |  | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-get-extracted-file-contents

***
Get RTR extracted file contents for specified session and sha256.

#### Base Command

`cs-rtr-get-extracted-file-contents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | RTR Session id. | Required | 
| sha256 | Extracted SHA256 (e.g. 'efa256a96af3b556cd3fc9d8b1cf587d72807d7805ced441e8149fc279db422b'). | Required | 
| filename | Filename to use for the archive name and the file within the archive. | Optional | 

#### Context Output

There is no context output for this command.
### cs-rtr-get-put-files

***
Get put-files based on the ID's given. These are used for the RTR `put` command.

#### Base Command

`cs-rtr-get-put-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | File IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.binservclientMsaPFResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.bucket | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.cid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.comments_for_audit_log | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.content | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.description | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.file_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.name | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.path | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.permission_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_attempt_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_success_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.sha256 | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.size | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.write_access | Boolean |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.bucket | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.cid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.comments_for_audit_log | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.content | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.description | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.file_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.name | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.path | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.permission_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_attempt_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_success_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.sha256 | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.size | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.write_access | Boolean |  | 
### cs-rtr-get-scripts

***
Get custom-scripts based on the ID's given. These are used for the RTR `runscript` command.

#### Base Command

`cs-rtr-get-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | File IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.binservclientMsaPFResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.bucket | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.cid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.comments_for_audit_log | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.content | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.description | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.file_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.name | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.path | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.permission_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_attempt_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_success_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.sha256 | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.size | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.write_access | Boolean |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.bucket | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.cid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.comments_for_audit_log | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.content | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.created_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.description | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.file_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.id | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_by_uuid | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.modified_timestamp | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.name | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.path | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.permission_type | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_attempt_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.run_success_count | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.sha256 | String |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.size | Number |  | 
| CrowdStrike.binservclientMsaPFResponse.resources.write_access | Boolean |  | 
### cs-rtr-init-session

***
Initialize a new session with the RTR cloud.

#### Base Command

`cs-rtr-init-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_initrequest_device_id |  | Required | 
| domain_initrequest_origin |  | Required | 
| domain_initrequest_queue_offline |  | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-list-all-sessions

***
Get a list of session_ids.

#### Base Command

`cs-rtr-list-all-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 
| sort | Sort by spec. Ex: 'date_created\|asc'. | Optional | 
| filter_ | Optional filter criteria in the form of an FQL query. For more information about FQL queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). “user_id” can accept a special value ‘@me’ which will restrict results to records with current user’s ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainListSessionsResponseMsa.errors.code | Number |  | 
| CrowdStrike.domainListSessionsResponseMsa.errors.id | String |  | 
| CrowdStrike.domainListSessionsResponseMsa.errors.message | String |  | 
| CrowdStrike.domainListSessionsResponseMsa.errors.code | Number |  | 
| CrowdStrike.domainListSessionsResponseMsa.errors.id | String |  | 
| CrowdStrike.domainListSessionsResponseMsa.errors.message | String |  | 
### cs-rtr-list-files

***
Get a list of files for the specified RTR session.

#### Base Command

`cs-rtr-list-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | RTR Session id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainListFilesResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.cloud_request_id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.id | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.name | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.sha256 | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.size | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.updated_at | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.cloud_request_id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.id | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.name | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.session_id | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.sha256 | String |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.size | Number |  | 
| CrowdStrike.domainListFilesResponseWrapper.resources.updated_at | String |  | 
### cs-rtr-list-put-files

***
Get a list of put-file ID's that are available to the user for the `put` command.

#### Base Command

`cs-rtr-list-put-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter criteria in the form of an FQL query. For more information about FQL queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 
| sort | Sort by spec. Ex: 'created_at\|asc'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.binservclientMsaPutFileResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.message | String |  | 
### cs-rtr-list-queued-sessions

***
Get queued session metadata by session ID.

#### Base Command

`cs-rtr-list-queued-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.base_command | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.cloud_request_id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.command_string | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.created_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.deleted_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.status | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.status_text | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.updated_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.aid | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.status | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.updated_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.user_id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.user_uuid | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.base_command | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.cloud_request_id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.command_string | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.created_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.deleted_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.status | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.status_text | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.Commands.updated_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.aid | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.status | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.updated_at | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.user_id | String |  | 
| CrowdStrike.domainQueuedSessionResponseWrapper.resources.user_uuid | String |  | 
### cs-rtr-list-scripts

***
Get a list of custom-script ID's that are available to the user for the `runscript` command.

#### Base Command

`cs-rtr-list-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ | Optional filter criteria in the form of an FQL query. For more information about FQL queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide). | Optional | 
| offset | Starting index of overall result set from which to return ids. | Optional | 
| limit | Number of ids to return. | Optional | 
| sort | Sort by spec. Ex: 'created_at\|asc'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.binservclientMsaPutFileResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.message | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.code | Number |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.id | String |  | 
| CrowdStrike.binservclientMsaPutFileResponse.errors.message | String |  | 
### cs-rtr-list-sessions

***
Get session metadata by session id.

#### Base Command

`cs-rtr-list-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| msa_idsrequest_ids |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainSessionResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.cid | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.commands_queued | Boolean |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.device_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.duration | Unknown |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.hostname | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.base_command | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.cloud_request_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.command_string | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.created_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.current_directory | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.id | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.session_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.updated_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.offline_queued | Boolean |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.origin | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.platform_id | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.platform_name | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.pwd | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.updated_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.user_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.user_uuid | String |  | 
| CrowdStrike.domainSessionResponseWrapper.errors.code | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.errors.id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.errors.message | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.cid | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.commands_queued | Boolean |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.created_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.deleted_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.device_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.duration | Unknown |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.hostname | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.base_command | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.cloud_request_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.command_string | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.created_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.current_directory | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.id | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.session_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.logs.updated_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.offline_queued | Boolean |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.origin | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.platform_id | Number |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.platform_name | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.pwd | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.updated_at | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.user_id | String |  | 
| CrowdStrike.domainSessionResponseWrapper.resources.user_uuid | String |  | 
### cs-rtr-pulse-session

***
Refresh a session timeout on a single host.

#### Base Command

`cs-rtr-pulse-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_initrequest_device_id |  | Required | 
| domain_initrequest_origin |  | Required | 
| domain_initrequest_queue_offline |  | Required | 

#### Context Output

There is no context output for this command.
### cs-rtr-update-scripts

***
Upload a new scripts to replace an existing one.

#### Base Command

`cs-rtr-update-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ID to update. | Required | 
| file | custom-script file to upload.  These should be powershell scripts. | Optional | 
| description | File description. | Optional | 
| name | File name (if different than actual file name). | Optional | 
| comments_for_audit_log | The audit log comment. | Optional | 
| permission_type | Permission for the custom-script. Valid permission values:   - `private`, usable by only the user who uploaded it   - `group`, usable by all RTR Admins   - `public`, usable by all active-responders and RTR admins. | Optional | 
| content | The script text that you want to use to upload. | Optional | 
| platform | Platforms for the file. Currently supports: windows, mac,. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-scan-samples

***
Submit a volume of files for ml scanning. Time required for analysis increases with the number of samples in a volume but usually it should take less than 1 minute.

#### Base Command

`cs-scan-samples`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mlscanner_samplesscanparameters_samples |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.mlscannerQueryResponse.errors.code | Number |  | 
| CrowdStrike.mlscannerQueryResponse.errors.id | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.message | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.code | Number |  | 
| CrowdStrike.mlscannerQueryResponse.errors.id | String |  | 
| CrowdStrike.mlscannerQueryResponse.errors.message | String |  | 
### cs-set-device-control-policies-precedence

***
Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence.

#### Base Command

`cs-set-device-control-policies-precedence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_setpolicyprecedencereqv1_ids | The ids of all current prevention policies for the platform specified. The precedence will be set in the order the ids are specified. | Required | 
| requests_setpolicyprecedencereqv1_platform_name | The name of the platform for which to set precedence. Possible values are: Windows, Mac, Linux. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-set-firewall-policies-precedence

***
Sets the precedence of Firewall Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence.

#### Base Command

`cs-set-firewall-policies-precedence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_setpolicyprecedencereqv1_ids | The ids of all current prevention policies for the platform specified. The precedence will be set in the order the ids are specified. | Required | 
| requests_setpolicyprecedencereqv1_platform_name | The name of the platform for which to set precedence. Possible values are: Windows, Mac, Linux. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-set-prevention-policies-precedence

***
Sets the precedence of Prevention Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence.

#### Base Command

`cs-set-prevention-policies-precedence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_setpolicyprecedencereqv1_ids | The ids of all current prevention policies for the platform specified. The precedence will be set in the order the ids are specified. | Required | 
| requests_setpolicyprecedencereqv1_platform_name | The name of the platform for which to set precedence. Possible values are: Windows, Mac, Linux. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-set-sensor-update-policies-precedence

***
Sets the precedence of Sensor Update Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence.

#### Base Command

`cs-set-sensor-update-policies-precedence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_setpolicyprecedencereqv1_ids | The ids of all current prevention policies for the platform specified. The precedence will be set in the order the ids are specified. | Required | 
| requests_setpolicyprecedencereqv1_platform_name | The name of the platform for which to set precedence. Possible values are: Windows, Mac, Linux. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-setrt-response-policies-precedence

***
Sets the precedence of Response Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence.

#### Base Command

`cs-setrt-response-policies-precedence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_setpolicyprecedencereqv1_ids | The ids of all current prevention policies for the platform specified. The precedence will be set in the order the ids are specified. | Required | 
| requests_setpolicyprecedencereqv1_platform_name | The name of the platform for which to set precedence. Possible values are: Windows, Mac, Linux. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-submit

***
Submit an uploaded file or a URL for sandbox analysis. Time required for analysis varies but is usually less than 15 minutes.

#### Base Command

`cs-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| falconx_submissionparametersv1_sandbox |  | Optional | 
| falconx_submissionparametersv1_user_tags |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.falconxSubmissionV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.message | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.action_script | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.command_line | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.document_password | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.enable_tor | Boolean |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_date | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_time | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.url | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.state | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_uuid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.code | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.errors.message | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.cid | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.created_timestamp | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.origin | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.action_script | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.command_line | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.document_password | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.enable_tor | Boolean |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.environment_id | Number |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.sha256 | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.submit_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_date | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.system_time | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.sandbox.url | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.state | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_id | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_name | String |  | 
| CrowdStrike.falconxSubmissionV1Response.resources.user_uuid | String |  | 
### cs-tokenscreate

***
Creates a token.

#### Base Command

`cs-tokenscreate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_tokencreaterequestv1_expires_timestamp | The token's expiration time (RFC-3339). Null, if the token never expires. | Optional | 
| api_tokencreaterequestv1_label | The token label. | Optional | 
| api_tokencreaterequestv1_type | The token type. | Optional | 

#### Context Output

There is no context output for this command.
### cs-tokensdelete

***
Deletes a token immediately. To revoke a token, use PATCH /installation-tokens/entities/tokens/v1 instead.

#### Base Command

`cs-tokensdelete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The token ids to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-tokensquery

***
Search for tokens by providing an FQL filter and paging details.

#### Base Command

`cs-tokensquery`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The offset to start retrieving records from. | Optional | 
| limit | The maximum records to return. [1-1000]. Defaults to 50. | Optional | 
| sort | The property to sort by (e.g. created_timestamp.desc). | Optional | 
| filter_ | The filter expression that should be used to limit the results (e.g., `status:'valid'`). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-tokensread

***
Gets the details of one or more tokens by id.

#### Base Command

`cs-tokensread`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of tokens to retrieve details for. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apitokenDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.apitokenDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.created_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.expires_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.id | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.label | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.last_used_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.revoked_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.status | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.type | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.value | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.errors.code | Number |  | 
| CrowdStrike.apitokenDetailsResponseV1.errors.id | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.errors.message | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.created_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.expires_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.id | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.label | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.last_used_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.revoked_timestamp | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.status | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.type | String |  | 
| CrowdStrike.apitokenDetailsResponseV1.resources.value | String |  | 
### cs-tokensupdate

***
Updates one or more tokens. Use this endpoint to edit labels, change expiration, revoke, or restore.

#### Base Command

`cs-tokensupdate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The token ids to update. | Required | 
| api_tokenpatchrequestv1_expires_timestamp | The token's expiration time (RFC-3339). Null, if the token never expires. | Optional | 
| api_tokenpatchrequestv1_label | The token label. | Optional | 
| api_tokenpatchrequestv1_revoked | Set to true to revoke the token, false to un-revoked it. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
| CrowdStrike.msaQueryResponse.errors.code | Number |  | 
| CrowdStrike.msaQueryResponse.errors.id | String |  | 
| CrowdStrike.msaQueryResponse.errors.message | String |  | 
### cs-trigger-scan

***
Triggers a dry run or a full scan of a customer's kubernetes footprint.

#### Base Command

`cs-trigger-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_type | Scan Type to do. Possible values are: cluster-refresh, dry-run, full. | Required | 

#### Context Output

There is no context output for this command.
### cs-update-actionv1

***
Update an action for a monitoring rule.

#### Base Command

`cs-update-actionv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_updateactionrequest_frequency |  | Required | 
| domain_updateactionrequest_id |  | Required | 
| domain_updateactionrequest_recipients |  | Required | 
| domain_updateactionrequest_status |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainActionEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.cid | String | The ID of the customer who created the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.created_timestamp | String | The date when the action was created. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.frequency | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.id | String | The ID of the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.rule_id | String | The ID of the rule on which this action is attached. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.status | String | The action status. It can be either 'enabled' or 'muted'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.type | String | The action type. The only type currently supported is 'email'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.updated_timestamp | String | The date when the action was updated. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.user_uuid | String | The UUID of the user who created the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.cid | String | The ID of the customer who created the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.created_timestamp | String | The date when the action was created. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.frequency | String |  | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.id | String | The ID of the action. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.rule_id | String | The ID of the rule on which this action is attached. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.status | String | The action status. It can be either 'enabled' or 'muted'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.type | String | The action type. The only type currently supported is 'email'. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.updated_timestamp | String | The date when the action was updated. | 
| CrowdStrike.domainActionEntitiesResponseV1.resources.user_uuid | String | The UUID of the user who created the action. | 
### cs-update-detects-by-idsv2

***
Modify the state, assignee, and visibility of detections.

#### Base Command

`cs-update-detects-by-idsv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_detectsentitiespatchrequest_assigned_to_uuid |  | Optional | 
| domain_detectsentitiespatchrequest_comment |  | Optional | 
| domain_detectsentitiespatchrequest_ids |  | Optional | 
| domain_detectsentitiespatchrequest_show_in_ui |  | Optional | 
| domain_detectsentitiespatchrequest_status |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.msaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.msaReplyMetaOnly.errors.message | String |  | 
### cs-update-device-control-policies

***
Update Device Control Policies by specifying the ID of the policy and details to update.

#### Base Command

`cs-update-device-control-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatedevicecontrolpoliciesv1_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesDeviceControlPoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-update-device-tags

***
Append or remove one or more Falcon Grouping Tags on one or more hosts.

#### Base Command

`cs-update-device-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_updatedevicetagsrequestv1_action |  | Required | 
| domain_updatedevicetagsrequestv1_device_ids |  | Required | 
| domain_updatedevicetagsrequestv1_tags |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaEntitiesResponse.errors.message | String |  | 
| CrowdStrike.msaEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaEntitiesResponse.errors.message | String |  | 
### cs-update-firewall-policies

***
Update Firewall Policies by specifying the ID of the policy and details to update.

#### Base Command

`cs-update-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatefirewallpoliciesv1_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.channel_version | Number | Channel file version for the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesFirewallPoliciesV1.resources.rule_set_id | String | Firewall rule set id. This id combines several firewall rules and gets attached to the policy. | 
### cs-update-host-groups

***
Update Host Groups by specifying the ID of the group and details to update.

#### Base Command

`cs-update-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updategroupsv1_resources | A collection of groups to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
| CrowdStrike.responsesHostGroupsV1.errors.code | Number |  | 
| CrowdStrike.responsesHostGroupsV1.errors.id | String |  | 
| CrowdStrike.responsesHostGroupsV1.errors.message | String |  | 
| CrowdStrike.responsesHostGroupsV1.resources.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesHostGroupsV1.resources.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesHostGroupsV1.resources.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesHostGroupsV1.resources.id | String | The identifier of this host group. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesHostGroupsV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesHostGroupsV1.resources.name | String | The name of the group. | 
### cs-update-notificationsv1

***
Update notification status or assignee. Accepts bulk requests.

#### Base Command

`cs-update-notificationsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_updatenotificationrequestv1_assigned_to_uuid | The unique ID of the user who is assigned to this notification. | Required | 
| domain_updatenotificationrequestv1_id | The ID of the notifications. | Required | 
| domain_updatenotificationrequestv1_status | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uid | String | The email of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_username | String | The name of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.assigned_to_uuid | String | The unique ID of the user who is assigned to this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.created_date | String | The date when the notification was generated. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.id | String | The ID of the notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_date | String | Timestamp when the intelligence item is considered to have been posted. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_id | String | ID of the intelligence item which generated the match. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.item_type | String | Type of intelligence item based on format, e.g. post, reply, botnet_config. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_id | String | The ID of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_name | String | The name of the rule that generated this notification. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_priority | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.rule_topic | String |  | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.status | String | The notification status. This can be one of: new, in-progress, closed-false-positive, closed-true-positive. | 
| CrowdStrike.domainNotificationEntitiesResponseV1.resources.updated_date | String | The date when the notification was updated. | 
### cs-update-prevention-policies

***
Update Prevention Policies by specifying the ID of the policy and details to update.

#### Base Command

`cs-update-prevention-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatepreventionpoliciesv1_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.name | String | The name of the category. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesPreventionPoliciesV1.resources.prevention_settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-update-rulesv1

***
Update monitoring rules.

#### Base Command

`cs-update-rulesv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| domain_updaterulerequestv1_filter | The filter to be used for searching. | Required | 
| domain_updaterulerequestv1_id | The rule ID to be updated. | Required | 
| domain_updaterulerequestv1_name | The name of a particular rule. | Required | 
| domain_updaterulerequestv1_permissions | The permissions for a particular rule which specifies the rule's access by other users. Possible values: [private public]. | Required | 
| domain_updaterulerequestv1_priority | The priority for a particular rule. Possible values: [low medium high]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainRulesEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.cid | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.created_timestamp | String | The creation time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.filter | String | The FQL filter contained in a rule and used for searching. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.id | String | The ID of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.name | String | The name for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.permissions | String | The permissions of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.priority | String | The priority of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status | String | The status of a rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status_message | String | The detailed status message. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.topic | String | The topic of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.updated_timestamp | String | The last updated time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_id | String | The user ID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_name | String | The user name of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_uuid | String | The UUID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.code | Number |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.field | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.details.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.id | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.errors.message_key | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.cid | String |  | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.created_timestamp | String | The creation time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.filter | String | The FQL filter contained in a rule and used for searching. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.id | String | The ID of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.name | String | The name for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.permissions | String | The permissions of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.priority | String | The priority of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status | String | The status of a rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.status_message | String | The detailed status message. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.topic | String | The topic of a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.updated_timestamp | String | The last updated time for a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_id | String | The user ID of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_name | String | The user name of the user that created a given rule. | 
| CrowdStrike.domainRulesEntitiesResponseV1.resources.user_uuid | String | The UUID of the user that created a given rule. | 
### cs-update-sensor-update-policies

***
Update Sensor Update Policies by specifying the ID of the policy and details to update.

#### Base Command

`cs-update-sensor-update-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatesensorupdatepoliciesv1_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV1.resources.platform_name | String | The name of the platform. | 
### cs-update-sensor-update-policiesv2

***
Update Sensor Update Policies by specifying the ID of the policy and details to update with additional support for uninstall protection.

#### Base Command

`cs-update-sensor-update-policiesv2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatesensorupdatepoliciesv2_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.code | Number |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.id | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.errors.message | String |  | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesSensorUpdatePoliciesV2.resources.platform_name | String | The name of the platform. | 
### cs-update-sensor-visibility-exclusionsv1

***
Update the sensor visibility exclusions.

#### Base Command

`cs-update-sensor-visibility-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_svexclusionupdatereqv1_comment |  | Optional | 
| requests_svexclusionupdatereqv1_groups |  | Optional | 
| requests_svexclusionupdatereqv1_id |  | Required | 
| requests_svexclusionupdatereqv1_value |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesSvExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value_hash | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesSvExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesSvExclusionRespV1.resources.value_hash | String |  | 
### cs-update-user

***
Modify an existing user's first or last name.

#### Base Command

`cs-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | ID of a user. Find a user's ID from `/users/entities/user/v1`. | Required | 
| domain_updateuserfields_firstname |  | Optional | 
| domain_updateuserfields_lastname |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserMetaDataResponse.errors.code | Number |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.id | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.message | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.customer | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.firstName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.lastName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uuid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.code | Number |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.id | String |  | 
| CrowdStrike.domainUserMetaDataResponse.errors.message | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.customer | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.firstName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.lastName | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uid | String |  | 
| CrowdStrike.domainUserMetaDataResponse.resources.uuid | String |  | 
### cs-update-user-groups

***
Update existing User Group(s). User Group ID is expected for each User Group definition provided in request body. User Group member(s) remain unaffected.

#### Base Command

`cs-update-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_usergroupsrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainUserGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.user_group_id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainUserGroupsResponseV1.resources.user_group_id | String |  | 
### cs-updateaws-account

***
Updates the AWS account per the query  meters provided.

#### Base Command

`cs-updateaws-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | AWS Account ID. | Required | 
| region | Default Region for Account Automation. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.msaBaseEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaBaseEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaBaseEntitiesResponse.errors.message | String |  | 
| CrowdStrike.msaBaseEntitiesResponse.errors.code | Number |  | 
| CrowdStrike.msaBaseEntitiesResponse.errors.id | String |  | 
| CrowdStrike.msaBaseEntitiesResponse.errors.message | String |  | 
### cs-updateaws-accounts

***
Update AWS Accounts by specifying the ID of the account and details to update.

#### Base Command

`cs-updateaws-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| models_updateawsaccountsv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
| CrowdStrike.modelsAWSAccountsV1.errors.code | Number |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.id | String |  | 
| CrowdStrike.modelsAWSAccountsV1.errors.message | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.alias | String | Alias/Name associated with the account. This is only updated once the account is in a registered state. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cid | String |  | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_stack_id | String | Unique identifier for the cloudformation stack id used for provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudformation_url | String | URL of the CloudFormation template to execute. This is returned when mode is to set 'cloudformation' when provisioning. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_owner_id | String | The 12 digit AWS account which is hosting the S3 bucket containing cloudtrail logs for this account. If this field is set, it takes precedence of the settings level field. | 
| CrowdStrike.modelsAWSAccountsV1.resources.cloudtrail_bucket_region | String | Region where the S3 bucket containing cloudtrail logs resides. This is only set if using cloudformation to provision and create the trail. | 
| CrowdStrike.modelsAWSAccountsV1.resources.created_timestamp | String | Timestamp of when the account was first provisioned within CrowdStrike's system.' | 
| CrowdStrike.modelsAWSAccountsV1.resources.external_id | String | ID assigned for use with cross account IAM role access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.iam_role_arn | String | The full arn of the IAM role created in this account to control access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.id | String | 12 digit AWS provided unique identifier for the account. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_modified_timestamp | String | Timestamp of when the account was last modified. | 
| CrowdStrike.modelsAWSAccountsV1.resources.last_scanned_timestamp | String | Timestamp of when the account was scanned. | 
| CrowdStrike.modelsAWSAccountsV1.resources.policy_version | String | Current version of permissions associated with IAM role and granted access. | 
| CrowdStrike.modelsAWSAccountsV1.resources.provisioning_state | String | Provisioning state of the account. Values can be; initiated, registered, unregistered. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_reqs | Number | Rate limiting setting to control the maximum number of requests that can be made within the rate_limit_time duration. | 
| CrowdStrike.modelsAWSAccountsV1.resources.rate_limit_time | Number | Rate limiting setting to control the number of seconds for which rate_limit_reqs applies. | 
| CrowdStrike.modelsAWSAccountsV1.resources.template_version | String | Current version of cloudformation template used to manage access. | 
### cs-updatecid-groups

***
Update existing CID Group(s). CID Group ID is expected for each CID Group definition provided in request body. CID Group member(s) remain unaffected.

#### Base Command

`cs-updatecid-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_cidgroupsrequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.domainCIDGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.name | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.code | Number |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.errors.message | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.cid_group_id | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.description | String |  | 
| CrowdStrike.domainCIDGroupsResponseV1.resources.name | String |  | 
### cs-updatecspm-azure-tenant-default-subscriptionid

***
Update an Azure default subscription_id in our system for given tenant_id.

#### Base Command

`cs-updatecspm-azure-tenant-default-subscriptionid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | Tenant ID to update client ID for. Required if multiple tenants are registered. | Optional | 
| subscription_id | Default Subscription ID to patch for all subscriptions belonged to a tenant. | Required | 

#### Context Output

There is no context output for this command.
### cs-updatecspm-policy-settings

***
Updates a policy setting - can be used to override policy severity or to disable a policy entirely.

#### Base Command

`cs-updatecspm-policy-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_policyrequestextv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationPolicySettingsResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.name | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.account_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.enabled | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tag_excluded | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tenant_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_timestamp | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_type | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.errors.message | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cid | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cis_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.cloud_service_subtype | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.default_severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.name | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.nist_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.benchmark_short | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.pci_benchmark.recommendation_number | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_id | Number |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.account_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.enabled | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.severity | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tag_excluded | Boolean |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_settings.tenant_id | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_timestamp | String |  | 
| CrowdStrike.registrationPolicySettingsResponseV1.resources.policy_type | String |  | 
### cs-updatecspm-scan-schedule

***
Updates scan schedule configuration for one or more cloud platforms.

#### Base Command

`cs-updatecspm-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registration_scanscheduleupdaterequestv1_resources |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.registrationScanScheduleResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.id | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.message | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.cloud_platform | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.next_scan_timestamp | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.scan_schedule | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.code | Number |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.id | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.errors.message | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.cloud_platform | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.next_scan_timestamp | String |  | 
| CrowdStrike.registrationScanScheduleResponseV1.resources.scan_schedule | String |  | 
### cs-updateioa-exclusionsv1

***
Update the IOA exclusions.

#### Base Command

`cs-updateioa-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_ioaexclusionupdatereqv1_cl_regex |  | Required | 
| requests_ioaexclusionupdatereqv1_comment |  | Optional | 
| requests_ioaexclusionupdatereqv1_description |  | Required | 
| requests_ioaexclusionupdatereqv1_detection_json |  | Required | 
| requests_ioaexclusionupdatereqv1_groups |  | Required | 
| requests_ioaexclusionupdatereqv1_id |  | Required | 
| requests_ioaexclusionupdatereqv1_ifn_regex |  | Required | 
| requests_ioaexclusionupdatereqv1_name |  | Required | 
| requests_ioaexclusionupdatereqv1_pattern_id |  | Required | 
| requests_ioaexclusionupdatereqv1_pattern_name |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesIoaExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.cl_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.description | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.detection_json | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.ifn_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.cl_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.description | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.detection_json | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.ifn_regex | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.name | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_id | String |  | 
| CrowdStrike.responsesIoaExclusionRespV1.resources.pattern_name | String |  | 
### cs-updateioc

***
    DEPRECATED     Use the new IOC Management endpoint (PATCH /iocs/entities/indicators/v1).     Update an IOC by providing a type and value.

#### Base Command

`cs-updateioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_iocviewrecord_batch_id |  | Optional | 
| api_iocviewrecord_created_by |  | Optional | 
| api_iocviewrecord_created_timestamp |  | Optional | 
| api_iocviewrecord_description |  | Optional | 
| api_iocviewrecord_expiration_days |  | Optional | 
| api_iocviewrecord_expiration_timestamp |  | Optional | 
| api_iocviewrecord_modified_by |  | Optional | 
| api_iocviewrecord_modified_timestamp |  | Optional | 
| api_iocviewrecord_policy |  | Optional | 
| api_iocviewrecord_share_level |  | Optional | 
| api_iocviewrecord_source |  | Optional | 
| api_iocviewrecord_type |  | Optional | 
| api_iocviewrecord_value |  | Optional | 
| type_ |  The type of the indicator. Valid types include:  sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.  md5: A hex-encoded md5 hash string. Length - min 32, max: 32.  domain: A domain name. Length - min: 1, max: 200.  ipv4: An IPv4 address. Must be a valid IP address.  ipv6: An IPv6 address. Must be a valid IP address. . | Required | 
| value | The string representation of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiMsaReplyIOC.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOC.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.batch_id | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.description | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_days | Number |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.policy | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.share_level | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.source | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.type | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.value | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.code | Number |  | 
| CrowdStrike.apiMsaReplyIOC.errors.id | String |  | 
| CrowdStrike.apiMsaReplyIOC.errors.message | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.batch_id | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.created_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.description | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_days | Number |  | 
| CrowdStrike.apiMsaReplyIOC.resources.expiration_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_by | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.modified_timestamp | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.policy | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.share_level | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.source | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.type | String |  | 
| CrowdStrike.apiMsaReplyIOC.resources.value | String |  | 
### cs-updateml-exclusionsv1

***
Update the ML exclusions.

#### Base Command

`cs-updateml-exclusionsv1`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_svexclusionupdatereqv1_comment |  | Optional | 
| requests_svexclusionupdatereqv1_groups |  | Optional | 
| requests_svexclusionupdatereqv1_id |  | Required | 
| requests_svexclusionupdatereqv1_value |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.code | Number |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.errors.message | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.applied_globally | Boolean |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.created_on | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesMlExclusionRespV1.resources.id | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.last_modified | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.modified_by | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.regexp_value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value | String |  | 
| CrowdStrike.responsesMlExclusionRespV1.resources.value_hash | String |  | 
### cs-updatepolicycontainer

***
Update an identified policy container.

#### Base Command

`cs-updatepolicycontainer`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The user id. | Required | 
| fwmgr_api_policycontainerupsertrequestv1_default_inbound |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_default_outbound |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_enforce |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_is_default_policy |  | Optional | 
| fwmgr_api_policycontainerupsertrequestv1_platform_id |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_policy_id |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_rule_group_ids |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_test_mode |  | Required | 
| fwmgr_api_policycontainerupsertrequestv1_tracking |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.message | String |  | 
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.code | Number |  | 
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.id | String |  | 
| CrowdStrike.fwmgrmsaReplyMetaOnly.errors.message | String |  | 
### cs-updatert-response-policies

***
Update Response Policies by specifying the ID of the policy and details to update.

#### Base Command

`cs-updatert-response-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requests_updatertresponsepoliciesv1_resources | A collection of policies to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.code | Number |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.id | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.errors.message | String |  | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.description | String | The description of a policy. Use this field to provide a high level summary of what this policy enforces. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.enabled | Boolean | If a policy is enabled it will be used during the course of policy evaluation. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.assignment_rule | String | The assignment rule of a group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_by | String | The email of the user which created the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.created_timestamp | String | The time at which the policy was created. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.description | String | An additional description of the group or the devices it targets. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.group_type | String | The method by which this host group is managed. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.id | String | The identifier of this host group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.groups.name | String | The name of the group. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.id | String | The unique id of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_by | String | The email of the user which last modified the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.modified_timestamp | String | The time at which the policy was last modified. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.name | String | The human readable name of the policy. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.platform_name | String | The name of the platform. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.name | String | The name of the category. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.description | String | The human readable description of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.id | String | The id of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.name | String | The name of the setting. | 
| CrowdStrike.responsesRTResponsePoliciesV1.resources.settings.settings.type | String | The type of the setting which can be used as a hint when displaying in the UI. | 
### cs-updaterulegroup

***
Update name, description, or enabled status of a rule group, or create, edit, delete, or reorder rules.

#### Base Command

`cs-updaterulegroup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERNAME | The user id. | Required | 
| comment | Audit log comment for this action. | Optional | 
| fwmgr_api_rulegroupmodifyrequestv1_diff_operations |  | Required | 
| fwmgr_api_rulegroupmodifyrequestv1_diff_type |  | Required | 
| fwmgr_api_rulegroupmodifyrequestv1_id |  | Required | 
| fwmgr_api_rulegroupmodifyrequestv1_rule_ids |  | Required | 
| fwmgr_api_rulegroupmodifyrequestv1_rule_versions |  | Required | 
| fwmgr_api_rulegroupmodifyrequestv1_tracking |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.code | Number |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.id | String |  | 
| CrowdStrike.fwmgrapiQueryResponse.errors.message | String |  | 
### cs-updaterulegroup-mixin0

***
Update a rule group. The following properties can be modified: name, description, enabled.

#### Base Command

`cs-updaterulegroup-mixin0`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_rulegroupmodifyrequestv1_comment |  | Required | 
| api_rulegroupmodifyrequestv1_description |  | Required | 
| api_rulegroupmodifyrequestv1_enabled |  | Required | 
| api_rulegroupmodifyrequestv1_id |  | Required | 
| api_rulegroupmodifyrequestv1_name |  | Required | 
| api_rulegroupmodifyrequestv1_rulegroup_version |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.action_label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.disposition_id | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.final_value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.type | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.magic_cookie | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_severity | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.rulegroup_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.code | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.errors.message | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.platform | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.action_label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.comment | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.committed_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.created_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.customer_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.deleted | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.description | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.disposition_id | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.enabled | Boolean |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.final_value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.type | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.label | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.field_values.values.value | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.instance_version | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.magic_cookie | Number |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_by | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.modified_on | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.pattern_severity | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.rulegroup_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_id | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.rules.ruletype_name | String |  | 
| CrowdStrike.apiRuleGroupsResponse.resources.version | Number |  | 
### cs-updaterules

***
Update rules within a rule group. Return the updated rules.

#### Base Command

`cs-updaterules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_ruleupdatesrequestv1_comment |  | Required | 
| api_ruleupdatesrequestv1_rule_updates |  | Required | 
| api_ruleupdatesrequestv1_rulegroup_id |  | Required | 
| api_ruleupdatesrequestv1_rulegroup_version |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
| CrowdStrike.apiRulesResponse.errors.code | Number |  | 
| CrowdStrike.apiRulesResponse.errors.id | String |  | 
| CrowdStrike.apiRulesResponse.errors.message | String |  | 
| CrowdStrike.apiRulesResponse.resources.action_label | String |  | 
| CrowdStrike.apiRulesResponse.resources.comment | String |  | 
| CrowdStrike.apiRulesResponse.resources.committed_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.created_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.customer_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.deleted | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.description | String |  | 
| CrowdStrike.apiRulesResponse.resources.disposition_id | Number |  | 
| CrowdStrike.apiRulesResponse.resources.enabled | Boolean |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.final_value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.type | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.label | String |  | 
| CrowdStrike.apiRulesResponse.resources.field_values.values.value | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.instance_version | Number |  | 
| CrowdStrike.apiRulesResponse.resources.magic_cookie | Number |  | 
| CrowdStrike.apiRulesResponse.resources.modified_by | String |  | 
| CrowdStrike.apiRulesResponse.resources.modified_on | String |  | 
| CrowdStrike.apiRulesResponse.resources.name | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.pattern_severity | String |  | 
| CrowdStrike.apiRulesResponse.resources.rulegroup_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_id | String |  | 
| CrowdStrike.apiRulesResponse.resources.ruletype_name | String |  | 
### cs-upload-samplev2

***
Upload a file for sandbox analysis. After uploading, use `/falconx/entities/submissions/v1` to start analyzing the file.

#### Base Command

`cs-upload-samplev2`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| body | Content of the uploaded sample in binary format. For example, use `--data-binary @$FILE_PATH` when using cURL. Max file size: 100 MB.  Accepted file formats:  - Portable executables: `.exe`, `.scr`, `.pif`, `.dll`, `.com`, `.cpl`, etc. - Office documents: `.doc`, `.docx`, `.ppt`, `.pps`, `.pptx`, `.ppsx`, `.xls`, `.xlsx`, `.rtf`, `.pub` - PDF - APK - Executable JAR - Windows script component: `.sct` - Windows shortcut: `.lnk` - Windows help: `.chm` - HTML application: `.hta` - Windows script file: `.wsf` - Javascript: `.js` - Visual Basic: `.vbs`,  `.vbe` - Shockwave Flash: `.swf` - Perl: `.pl` - Powershell: `.ps1`, `.psd1`, `.psm1` - Scalable vector graphics: `.svg` - Python: `.py` - Linux ELF executables - Email files: MIME RFC 822 `.eml`, Outlook `.msg`. | Required | 
| upfile | The binary file. | Required | 
| file_name | Name of the file. | Required | 
| comment | A descriptive comment to identify the file for other users. | Optional | 
| is_confidential | Defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console.  - `true`: File is only shown to users within your customer account - `false`: File can be seen by other CrowdStrike customers   Default: `true`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.code | Number |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.id | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.message | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.file_name | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.sha256 | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.code | Number |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.id | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.message | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.file_name | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.sha256 | String |  | 
### cs-upload-samplev3

***
Upload a file for further cloud analysis. After uploading, call the specific analysis API endpoint.

#### Base Command

`cs-upload-samplev3`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| X_CS_USERUUID | User UUID. | Optional | 
| body | Content of the uploaded sample in binary format. For example, use `--data-binary @$FILE_PATH` when using cURL. Max file size: 100 MB.  Accepted file formats:  - Portable executables: `.exe`, `.scr`, `.pif`, `.dll`, `.com`, `.cpl`, etc. - Office documents: `.doc`, `.docx`, `.ppt`, `.pps`, `.pptx`, `.ppsx`, `.xls`, `.xlsx`, `.rtf`, `.pub` - PDF - APK - Executable JAR - Windows script component: `.sct` - Windows shortcut: `.lnk` - Windows help: `.chm` - HTML application: `.hta` - Windows script file: `.wsf` - Javascript: `.js` - Visual Basic: `.vbs`,  `.vbe` - Shockwave Flash: `.swf` - Perl: `.pl` - Powershell: `.ps1`, `.psd1`, `.psm1` - Scalable vector graphics: `.svg` - Python: `.py` - Linux ELF executables - Email files: MIME RFC 822 `.eml`, Outlook `.msg`. | Required | 
| upfile | The binary file. | Required | 
| file_name | Name of the file. | Required | 
| comment | A descriptive comment to identify the file for other users. | Optional | 
| is_confidential | Defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console.  - `true`: File is only shown to users within your customer account - `false`: File can be seen by other CrowdStrike customers   Default: `true`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.code | Number |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.id | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.message | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.file_name | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.sha256 | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.code | Number |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.id | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.errors.message | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.file_name | String |  | 
| CrowdStrike.samplestoreSampleMetadataResponseV2.resources.sha256 | String |  | 
### cs-validate

***
Validates field values and checks for matches if a test string is provided.

#### Base Command

`cs-validate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_validationrequestv1_fields |  | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.apiValidationResponseV1.errors.code | Number |  | 
| CrowdStrike.apiValidationResponseV1.errors.id | String |  | 
| CrowdStrike.apiValidationResponseV1.errors.message | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.bytes | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.error | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.matches_test | Boolean |  | 
| CrowdStrike.apiValidationResponseV1.resources.name | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.test_data | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.valid | Boolean |  | 
| CrowdStrike.apiValidationResponseV1.resources.value | String |  | 
| CrowdStrike.apiValidationResponseV1.errors.code | Number |  | 
| CrowdStrike.apiValidationResponseV1.errors.id | String |  | 
| CrowdStrike.apiValidationResponseV1.errors.message | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.bytes | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.error | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.matches_test | Boolean |  | 
| CrowdStrike.apiValidationResponseV1.resources.name | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.test_data | String |  | 
| CrowdStrike.apiValidationResponseV1.resources.valid | Boolean |  | 
| CrowdStrike.apiValidationResponseV1.resources.value | String |  | 
### cs-verifyaws-account-access

***
Performs an Access Verification check on the specified AWS Account IDs.

#### Base Command

`cs-verifyaws-account-access`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of accounts to verify access on. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.modelsVerifyAccessResponseV1.errors.code | Number |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.errors.id | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.errors.message | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.id | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.reason | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.successful | Boolean |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.errors.code | Number |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.errors.id | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.errors.message | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.id | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.reason | String |  | 
| CrowdStrike.modelsVerifyAccessResponseV1.resources.successful | Boolean |  | 
### cs-get-device-login-history

***
Retrieve details about recent login sessions for a set of devices.

#### Base Command

`cs-get-device-login-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of devices to get the login history for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.deviceHistoryLogin.errors.code | Number |  | 
| CrowdStrike.deviceHistoryLogin.errors.id | String |  | 
| CrowdStrike.deviceHistoryLogin.errors.message | String |  | 
| CrowdStrike.deviceHistoryLogin.resources.device_id | String |  | 
| CrowdStrike.deviceHistoryLogin.resources.recent_logins.login_time | String |  | 
| CrowdStrike.deviceHistoryLogin.resources.recent_logins.user_name | String |  | 
| CrowdStrike.deviceHistoryLogin.meta.powered_by | String |  | 
| CrowdStrike.deviceHistoryLogin.meta.trace_id | String |  | 
| CrowdStrike.deviceHistoryLogin.meta.query_time | Number |  | 
| CrowdStrike.deviceHistoryLogin.meta.writes | Unknown |  | 
### cs-get-device-network-history

***
Retrieve history of IP and MAC addresses of devices.

#### Base Command

`cs-get-device-network-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of devices to get the network adres history for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.deviceNetworkHistory.error.code | Number |  | 
| CrowdStrike.deviceNetworkHistory.errors.id | String |  | 
| CrowdStrike.deviceNetworkHistory.errors.message | String |  | 
| CrowdStrike.deviceNetworkHistory.meta.powered_by | String |  | 
| CrowdStrike.deviceNetworkHistory.meta.trace_id | String |  | 
| CrowdStrike.deviceNetworkHistory.meta.query_time | Number |  | 
| CrowdStrike.deviceNetworkHistory.meta.writes | Unknown |  | 
| CrowdStrike.deviceNetworkHistory.resources.device_id | String |  | 
| CrowdStrike.deviceNetworkHistory.resources.cid | String |  | 
| CrowdStrike.deviceNetworkHistory.resources.history.ip_address | String |  | 
| CrowdStrike.deviceNetworkHistory.resources.history.mac_address | String |  | 
| CrowdStrike.deviceNetworkHistory.resources.history.timestamp | String |  | 
