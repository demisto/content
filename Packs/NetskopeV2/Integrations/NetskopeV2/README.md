Manage Netskope policy enforcement workflows for URLs, domains, file hashes, destination and network profiles, device classification, private applications, file inspection, and URL reputation.

This integration uses both Netskope API v1 and API v2, depending on the command.

## Configure Netskope - Direct to Zero Trust in Cortex

| **Parameter** | **Required** |
| --- | --- |
| URL of Netskope Tenant (e.g. https://tenant.goskope.com) | True |
| API Key | False |
| API v1 Token (for file hash list commands) | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netskopev2-add-url

***
Add URLs to the Netskope URL block list.

#### Base Command

`netskopev2-add-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required |
| url | URLs to add to the list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number | URL List ID. |
| Netskope.URLList.name | string | URL List name. |
| Netskope.URLList.data | unknown | URL List contents. |
| Netskope.URLList.data.urls | unknown | List of URLs in URL List. |
| Netskope.URLList.data.type | string | URL List type \('exact' or 'regex'\). |
| Netskope.URLList.modify_by | string | User which last modified URL List. |
| Netskope.URLList.modify_time | date | Time which URL List was last modified. |
| Netskope.URLList.modify_type | string | URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.URLList.pending | number | URL List pending status \('1' if pending, '0' if not\). |

### netskopev2-remove-url

***
Remove URLs from the Netskope URL block list.

#### Base Command

`netskopev2-remove-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required |
| url | URLs to remove from the list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number | URL List ID. |
| Netskope.URLList.name | string | URL List name. |
| Netskope.URLList.data | unknown | URL List contents. |
| Netskope.URLList.data.urls | unknown | List of URLs in URL List. |
| Netskope.URLList.data.type | string | URL List type \('exact' or 'regex'\). |
| Netskope.URLList.modify_by | string | User which last modified URL List. |
| Netskope.URLList.modify_time | date | Time which URL List was last modified. |
| Netskope.URLList.modify_type | string | URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.URLList.pending | number | URL List pending status \('1' if pending, '0' if not\). |

### netskopev2-get-lists

***
Get all applied and pending URL lists.

#### Base Command

`netskopev2-get-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number | URL List ID. |
| Netskope.List.name | string | URL List name. |
| Netskope.List.data | unknown | URL List contents. |
| Netskope.List.data.urls | unknown | List of URLs in URL List. |
| Netskope.List.data.type | string | URL List type \('exact' or 'regex'\). |
| Netskope.List.modify_by | string | User which last modified URL List. |
| Netskope.List.modify_time | date | Time which URL List was last modified. |
| Netskope.List.modify_type | string | URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.List.pending | number | URL List pending status \('1' if pending, '0' if not\). |

### netskopev2-get-list

***
Get URL list by ID.

#### Base Command

`netskopev2-get-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | Name of the URL list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number | URL List ID. |
| Netskope.List.name | string | URL List name. |
| Netskope.List.data | unknown | URL List contents. |
| Netskope.List.data.urls | unknown | List of URLs in URL List. |
| Netskope.List.data.type | string | URL List type \('exact' or 'regex'\). |
| Netskope.List.modify_by | string | User which last modified URL List. |
| Netskope.List.modify_time | date | Time which URL List was last modified. |
| Netskope.List.modify_type | string | URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.List.pending | number | URL List pending status \('1' if pending, '0' if not\). |

### netskopev2-list-device-classification-tags

***
View existing device classification tags. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-list-device-classification-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationTag.id | number | Device classification tag ID. |
| Netskope.DeviceClassificationTag.priority | number | Device classification tag priority. |
| Netskope.DeviceClassificationTag.name | string | Device classification tag name. |
| Netskope.DeviceClassificationTag.description | string | Device classification tag description. |
| Netskope.DeviceClassificationTag.modifiedBy | string | User which last modified the tag. |
| Netskope.DeviceClassificationTag.modifiedTime | date | Time the tag was last modified. |
| Netskope.DeviceClassificationTag.policyNames | unknown | Names of policies referencing this classification tag. |

### netskopev2-create-device-classification-tag

***
Create a new device classification tag (label). Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-classification-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the device classification tag. | Required |
| description | Description of the device classification tag. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationTag.ids | unknown | IDs of the created device classification tag\(s\). |
| Netskope.DeviceClassificationTag.name | string | Device classification tag name. |
| Netskope.DeviceClassificationTag.description | string | Device classification tag description. |

### netskopev2-create-device-classification-rule

***
Create a device classification rule linking conditions (OS version, device tag presence, etc.) to a classification label. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-classification-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the classification rule. | Required |
| label | Name of the classification tag this rule applies (must already exist). | Required |
| os | Operating system this rule applies to. Possible values are: windows, mac, linux, android, ios. | Required |
| conditions | JSON object describing the rule conditions, e.g. {"$and": [{"device_tag_check": {"tag_id": 1137}}]}. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationRule.ids | unknown | IDs of the created device classification rule\(s\). |
| Netskope.DeviceClassificationRule.name | string | Device classification rule name. |
| Netskope.DeviceClassificationRule.label | string | Device classification tag name this rule applies. |
| Netskope.DeviceClassificationRule.os | string | Operating system this rule applies to. |

### netskopev2-find-device

***
Find devices by client status query, to resolve a device's nsdeviceuid before tagging it. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-find-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Unix timestamp for the start of the query window. | Required |
| end_time | Unix timestamp for the end of the query window. | Required |
| fields | Comma-separated list of fields to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Device.nsdeviceuid | string | Netskope device UID. |
| Netskope.Device.hostname | string | Device hostname. |
| Netskope.Device.os | string | Device operating system. |
| Netskope.Device.client_version | string | Netskope client version installed on the device. |

### netskopev2-create-device-tag

***
Register a new device tag. Check netskopev2-list-device-tags first to avoid creating a duplicate. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the device tag. | Required |
| description | Description of the device tag. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTag.id | number | Device tag ID. |
| Netskope.DeviceTag.name | string | Device tag name. |
| Netskope.DeviceTag.description | string | Device tag description. |

### netskopev2-list-device-tags

***
Find existing device tags applied to a device. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-list-device-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Netskope device UID (nsdeviceuid) to look up tags for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTag.id | number | Device tag ID. |
| Netskope.DeviceTag.name | string | Device tag name. |

### netskopev2-apply-device-tags

***
Apply device tag(s) to one or more devices. This replaces all existing tags on the specified devices — it is not additive. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-apply-device-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | Device tag ID(s) to apply. A device supports a maximum of 5 tags. | Required |
| nsdeviceuid | Netskope device UID(s) (nsdeviceuid) to apply the tag(s) to. | Required |
| hostname | Hostname to associate with the device entries. | Optional |
| userkey | User key to associate with the device entries. Defaults to the device UID if not provided. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTagApplication.affected_device_tags | number | Number of device tags affected. |
| Netskope.DeviceTagApplication.affected_device_classification_tags | number | Number of device classification tags affected. |
| Netskope.DeviceTagApplication.message | string | Result message. |

### netskopev2-list-destination-profiles

***
List and filter destination profiles.

#### Base Command

`netskopev2-list-destination-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma-separated list of fields to return. The id field is always returned. | Optional |
| offset | Zero-based offset of the first item to return. Default is 0. | Optional |
| limit | Maximum number of items to return. Default is 10, maximum is 100. | Optional |
| sortby | Field to sort by: name, create_time, or modify_time. | Optional |
| sortorder | Sort order. Possible values are: asc, desc. | Optional |
| filter | Filter expression, e.g. name co "eng" or status in ("pending-update","pending-delete"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-create-destination-profile

***
Create a new destination profile.

#### Base Command

`netskopev2-create-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the profile. Must be unique, maximum 100 characters. | Required |
| description | Description of the profile. Maximum 200 characters. | Optional |
| values | Values for the profile. | Optional |
| type | Profile match type. Possible values are: regex, sensitive, insensitive. | Required |
| label_ids | Label IDs to associate with the profile. | Optional |
| id | Client-supplied ID for the profile. Must be a UUID if provided. | Optional |
| interactive | If true, stage the change as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-get-destination-profile

***
Get a destination profile by ID.

#### Base Command

`netskopev2-get-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-update-destination-profile

***
Partially update a destination profile.

#### Base Command

`netskopev2-update-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| name | New name for the profile. | Optional |
| description | New description for the profile. | Optional |
| values | New values for the profile (replaces the full list). | Optional |
| type | New profile match type. If provided, "values" must also be provided. Possible values are: regex, sensitive, insensitive. | Optional |
| label_ids | New label IDs. An empty list clears existing labels. | Optional |
| interactive | If true, stage the change as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-update-destination-profile-values

***
Append or remove values on a destination profile without replacing the full list.

#### Base Command

`netskopev2-update-destination-profile-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| operation | Whether to append or remove values. Possible values are: append, remove. | Required |
| values | Values to append or remove (1-10 per call). For remove, this is a case-sensitive exact match. | Optional |
| indexes | Index positions to remove (1-10 per call). Only supported for remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-delete-destination-profile

***
Delete a destination profile.

#### Base Command

`netskopev2-delete-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| interactive | If true, stage the deletion as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.status | string | Result status \('success' or 'pending-delete'\). |

### netskopev2-deploy-destination-profiles

***
Deploy staged (pending) changes for destination profiles. Maximum 50 profile IDs per call.

#### Base Command

`netskopev2-deploy-destination-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Profile IDs to deploy (maximum 50). | Optional |
| all | Deploy every pending profile. Requires ids to be empty. Only allowed when 50 or fewer profiles are pending. Possible values are: true, false. Default is false. | Optional |
| change_note | Note describing the change. Maximum 100 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfileDeploy.applied | unknown | IDs of the profiles that were applied. |

### netskopev2-revert-destination-profile

***
Revert a pending update or delete on a destination profile back to its applied version.

#### Base Command

`netskopev2-revert-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-get-destination-profile-applied-version

***
Get the currently applied version of a destination profile, even if a pending change exists.

#### Base Command

`netskopev2-get-destination-profile-applied-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-migrate-url-list-to-destination-profile

***
Migrate an existing URL List into a new Destination Profile. The new profile is created in pending-create status and must be deployed to take effect.

#### Base Command

`netskopev2-migrate-url-list-to-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url_list_id | ID of the URL List to migrate. | Required |
| destination_profile_name | Name for the new destination profile. Defaults to the URL List's name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-migrate-url-list-into-destination-profile

***
Override an existing Destination Profile's values with a URL List's content. The profile is placed in pending-update status and must be deployed to take effect.

#### Base Command

`netskopev2-migrate-url-list-into-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the destination profile to override. | Required |
| url_list_id | ID of the URL List to migrate in. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | Profile ID. |
| Netskope.DestinationProfile.name | string | Profile name. |
| Netskope.DestinationProfile.description | string | Profile description. |
| Netskope.DestinationProfile.type | string | Profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | Profile values. |
| Netskope.DestinationProfile.values_count | number | Number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | Label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | Who created the profile. |
| Netskope.DestinationProfile.create_time | date | When the profile was created. |
| Netskope.DestinationProfile.modify_by | string | Who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | When the profile was last modified. |

### netskopev2-list-network-profiles

***
List and filter network profiles.

#### Base Command

`netskopev2-list-network-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma-separated list of fields to return. The id field is always returned. | Optional |
| offset | Zero-based offset of the first item to return. Default is 0. | Optional |
| limit | Maximum number of items to return. Default is 10, maximum is 100. | Optional |
| sortby | Field to sort by: name, create_time, or modify_time. | Optional |
| sortorder | Sort order. Possible values are: asc, desc. | Optional |
| filter | Filter expression, e.g. name co "eng" or status in ("pending-update","pending-delete"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-create-network-profile

***
Create a new network profile.

#### Base Command

`netskopev2-create-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the profile. Must be unique, maximum 100 characters. | Required |
| description | Description of the profile. Maximum 200 characters. | Optional |
| values | Values for the profile. | Optional |
| id | Client-supplied ID for the profile. Must be a UUID if provided. | Optional |
| interactive | If true, stage the change as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-get-network-profile

***
Get a network profile by ID.

#### Base Command

`netskopev2-get-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-update-network-profile

***
Partially update a network profile.

#### Base Command

`netskopev2-update-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| name | New name for the profile. | Optional |
| description | New description for the profile. | Optional |
| values | New values for the profile (replaces the full list). | Optional |
| interactive | If true, stage the change as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-update-network-profile-values

***
Append or remove values on a network profile without replacing the full list.

#### Base Command

`netskopev2-update-network-profile-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| operation | Whether to append or remove values. Possible values are: append, remove. | Required |
| values | Values to append or remove (1-10 per call). For remove, this is a case-sensitive exact match. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-delete-network-profile

***
Delete a network profile.

#### Base Command

`netskopev2-delete-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| interactive | If true, stage the deletion as pending instead of applying it immediately. Default is false. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.status | string | Result status \('success' or 'pending-delete'\). |

### netskopev2-deploy-network-profiles

***
Deploy staged (pending) changes for network profiles. Maximum 50 profile IDs per call.

#### Base Command

`netskopev2-deploy-network-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Profile IDs to deploy (maximum 50). | Optional |
| all | Deploy every pending profile. Requires ids to be empty. Only allowed when 50 or fewer profiles are pending. Possible values are: true, false. Default is false. | Optional |
| change_note | Note describing the change. Maximum 100 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfileDeploy.applied | unknown | IDs of the profiles that were applied. |

### netskopev2-revert-network-profile

***
Revert a pending update or delete on a network profile back to its applied version.

#### Base Command

`netskopev2-revert-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |
| details | If false, omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-get-network-profile-applied-version

***
Get the currently applied version of a network profile, even if a pending change exists.

#### Base Command

`netskopev2-get-network-profile-applied-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the profile. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | Profile ID. |
| Netskope.NetworkProfile.name | string | Profile name. |
| Netskope.NetworkProfile.description | string | Profile description. |
| Netskope.NetworkProfile.values | unknown | Profile values. |
| Netskope.NetworkProfile.values_count | number | Number of values in the profile. |
| Netskope.NetworkProfile.status | string | Profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | Who created the profile. |
| Netskope.NetworkProfile.create_time | date | When the profile was created. |
| Netskope.NetworkProfile.modify_by | string | Who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | When the profile was last modified. |

### netskopev2-update-file-hash-list

***
Update a Netskope file hash list (Netskope API v1) with the values provided. This replaces the full list content - there is no v1 endpoint to read the current list first. The list must already exist in the Netskope UI.

#### Base Command

`netskopev2-update-file-hash-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of an existing file hash list shown in the Netskope UI. | Required |
| hash | File hashes to set as the full list content. Only MD5 (32 hex characters) or SHA256 (64 hex characters) are accepted - anything else is rejected. This replaces the entire list, so include existing hashes here too if you don't want to lose them. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileHashList.name | string | File hash list name. |
| Netskope.FileHashList.hash | unknown | File hashes set on the list. |

### netskopev2-list-private-apps

***
Query all configured private applications (ZTNA/NPA) and their details.

#### Base Command

`netskopev2-list-private-apps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | Private app ID. |
| Netskope.PrivateApp.id | number | Private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | Private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | Private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | Private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | Public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | Whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | Whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | Whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | Primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | Publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | Policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | Tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | Reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | Who last modified the app. |
| Netskope.PrivateApp.modify_time | date | When the app was last modified. |

### netskopev2-list-publishers

***
List all NPA publishers and their connection status.

#### Base Command

`netskopev2-list-publishers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma-separated list of fields to return (e.g. "publisher_id,publisher_name"). Omit to get every field. Restricting fields is recommended when a publisher has many connected app segments - the full unrestricted response can be large enough that XSOAR strips it from context and attaches it as a file instead. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Publisher.publisher_id | number | Publisher ID. |
| Netskope.Publisher.publisher_name | string | Publisher name. |
| Netskope.Publisher.status | string | Publisher connection status \('connected' or disconnected\). |
| Netskope.Publisher.apps_count | number | Number of apps assigned to this publisher. |
| Netskope.Publisher.connected_apps | unknown | Names of apps currently assigned to this publisher. |
| Netskope.Publisher.common_name | string | Publisher common name. |
| Netskope.Publisher.registered | boolean | Whether the publisher is registered. |
| Netskope.Publisher.assessment | unknown | Publisher host assessment \(version, latency, disk, etc.\). |
| Netskope.Publisher.tags | unknown | Tags associated with the publisher. |
| Netskope.Publisher.upgrade_status | unknown | Publisher upgrade status. |
| Netskope.Publisher.upgrade_request | boolean | Whether an upgrade has been requested. |
| Netskope.Publisher.upgrade_failed_reason | string | Reason the last upgrade failed, if any. |

### netskopev2-create-private-app

***
Create a new private application (ZTNA/NPA) with protocols, host, publishers, and tags.

#### Base Command

`netskopev2-create-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | Name of the private app. Netskope wraps it as "[app_name]". | Required |
| host | IP address or hostname of the private app. | Required |
| protocols | JSON array of {type, port} objects, e.g. [{"type": "tcp", "port": "443"}]. | Required |
| publishers | JSON array of {publisher_id, publisher_name} objects, e.g. [{"publisher_id": "15", "publisher_name": "AWS-NPA"}]. | Required |
| tags | Tag names to associate with the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | Private app ID. |
| Netskope.PrivateApp.id | number | Private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | Private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | Private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | Private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | Public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | Whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | Whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | Whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | Primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | Publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | Policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | Tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | Reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | Who last modified the app. |
| Netskope.PrivateApp.modify_time | date | When the app was last modified. |

### netskopev2-update-private-app

***
Update an existing private application's host, protocols, publishers, or tags. Only fields provided are changed.

#### Base Command

`netskopev2-update-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | ID of the private app to update. | Required |
| app_name | New name for the private app. | Optional |
| host | New IP address or hostname for the private app. | Optional |
| protocols | JSON array of {type, port} objects to replace the app's protocols. | Optional |
| publishers | JSON array of {publisher_id, publisher_name} objects to replace the app's publishers. | Optional |
| tags | Tag names to set on the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | Private app ID. |
| Netskope.PrivateApp.id | number | Private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | Private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | Private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | Private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | Public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | Whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | Whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | Whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | Primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | Publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | Policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | Tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | Reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | Who last modified the app. |
| Netskope.PrivateApp.modify_time | date | When the app was last modified. |

### netskopev2-replace-private-app

***
Full replace of an existing private application via PUT (Netskope's own docs call this "Update a private application" - the same wording as the PATCH-based netskopev2-update-private-app, so "replace" is used here to keep the two unambiguous). Unlike netskopev2-update-private-app, this is not a partial merge: host, protocols, and publishers must all be provided, and any other field you omit may be cleared rather than left unchanged.

#### Base Command

`netskopev2-replace-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | ID of the private app to replace. | Required |
| app_name | New name for the private app. | Optional |
| host | IP address or hostname for the private app. | Required |
| protocols | JSON array of {type, port} objects, e.g. [{"type": "tcp", "port": "443"}]. | Required |
| publishers | JSON array of {publisher_id, publisher_name} objects, e.g. [{"publisher_id": "15", "publisher_name": "AWS-NPA"}]. | Required |
| tags | Tag names to set on the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | Private app ID. |
| Netskope.PrivateApp.id | number | Private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | Private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | Private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | Private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | Public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | Whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | Whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | Whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | Primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | Publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | Policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | Tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | Reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | Who last modified the app. |
| Netskope.PrivateApp.modify_time | date | When the app was last modified. |

### netskopev2-update-private-app-tags

***
Add or replace the tags on one or more existing private apps in bulk, without touching host/protocol/publisher configuration. Powers dynamic, risk-based ZTNA routing by re-tagging apps in place.

#### Base Command

`netskopev2-update-private-app-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Private app ID(s) to re-tag. | Required |
| tags | Tag names to set on the app(s). Replaces the existing tag set. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | Private app ID. |
| Netskope.PrivateApp.app_name | string | Private app name. |
| Netskope.PrivateApp.tags | unknown | Tags now set on the app. |

### netskopev2-delete-private-app

***
Permanently delete a private application. Use when an app is decommissioned or was created for a temporary workflow.

#### Base Command

`netskopev2-delete-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | ID of the private app to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | ID of the deleted private app. |

### netskopev2-submit-file-scan

***
Submit a password-protected .zip file for scan by the Netskope sandbox. Supported encryption: ZipCrypto. Supported member file types: .exe, .pdf, .doc, .xls, .ppt, .rtf. One file per zip, up to 16MB, up to 1000 requests per day.

#### Base Command

`netskopev2-submit-file-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | War Room entry ID of the .zip file to submit for scanning. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileScan.jobid | string | Job ID to use with netskopev2-get-scan-report to retrieve the analysis report. |
| Netskope.FileScan.md5 | string | MD5 hash of the submitted file. |
| Netskope.FileScan.sha256 | string | SHA256 hash of the submitted file. |
| Netskope.FileScan.status | string | Submission status. |

### netskopev2-get-scan-report

***
Get the sandbox analysis report for a file scan job. Up to 10,000 requests per day. Returns a 202-equivalent 'InProgress' status while the scan is still running.

#### Base Command

`netskopev2-get-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jobid | Job ID returned by netskopev2-submit-file-scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileScanReport.jobid | string | Job ID of the scan. |
| Netskope.FileScanReport.md5 | string | MD5 hash of the scanned file. |
| Netskope.FileScanReport.sha256 | string | SHA256 hash of the scanned file. |
| Netskope.FileScanReport.status | string | Scan status \('Ok' if the report is ready, 'InProgress' if the scan is still running\). |
| Netskope.FileScanReport.verdict | string | Sandbox verdict \(e.g. 'malicious', 'benign'\). Only present once status is 'Ok'. |
| Netskope.FileScanReport.av_detection | unknown | Antivirus detection details. |
| Netskope.FileScanReport.dropped | unknown | Files dropped by the sample during sandbox execution. |
| Netskope.FileScanReport.network | unknown | Network activity observed during sandbox execution \(DNS, HTTP, TCP/UDP, etc.\). |
| Netskope.FileScanReport.observed_behavior | unknown | Behavioral summary, grouped by MITRE-style category with severity scores. |
| Netskope.FileScanReport.process_tree | unknown | Process tree observed during sandbox execution. |

### netskopev2-url-lookup

***
Bulk look up URL categorization/reputation info (up to 100 URLs per call). This is a licensed feature - Netskope returns an error if URL Lookup isn't enabled for the tenant.

#### Base Command

`netskopev2-url-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | URLs to look up (maximum 100 per call). | Required |
| disable_dns_lookup | If true, turn off DNS resolution and IP address matching on the queried URLs. Default is false. Possible values are: true, false. | Optional |
| category | Restrict which pre-defined category type is returned. Possible values are: casb, swg. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLLookup.url | string | The queried URL. |
| Netskope.URLLookup.site | string | Site or app name associated with the URL. |
| Netskope.URLLookup.app | string | Application name associated with the URL, if any \(empty otherwise\). |
| Netskope.URLLookup.dynamic_classification | boolean | Whether the site was dynamically categorized based on website content. |
| Netskope.URLLookup.resolved_ip | string | Resolved IP used for URL matching, if DNS resolution succeeded. |
| Netskope.URLLookup.categories.id | string | Matched category ID. |
| Netskope.URLLookup.categories.name | string | Matched category name. |
| Netskope.URLLookup.categories.type | string | Category type \('predefined' or 'custom'\). |
| Netskope.URLLookup.url_lists.id | string | ID of a matched custom URL list. |
| Netskope.URLLookup.url_lists.name | string | Name of a matched custom URL list. |
