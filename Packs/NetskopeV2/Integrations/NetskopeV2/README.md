Manages Netskope policy enforcement workflows for URLs, domains, file hashes, destination and network profiles, device classification, private applications, file inspection, and URL reputation.
This integration was integrated and tested with version xx of Netskope (API v2).

## Configure Netskope - Direct to Zero Trust in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL of Netskope Tenant (e.g. https://tenant.goskope.com) | The URL of the Netskope tenant. | True |
| API Key | The API v2 key used to authenticate to Netskope. | False |
| API v1 Token (for file hash list commands) | The API v1 token used by the file hash list command. | False |
| Trust any certificate (not secure) | Whether to trust unverified TLS certificates. Not recommended. | False |
| Use system proxy settings | Whether to use the system proxy settings for connections. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netskopev2-add-url

***
Adds URLs to the Netskope URL block list.

#### Base Command

`netskopev2-add-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The name of the URL list. | Required |
| url | A comma-separated list of URLs to add to the list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number | The URL List ID. |
| Netskope.URLList.name | string | The URL List name. |
| Netskope.URLList.data | unknown | The URL List contents. |
| Netskope.URLList.data.urls | unknown | The list of URLs in URL List. |
| Netskope.URLList.data.type | string | The URL List type \('exact' or 'regex'\). |
| Netskope.URLList.modify_by | string | The user which last modified URL List. |
| Netskope.URLList.modify_time | date | The date and time when URL List was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.URLList.modify_type | string | The URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.URLList.pending | number | The URL List pending status \('1' if pending, '0' if not\). |

#### Command Example

```
!netskopev2-add-url list_name="Blocked Domains" url=example.com
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-remove-url

***
Removes URLs from the Netskope URL block list.

#### Base Command

`netskopev2-remove-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The name of the URL list. | Required |
| url | A comma-separated list of URLs to remove from the list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.id | number | The URL List ID. |
| Netskope.URLList.name | string | The URL List name. |
| Netskope.URLList.data | unknown | The URL List contents. |
| Netskope.URLList.data.urls | unknown | The list of URLs in URL List. |
| Netskope.URLList.data.type | string | The URL List type \('exact' or 'regex'\). |
| Netskope.URLList.modify_by | string | The user which last modified URL List. |
| Netskope.URLList.modify_time | date | The date and time when URL List was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.URLList.modify_type | string | The URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.URLList.pending | number | The URL List pending status \('1' if pending, '0' if not\). |

#### Command Example

```
!netskopev2-remove-url list_name="Blocked Domains" url=example.com
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-lists

***
Gets all applied and pending URL lists.

#### Base Command

`netskopev2-get-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number | The URL List ID. |
| Netskope.List.name | string | The URL List name. |
| Netskope.List.data | unknown | The URL List contents. |
| Netskope.List.data.urls | unknown | The list of URLs in URL List. |
| Netskope.List.data.type | string | The URL List type \('exact' or 'regex'\). |
| Netskope.List.modify_by | string | The user which last modified URL List. |
| Netskope.List.modify_time | date | The date and time when URL List was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.List.modify_type | string | The URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.List.pending | number | The URL List pending status \('1' if pending, '0' if not\). |

#### Command Example

```
!netskopev2-get-lists
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-list

***
Gets URL list by ID.

#### Base Command

`netskopev2-get-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The name of the URL list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.List.id | number | The URL List ID. |
| Netskope.List.name | string | The URL List name. |
| Netskope.List.data | unknown | The URL List contents. |
| Netskope.List.data.urls | unknown | The list of URLs in URL List. |
| Netskope.List.data.type | string | The URL List type \('exact' or 'regex'\). |
| Netskope.List.modify_by | string | The user which last modified URL List. |
| Netskope.List.modify_time | date | The date and time when URL List was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.List.modify_type | string | The URL List modification type \('Created', 'Edited' or 'Deleted'\). |
| Netskope.List.pending | number | The URL List pending status \('1' if pending, '0' if not\). |

#### Command Example

```
!netskopev2-get-list list_name="Blocked Domains"
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-device-classification-tags

***
Lists existing device classification tags. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-list-device-classification-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationTag.id | number | The device classification tag ID. |
| Netskope.DeviceClassificationTag.priority | number | The device classification tag priority. |
| Netskope.DeviceClassificationTag.name | string | The device classification tag name. |
| Netskope.DeviceClassificationTag.description | string | The device classification tag description. |
| Netskope.DeviceClassificationTag.modifiedBy | string | The user which last modified the tag. |
| Netskope.DeviceClassificationTag.modifiedTime | date | The time the tag was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DeviceClassificationTag.policyNames | unknown | The names of policies referencing this classification tag. |

#### Command Example

```
!netskopev2-list-device-classification-tags
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-device-classification-tag

***
Creates a new device classification tag (label). Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-classification-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the device classification tag. | Required |
| description | The description of the device classification tag. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationTag.ids | unknown | The IDs of the created device classification tag\(s\). |
| Netskope.DeviceClassificationTag.name | string | The device classification tag name. |
| Netskope.DeviceClassificationTag.description | string | The device classification tag description. |

#### Command Example

```
!netskopev2-create-device-classification-tag name="Sample Profile"
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-device-classification-rule

***
Creates a device classification rule linking conditions (OS version, device tag presence, etc.) to a classification label. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-classification-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the classification rule. | Required |
| label | The name of the classification tag this rule applies (must already exist). | Required |
| os | The operating system this rule applies to. Possible values are: windows, mac, linux, android, ios. | Required |
| conditions | The JSON object describing the rule conditions, e.g. {"$and": [{"device_tag_check": {"tag_id": 1137}}]}. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceClassificationRule.ids | unknown | The IDs of the created device classification rule\(s\). |
| Netskope.DeviceClassificationRule.name | string | The device classification rule name. |
| Netskope.DeviceClassificationRule.label | string | The device classification tag name this rule applies. |
| Netskope.DeviceClassificationRule.os | string | The operating system this rule applies to. |

#### Command Example

```
!netskopev2-create-device-classification-rule name="Sample Profile" label="Low Risk" os=windows conditions='{"$and":[{"device_tag_check":{"tag_id":1137}}]}'
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-find-device

***
Finds devices by client status query, to resolve a device's nsdeviceuid before tagging it. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-find-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The UNIX timestamp for the start of the query window. | Required |
| end_time | The UNIX timestamp for the end of the query window. | Required |
| fields | The comma-separated list of fields to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Device.nsdeviceuid | string | The Netskope device UID. |
| Netskope.Device.hostname | string | The device hostname. |
| Netskope.Device.os | string | The device operating system. |
| Netskope.Device.client_version | string | The Netskope client version installed on the device. |

#### Command Example

```
!netskopev2-find-device start_time="2026-01-01T00:00:00Z" end_time="2026-01-02T00:00:00Z"
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-device-tag

***
Registers a new device tag. Check netskopev2-list-device-tags first to avoid creating a duplicate. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-create-device-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the device tag. | Required |
| description | The description of the device tag. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTag.id | number | The device tag ID. |
| Netskope.DeviceTag.name | string | The device tag name. |
| Netskope.DeviceTag.description | string | The device tag description. |

#### Command Example

```
!netskopev2-create-device-tag name="Sample Profile"
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-device-tags

***
Finds existing device tags applied to a device. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-list-device-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The Netskope device UID (nsdeviceuid) to look up tags for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTag.id | number | The device tag ID. |
| Netskope.DeviceTag.name | string | The device tag name. |

#### Command Example

```
!netskopev2-list-device-tags device_id=device-123
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-apply-device-tags

***
Applies device tag(s) to one or more devices. This replaces all existing tags on the specified devices — it is not additive. Requires the Device Classification API (beta) to be enabled for the tenant.

#### Base Command

`netskopev2-apply-device-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | A comma-separated list of device tag IDs to apply. A device supports a maximum of 5 tags. | Required |
| nsdeviceuid | A comma-separated list of netskope device UIDs (nsdeviceuid) to apply the tags to. | Required |
| hostname | The hostname to associate with the device entries. | Optional |
| userkey | The user key to associate with the device entries. If omitted, the device UID is used. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DeviceTagApplication.affected_device_tags | number | The number of device tags affected. |
| Netskope.DeviceTagApplication.affected_device_classification_tags | number | The number of device classification tags affected. |
| Netskope.DeviceTagApplication.message | string | The result message. |

#### Command Example

```
!netskopev2-apply-device-tags tag_id=1137 nsdeviceuid=device-uid-123
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-destination-profiles

***
Lists and filters destination profiles.

#### Base Command

`netskopev2-list-destination-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | The comma-separated list of fields to return. The id field is always returned. | Optional |
| page | The page number to return. Must be used with page_size. | Optional |
| page_size | The number of items per page, from 1 through 100. | Optional |
| limit | The maximum number of items to return when page is not specified, up to 100. Default is 10. | Optional |
| sortby | The field to sort by: name, create_time, or modify_time. | Optional |
| sortorder | The sort order. Possible values are: asc, desc. | Optional |
| filter | The filter expression, e.g. name co "eng" or status in ("pending-update","pending-delete"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-list-destination-profiles
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-destination-profile

***
Creates a new destination profile.

#### Base Command

`netskopev2-create-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the profile. Must be unique, maximum 100 characters. | Required |
| description | The description of the profile. Maximum 200 characters. | Optional |
| values | A comma-separated list of values for the profile. | Optional |
| type | The profile match type. Possible values are: regex, sensitive, insensitive. | Required |
| label_ids | A comma-separated list of label IDs to associate with the profile. | Optional |
| id | The client-supplied ID for the profile. Must be a UUID if provided. | Optional |
| interactive | Whether to stage the change as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-create-destination-profile name="Sample Profile" type=regex
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-destination-profile

***
Gets a destination profile by ID.

#### Base Command

`netskopev2-get-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-get-destination-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-destination-profile

***
Partially updates a destination profile.

#### Base Command

`netskopev2-update-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| name | The new name for the profile. | Optional |
| description | The new description for the profile. | Optional |
| values | A comma-separated list of new values for the profile (replaces the full list). | Optional |
| type | The new profile match type. If provided, "values" must also be provided. Possible values are: regex, sensitive, insensitive. | Optional |
| label_ids | A comma-separated list of new label IDs. An empty list clears existing labels. | Optional |
| interactive | Whether to stage the change as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-update-destination-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-destination-profile-values

***
Appends or removes values on a destination profile without replacing the full list.

#### Base Command

`netskopev2-update-destination-profile-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| operation | Whether to append or remove values. Possible values are: append, remove. | Required |
| values | A comma-separated list of values to append or remove (1-10 per call). For remove, this is a case-sensitive exact match. | Optional |
| indexes | A comma-separated list of index positions to remove (1-10 per call). Only supported for remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-update-destination-profile-values id=profile-1 operation=append
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-delete-destination-profile

***
Deletes a destination profile.

#### Base Command

`netskopev2-delete-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| interactive | Whether to stage the deletion as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.status | string | The result status \('success' or 'pending-delete'\). |

#### Command Example

```
!netskopev2-delete-destination-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-deploy-destination-profiles

***
Deploys staged (pending) changes for destination profiles. Maximum 50 profile IDs per call.

#### Base Command

`netskopev2-deploy-destination-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of profile IDs to deploy (maximum 50). | Optional |
| all | Whether the all option is enabled. Deploy every pending profile. Requires ids to be empty. Only allowed when 50 or fewer profiles are pending. Possible values are: true, false. Default is false. | Optional |
| change_note | The note describing the change. Maximum 100 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfileDeploy.applied | unknown | The IDs of the profiles that were applied. |

#### Command Example

```
!netskopev2-deploy-destination-profiles
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-revert-destination-profile

***
Reverts a pending update or delete on a destination profile back to its applied version.

#### Base Command

`netskopev2-revert-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-revert-destination-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-destination-profile-applied-version

***
Gets the currently applied version of a destination profile, even if a pending change exists.

#### Base Command

`netskopev2-get-destination-profile-applied-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-get-destination-profile-applied-version id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-migrate-url-list-to-destination-profile

***
Migrates an existing URL List into a new Destination Profile. The new profile is created in pending-create status and must be deployed to take effect.

#### Base Command

`netskopev2-migrate-url-list-to-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url_list_id | The ID of the URL List to migrate. | Required |
| destination_profile_name | The name for the new destination profile. If omitted, the URL List's name is used. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-migrate-url-list-to-destination-profile url_list_id=1234
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-migrate-url-list-into-destination-profile

***
Overrides an existing Destination Profile's values with a URL List's content. The profile is placed in pending-update status and must be deployed to take effect.

#### Base Command

`netskopev2-migrate-url-list-into-destination-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the destination profile to override. | Required |
| url_list_id | The ID of the URL List to migrate in. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.DestinationProfile.id | string | The profile ID. |
| Netskope.DestinationProfile.name | string | The profile name. |
| Netskope.DestinationProfile.description | string | The profile description. |
| Netskope.DestinationProfile.type | string | The profile type \('regex', 'sensitive', or 'insensitive'\). |
| Netskope.DestinationProfile.values | unknown | The profile values. |
| Netskope.DestinationProfile.values_count | number | The number of values in the profile. |
| Netskope.DestinationProfile.label_ids | unknown | The label IDs associated with the profile. |
| Netskope.DestinationProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.DestinationProfile.create_by | string | The user who created the profile. |
| Netskope.DestinationProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.DestinationProfile.modify_by | string | The user who last modified the profile. |
| Netskope.DestinationProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-migrate-url-list-into-destination-profile id=profile-1 url_list_id=1234
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-network-profiles

***
Lists and filters network profiles.

#### Base Command

`netskopev2-list-network-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | The comma-separated list of fields to return. The id field is always returned. | Optional |
| page | The page number to return. Must be used with page_size. | Optional |
| page_size | The number of items per page, from 1 through 100. | Optional |
| limit | The maximum number of items to return when page is not specified, up to 100. Default is 10. | Optional |
| sortby | The field to sort by: name, create_time, or modify_time. | Optional |
| sortorder | The sort order. Possible values are: asc, desc. | Optional |
| filter | The filter expression, e.g. name co "eng" or status in ("pending-update","pending-delete"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-list-network-profiles
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-network-profile

***
Creates a new network profile.

#### Base Command

`netskopev2-create-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the profile. Must be unique, maximum 100 characters. | Required |
| description | The description of the profile. Maximum 200 characters. | Optional |
| values | A comma-separated list of values for the profile. | Optional |
| id | The client-supplied ID for the profile. Must be a UUID if provided. | Optional |
| interactive | Whether to stage the change as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-create-network-profile name="Sample Profile"
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-network-profile

***
Gets a network profile by ID.

#### Base Command

`netskopev2-get-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-get-network-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-network-profile

***
Partially updates a network profile.

#### Base Command

`netskopev2-update-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| name | The new name for the profile. | Optional |
| description | The new description for the profile. | Optional |
| values | A comma-separated list of new values for the profile (replaces the full list). | Optional |
| interactive | Whether to stage the change as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-update-network-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-network-profile-values

***
Appends or removes values on a network profile without replacing the full list.

#### Base Command

`netskopev2-update-network-profile-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| operation | Whether to append or remove values. Possible values are: append, remove. | Required |
| values | A comma-separated list of values to append or remove (1-10 per call). For remove, this is a case-sensitive exact match. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-update-network-profile-values id=profile-1 operation=append
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-delete-network-profile

***
Deletes a network profile.

#### Base Command

`netskopev2-delete-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| interactive | Whether to stage the deletion as pending instead of applying it immediately. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.status | string | The result status \('success' or 'pending-delete'\). |

#### Command Example

```
!netskopev2-delete-network-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-deploy-network-profiles

***
Deploys staged (pending) changes for network profiles. Maximum 50 profile IDs per call.

#### Base Command

`netskopev2-deploy-network-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of profile IDs to deploy (maximum 50). | Optional |
| all | Whether the all option is enabled. Deploy every pending profile. Requires ids to be empty. Only allowed when 50 or fewer profiles are pending. Possible values are: true, false. Default is false. | Optional |
| change_note | The note describing the change. Maximum 100 characters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfileDeploy.applied | unknown | The IDs of the profiles that were applied. |

#### Command Example

```
!netskopev2-deploy-network-profiles
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-revert-network-profile

***
Reverts a pending update or delete on a network profile back to its applied version.

#### Base Command

`netskopev2-revert-network-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |
| details | Whether to omit the values array from the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-revert-network-profile id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-network-profile-applied-version

***
Gets the currently applied version of a network profile, even if a pending change exists.

#### Base Command

`netskopev2-get-network-profile-applied-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the profile. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.NetworkProfile.id | string | The profile ID. |
| Netskope.NetworkProfile.name | string | The profile name. |
| Netskope.NetworkProfile.description | string | The profile description. |
| Netskope.NetworkProfile.values | unknown | The profile values. |
| Netskope.NetworkProfile.values_count | number | The number of values in the profile. |
| Netskope.NetworkProfile.status | string | The profile status \('applied', 'pending-create', 'pending-update', or 'pending-delete'\). |
| Netskope.NetworkProfile.create_by | string | The user who created the profile. |
| Netskope.NetworkProfile.create_time | date | The date and time when the profile was created, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |
| Netskope.NetworkProfile.modify_by | string | The user who last modified the profile. |
| Netskope.NetworkProfile.modify_time | date | The date and time when the profile was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-get-network-profile-applied-version id=profile-1
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-file-hash-list

***
Updates a Netskope file hash list (Netskope API v1) with the values provided. This replaces the full list content—there is no v1 endpoint to read the current list first. The list must already exist in the Netskope UI.

#### Base Command

`netskopev2-update-file-hash-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of an existing file hash list shown in the Netskope UI. | Required |
| hash | A comma-separated list of file hashes to set as the full list content. Only MD5 (32 hex characters) or SHA256 (64 hex characters) are accepted - anything else is rejected. This replaces the entire list, so include existing hashes here too if you don't want to lose them. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileHashList.name | string | The file hash list name. |
| Netskope.FileHashList.hash | unknown | The file hashes set on the list. |

#### Command Example

```
!netskopev2-update-file-hash-list name="Sample Profile" hash=44d88612fea8a8f36de82e1278abb02f
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-private-apps

***
Queries all configured private applications (ZTNA/NPA) and their details.

#### Base Command

`netskopev2-list-private-apps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of private applications to return. Default is 50. | Optional |
| all_results | Whether to return all private applications and ignore the limit argument. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The private app ID. |
| Netskope.PrivateApp.id | number | The private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | The private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | The private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | The private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | The public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | The value indicating whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | The value indicating whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | The value indicating whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | The primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | The TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | The publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | The policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | The tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | The reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | The user who last modified the app. |
| Netskope.PrivateApp.modify_time | date | The date and time when the app was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-list-private-apps
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-list-publishers

***
Lists all NPA publishers and their connection status.

#### Base Command

`netskopev2-list-publishers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | The comma-separated list of fields to return (e.g. "publisher_id,publisher_name"). Omit to get every field. Restricting fields is recommended when a publisher has many connected app segments - the full unrestricted response can be large enough that Cortex XSOAR strips it from context and attaches it as a file instead. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Publisher.publisher_id | number | The publisher ID. |
| Netskope.Publisher.publisher_name | string | The publisher name. |
| Netskope.Publisher.status | string | The publisher connection status \('connected' or disconnected\). |
| Netskope.Publisher.apps_count | number | The number of apps assigned to this publisher. |
| Netskope.Publisher.connected_apps | unknown | The names of apps currently assigned to this publisher. |
| Netskope.Publisher.common_name | string | The publisher common name. |
| Netskope.Publisher.registered | boolean | The value indicating whether the publisher is registered. |
| Netskope.Publisher.assessment | unknown | The publisher host assessment \(version, latency, disk, etc.\). |
| Netskope.Publisher.tags | unknown | The tags associated with the publisher. |
| Netskope.Publisher.upgrade_status | unknown | The publisher upgrade status. |
| Netskope.Publisher.upgrade_request | boolean | The value indicating whether an upgrade has been requested. |
| Netskope.Publisher.upgrade_failed_reason | string | The reason the last upgrade failed, if any. |

#### Command Example

```
!netskopev2-list-publishers
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-create-private-app

***
Creates a new private application (ZTNA/NPA) with protocols, host, publishers, and tags.

#### Base Command

`netskopev2-create-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the private app. Netskope wraps it as "[app_name]". | Required |
| host | The IP address or hostname of the private app. | Required |
| protocols | The JSON array of {type, port} objects, e.g. [{"type": "tcp", "port": "443"}]. | Required |
| publishers | The JSON array of {publisher_id, publisher_name} objects, e.g. [{"publisher_id": "15", "publisher_name": "AWS-NPA"}]. | Required |
| tags | A comma-separated list of tag names to associate with the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Whether to enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Whether to allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Whether to accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The private app ID. |
| Netskope.PrivateApp.id | number | The private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | The private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | The private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | The private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | The public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | The value indicating whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | The value indicating whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | The value indicating whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | The primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | The TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | The publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | The policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | The tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | The reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | The user who last modified the app. |
| Netskope.PrivateApp.modify_time | date | The date and time when the app was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-create-private-app app_name="Sample Private App" host=10.0.0.10 protocols='[{"type":"tcp","port":"443"}]' publishers='[{"publisher_id":"15","publisher_name":"AWS-NPA"}]'
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-private-app

***
Updates an existing private application's host, protocols, publishers, or tags. Only fields provided are changed.

#### Base Command

`netskopev2-update-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The ID of the private app to update. | Required |
| app_name | The new name for the private app. | Optional |
| host | The new IP address or hostname for the private app. | Optional |
| protocols | The JSON array of {type, port} objects to replace the app's protocols. | Optional |
| publishers | The JSON array of {publisher_id, publisher_name} objects to replace the app's publishers. | Optional |
| tags | A comma-separated list of tag names to set on the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Whether to enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Whether to allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Whether to accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The private app ID. |
| Netskope.PrivateApp.id | number | The private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | The private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | The private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | The private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | The public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | The value indicating whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | The value indicating whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | The value indicating whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | The primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | The TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | The publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | The policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | The tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | The reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | The user who last modified the app. |
| Netskope.PrivateApp.modify_time | date | The date and time when the app was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-update-private-app app_id=3
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-replace-private-app

***
Fully replaces an existing private application through PUT. Netskope's documentation calls this operation "Update a private application," which is also the wording used for the PATCH-based netskopev2-update-private-app command. This command uses "replace" to distinguish the two operations. Unlike netskopev2-update-private-app, this is not a partial merge: host, protocols, and publishers must all be provided, and any other omitted field may be cleared rather than left unchanged.

#### Base Command

`netskopev2-replace-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The ID of the private app to replace. | Required |
| app_name | The new name for the private app. | Optional |
| host | The IP address or hostname for the private app. | Required |
| protocols | The JSON array of {type, port} objects, e.g. [{"type": "tcp", "port": "443"}]. | Required |
| publishers | The JSON array of {publisher_id, publisher_name} objects, e.g. [{"publisher_id": "15", "publisher_name": "AWS-NPA"}]. | Required |
| tags | A comma-separated list of tag names to set on the app, for policy matching. | Optional |
| use_publisher_dns | Whether to use the publisher's DNS. | Optional |
| clientless_access | Whether to enable browser-based (clientless) access. | Optional |
| allow_unauthenticated_cors | Whether to allow unauthenticated CORS requests. | Optional |
| trust_self_signed_certs | Whether to accept self-signed certificates. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The private app ID. |
| Netskope.PrivateApp.id | number | The private app ID \(alias returned on create/update\). |
| Netskope.PrivateApp.app_name | string | The private app name \(wrapped in brackets by Netskope\). |
| Netskope.PrivateApp.name | string | The private app name \(alias returned on create\). |
| Netskope.PrivateApp.host | string | The private IP address or hostname of the app. |
| Netskope.PrivateApp.public_host | string | The public host, if configured. |
| Netskope.PrivateApp.clientless_access | boolean | The value indicating whether browser-based \(clientless\) access is enabled. |
| Netskope.PrivateApp.trust_self_signed_certs | boolean | The value indicating whether self-signed certificates are trusted. |
| Netskope.PrivateApp.use_publisher_dns | boolean | The value indicating whether the publisher's DNS is used. |
| Netskope.PrivateApp.private_app_protocol | string | The primary protocol of the private app. |
| Netskope.PrivateApp.protocols | unknown | The TCP/UDP ports and transport configured for the app. |
| Netskope.PrivateApp.service_publisher_assignments | unknown | The publishers providing access to the app. |
| Netskope.PrivateApp.policies | unknown | The policies referencing this app. |
| Netskope.PrivateApp.tags | unknown | The tags associated with the app, used for policy matching. |
| Netskope.PrivateApp.reachability | unknown | The reachability status of the app. |
| Netskope.PrivateApp.modified_by | string | The user who last modified the app. |
| Netskope.PrivateApp.modify_time | date | The date and time when the app was last modified, in ISO 8601 format \(for example, 2026-01-01T12:00:00Z\). |

#### Command Example

```
!netskopev2-replace-private-app app_id=3 host=10.0.0.10 protocols='[{"type":"tcp","port":"443"}]' publishers='[{"publisher_id":"15","publisher_name":"AWS-NPA"}]'
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-update-private-app-tags

***
Adds or replaces the tags on one or more existing private apps in bulk, without touching host/protocol/publisher configuration. Powers dynamic, risk-based ZTNA routing by re-tagging apps in place.

#### Base Command

`netskopev2-update-private-app-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | A comma-separated list of private app IDs to re-tag. | Required |
| tags | A comma-separated list of tag names to set on the apps. Replaces the existing tag set. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The private app ID. |
| Netskope.PrivateApp.app_name | string | The private app name. |
| Netskope.PrivateApp.tags | unknown | The tags now set on the app. |

#### Command Example

```
!netskopev2-update-private-app-tags app_id=3 tags=quarantine
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-delete-private-app

***
Permanently deletes a private application. Use when an app is decommissioned or was created for a temporary workflow.

#### Base Command

`netskopev2-delete-private-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The ID of the private app to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.PrivateApp.app_id | number | The ID of the deleted private app. |

#### Command Example

```
!netskopev2-delete-private-app app_id=3
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-submit-file-scan

***
Submits a password-protected .zip file for scan by the Netskope sandbox. Supported encryption: ZipCrypto. Supported member file types: .exe, .pdf, .doc, .xls, .ppt, .rtf. One file per zip, up to 16MB, up to 1000 requests per day.

#### Base Command

`netskopev2-submit-file-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the .zip file to submit for scanning. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileScan.jobid | string | The job ID to use with netskopev2-get-scan-report to retrieve the analysis report. |
| Netskope.FileScan.md5 | string | The MD5 hash of the submitted file. |
| Netskope.FileScan.sha256 | string | The SHA256 hash of the submitted file. |
| Netskope.FileScan.status | string | The submission status. |

#### Command Example

```
!netskopev2-submit-file-scan entry_id=123@abc
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-get-scan-report

***
Gets the sandbox analysis report for a file scan job. Up to 10,000 requests per day. Returns a 202-equivalent 'InProgress' status while the scan is still running.

#### Base Command

`netskopev2-get-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jobid | The job ID returned by netskopev2-submit-file-scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.FileScanReport.jobid | string | The job ID of the scan. |
| Netskope.FileScanReport.md5 | string | The MD5 hash of the scanned file. |
| Netskope.FileScanReport.sha256 | string | The SHA256 hash of the scanned file. |
| Netskope.FileScanReport.status | string | The scan status \('Ok' if the report is ready, 'InProgress' if the scan is still running\). |
| Netskope.FileScanReport.verdict | string | The sandbox verdict \(e.g. 'malicious', 'benign'\). Only present once status is 'Ok'. |
| Netskope.FileScanReport.av_detection | unknown | The antivirus detection details. |
| Netskope.FileScanReport.dropped | unknown | The files dropped by the sample during sandbox execution. |
| Netskope.FileScanReport.network | unknown | The network activity observed during sandbox execution \(DNS, HTTP, TCP/UDP, etc.\). |
| Netskope.FileScanReport.observed_behavior | unknown | The behavioral summary, grouped by MITRE-style category with severity scores. |
| Netskope.FileScanReport.process_tree | unknown | The process tree observed during sandbox execution. |

#### Command Example

```
!netskopev2-get-scan-report jobid=8ffdffbdbe1efccb32edfaca
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.

### netskopev2-url-lookup

***
Looks up URL categorization/reputation info (up to 100 URLs per call). This is a licensed feature - Netskope returns an error if URL Lookup isn't enabled for the tenant.

#### Base Command

`netskopev2-url-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma-separated list of URLs to look up (maximum 100 per call). | Required |
| disable_dns_lookup | Whether to turn off DNS resolution and IP address matching on the queried URLs. Possible values are: true, false. Default is false. | Optional |
| category | The predefined category type to return. Possible values are: casb, swg. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLLookup.url | string | The queried URL. |
| Netskope.URLLookup.site | string | The site or app name associated with the URL. |
| Netskope.URLLookup.app | string | The application name associated with the URL, if any \(empty otherwise\). |
| Netskope.URLLookup.dynamic_classification | boolean | The value indicating whether the site was dynamically categorized based on website content. |
| Netskope.URLLookup.resolved_ip | string | The resolved IP used for URL matching, if DNS resolution succeeded. |
| Netskope.URLLookup.categories.id | string | The matched category ID. |
| Netskope.URLLookup.categories.name | string | The matched category name. |
| Netskope.URLLookup.categories.type | string | The category type \('predefined' or 'custom'\). |
| Netskope.URLLookup.url_lists.id | string | The ID of a matched custom URL list. |
| Netskope.URLLookup.url_lists.name | string | The name of a matched custom URL list. |

#### Command Example

```
!netskopev2-url-lookup urls=https://www.example.com
```

#### Human Readable Output

The command returns the result in the War Room and stores the documented Netskope data in context.
