This integration uses ZIdentity OAuth 2.0 client credentials to authenticate with Zscaler Internet Access (ZIA). It enables the management of denylists, allowlists, URL categories, IP destination groups, and users/groups, while also providing URL, IP, and domain classifications and sandbox reporting..

This integration is currently in Beta, allowing you to test pre-release software. Note that it may contain bugs, and future updates could include changes that are not backward compatible. We welcome your feedback to help us identify issues and improve the integration.

## Configure Zscaler Internet Access via ZIdentity (Beta) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Server URL assigned to your organization. For example, www.acme.zslogin.net. | True |
| Client ID | The OAuth 2.0 client ID from ZIdentity. | True |
| Client Secret | The OAuth 2.0 client secret from ZIdentity. | True |
| Auto Activate Changes | If enabled, the integration will activate the command changes after each execution. If disabled, use the 'zia-activate-changes' command to activate Zscaler command changes. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Suspicious URL categories | Suspicious URL categories for security alerts. Default: SUSPICIOUS_DESTINATION, SPYWARE_OR_ADWARE. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zia-denylist-list

***
Gets a list of URLs and IPs that are in the denylist.

#### Base Command

`zia-denylist-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter results by URL or IP objects. Possible values are: url, ip. | Optional |
| query | Query to match against (Python regular expressions, for example, 8.*.*.8). | Optional |
| limit | The number of items to return. Default is 50. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.DenyList | String | The list of URLs and IPs on the denylist. |

#### Command Example

```!zia-denylist-list filter=url limit=10```

#### Human Readable Output

>### Denylist
>
>|URL|
>|---|
>| malware.com |
>| phishing.net |

### zia-denylist-update

***
Updates the list of URLs and IPs that are in the denylist.

#### Base Command

`zia-denylist-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to update the denylist. For example, snapchat.com,facebook.com. | Optional |
| ip | A comma-separated list of IPs to update the denylist. For example, 1.2.3.4,8.8.8.8. | Optional |
| action | The action applied to the denylist. Possible values are: ADD_TO_LIST, REMOVE_FROM_LIST, OVERWRITE. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zia-denylist-update url=malware.com,phishing.net action=ADD_TO_LIST```

#### Human Readable Output

>Denylist updated successfully.

### zia-allowlist-list

***
Gets a list of URLs and IPs that are in the allowlist.

#### Base Command

`zia-allowlist-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter results by URL or IP objects. Possible values are: url, ip. | Optional |
| query | Query to match against (Python regular expressions, for example, 8.*.*.8). | Optional |
| limit | The number of items to return. Default is 50. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.AllowList | String | The list of URLs in the allowlist. |

#### Command Example

```!zia-allowlist-list filter=url limit=10```

#### Human Readable Output

>### Allowlist
>
>|URL|
>|---|
>| trusted.com |
>| safe.net |

### zia-allowlist-update

***
Updates the list of URLs that are in the allowlist.

#### Base Command

`zia-allowlist-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to update in the allowlist. For example, snapchat.com,facebook.com. | Optional |
| ip | A comma-separated list of IPs to update in the allowlist. For example, 1.2.3.4,8.8.8.8. | Optional |
| action | The action applied to the allowlist. Possible values are: ADD_TO_LIST, REMOVE_FROM_LIST, OVERWRITE. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zia-allowlist-update url=trusted.com action=ADD_TO_LIST```

#### Human Readable Output

>Allowlist updated successfully.

### zia-category-list

***
Gets information about all or custom URL categories. By default, the response includes keywords. The lite option cannot be used in combination with other parameters.

#### Base Command

`zia-category-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category_id | The URL category for the specified ID. For more information about category ID values, see [the Zscaler documentation](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/url-categories/get-url-categories). | Optional |
| custom_only | If set to true, gets information on custom URL categories only. Default  is false. | Optional |
| include_only_url_keyword_counts | If set to true, the response only includes URL and keyword counts. Default is false. | Optional |
| lite | Whether to get a lightweight key-value list of all or custom URL categories. Cannot be used with other parameters. Default is false. | Optional |
| limit | The number of items to return. Default is 50. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |
| display_url | Whether to display the URLs of each category in the War Room. URLs will always be returned to the Context Data. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.Category.id | String | The ID of the category. |
| ZIA.Category.configuredName | String | The configured name of the category. |
| ZIA.Category.superCategory | String | The super category of the category. |
| ZIA.Category.keywords | String | The keywords associated with the category. |
| ZIA.Category.urls | String | The URLs in the category. |
| ZIA.Category.customCategory | Boolean | Whether the category is a custom category. |

#### Command Example

```!zia-category-list custom_only=true```

#### Context Example

```json
{
    "ZIA": {
        "Category": [
            {
                "id": "CUSTOM_01",
                "configuredName": "My Custom Category",
                "superCategory": "USER_DEFINED",
                "keywords": ["example"],
                "urls": ["example.com"],
                "customCategory": true
            }
        ]
    }
}
```

#### Human Readable Output

>### URL Categories
>
>|ID|Configured Name|Super Category|Custom Category|
>|---|---|---|---|
>| CUSTOM_01 | My Custom Category | USER_DEFINED | true |

### zia-category-update

***
Updates the URL category for the specified ID.

#### Base Command

`zia-category-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category_id | The URL category for the specified ID. For more information about category ID values, see [the Zscaler documentation](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/url-categories/get-url-categories). | Required |
| url | A comma-separated list of URLs to update in the specified category. For example, pandora.com,spotify.com. Important: If any URL contains a comma (,), you must pass the url argument as a JSON list wrapped in backticks (\`). Example: url=\`["https://example.com/foo,bar"]\`. | Optional |
| ip | A comma-separated list of IP ranges to update in the specified category. For example, 1.2.3.4,8.8.8.8. | Optional |
| action | The action applied to the URL category. Possible values are: ADD_TO_LIST, REMOVE_FROM_LIST, OVERWRITE. | Required |
| keywords | Custom keywords associated with a URL category. Up to 2048 custom keywords can be added per organization across all categories. | Optional |
| description | Description of the URL category. Contains tag name and needs to be localized on client side in case of predefined category. | Optional |
| db_categorized_urls | URLs added to a custom URL category that are also retained under the original parent URL category. | Optional |
| keywords_retaining_parent_category | Retained custom keywords from the parent URL category. Up to 2048 retained parent keywords can be added per organization across all categories. | Optional |
| ip_ranges_retaining_parent_category | The retaining parent custom IP address ranges associated with a URL category. Up to 2000 custom IP ranges and retaining parent custom IP address ranges can be added, per organization, across all categories. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!zia-category-update category_id=CUSTOM_01 url=pandora.com,spotify.com action=ADD_TO_LIST```

#### Human Readable Output

>Category CUSTOM_01 updated successfully.

### zia-url-quota-get

***
Gets information on the number of unique URLs that are currently provisioned for your organization as well as how many URLs you can add before reaching that number.

#### Base Command

`zia-url-quota-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.UrlQuota.uniqueUrlsProvisioned | Number | The number of unique URLs that are currently provisioned for your organization. |
| ZIA.UrlQuota.remainingUrlsQuota | Number | The number of URLs you can add before reaching the quota. |

#### Command Example

```!zia-url-quota-get```

#### Context Example

```json
{
    "ZIA": {
        "UrlQuota": {
            "uniqueUrlsProvisioned": 25000,
            "remainingUrlsQuota": 24850
        }
    }
}
```

#### Human Readable Output

>### URL Quota
>
>|Unique URLs Provisioned|Remaining URLs Quota|
>|---|---|
>| 25000 | 24850 |

### zia-ip-destination-group-list

***
Gets a list of all IP destination groups or for the specified ID.

#### Base Command

`zia-ip-destination-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The unique identifier for the IP destination group. | Optional |
| include_ipv6 | Whether to retrieve IPv6 destination groups. Default is False. | Optional |
| exclude_type | Filter based on the IP destination group's type. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| category_type | Filter based on the IP destination group's type. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| lite | Gets a lightweight dictionary (name and ID) of all IP destination groups. Default is False. | Optional |
| limit | The number of items to return. Default is 50. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.IPDestinationGroup.id | Number | Unique identifier for the destination IP group. |
| ZIA.IPDestinationGroup.name | String | Destination IP group name. |
| ZIA.IPDestinationGroup.type | String | Destination IP group type. |
| ZIA.IPDestinationGroup.addresses | String | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| ZIA.IPDestinationGroup.description | String | Additional information about the destination IP group. |
| ZIA.IPDestinationGroup.countries | String | Destination IP address countries. |
| ZIA.IPDestinationGroup.ipCategories | String | Destination IP address URL categories. |

#### Command Example

```!zia-ip-destination-group-list limit=5```

#### Context Example

```json
{
    "ZIA": {
        "IPDestinationGroup": [
            {
                "id": 1234,
                "name": "My IP Group",
                "type": "DSTN_IP",
                "addresses": ["8.8.8.8", "1.1.1.1"],
                "description": "DNS servers",
                "countries": [],
                "ipCategories": []
            }
        ]
    }
}
```

#### Human Readable Output

>### IP Destination Groups
>
>|ID|Name|Type|Addresses|Description|
>|---|---|---|---|---|
>| 1234 | My IP Group | DSTN_IP | 8.8.8.8, 1.1.1.1 | DNS servers |

### zia-ip-destination-group-update

***
Updates an existing IP destination group.

#### Base Command

`zia-ip-destination-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The unique identifier for the IP destination group. | Required |
| group_name | Destination IP group name. | Optional |
| group_type | Destination IP group type. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| address | Destination IP addresses. | Optional |
| action | The action applied to the addresses list. Possible values are: ADD_TO_LIST, REMOVE_FROM_LIST, OVERWRITE. | Required |
| description | Additional information about the destination IP group. | Optional |
| ip_category | Destination IP address URL categories. Possible values can be found [here](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/firewall-policies/ip-destination-group-resource-edit-destination-ip-group). | Optional |
| country | Destination IP address countries. Possible values can be found [here](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/firewall-policies/ip-destination-group-resource-edit-destination-ip-group). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.IPDestinationGroup.id | Number | Unique identifier for the destination IP group. |
| ZIA.IPDestinationGroup.name | String | Destination IP group name. |
| ZIA.IPDestinationGroup.type | String | Destination IP group type. |
| ZIA.IPDestinationGroup.addresses | String | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| ZIA.IPDestinationGroup.description | String | Additional information about the destination IP group. |
| ZIA.IPDestinationGroup.countries | String | Destination IP address countries. |
| ZIA.IPDestinationGroup.ipCategories | String | Destination IP address URL categories. |

#### Command Example

```!zia-ip-destination-group-update group_id=1234 address=9.9.9.9 action=ADD_TO_LIST```

#### Human Readable Output

>IP destination group 1234 updated successfully.

### zia-ip-destination-group-add

***
Adds a new IP destination group.

#### Base Command

`zia-ip-destination-group-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Destination IP group name. | Optional |
| group_type | Destination IP group type. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| address | Destination IP addresses. | Optional |
| description | Additional information about the destination IP group. | Optional |
| ip_category | Destination IP address URL categories. Possible values can be found [here](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/firewall-policies/ip-destination-group-resource-edit-destination-ip-group). | Optional |
| country | Destination IP address countries. Possible values can be found [here](https://automate.zscaler.com/docs/api-reference-and-guides/api-reference/zia/firewall-policies/ip-destination-group-resource-edit-destination-ip-group). | Optional |
| is_non_editable | If set to true, the destination IP address group is non-editable. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.IPDestinationGroup.id | Number | Unique identifier for the destination IP group. |
| ZIA.IPDestinationGroup.name | String | Destination IP group name. |
| ZIA.IPDestinationGroup.type | String | Destination IP group type. |
| ZIA.IPDestinationGroup.addresses | String | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| ZIA.IPDestinationGroup.description | String | Additional information about the destination IP group. |
| ZIA.IPDestinationGroup.countries | String | Destination IP address countries. |
| ZIA.IPDestinationGroup.ipCategories | String | Destination IP address URL categories. |

#### Command Example

```!zia-ip-destination-group-add group_name="New Group" group_type=DSTN_IP address=10.0.0.1```

#### Context Example

```json
{
    "ZIA": {
        "IPDestinationGroup": {
            "id": 5678,
            "name": "New Group",
            "type": "DSTN_IP",
            "addresses": ["10.0.0.1"],
            "description": "",
            "countries": [],
            "ipCategories": []
        }
    }
}
```

#### Human Readable Output

>IP destination group created successfully with ID 5678.

### zia-ip-destination-group-delete

***
Deletes the IP destination group for the specified ID.

#### Base Command

`zia-ip-destination-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The unique identifier for the IP destination group. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zia-ip-destination-group-delete group_id=5678```

#### Human Readable Output

>IP destination group 5678 deleted successfully.

### zia-user-list

***
Gets a list of all users or the user information for the specified ID.

#### Base Command

`zia-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Filters by the unique identifier for the user. | Optional |
| dept | Filters by department name. | Optional |
| group | Filters by group name. | Optional |
| page | Specifies the page offset. Default is 1. | Optional |
| page_size | Specifies the page size. The maximum size is 10,000. Default is 100. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.User.id | Number | The unique identifier for the user. |
| ZIA.User.name | String | User name. |
| ZIA.User.email | String | User email address. |
| ZIA.User.comments | String | Additional information about the user. |

#### Command Example

```!zia-user-list dept="Engineering" page_size=50```

#### Context Example

```json
{
    "ZIA": {
        "User": [
            {
                "id": 100,
                "name": "John Doe",
                "email": "john.doe@example.com",
                "comments": "Engineering team member"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>
>|ID|Name|Email|Comments|
>|---|---|---|---|
>| 100 | John Doe | john.doe@example.com | Engineering team member |

### zia-user-update

***
Updates the user information for the specified ID.

#### Base Command

`zia-user-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The unique identifier for the user. | Required |
| user | Full user object as JSON. If provided, individual field arguments are applied on top of this. | Optional |
| user_name | User name. This appears when choosing users for policies. | Optional |
| email | User email consists of a user name and domain name. | Optional |
| comments | Additional information about this user. | Optional |
| temp_auth_email | Temporary Authentication Email. | Optional |
| password | User's password. Applicable only when authentication type is Hosted DB. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.User.id | Number | The unique identifier for the user. |
| ZIA.User.name | String | User name. |
| ZIA.User.email | String | User email address. |
| ZIA.User.comments | String | Additional information about the user. |

#### Command Example

```!zia-user-update user_id=100 comments="Updated comment"```

#### Human Readable Output

>User 100 updated successfully.

### zia-groups-list

***
Gets a list of groups.

#### Base Command

`zia-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | The search string used to match against a group's name or comments attributes. | Optional |
| defined_by | The string value defined by the group name or other applicable attributes. | Optional |
| sort_by | Sorts the groups based on available values. Possible values are: id, name, expiry, status, externalId, rank, modTime. Default is id. | Optional |
| sort_order | Sorts the order of groups based on available values. Possible values are: asc, desc, ruleExecution. Default is asc. | Optional |
| page | Specifies the page offset. Default is 1. | Optional |
| page_size | Specifies the page size. The maximum size is 10,000. Default is 100. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.Groups.id | Number | The unique identifier for the group. |
| ZIA.Groups.name | String | Group name. |
| ZIA.Groups.idpId | Number | Unique identifier for the identity provider (IdP). |
| ZIA.Groups.comments | String | Additional information about the group. |
| ZIA.Groups.isSystemDefined | Boolean | Whether the group is system-defined. |

#### Command Example

```!zia-groups-list search="Engineering" sort_by=name sort_order=asc```

#### Context Example

```json
{
    "ZIA": {
        "Groups": [
            {
                "id": 200,
                "name": "Engineering",
                "idpId": 1,
                "comments": "Engineering department group",
                "isSystemDefined": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Groups
>
>|ID|Name|IdP ID|Comments|System Defined|
>|---|---|---|---|---|
>| 200 | Engineering | 1 | Engineering department group | false |

### zia-departments-list

***
Gets a list of all departments or the department information for the specified ID.

#### Base Command

`zia-departments-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| department_id | Unique identifier for the department. | Optional |
| search | The search string used to match against a department's name or comments attributes. | Optional |
| limit_search | Whether to limit the search to match only against the department name. Default is false. | Optional |
| sort_by | Sorts the departments based on available values. Possible values are: id, name, expiry, status, externalId, rank. Default is id. | Optional |
| sort_order | Sorts the order of departments based on available values. Possible values are: asc, desc, ruleExecution. Default is asc. | Optional |
| page | Specifies the page offset. Default is 1. | Optional |
| page_size | Specifies the page size. The maximum size is 10,000. Default is 100. | Optional |
| all_results | Whether to retrieve all results at once. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.Department.id | Number | The unique identifier for the department. |
| ZIA.Department.name | String | Department name. |
| ZIA.Department.idpId | Number | Unique identifier for the identity provider (IdP). |
| ZIA.Department.comments | String | Additional information about the department. |
| ZIA.Department.deleted | Boolean | Whether the department is deleted. |

#### Command Example

```!zia-departments-list search="Engineering"```

#### Context Example

```json
{
    "ZIA": {
        "Department": [
            {
                "id": 300,
                "name": "Engineering",
                "idpId": 1,
                "comments": "Engineering department",
                "deleted": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Departments
>
>|ID|Name|IdP ID|Comments|Deleted|
>|---|---|---|---|---|
>| 300 | Engineering | 1 | Engineering department | false |

### zia-sandbox-report-get

***
Gets a full or summary detail report for an MD5 hash of a file that was analyzed by Sandbox.

#### Base Command

`zia-sandbox-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash of the file that was analyzed by Sandbox. | Required |
| report_type | Type of report, full or summary. Possible values are: full, summary. Default is summary. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.SandboxReport | Unknown | The full sandbox report response. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| File.MD5 | String | The MD5 hash of the file. |
| File.Malicious.Vendor | String | For malicious files, the vendor that tagged the file as malicious. |
| File.Malicious.Description | String | For malicious files, the reason the vendor tagged the file as malicious. |
| File.FileType | String | The file type. |

#### Command Example

```!zia-sandbox-report-get md5=9de5069c5afe602b2ea0a04b66beb2c0 report_type=summary```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "9de5069c5afe602b2ea0a04b66beb2c0",
        "Score": 3,
        "Type": "file",
        "Vendor": "Zscaler"
    },
    "File": {
        "MD5": "9de5069c5afe602b2ea0a04b66beb2c0",
        "FileType": "PE32",
        "Malicious": {
            "Vendor": "Zscaler",
            "Description": "Malware detected"
        }
    },
    "ZIA": {
        "SandboxReport": {
            "Summary": {
                "Status": "MALICIOUS",
                "Category": "Malware"
            }
        }
    }
}
```

#### Human Readable Output

>### Sandbox Report for 9de5069c5afe602b2ea0a04b66beb2c0
>
>|Status|Category|File Type|Score|
>|---|---|---|---|
>| MALICIOUS | Malware | PE32 | 3 |

### zia-activate-changes

***
Activates the saved configuration changes.

#### Base Command

`zia-activate-changes`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.ActivationStatus.status | String | The activation status. |

#### Command Example

```!zia-activate-changes```

#### Context Example

```json
{
    "ZIA": {
        "ActivationStatus": {
            "status": "ACTIVE"
        }
    }
}
```

#### Human Readable Output

>### Activation Status
>
>|Status|
>|---|
>| ACTIVE |

### url

***
Retrieve Zscaler's default classification for a given set of URLs.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs for which to look up the classification. For example, abc.com,xyz.com. Up to 100 URLs can be looked up per request, and a URL cannot exceed 1,024 characters. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.URL.Data | String | The URL that was searched. |
| ZIA.URL.Address | String | The URL that was searched. |
| ZIA.URL.urlClassifications | String | The classification of the URL. |
| ZIA.URL.urlClassificationsWithSecurityAlert | String | The classifications of the URLs that have security alerts. |
| URL.Data | String | The URL that was searched. |
| URL.Address | String | The URL that was searched. |
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that tagged the URL as malicious. |
| URL.Malicious.Description | String | For malicious URLs, the reason the vendor tagged the URL as malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

#### Command Example

```!url url=facebook.com```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "facebook.com",
            "Score": 1,
            "Type": "url",
            "Vendor": "Zscaler",
            "Reliability": "C - Fairly reliable"
        }
    ],
    "URL": {
        "Address": "facebook.com",
        "Data": "facebook.com"
    },
    "ZIA": {
        "URL": {
            "Address": "facebook.com",
            "Data": "facebook.com",
            "urlClassifications": "SOCIAL_NETWORKING",
            "urlClassificationsWithSecurityAlert": []
        }
    }
}
```

#### Human Readable Output

>### Zscaler URL Lookup
>
>|URL|Classifications|Security Alert Classifications|
>|---|---|---|
>| facebook.com | SOCIAL_NETWORKING |  |

### ip

***
Retrieve the classification for each of the specified IP addresses.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses for which to look up the classification. For example, 8.8.8.8,1.2.3.4. The maximum number of IPs per call is 100. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.IP.Address | String | The IP address that was searched. |
| ZIA.IP.Classifications | String | The classification of the IP address. |
| ZIA.IP.ClassificationsWithSecurityAlert | String | Classifications that have a security alert for the IP address. |
| IP.Address | String | The IP address that was searched. |
| IP.Malicious.Vendor | String | For malicious IP addresses, the vendor that tagged the IP address as malicious. |
| IP.Malicious.Description | String | For malicious IP addresses, the reason the vendor tagged the IP address as malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

#### Command Example

```!ip ip=8.8.8.8```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "8.8.8.8",
            "Score": 1,
            "Type": "ip",
            "Vendor": "Zscaler",
            "Reliability": "C - Fairly reliable"
        }
    ],
    "IP": {
        "Address": "8.8.8.8"
    },
    "ZIA": {
        "IP": {
            "Address": "8.8.8.8",
            "Classifications": "WEB_SEARCH",
            "ClassificationsWithSecurityAlert": []
        }
    }
}
```

#### Human Readable Output

>### Zscaler IP Lookup
>
>|IP|Classifications|Security Alert Classifications|
>|---|---|---|
>| 8.8.8.8 | WEB_SEARCH |  |

### domain

***
Retrieve Zscaler's default classification for a given set of domains.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains for which to look up the classification. For example, abc.com,xyz.com. The maximum number of domains per call is 100. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZIA.Domain.Data | String | The domain that was searched. |
| ZIA.Domain.Address | String | The domain that was searched. |
| ZIA.Domain.Classifications | String | The classification of the domain. |
| ZIA.Domain.ClassificationsWithSecurityAlert | String | Classifications that have a security alert for the domain. |
| Domain.Name | String | The domain that was searched. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that tagged the domain as malicious. |
| Domain.Malicious.Description | String | For malicious domains, the reason the vendor tagged the domain as malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

#### Command Example

```!domain domain=google.com```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "google.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "Zscaler",
            "Reliability": "C - Fairly reliable"
        }
    ],
    "Domain": {
        "Name": "google.com"
    },
    "ZIA": {
        "Domain": {
            "Data": "google.com",
            "Address": "google.com",
            "Classifications": "WEB_SEARCH",
            "ClassificationsWithSecurityAlert": []
        }
    }
}
```

#### Human Readable Output

>### Zscaler Domain Lookup
>
>|Domain|Classifications|Security Alert Classifications|
>|---|---|---|
>| google.com | WEB_SEARCH |  |
