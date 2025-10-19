Zscaler is a cloud security solution built for performance and flexible scalability. This integration enables you to manage URL and IP address allow lists and block lists, manage and update categories, get Sandbox reports, create, manage, and update IP destination groups and manually log in, log out, and activate changes in a Zscaler session.

For the integration to work properly, the Zscaler user must have admin permissions.

Category ID is the same as the category name, except all letters are capitalized and each word is separated with an underscore instead of spaces. For example, if the category name is Other Education, then the Category ID is OTHER_EDUCATION.

A custom category ID has the format `CUSTOM_01`, which is not indicative of the category. Use the `zscaler-get-categories` command to get a custom category and its configured name.

## Configure Zscaler Internet Access in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cloud Name (i.e., &lt;https://zsapi.zscalertwo.net&gt;) |  | True |
| Username |  | True |
| Password |  | True |
| API Key |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Auto Logout | If enabled, the integration will log out after executing each command. | False |
| Auto Activate Changes | If enabled, the integration will activate the command changes after each execution. If disabled, use the 'zscaler-activate-changes' command to activate Zscaler command changes. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Timeout (in seconds) for HTTP requests to Zscaler |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zscaler-blacklist-url

***
Adds the specified URLs to the block list.

#### Base Command

`zscaler-blacklist-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to add to block list. For example, snapchat.com,facebook.com. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-blacklist-url url=phishing.com,malware.net```

#### Human Readable Output

Added the following URLs to the block list successfully:
phishing.com
malware.net

### url

***
Looks up the classification for the each of the specified URLs.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs for which to look up the classification.  For example, abc.com,xyz.com. The maximum number of URLs per call is 100. A URL cannot exceed 1024 characters. If there are multiple URLs, set the 'multiple' argument to 'true'. | Required |
| multiple | Whether there are multiple URLs in the 'url' argument. If a URL contains commas, set this argument to 'false' and enter the single URL as the 'url' argument. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL that was searched. |
| URL.Address | string | The URL that was searched. |
| Zscaler.URL.urlClassifications | string | The classification of the URL. For example, MUSIC or WEB_SEARCH. |
| Zscaler.URL.urlClassificationsWithSecurityAlert | string | The classifications of the URLs that have security alerts. |
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that tagged the URL as malicious. |
| URL.Malicious.Description | string | For malicious URLs, the reason the vendor tagged the URL as malicious. |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| DBotScore.Score | number | The actual score. |

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
            "Vendor": "Zscaler"
        }
    ],
    "URL": {
        "Address": "facebook.com",
        "Data": "facebook.com",
        "urlClassifications": "SOCIAL_NETWORKING"
    }
}
```

#### Human Readable Output

>### Zscaler URL Lookup

>|url|urlClassifications|
>|---|---|
>| facebook.com | SOCIAL_NETWORKING |

### ip

***
Looks up the classification for each of the specified IP addresses.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP address for which to look up the classification. For example, 8.8.8.8,1.2.3.4. The maximum number of URLs per call is 100. An IP address cannot exceed 1024 characters. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | The IP address that was searched. |
| Zscaler.IP.ipClassifications | string | The classification of the IP address. For example, MUSIC or WEB_SEARCH. |
| Zscaler.IP.iplClassificationsWithSecurityAlert | string | Classifications that have a security alert for the IP address. |
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that tagged the IP address as malicious. |
| IP.Malicious.Description | string | For malicious IP addresses, the reason the vendor tagged the IP address as malicious. |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| DBotScore.Score | number | The actual score. |

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
            "Vendor": "Zscaler"
        }
    ],
    "IP": {
        "Address": "8.8.8.8",
        "ipClassifications": "WEB_SEARCH"
    }
}
```

#### Human Readable Output

>### Zscaler IP Lookup

>|ip|ipClassifications|
>|---|---|
>| 8.8.8.8 | WEB_SEARCH |

### zscaler-undo-blacklist-url

***
Removes the specified URLs from the block list.

#### Base Command

`zscaler-undo-blacklist-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to remove from the block list. For example, snapchat.com,facebook.com. | Required |

#### Context Output

There is no context output for this command.

### zscaler-whitelist-url

***
Adds the specified URLs to the allow list.

#### Base Command

`zscaler-whitelist-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to add to the allow list. For example, snapchat.com,facebook.com. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-whitelist-url url=phising.com,malware.net```

#### Human Readable Output

Added the following URLs to the allow list successfully:
phishing.com
malware.net

### zscaler-undo-whitelist-url

***
Removes the specified URLs from the allow list.

#### Base Command

`zscaler-undo-whitelist-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to remove from the allow list. For example, snapchat.com,facebook.com. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-undo-whitelist-url url=phising.com,malware.net```

#### Human Readable Output

Removed the following URLs from the allow list successfully:
phishing.com
malware.net

### zscaler-undo-whitelist-ip

***
Removes the specified IP addresses from the allow list.

#### Base Command

`zscaler-undo-whitelist-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to remove from the allow list. For example, 8.8.8.8,1.2.3.4. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-undo-whitelist-ip ip=2.2.2.2,3.3.3.3```

#### Human Readable Output

Removed the following IP addresses from the allow list successfully:
2.2.2.2
3.3.3.3

### zscaler-whitelist-ip

***
Adds the specified IP address to the allow list.

#### Base Command

`zscaler-whitelist-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to add to the allow list. For example, 8.8.8.8,1.2.3.4. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-whitelist-ip ip=2.2.2.2,3.3.3.3```

#### Human Readable Output

Added the following IP addresses to the allow list successfully:
2.2.2.2
3.3.3.3

### zscaler-undo-blacklist-ip

***
Removes the specified IP addresses from the block list.

#### Base Command

`zscaler-undo-blacklist-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to remove from the block list. For example, 8.8.8.8,1.2.3.4. | Required | 

#### Context Output

There is no context output for this command.
### zscaler-blacklist-ip

***
Adds the specified IP addresses to the block list.

#### Base Command

`zscaler-blacklist-ip`

#### Input

### zscaler-blacklist-ip

***
Adds the specified IP addresses to the block list.

#### Base Command

`zscaler-blacklist-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to add to the block list. For example, 8.8.8.8,1.2.3.4. | Required | 

#### Context Output

There is no context output for this command.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to add the specified URLs to. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required |
| url | A comma-separated list of URLs to add to the specified category. For example, `pandora.com,spotify.com`. <br> **Important:** <br> If any URL contains a comma (`,`), you must pass the `url` argument as a JSON list wrapped in backticks (\`). <br> **Example (single URL with comma):** <br> url=\`["https://example.com/foo,bar"]\` <br> **Example (multiple URLs with commas):** <br> url=\`["https://example.com/foo,bar","https://example2.com/foo,bar"]\` | Optional |
| retaining-parent-category-url | A comma-separated list of URLs to add to the retaining parent category section inside the specified category. For example, pandora.com,spotify.com. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
### zscaler-category-add-url

***
Adds URLs to the specified category.

#### Base Command

`zscaler-category-add-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to add the specified URLs to. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| url | A comma-separated list of URLs to add to the specified category. For example, pandora.com,spotify.com. | Optional | 
| retaining-parent-category-url | A comma-separated list of URLs to add to the retaining parent category section inside the specified category. For example, pandora.com,spotify.com. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 

| Zscaler.Category.Description | string | The description of the category. |
| Zscaler.Category.ID | string | The ID of the category. |
| Zscaler.Category.URL | string | The URL of the category |

#### Command Example

`!zscaler-category-add-ip category-id=REFERENCE_SITES ip=1.2.3.4,8.8.8.8`

#### Context Example

```json
{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "REFERENCE_SITES_DESC",
        "ID": "REFERENCE_SITES",
        "URL": [
            "1.2.3.4",
            "8.8.8.8"
        ]
      }
    }
}
```

#### Human Readable Output

Added the following IP addresses to category REFERENCE_SITES:

* 1.2.3.4
* 8.8.8.8

### zscaler-category-remove-url
### zscaler-category-add-ip

***
Adds IP address to the specified category.

#### Base Command

`zscaler-category-add-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to add the specified IP addresses to. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| ip | A comma-separated list of IP address to add to the specified category. For example, 1.2.3.4,8.8.8.8. | Optional | 
| retaining-parent-category-ip | A comma-separated list of IP address to add to the retaining parent category section inside the specified category. For example, 1.2.3.4,8.8.8.8. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 

Removes IP address from the specified category.

#### Base Command

`zscaler-category-remove-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to remove the specified IP addresses from. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required |
| ip | A comma-separated list of IP addresses to remove from the specified category. For example, 1.2.3.4,8.8.8.8. | Optional |
| retaining-parent-category-ip | A comma-separated list of IP address to remove from the retaining parent category section inside the specified category. For example, 1.2.3.4,8.8.8.8. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. |
| Zscaler.Category.Description | string | The description of the category. |
| Zscaler.Category.ID | string | The ID of the category. |
| Zscaler.Category.URL | string | The URL of the category. |

#### Command Example

`!zscaler-category-remove-ip category-id=REFERENCE_SITES ip=1.2.3.4`

##### Context Example

### zscaler-category-remove-url

***
Removes URLs from the specified category.

#### Base Command

`zscaler-category-remove-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to remove the specified URLs from. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| url | A comma-separated list of URLs to remove from the specified category. For example, pandora.com,spotify.com. | Optional | 
| retaining-parent-category-url | A comma-separated list of URLs to remove from the retaining parent category section inside the specified category. For example, pandora.com,spotify.com. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 

#### Context Example

```json
{  
   "Zscaler":{  
      "Category":{  
         "ID":"INTERNET_SERVICES",
         "Description":"INTERNET_SERVICES_DESC",
         "URL":[  
            "google.com",
            "facebook.com"
         ],
         "CustomCategory":"false"
      },
      "ID":"CUSTOM_01",
      "Name":"CustomCategory",
      "URL":[  
         "demisto.com",
         "apple.com"
      ],
      "RetainingParentCategoryURL":[  
         "pandora.com",
         "spotify.com"
      ],
      "CustomCategory":"true"
   }
}
### zscaler-category-remove-ip

***
Removes IP address from the specified category.

#### Base Command

`zscaler-category-remove-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to remove the specified IP addresses from. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| ip | A comma-separated list of IP addresses to remove from the specified category. For example, 1.2.3.4,8.8.8.8. | Optional | 
| retaining-parent-category-ip | A comma-separated list of IP address to remove from the retaining parent category section inside the specified category. For example, 1.2.3.4,8.8.8.8. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 

* bad.net

### zscaler-get-whitelist

***
Retrieves the Zscaler default allow list.

#### Base Command

`zscaler-get-whitelist`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Whitelist | string | The Zscaler allow list. |

#### Command Example

````!zscaler-get-whitelist````

#### Context Example

```json
{
    "Zscaler": {
        "Whitelist": [
            "demisto.com,
            "apple.com"
        ]
    }
}
```

#### Human Readable Output

Zscaler whitelist

* demisto.com
* apple.net

### zscaler-sandbox-report

***
Retrieves a full or summary report of the file that was analyzed by Sandbox. The file is represented by the specified MD5 hash.

#### Base Command

`zscaler-sandbox-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The MD5 hash of a file. | Required |
| details | The type of report. Possible values are 'full' or 'summary'. Default is 'full'. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | string | The MD5 hash of the file. |
| File.Malicious.Vendor | string | For malicious files, the vendor that tagged the file as malicious. |
| File.Malicious.Description | string | For malicious files, the reason the vendor tagged the file as malicious. |
| File.DetectedMalware | string | The malware detected in the file. |
| File.FileType | string | The file type. |
| DBotScore.Indicator | string | The MD5 hash file that was tested. |
| DBotScore.Type | string | The MD5 hash file type. |
| DBotScore.Vendor | string | The vendor that calculated the DBot score. |
| DBotScore.Score | number | The actual DBot score. |

#### Command Example

`!zscaler-sandbox-report md5=3FD0EA0AE759D58274310C022FB0CBBA details=summary`

#### Context Example

```json
{
    "DBotScore": {
        "Vendor": "Zscaler", 
        "Indicator": "3FD0EA0AE759D58274310C022FB0CBBA", 
        "Score": 3, 
        "Type": "file"
    }, 
    "File": {
        "Zscaler": {
            "FileType": null, 
            "DetectedMalware": ""
        }, 
        "Malicious": {
            "Vendor": "Zscaler", 
            "Description": "Classified as Malicious, with threat score: 100"
        }, 
        "MD5": "3FD0EA0AE759D58274310C022FB0CBBA"
    }
}
```

#### Human Readable Output

##### Full Sandbox Report

|Category|Indicator|Vendor|Score|Zscaler Score|Type|
|--- |--- |--- |--- |--- |--- |
|MALWARE_BOTNET|3FD0EA0AE759D58274310C022FB0CBBA|Zscaler|3|100|file|

#### Additional Information

[![image](https://../../doc_files/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png)](../../doc_files/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png)

[![image](https://../../doc_files/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png)](../../doc_files/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png)

### zscaler-login

***
Manually create a Zscaler login session. This command will also try to log out of the previous session.

#### Base Command

`zscaler-login`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-login```

#### Human Readable Output

>Zscaler session created successfully.

### zscaler-logout

***
Logs out of the current Zscaler session.

#### Base Command

`zscaler-logout`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-logout```

#### Human Readable Output

>API session logged out of Zscaler successfully.

### zscaler-activate-changes

***
Activates the changes executed by other Zscaler commands in this session.

#### Base Command

`zscaler-activate-changes`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!zscaler-activate-changes```

#### Human Readable Output

>Changes have been activated successfully.

### zscaler-url-quota

***
Gets information on the number of unique URLs that are currently provisioned for your organization as well as how many URLs you can add before reaching that number.

#### Base Command

`zscaler-url-quota`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.remainingUrlsQuota | Number | The number of URLs you can add before reaching the quota. |
| Zscaler.uniqueUrlsProvisioned | Number | The number of unique URLs that are currently provisioned for your organization. |

### zscaler-get-users

***
Get Zscaler users

#### Base Command

`zscaler-get-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filer by user name. | Optional |
| page | Specifies the page offset. | Optional |
| pageSize | Specifies the page size. Default is 100. | Optional |

#### Context Output

There is no context output for this command.

### zscaler-update-user

***
Updates the user information for the specified ID.

#### Base Command

`zscaler-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique identifier for the user. | Required |
| user | New user information. Docs: <https://help.zscaler.com/zia/api#/User%20Management/updateUser>. | Required |

#### Context Output

There is no context output for this command.

### zscaler-get-departments

***
Get a list of departments. It can be searched by name.

#### Base Command

`zscaler-get-departments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filter by department name. | Optional |
| page | Specifies the page offset. | Optional |
| pageSize | Specifies the page size. Default is 100. | Optional |

#### Context Output

There is no context output for this command.

### zscaler-get-usergroups

***
Gets a list of groups

#### Base Command

`zscaler-get-usergroups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filter by group name or comment. | Optional |
| page | Specifies the page offset. | Optional |
| pageSize | Specifies the page size. Default is 100. | Optional |

#### Context Output

There is no context output for this command.

### zscaler-create-ip-destination-group

***
Adds a new IP destination group.

#### Base Command

`zscaler-create-ip-destination-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Destination IP group name. | Required |
| type | Destination IP group type (i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs). Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Required |
| addresses | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. | Optional |
| description | Additional information about the destination IP group. | Optional |
| ip_categories | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. To retrieve a list of possible values, you can execute the zscaler-get-categories command. | Optional |
| countries | Destination IP address countries. You can identify destinations based on the location of a server. A list of possible values can be found here <https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups-post>. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.IPDestinationGroup.ID | number | Unique identifier for the destination IP group. |
| Zscaler.IPDestinationGroup.Name | string | Destination IP group name. |
| Zscaler.IPDestinationGroup.Type | string | Destination IP group type \(i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs\). |
| Zscaler.IPDestinationGroup.Description | string | Destination IP group description. |
| Zscaler.IPDestinationGroup.Addresses | string | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| Zscaler.IPDestinationGroup.IpCategories | string | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. |
| Zscaler.IPDestinationGroup.Countries | string | Destination IP address countries. You can identify destinations based on the location of a server. |
| Zscaler.IPDestinationGroup.IsNonEditable | boolean | If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified. |

#### Command Example

```!zscaler-create-ip-destination-group addresses="127.0.0.2,127.0.0.1" description=Localhost name=Test99 type=DSTN_IP```

#### Context example

```json
{
    "Zscaler.IPDestinationGroup": {
        "ID": 2000359, 
        "Name": "Test99", 
        "Type": "DSTN_IP", 
        "Addresses": [
            "127.0.0.2", 
            "127.0.0.1"
        ], 
        "Description": "Localhost",
        "IpCategories": [], 
        "Countries": [], 
        "IsNonEditable": false
    }
}
```

#### Human Readable Output

IP Destination group created

|Addresses|Countries|Description|ID|IpCategories|IsNonEditable|Name|Type|
|---|---|---|---|---|---|---|---|
| 127.0.0.2,<br>127.0.0.1 |  | Localhost | 2000359 |  | false | Test99 | DSTN_IP |

### zscaler-edit-ip-destination-group

***
Updates the IP destination group information for the specified group ID.

#### Base Command

`zscaler-edit-ip-destination-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_id | The unique identifier for the IP destination group. | Required |
| name | Destination IP group name. | Optional |
| addresses | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. | Optional |
| description | Additional information about the destination IP group. | Optional |
| ip_categories | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. To retrieve a list of possible values you can execute the zscaler-get-categories command. | Optional |
| countries | Destination IP address countries. You can identify destinations based on the location of a server. A list of possible values can be found here <https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups/{ipGroupId}-put>. | Optional |
| is_non_editable | If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.IPDestinationGroup.ID | number | Unique identifier for the destination IP group. |
| Zscaler.IPDestinationGroup.Name | string | Destination IP group name. |
| Zscaler.IPDestinationGroup.Type | string | Destination IP group type \(i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs\). |
| Zscaler.IPDestinationGroup.Description | string | Destination IP group description. |
| Zscaler.IPDestinationGroup.Addresses | string | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| Zscaler.IPDestinationGroup.IpCategories | string | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. |
| Zscaler.IPDestinationGroup.Countries | string | Destination IP address countries. You can identify destinations based on the location of a server. |

#### Command Example

```!zscaler-edit-ip-destination-group ip_group_id=2000359 addresses="127.0.0.2" description="Localhost v2" name=Test01```

#### Context example

```json
{
    "Zscaler.IPDestinationGroup": {
        "ID": 2000359, 
        "Name": "Test01", 
        "Type": "DSTN_IP", 
        "Description": "Localhost v2",
        "Addresses": [
          "127.0.0.2"
        ],
        "IpCategories": [], 
        "Countries": []
    }
}
```

#### Human Readable Output

IP Destination group updated

|Addresses|Countries|Description|ID|IpCategories|Name|Type|
|---|---|---|---|---|---|---|
| 127.0.0.2 |  | Localhost v2 | 2000359 |  | Test01 | DSTN_IP |

### zscaler-list-ip-destination-groups

***
Gets a list of all IP destination groups or the IP destination group information for the specified group ID.

#### Base Command

`zscaler-list-ip-destination-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_id | A comma-separated list of unique identifiers for the IP destination groups. | Optional |
| exclude_type | The IP group type to be excluded from the results. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| category_type | The IP group type to be filtered from results. This argument is only supported when the 'lite' argument is set to True. Possible values are: DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER. | Optional |
| include_ipv6 | Retrieve IPv6 destination groups. Possible values are: True, False. Default is False. | Optional |
| limit | Limit of the results to be retrieved. Default is 50. | Optional |
| all_results | Whether to retrieve all results at once. Possible values are: True, False. Default is False. | Optional |
| lite | Whether to retrieve only limited information of IP destination groups. Includes ID, name and type of the IP destination groups. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.IPDestinationGroup.ID | string | Unique identifier for the destination IP group. |
| Zscaler.IPDestinationGroup.Name | string | Destination IP group name. |
| Zscaler.IPDestinationGroup.Type | string | Destination IP group type \(i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs\). |
| Zscaler.IPDestinationGroup.Addresses | string | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. |
| Zscaler.IPDestinationGroup.Description | string | Additional information about the destination IP group |
| Zscaler.IPDestinationGroup.IpCategories | string | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. |
| Zscaler.IPDestinationGroup.Countries | string | Destination IP address countries. You can identify destinations based on the location of a server. |

#### Command Example

```!zscaler-list-ip-destination-groups exclude_type=DSTN_OTHER```

#### Context example

```json
{
    "Zscaler.IPDestinationGroup": [
    {
        "ID": 1997898, 
        "Name": "Test99", 
        "Type": "DSTN_IP", 
        "Addresses": ["127.0.0.2"], 
        "Description": "Localhost v2", 
        "IpCategories": [], 
        "Countries": []
    },
    {
        "ID": 2001335, 
        "Name": "Test01", 
        "Type": "DSTN_IP", 
        "Addresses": ["127.0.0.1"], 
        "Description": "Localhost v1", 
        "IpCategories": [], 
        "Countries": []
    }      
    ]
}
```

#### Human Readable Output

IPv4 Destination groups (2)

|Addresses|Countries|Description|ID|IpCategories|Name|Type|
|---|---|---|---|---|---|---|
| 127.0.0.2 |  | Localhost v2 | 1997898 |  | Test99 | DSTN_IP |
| 127.0.0.1 |  | Localhost v1 | 2001335 |  | Test01 | DSTN_IP |

```!zscaler-list-ip-destination-groups lite=True```

#### Context Example
### zscaler-edit-ip-destination-group

***
Updates the IP destination group information for the specified group ID.

#### Base Command

`zscaler-edit-ip-destination-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_id | The unique identifier for the IP destination group. | Required | 
| name | Destination IP group name. | Optional | 
| addresses | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. | Optional | 
| description | Additional information about the destination IP group. | Optional | 
| ip_categories | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. To retrieve a list of possible values you can execute the zscaler-get-categories command. Possible values are: ANY, NONE, OTHER_ADULT_MATERIAL, ADULT_THEMES, LINGERIE_BIKINI, NUDITY, PORNOGRAPHY, SEXUALITY, ADULT_SEX_EDUCATION, K_12_SEX_EDUCATION, SOCIAL_ADULT, OTHER_BUSINESS_AND_ECONOMY, CORPORATE_MARKETING, FINANCE, PROFESSIONAL_SERVICES, CLASSIFIEDS, TRADING_BROKARAGE_INSURANCE, CUSTOM_00, CUSTOM_01, CUSTOM_02, CUSTOM_03, CUSTOM_04, CUSTOM_05, CUSTOM_06, CUSTOM_07, CUSTOM_08, CUSTOM_09, CUSTOM_10, CUSTOM_11, CUSTOM_12, CUSTOM_13, CUSTOM_14, CUSTOM_15, CUSTOM_16, CUSTOM_17, CUSTOM_18, CUSTOM_19, CUSTOM_20, CUSTOM_21, CUSTOM_22, CUSTOM_23, CUSTOM_24, CUSTOM_25, CUSTOM_26, CUSTOM_27, CUSTOM_28, CUSTOM_29, CUSTOM_30, CUSTOM_31, CUSTOM_32, CUSTOM_33, CUSTOM_34, CUSTOM_35, CUSTOM_36, CUSTOM_37, CUSTOM_38, CUSTOM_39, CUSTOM_40, CUSTOM_41, CUSTOM_42, CUSTOM_43, CUSTOM_44, CUSTOM_45, CUSTOM_46, CUSTOM_47, CUSTOM_48, CUSTOM_49, CUSTOM_50, CUSTOM_51, CUSTOM_52, CUSTOM_53, CUSTOM_54, CUSTOM_55, CUSTOM_56, CUSTOM_57, CUSTOM_58, CUSTOM_59, CUSTOM_60, CUSTOM_61, CUSTOM_62, CUSTOM_63, CUSTOM_64, CUSTOM_65, CUSTOM_66, CUSTOM_67, CUSTOM_68, CUSTOM_69, CUSTOM_70, CUSTOM_71, CUSTOM_72, CUSTOM_73, CUSTOM_74, CUSTOM_75, CUSTOM_76, CUSTOM_77, CUSTOM_78, CUSTOM_79, CUSTOM_80, CUSTOM_81, CUSTOM_82, CUSTOM_83, CUSTOM_84, CUSTOM_85, CUSTOM_86, CUSTOM_87, CUSTOM_88, CUSTOM_89, CUSTOM_90, CUSTOM_91, CUSTOM_92, CUSTOM_93, CUSTOM_94, CUSTOM_95, CUSTOM_96, CUSTOM_97, CUSTOM_98, CUSTOM_99, CUSTOM_100, CUSTOM_101, CUSTOM_102, CUSTOM_103, CUSTOM_104, CUSTOM_105, CUSTOM_106, CUSTOM_107, CUSTOM_108, CUSTOM_109, CUSTOM_110, CUSTOM_111, CUSTOM_112, CUSTOM_113, CUSTOM_114, CUSTOM_115, CUSTOM_116, CUSTOM_117, CUSTOM_118, CUSTOM_119, CUSTOM_120, CUSTOM_121, CUSTOM_122, CUSTOM_123, CUSTOM_124, CUSTOM_125, CUSTOM_126, CUSTOM_127, CUSTOM_128, CUSTOM_129, CUSTOM_130, CUSTOM_131, CUSTOM_132, CUSTOM_133, CUSTOM_134, CUSTOM_135, CUSTOM_136, CUSTOM_137, CUSTOM_138, CUSTOM_139, CUSTOM_140, CUSTOM_141, CUSTOM_142, CUSTOM_143, CUSTOM_144, CUSTOM_145, CUSTOM_146, CUSTOM_147, CUSTOM_148, CUSTOM_149, CUSTOM_150, CUSTOM_151, CUSTOM_152, CUSTOM_153, CUSTOM_154, CUSTOM_155, CUSTOM_156, CUSTOM_157, CUSTOM_158, CUSTOM_159, CUSTOM_160, CUSTOM_161, CUSTOM_162, CUSTOM_163, CUSTOM_164, CUSTOM_165, CUSTOM_166, CUSTOM_167, CUSTOM_168, CUSTOM_169, CUSTOM_170, CUSTOM_171, CUSTOM_172, CUSTOM_173, CUSTOM_174, CUSTOM_175, CUSTOM_176, CUSTOM_177, CUSTOM_178, CUSTOM_179, CUSTOM_180, CUSTOM_181, CUSTOM_182, CUSTOM_183, CUSTOM_184, CUSTOM_185, CUSTOM_186, CUSTOM_187, CUSTOM_188, CUSTOM_189, CUSTOM_190, CUSTOM_191, CUSTOM_192, CUSTOM_193, CUSTOM_194, CUSTOM_195, CUSTOM_196, CUSTOM_197, CUSTOM_198, CUSTOM_199, CUSTOM_200, CUSTOM_201, CUSTOM_202, CUSTOM_203, CUSTOM_204, CUSTOM_205, CUSTOM_206, CUSTOM_207, CUSTOM_208, CUSTOM_209, CUSTOM_210, CUSTOM_211, CUSTOM_212, CUSTOM_213, CUSTOM_214, CUSTOM_215, CUSTOM_216, CUSTOM_217, CUSTOM_218, CUSTOM_219, CUSTOM_220, CUSTOM_221, CUSTOM_222, CUSTOM_223, CUSTOM_224, CUSTOM_225, CUSTOM_226, CUSTOM_227, CUSTOM_228, CUSTOM_229, CUSTOM_230, CUSTOM_231, CUSTOM_232, CUSTOM_233, CUSTOM_234, CUSTOM_235, CUSTOM_236, CUSTOM_237, CUSTOM_238, CUSTOM_239, CUSTOM_240, CUSTOM_241, CUSTOM_242, CUSTOM_243, CUSTOM_244, CUSTOM_245, CUSTOM_246, CUSTOM_247, CUSTOM_248, CUSTOM_249, CUSTOM_250, CUSTOM_251, CUSTOM_252, CUSTOM_253, CUSTOM_254, CUSTOM_255, CUSTOM_256, OTHER_DRUGS, MARIJUANA, OTHER_EDUCATION, CONTINUING_EDUCATION_COLLEGES, HISTORY, K_12, REFERENCE_SITES, SCIENCE_AND_TECHNOLOGY, OTHER_ENTERTAINMENT_AND_RECREATION, ENTERTAINMENT, TELEVISION_AND_MOVIES, MUSIC, STREAMING_MEDIA, RADIO_STATIONS, GAMBLING, OTHER_GAMES, SOCIAL_NETWORKING_GAMES, OTHER_GOVERNMENT_AND_POLITICS, GOVERNMENT, POLITICS, HEALTH, OTHER_ILLEGAL_OR_QUESTIONABLE, COPYRIGHT_INFRINGEMENT, COMPUTER_HACKING, QUESTIONABLE, PROFANITY, MATURE_HUMOR, ANONYMIZER, OTHER_INFORMATION_TECHNOLOGY, TRANSLATORS, IMAGE_HOST, FILE_HOST, SHAREWARE_DOWNLOAD, WEB_BANNERS, WEB_HOST, WEB_SEARCH, PORTALS, SAFE_SEARCH_ENGINE, CDN, OSS_UPDATES, DNS_OVER_HTTPS, OTHER_INTERNET_COMMUNICATION, INTERNET_SERVICES, DISCUSSION_FORUMS, ONLINE_CHAT, EMAIL_HOST, BLOG, P2P_COMMUNICATION, REMOTE_ACCESS, WEB_CONFERENCING, ZSPROXY_IPS, JOB_SEARCH, MILITANCY_HATE_AND_EXTREMISM, OTHER_MISCELLANEOUS, MISCELLANEOUS_OR_UNKNOWN, NEWLY_REG_DOMAINS, NON_CATEGORIZABLE, NEWS_AND_MEDIA, OTHER_RELIGION, TRADITIONAL_RELIGION, CULT, ALT_NEW_AGE, OTHER_SECURITY, ADWARE_OR_SPYWARE, ENCR_WEB_CONTENT, MALICIOUS_TLD, OTHER_SHOPPING_AND_AUCTIONS, SPECIALIZED_SHOPPING, REAL_ESTATE, ONLINE_AUCTIONS, OTHER_SOCIAL_AND_FAMILY_ISSUES, SOCIAL_ISSUES, FAMILY_ISSUES, OTHER_SOCIETY_AND_LIFESTYLE, ART_CULTURE, ALTERNATE_LIFESTYLE, HOBBIES_AND_LEISURE, DINING_AND_RESTAURANT, ALCOHOL_TOBACCO, SOCIAL_NETWORKING, SPECIAL_INTERESTS, SPORTS, TASTELESS, TRAVEL, USER_DEFINED, VEHICLES, VIOLENCE, WEAPONS_AND_BOMBS. | Optional | 
| countries | Destination IP address countries. You can identify destinations based on the location of a server. A list of possible values can be found here https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups/{ipGroupId}-put. Possible values are: ANY, NONE, COUNTRY_AD, COUNTRY_AE, COUNTRY_AF, COUNTRY_AG, COUNTRY_AI, COUNTRY_AL, COUNTRY_AM, COUNTRY_AN, COUNTRY_AO, COUNTRY_AQ, COUNTRY_AR, COUNTRY_AS, COUNTRY_AT, COUNTRY_AU, COUNTRY_AW, COUNTRY_AZ, COUNTRY_BA, COUNTRY_BB, COUNTRY_BD, COUNTRY_BE, COUNTRY_BF, COUNTRY_BG, COUNTRY_BH, COUNTRY_BI, COUNTRY_BJ, COUNTRY_BM, COUNTRY_BN, COUNTRY_BO, COUNTRY_BR, COUNTRY_BS, COUNTRY_BT, COUNTRY_BV, COUNTRY_BW, COUNTRY_BY, COUNTRY_BZ, COUNTRY_CA, COUNTRY_CC, COUNTRY_CD, COUNTRY_CF, COUNTRY_CG, COUNTRY_CH, COUNTRY_CI, COUNTRY_CK, COUNTRY_CL, COUNTRY_CM, COUNTRY_CN, COUNTRY_CO, COUNTRY_CR, COUNTRY_CU, COUNTRY_CV, COUNTRY_CX, COUNTRY_CY, COUNTRY_CZ, COUNTRY_DE, COUNTRY_DJ, COUNTRY_DK, COUNTRY_DM, COUNTRY_DO, COUNTRY_DZ, COUNTRY_EC, COUNTRY_EE, COUNTRY_EG, COUNTRY_EH, COUNTRY_ER, COUNTRY_ES, COUNTRY_ET, COUNTRY_FI, COUNTRY_FJ, COUNTRY_FK, COUNTRY_FM, COUNTRY_FO, COUNTRY_FR, COUNTRY_FX, COUNTRY_GA, COUNTRY_GB, COUNTRY_GD, COUNTRY_GE, COUNTRY_GF, COUNTRY_GH, COUNTRY_GI, COUNTRY_GL, COUNTRY_GM, COUNTRY_GN, COUNTRY_GP, COUNTRY_GQ, COUNTRY_GR, COUNTRY_GS, COUNTRY_GT, COUNTRY_GU, COUNTRY_GW, COUNTRY_GY, COUNTRY_HK, COUNTRY_HM, COUNTRY_HN, COUNTRY_HR, COUNTRY_HT, COUNTRY_HU, COUNTRY_ID, COUNTRY_IE, COUNTRY_IL, COUNTRY_IN, COUNTRY_IO, COUNTRY_IQ, COUNTRY_IR, COUNTRY_IS, COUNTRY_IT, COUNTRY_JM, COUNTRY_JO, COUNTRY_JP, COUNTRY_KE, COUNTRY_KG, COUNTRY_KH, COUNTRY_KI, COUNTRY_KM, COUNTRY_KN, COUNTRY_KP, COUNTRY_KR, COUNTRY_KW, COUNTRY_KY, COUNTRY_KZ, COUNTRY_LA, COUNTRY_LB, COUNTRY_LC, COUNTRY_LI, COUNTRY_LK, COUNTRY_LR, COUNTRY_LS, COUNTRY_LT, COUNTRY_LU, COUNTRY_LV, COUNTRY_LY, COUNTRY_MA, COUNTRY_MC, COUNTRY_MD, COUNTRY_MG, COUNTRY_MH, COUNTRY_MK, COUNTRY_ML, COUNTRY_MM, COUNTRY_MN, COUNTRY_MO, COUNTRY_MP, COUNTRY_MQ, COUNTRY_MR, COUNTRY_MS, COUNTRY_MT, COUNTRY_MU, COUNTRY_MV, COUNTRY_MW, COUNTRY_MX, COUNTRY_MY, COUNTRY_MZ, COUNTRY_NA, COUNTRY_NC, COUNTRY_NE, COUNTRY_NF, COUNTRY_NG, COUNTRY_NI, COUNTRY_NL, COUNTRY_NO, COUNTRY_NP, COUNTRY_NR, COUNTRY_NU, COUNTRY_NZ, COUNTRY_OM, COUNTRY_PA, COUNTRY_PE, COUNTRY_PF, COUNTRY_PG, COUNTRY_PH, COUNTRY_PK, COUNTRY_PL, COUNTRY_PM, COUNTRY_PN, COUNTRY_PR, COUNTRY_PS, COUNTRY_PT, COUNTRY_PW, COUNTRY_PY, COUNTRY_QA, COUNTRY_RE, COUNTRY_RO, COUNTRY_RU, COUNTRY_RW, COUNTRY_SA, COUNTRY_SB, COUNTRY_SC, COUNTRY_SD, COUNTRY_SE, COUNTRY_SG, COUNTRY_SH, COUNTRY_SI, COUNTRY_SJ, COUNTRY_SK, COUNTRY_SL, COUNTRY_SM, COUNTRY_SN, COUNTRY_SO, COUNTRY_SR, COUNTRY_ST, COUNTRY_SV, COUNTRY_SY, COUNTRY_SZ, COUNTRY_TC, COUNTRY_TD, COUNTRY_TF, COUNTRY_TG, COUNTRY_TH, COUNTRY_TJ, COUNTRY_TK, COUNTRY_TM, COUNTRY_TN, COUNTRY_TO, COUNTRY_TL, COUNTRY_TR, COUNTRY_TT, COUNTRY_TV, COUNTRY_TW, COUNTRY_TZ, COUNTRY_UA, COUNTRY_UG, COUNTRY_UM, COUNTRY_US, COUNTRY_UY, COUNTRY_UZ, COUNTRY_VA, COUNTRY_VC, COUNTRY_VE, COUNTRY_VG, COUNTRY_VI, COUNTRY_VN, COUNTRY_VU, COUNTRY_WF, COUNTRY_WS, COUNTRY_YE, COUNTRY_YT, COUNTRY_RS, COUNTRY_ZA, COUNTRY_ZM, COUNTRY_ME, COUNTRY_ZW, COUNTRY_AX, COUNTRY_GG, COUNTRY_IM, COUNTRY_JE, COUNTRY_BL, COUNTRY_MF. | Optional | 
| is_non_editable | If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified. Possible values are: True, False. Default is False. | Optional | 
| operation | if set to append, the IPs in the addresses argument will be appended to the  destination group , if set to remove the IPs will be removed from the group and if it is replace the current IPs in the destination group will be dropped and replaced by the IPs in the addresses argument. default is append. Possible values are: append, remove, replace. Default is append. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.IPDestinationGroup.ID | number | Unique identifier for the destination IP group. | 
| Zscaler.IPDestinationGroup.Name | string | Destination IP group name. | 
| Zscaler.IPDestinationGroup.Type | string | Destination IP group type \(i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs\). | 
| Zscaler.IPDestinationGroup.Description | string | Destination IP group description. | 
| Zscaler.IPDestinationGroup.Addresses | string | Destination IP addresses, FQDNs, or wildcard FQDNs added to the group. | 
| Zscaler.IPDestinationGroup.IpCategories | string | Destination IP address URL categories. You can identify destinations based on the URL category of the domain. | 
| Zscaler.IPDestinationGroup.Countries | string | Destination IP address countries. You can identify destinations based on the location of a server. | 
