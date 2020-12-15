Use the Zscaler integration to block manage domains using whitelists and blacklists..

For the integration to work properly, the Zscaler user must have admin permissions.

Category ID is the same as the category name, except all letters are capitalized and each word is separated with an underscore instead of spaces. For example, if the category name is Other Education, then the Category ID is OTHER_EDUCATION.

A custom category ID has the format `CUSTOM_01`, which is not indicative of the category. Use the `zscaler-get-categories` command to get a custom category and its configured name.

## Configure Zscaler on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zscaler.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| cloud | Cloud Name \(i.e., https://admin.zscalertwo.net\) | True |
| credentials | Credentials | True |
| key | API Key | True |
| auto_logout | Auto Logout | False |
| auto_activate | Auto Activate Changes | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### zscaler-blacklist-url
***
Adds the specified URLs to the blacklist.


#### Base Command

`zscaler-blacklist-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to blacklist. For example, snapchat.com,facebook.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-blacklist-url url=phishing.com,malware.net```

#### Human Readable Output
Added the following URLs to the blacklist successfully:
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
| url | A comma-separated list of URLs for which to look up the classification.  For example, abc.com,xyz.com. The maximum number of URLs per call is 100. A URL cannot exceed 1024 characters. If there are multiple URLs, set the 'multiple' argument to 'true'. | Optional | 
| multiple | Whether there are multiple URLs in the 'url' argument. If a URL contains commas, set this argument to 'false' and enter the single URL as the 'url' argument. Default is 'true'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL that was searched. | 
| URL.Address | string | The URL that was searched. | 
| URL.urlClassifications | string | The classification of the URL. For example, MUSIC or WEB_SEARCH. | 
| URL.urlClassificationsWithSecurityAlert | string | The classifications of the URLs that have security alerts. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that tagged the URL as malicious. | 
| URL.Malicious.Description | string | For malicious URLs, the reason the vendor tagged the URL as malicious. | 
| DBotScore.Indicator | string | The URL that was tested. | 
| DBotScore.Type | string | The URL type. | 
| DBotScore.Vendor | string | The vendor that calculated the DBot score. | 
| DBotScore.Score | number | The actual DBot score. | 


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
| IP.ipClassifications | string | The classification of the IP address. For example, MUSIC or WEB_SEARCH. | 
| IP.iplClassificationsWithSecurityAlert | string | Classifications that have a security alert for the IP address. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that tagged the IP address as malicious. | 
| IP.Malicious.Description | string | For malicious IP addresses, the reason the vendor tagged the IP address as malicious. | 
| DBotScore.Indicator | string | The IP address that was tested. | 
| DBotScore.Type | string | The IP address type. | 
| DBotScore.Vendor | string | The vendor used to calculate the DBot score. | 
| DBotScore.Score | number | The actual DBot score. | 


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
Removes the specified URLs from the blacklist.


#### Base Command

`zscaler-undo-blacklist-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to remove from the blacklist. For example, snapchat.com,facebook.com. | Required | 


#### Context Output

There is no context output for this command.


### zscaler-whitelist-url
***
Adds the specified URLs to the whitelist.


#### Base Command

`zscaler-whitelist-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to add to the whitelist. For example, snapchat.com,facebook.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-whitelist-url url=phising.com,malware.net```

#### Human Readable Output
Added the following URLs to the whitelist successfully:
phishing.com
malware.net


### zscaler-undo-whitelist-url
***
Removes the specified URLs from the whitelist.


#### Base Command

`zscaler-undo-whitelist-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to remove from the whitelist. For example, snapchat.com,facebook.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-undo-whitelist-url url=phising.com,malware.net```

#### Human Readable Output
Removed the following URLs from the whitelist successfully:
phishing.com
malware.net


### zscaler-undo-whitelist-ip
***
Removes the specified IP addresses from the whitelist.


#### Base Command

`zscaler-undo-whitelist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to remove from the whitelist. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-undo-whitelist-ip ip=2.2.2.2,3.3.3.3```

#### Human Readable Output
Removed the following IP addresses from the whitelist successfully:
2.2.2.2
3.3.3.3


### zscaler-whitelist-ip
***
Adds the specified IP address to the whitelist.


#### Base Command

`zscaler-whitelist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to add to the whitelist. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-whitelist-ip ip=2.2.2.2,3.3.3.3```

#### Human Readable Output
Added the following IP addresses to the whitelist successfully:
2.2.2.2
3.3.3.3

### zscaler-undo-blacklist-ip
***
Removes the specified IP addresses from the blacklist.


#### Base Command

`zscaler-undo-blacklist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to remove from the blacklist. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-undo-blacklist-ip ip=2.2.2.2,3.3.3.3```


#### Human Readable Output
Removed the following IP addresses from the blacklist successfully:
2.2.2.2
3.3.3.3


### zscaler-blacklist-ip
***
Adds the specified IP addresses to the blacklist.


#### Base Command

`zscaler-blacklist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to add to the blacklist. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!zscaler-blacklist-ip ip=2.2.2.2,3.3.3.3```


#### Human Readable Output
Added the following IP addresses to the blacklist successfully:
2.2.2.2
3.3.3.3


### zscaler-category-add-url
***
Adds URLs to the specified category.


#### Base Command

`zscaler-category-add-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to add the specified URLs to. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| url | A comma-separated list of URLs to add to the specified category. For example, pandora.com,spotify.com. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 


#### Command Example
```!zscaler-category-add-url category-id=MUSIC url=demisto.com,apple.com```

#### Context example
```json
{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "MUSIC_DESC",
        "ID": "MUSIC",
        "URL": [
            "demisto.com",
            "apple.com"
        ]
      }
    }
}
```


#### Human Readable Output
Added the following URL addresses to category MUSIC:

*   demisto.com
*   apple.com


### zscaler-category-add-ip
***
Adds IP address to the specified category.


#### Base Command

`zscaler-category-add-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to add the specified IP addresses to. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| ip | A comma-separated list of IP address to add to the specified category. For example, 1.2.3.4,8.8.8.8. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category | 


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

*   1.2.3.4
*   8.8.8.8

### zscaler-category-remove-url
***
Removes URLs from the specified category.


#### Base Command

`zscaler-category-remove-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to remove the specified URLs from. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| url | A comma-separated list of URLs to remove from the specified category. For example, pandora.com,spotify.com. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.URL | string | The URL of the category. | 

#### Command Example
`!zscaler-category-remove-url category-id=MUSIC url=apple.com`

#### Context Example
```json
{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "MUSIC_DESC",
        "ID": "MUSIC",
        "URL": [
            "demisto.com"
        ]
      }
    }
}
```

##### Human Readable Output

Removed the following URL addresses to category MUSIC:

*   apple.com

### zscaler-category-remove-ip
***
Removes IP address from the specified category.


#### Base Command

`zscaler-category-remove-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category-id | The ID of the category to remove the specified IP addresses from. For example, RADIO_STATIONS. You can retrieve the category IDs by running the 'zscaler-get-categories' command. | Required | 
| ip | A comma-separated list of IP addresses to remove from the specified category. For example, 1.2.3.4,8.8.8.8. | Required | 


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
```json
{
    "Zscaler": {
      "Category": {
        "CustomCategory": false,
        "Description": "REFERENCE_SITES_DESC",
        "ID": "REFERENCE_SITES",
        "URL": [
            "8.8.8.8"
        ]
      }
    }
}
```

##### Human Readable Output

Removed the following IP addresses to category REFERENCE\_SITES:

*   1.2.3.4

### zscaler-get-categories
***
Retrieves a list of all categories.


#### Base Command

`zscaler-get-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| displayURL | Whether to display the URLs of each category in the War Room. Default is 'false'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.URL | string | The URL of the category. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.Name | string | The name of the category. | 


#### Command Example
```!zscaler-get-categories```

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
      "CustomCategory":"true"
   }
}
```

#### Human Readable Output
|CustomCategory|Description|ID|Name|URL|
|--- |--- |--- |--- |--- |
|false|INTERNET_SERVICES_DESC|INTERNET_SERVICES||google.com,facebook.com|
|true||CUSTOM_01|CustomCategory|demisto.com,apple.com|


### zscaler-get-blacklist
***
Retrieves the Zscaler default blacklist.


#### Base Command

`zscaler-get-blacklist`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Blacklist | string | The Zscaler blacklist. | 


#### Command Example
```!zscaler-get-blacklist```

#### Context Example
```json
{
    "Zscaler": {
        "Blacklist": [
            "malicious.com,
            "bad.net"
        ]
    }
}
```

#### Human Readable Output
Zscaler blacklist

*   malicious.com
*   bad.net

### zscaler-get-whitelist
***
Retrieves the Zscaler default whitelist.


#### Base Command

`zscaler-get-whitelist`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Whitelist | string | The Zscaler whitelist. | 


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

*   demisto.com
*   apple.net


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
[![image](https://user-images.githubusercontent.com/44546251/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png)](https://user-images.githubusercontent.com/44546251/56854828-8a921480-6945-11e9-8784-cb55e6c7d83e.png)

[![image](https://user-images.githubusercontent.com/44546251/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png)](https://user-images.githubusercontent.com/44546251/56854735-291d7600-6944-11e9-8c05-b917cc25e322.png)

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
