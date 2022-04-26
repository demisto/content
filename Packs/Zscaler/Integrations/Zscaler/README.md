Zscaler is a cloud security solution built for performance and flexible scalability. This integration enables you to manage URL and IP address allow lists and block lists, manage and update categories, get Sandbox reports, and manually log in, log out, and activate changes in a Zscaler session.
This integration was integrated and tested with version xx of Zscaler

## Configure Zscaler Internet Access on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zscaler Internet Access.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Cloud Name (i.e., https://admin.zscalertwo.net) |  | True |
    | Username |  | True |
    | Password |  | True |
    | API Key |  | True |
    | Auto Logout | If enabled, the integration will log out after executing each command. | False |
    | Auto Activate Changes | If enabled, the integration will activate the command changes after each execution. If disabled, use the 'zscaler-activate-changes' command to activate Zscaler command changes. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| URL.urlClassifications | string | The classification of the URL. For example, MUSIC or WEB_SEARCH. | 
| URL.urlClassificationsWithSecurityAlert | string | The classifications of the URLs that have security alerts. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that tagged the URL as malicious. | 
| URL.Malicious.Description | string | For malicious URLs, the reason the vendor tagged the URL as malicious. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

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
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 

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
### zscaler-undo-blacklist-ip
***
Removes the specified IP addresses from the allow list.


#### Base Command

`zscaler-undo-blacklist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to remove from the allow list. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.
### zscaler-blacklist-ip
***
Adds the specified IP addresses to the allow list.


#### Base Command

`zscaler-blacklist-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to add to the allow list. For example, 8.8.8.8,1.2.3.4. | Required | 


#### Context Output

There is no context output for this command.
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

### zscaler-get-categories
***
Retrieves a list of all categories.


#### Base Command

`zscaler-get-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| displayURL | Whether to display the URLs of each category in the War Room. URLs will always be returned to the Context Data. Possible values are: true, false. Default is false. | Optional | 
| custom_categories_only | Whether to retrieve only custom categories to the War Room. Possible values are: true, false. Default is false. | Optional | 
| get_ids_and_names_only | Whether to retrieve only a list containing URL category IDs and names. Even if *displayURL* is set to true, URLs will not be returned. Please note - the API does not support the combination of custom_only and get_ids_and_names_only. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Category.ID | string | The ID of the category. | 
| Zscaler.Category.CustomCategory | boolean | True, if the category is a custom category. Otherwise, false. | 
| Zscaler.Category.URL | string | The URL of the category. | 
| Zscaler.Category.Description | string | The description of the category. | 
| Zscaler.Category.Name | string | The name of the category. | 

### zscaler-get-blacklist
***
Retrieves the Zscaler default block list.


#### Base Command

`zscaler-get-blacklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter results by URL or IP objects. Possible values are: url, ip. | Optional | 
| query | Query (Python regular expression) to match against. For example, 8.*.*.8. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Blacklist | string | The Zscaler block list. | 

### zscaler-get-whitelist
***
Retrieves the Zscaler default allow list.


#### Base Command

`zscaler-get-whitelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zscaler.Whitelist | string | The Zscaler allow list. | 

### zscaler-sandbox-report
***
Retrieves a full or summary report of the file that was analyzed by Sandbox. The file is represented by the specified MD5 hash.


#### Base Command

`zscaler-sandbox-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The MD5 hash of a file. | Required | 
| details | The type of report. Possible values are 'full' or 'summary'. Default is 'full'. Possible values are: full, summary. Default is full. | Optional | 


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

### zscaler-login
***
Manually create a Zscaler login session. This command will also try to log out of the previous session.


#### Base Command

`zscaler-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### zscaler-logout
***
Logs out of the current Zscaler session.


#### Base Command

`zscaler-logout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### zscaler-activate-changes
***
Activates the changes executed by other Zscaler commands in this session.


#### Base Command

`zscaler-activate-changes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### zscaler-url-quota
***
Gets information on the number of unique URLs that are currently provisioned for your organization as well as how many URLs you can add before reaching that number.


#### Base Command

`zscaler-url-quota`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


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
| id | The unique identifer for the user. | Required | 
| user | New user information. Docs: https://help.zscaler.com/zia/api#/User%20Management/updateUser. | Required | 


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