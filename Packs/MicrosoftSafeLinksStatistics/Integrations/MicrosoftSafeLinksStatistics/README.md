Use the integration to get statistics from the O365 service on Safe Links clicks
This integration was integrated and tested with Microsoft Office 365
## Configure Microsoft SafeLinks Statistics on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft SafeLinks Statistics.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Exchange Online URL | True |
    | Email (Password for basic authentication only) | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### o365-safelinks-stats-auth-start
***
Starts the OAuth2.0 authorization process.


#### Base Command

`o365-safelinks-stats-auth-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### o365-safelinks-stats-auth-complete
***
Completes the OAuth2.0 authorization process.


#### Base Command

`o365-safelinks-stats-auth-complete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### o365-safelinks-stats-auth-test
***
Tests the OAuth2.0 authorization process.


#### Base Command

`o365-safelinks-stats-auth-test`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### o365-safelinks-stats-search
***
Use the to search safelinks statistics in o365


#### Base Command

`o365-safelinks-stats-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The start date of the date range or a date range (3 days, 1 year, etc.). Entries are stored in the unified audit log in Coordinated Universal Time (UTC). If you specify a date/time value without a time zone, the value is in UTC. Default is 7 days. | Optional | 
| end_date | The end date of the date range. Entries are stored in the unified audit log in Coordinated Universal Time (UTC). If you specify a date/time value without a time zone, the value is in UTC. If empty, wll take current time. | Optional | 
| click_id | The ClickId parameter filters the results by the URL that was scanned in the message. Each URL is represented as a GUID value. | Optional | 
| recipient_address | The RecipientAddress parameter filters the results by the recipient's email address. You can specify multiple values separated by commas. | Optional | 
| url_or_domain | The UrlOrDomain parameter filters the results by the specified URL or domain value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365SafeLinksStats.ClickedTime | date | Time when link was clicked | 
| O365SafeLinksStats.Recipient | string | Recipient that had received the link | 
| O365SafeLinksStats.URL | string | URL that was clicked | 
| O365SafeLinksStats.UrlBlocked | string | The URL was detected as malicious by Safe Links \(only the initial block, not subsequent clicks\), or the user clicked the URL while the scan in progress \(users are taken to a notification page that asks them to try again after the scan is complete\). | 
| O365SafeLinksStats.UrlClicked | string | The URL is blocked, but the applicable Safe Links policy has the DoNotAllowClickThrough parameter value $false \(click through is allowed\). Updated policies aren't applied to existing messages that have already been scanned. New or updated policies are applied to new messages that were received after the policy is applied to the mailbox. | 
| O365SafeLinksStats.ClickAction | string | Click Action: The action of a specific click. Possible values are: • None: We were unable to capture the verdict for the URL. The user might have clicked through the URL. • Allowed: The user was allowed to navigate to the URL. • Blocked: The User was blocked from navigating to the URL. • Pending verdict: The user was presented with the detonation pending page. • Blocked overridden: The user was blocked from navigating to the URL; however, the user overrode the block to navigate to the URL. • Pending verdict bypassed: The user presented with the detonation page; however, the user overrode the page to navigate to the URL. • Error: The user was presented with the error page. This can also mean there was an error in capturing the verdict. • Failure: There was unknown exception while capturing the verdict. The user might have clicked through the URL. | 
| O365SafeLinksStats.Workload | string | Workload of the link being delivered | 
| O365SafeLinksStats.AppName | string | Application Name | 


#### Command Example
``` ```

#### Human Readable Output


