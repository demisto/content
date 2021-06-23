This integration fetches indicators from ThreatConnect.
This integration was integrated and tested with version 1.1.8 of ThreatConnect Feed.

## ThreatConnect Feed HMAC credentials
1. On the top navigation bar, hover the cursor over the Settings icon and select Org Settings from the dropdown menu.
2. Click the Create API User button on the Membership tab of the Organization Settings screen, and the API User Administration window will be displayed.
3. Fill up the following parts of the form:
    - First Name: Enter the API user’s first name.
    - Last Name: Enter the API user’s last name.
    - Organization Role: Use the dropdown menu to select an Organization role for the user.
    - Include in Observations and False Positives: Check this box to allow data provided by the API user to be included in observation and false-positive counts.
    - Disabled: Click the checkbox to disable an API user’s account in the event that the Administrator wishes to retain log integrity when the API user no longer requires ThreatConnect access.
4. Record the Secret Key, as it will not be accessible after the window is closed.
5. Click the SAVE button to create the API user account.

For more information - click [here](https://training.threatconnect.com/learn/article/creating-user-accounts-kb-article) (Section - Creating an API User).

## Configure ThreatConnect Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatConnect Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| tc_api_path | Base URL | True |
| api_access_id | Access ID | True |
| api_secret_key | Secret key | True |
| owners | Owners | False |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedTags | Tags | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tc-get-indicators
***
Get indicators from Threatconnect.

#### Base Command

`tc-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owners | Comma seprated list of owners which to fetch indicators from. (If<br/>not specified will retrieve only indicators owned by accout, overwrite integration<br/>parameter)<br/> | Optional |
| limit | The maximum number of indicators to return. | Optional |
| offset | The index of the first indicator to fetch. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example
```!tc-get-indicators limit=2 offset=0```

>#### Human Readable Output

>|rawJSON|score|type|value|
>|---|---|---|---|
>| id: Indicator01 | 2 | IP | 8.8.8.8 |
>| id: Indicator02 | 3 | IP | 8.8.4.4 |


### ThreatConnect Feed - Indicators

### tc-get-owners
***
Get availble indicators owners.


#### Base Command

`tc-get-owners`

#### Input

There are no input arguments for this command.

#### Command Example
```!tc-get-owners```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### ThreatConnect Feed - Owners
>|id|name|type|
>|---|---|---|
>| 10303 | NAME-01 | Organization |
>| 10666 | NAME-02 | Source |

