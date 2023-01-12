This integration fetches indicators from ThreatConnect.
This integration was integrated and tested with version 3 of ThreatConnect Feed.

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
    | Base URL | The API URL. | True |
    | Access ID | The API ID key | True |
    | Secret key | The secret key for the API. | True |
    | Access ID | API - Access ID | True |
    | Secret key | API - Secret key | True |
    | Tags to filter results by | A comma-separated list of tags to filter by. | False |
    | Owners | A comma-separated list of owners to fetch indicators from. | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Feed Fetch Interval | The time interval we send request to fetch indicators. | False |
    | Trust any certificate (not secure) | Whether to trust any certificate. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Tags | Supports CSV values. | False |
    | Indicator types | Fetch specific ThreatConnect indicator types. Default value is "All". | False |
    | Group type | Fetch specific ThreatConnect group types. Default value is "All". | False |
    | Active Indicators Only | Fetch active only indicators when true. Default is "True". | False |
    | Create Relationships | Fetch related indicators. Default is "False". | False |
    | Indicator Query | Filter results using ThreatConnect Query Language \(TQL\). For more information, see the ThreatConnect documentation https://training.threatconnect.com/learn/article/using-threatconnect-query-language-tql-kb-article | False |
    | Confidence Threshold | Minimal confidence value to fetch indicators by \(an integer between 0 to 100\). Note: this parameter is not relevant for groups. | False |
    | Threat Assess Score Threshold | Minimal threat assess score value to fetch indicators by \(an integer between 0 to 1000\).  Note: this parameter is not relevant for groups. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tc-get-indicators
***
Gets indicators from ThreatConnect.


#### Base Command

`tc-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owners | Comma-separated list of owners to fetch indicators from. (If not specified will retrieve only indicators owned by the account. If you supply this argument, it overwrites the "Owners" parameter.). | Optional | 
| limit | The maximum number of indicators to retrieve. Default is 50. | Optional | 
| offset | The index of the first indicator to fetch. Possible values are: . Default is 0. | Optional | 
| tql_query | Filter results using ThreatConnect Query Language (TQL), will override all other arguments. For more information, see the ThreatConnect documentation https://training.threatconnect.com/learn/article/using-threatconnect-query-language-tql-kb-article. | Optional | 
| indicator_type | Comma-separated list that will allow filtering of the retrieved indicators. Possible values are: All, EmailAddress, File, Host, URL, ASN, CIDR, Mutex, Registry Key, Address. | Optional | 
| active_indicators | If true, fetches only active indicators. Possible values are: true, false. Default is true. | Optional | 
| confidence | This will fetch indicators with confidence of “greater than” the (integer) input. | Optional | 
| threat_assess_score | An integer that will determine the threshold (an integer between 0 to 1000). | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!tc-get-indicators limit=1 offset=0 indicator_type=URL active_indicators=true```
#### Human Readable Output

>### ThreatConnect Feed - Indicators
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2022-09-27T17:20:19Z<br/>updateddate: 2022-09-27T17:20:19Z<br/>description: This indicator appears in a post from VirIT.<br/>name: name<br/>address: address<br/>reportedby: Technical Blogs and Reports | id: 98590287<br/>ownerName: Technical Blogs and Reports<br/>dateAdded: 2022-09-27T17:20:19Z<br/>webLink: link<br/>type: URL<br/>lastModified: 2022-09-27T17:20:19Z<br/>rating: 3.0<br/>confidence: 70<br/>source: source<br/>description: This indicator appears in a post from VirIT.<br/>summary: address/<br/>privateFlag: false<br/>active: true<br/>activeLocked: false<br/>text: address |  | 0 | URL | address |

#### Command Example
```!tc-get-indicators limit=2 offset=0```
#### Human Readable Output
>|rawJSON|score|type|value|
>|---|---|---|---|
>| id: Indicator01 | 2 | IP | 8.8.8.8 |
>| id: Indicator02 | 3 | IP | 8.8.4.4 |

### tc-get-owners
***
Gets available indicators owners.


#### Base Command

`tc-get-owners`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Human Readable Output
>### ThreatConnect Feed - Owners
>|id|name|type|
>|---|---|---|
>| 10303 | NAME-01 | Organization |
>| 10666 | NAME-02 | Source |